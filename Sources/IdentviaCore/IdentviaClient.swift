import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public let defaultIssuer = "https://id.identvia.com"

/// Sign in with Identvia: authorization code flow with PKCE S256 in the system browser, ID token validation,
/// secure session storage and refresh-token rotation. Public client: never give it a client secret.
public actor IdentviaClient {
    public nonisolated let issuer: String
    public nonisolated let clientId: String
    public nonisolated let redirectURI: URL
    public nonisolated let scopes: [String]
    public nonisolated let ephemeralSession: Bool
    let refreshLeeway: TimeInterval
    let presenter: AuthSessionPresenter
    let store: TokenStore
    let transport: HTTPTransport
    let clock: @Sendable () -> Date

    private var metadata: ProviderMetadata?
    private var jwks: JWKSCache?
    private var cached: IdentviaSession??
    private var refreshTask: Task<IdentviaSession, Error>?
    private var signingIn = false
    private var continuations: [UUID: AsyncStream<IdentviaSession?>.Continuation] = [:]

    public init(
        issuer: String = defaultIssuer,
        clientId: String,
        redirectURI: String,
        scopes: [String] = ["email", "profile", "offline_access"],
        presenter: AuthSessionPresenter,
        store: TokenStore,
        transport: HTTPTransport = URLSessionTransport(),
        ephemeralSession: Bool = false,
        refreshLeeway: TimeInterval = 60,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) throws {
        guard !clientId.trimmingCharacters(in: .whitespaces).isEmpty else { throw IdentviaError.configuration("clientId is required.") }
        self.issuer = try normalizeIssuer(issuer)
        self.clientId = clientId
        self.redirectURI = try RedirectURI.validate(redirectURI)
        var s = ["openid"]
        for x in scopes where !s.contains(x) { s.append(x) }
        self.scopes = s
        self.presenter = presenter
        self.store = store
        self.transport = transport
        self.ephemeralSession = ephemeralSession
        self.refreshLeeway = refreshLeeway
        self.clock = clock
    }

    // MARK: - Discovery

    public func discovery() async throws -> ProviderMetadata {
        if let metadata { return metadata }
        let (status, data) = try await request(URL(string: issuer + "/.well-known/openid-configuration")!)
        guard status == 200, let m = try? snakeDecoder.decode(ProviderMetadata.self, from: data) else {
            throw IdentviaError.network("Discovery failed (\(status)).")
        }
        guard m.issuer == issuer else { throw IdentviaError.validation("Discovery issuer \(m.issuer) is not \(issuer).") }
        if let methods = m.codeChallengeMethodsSupported, !methods.contains("S256") { throw IdentviaError.unsupported("Server does not support PKCE S256.") }
        metadata = m
        jwks = JWKSCache(url: try endpointURL(m.jwksUri), transport: transport, clock: clock)
        return m
    }

    private func endpointURL(_ s: String?) throws -> URL {
        guard let s, let u = URL(string: s), let scheme = u.scheme?.lowercased(),
              scheme == "https" || (scheme == "http" && loopbackHosts.contains(u.host?.lowercased() ?? "")) else {
            throw IdentviaError.unsupported("Endpoint missing or not https: \(s ?? "none")")
        }
        return u
    }

    // MARK: - Sign-in

    /// Builds the authorization URL. Use with `completeAuthorization` if you present the browser yourself.
    public func makeAuthorizationRequest(
        scopes extra: [String]? = nil, prompt: String? = nil, maxAge: Int? = nil, loginHint: String? = nil,
        uiLocales: [String]? = nil, authorizationDetails: [AuthorizationDetail]? = nil
    ) async throws -> (URL, AuthorizationTransaction) {
        let m = try await discovery()
        let pkce = PKCE.generate()
        let tx = AuthorizationTransaction(state: randomToken(), nonce: randomToken(), codeVerifier: pkce.verifier, redirectURI: redirectURI, maxAge: maxAge)
        var s = scopes
        for x in extra ?? [] where !s.contains(x) { s.append(x) }
        var q: [URLQueryItem] = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: clientId),
            .init(name: "redirect_uri", value: redirectURI.absoluteString),
            .init(name: "scope", value: s.joined(separator: " ")),
            .init(name: "state", value: tx.state),
            .init(name: "nonce", value: tx.nonce),
            .init(name: "code_challenge", value: pkce.challenge),
            .init(name: "code_challenge_method", value: "S256"),
        ]
        if let prompt { q.append(.init(name: "prompt", value: prompt)) }
        if let maxAge { q.append(.init(name: "max_age", value: String(maxAge))) }
        if let loginHint { q.append(.init(name: "login_hint", value: loginHint)) }
        if let uiLocales, !uiLocales.isEmpty { q.append(.init(name: "ui_locales", value: uiLocales.joined(separator: " "))) }
        if let details = authorizationDetails, !details.isEmpty {
            let supported = Set(m.authorizationDetailsTypesSupported ?? [])
            for d in details where !supported.contains(d.type) {
                throw IdentviaError.unsupported("authorization_details type \(d.type) needs server 2026-10-21_5+ (not advertised in discovery).")
            }
            let json = try JSONEncoder().encode(details)
            q.append(.init(name: "authorization_details", value: String(decoding: json, as: UTF8.self)))
        }
        var c = URLComponents(url: try endpointURL(m.authorizationEndpoint), resolvingAgainstBaseURL: false)!
        c.queryItems = (c.queryItems ?? []) + q
        // URLComponents leaves "+" unescaped; a server would read it as a space.
        c.percentEncodedQuery = c.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        return (c.url!, tx)
    }

    /// Validates the redirect (redirect URI, state, RFC 9207 iss), redeems the code and validates the ID token.
    public func completeAuthorization(callback: URL, transaction tx: AuthorizationTransaction) async throws -> IdentviaSession {
        let m = try await discovery()
        guard RedirectURI.matches(callback, tx.redirectURI) else { throw IdentviaError.invalidState("The callback is not this app's redirect URI.") }
        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func p(_ n: String) -> String? { items.first { $0.name == n }?.value }
        guard let state = p("state"), constantTimeEquals(state, tx.state) else { throw IdentviaError.invalidState("state does not match this sign-in.") }
        if let iss = p("iss") {
            guard iss == issuer else { throw IdentviaError.invalidState("iss \(iss) is not \(issuer) (mix-up attack?).") }
        } else if m.authorizationResponseIssParameterSupported == true {
            throw IdentviaError.invalidState("iss is missing from the authorization response.")
        }
        if let e = p("error") { throw IdentviaError.authorization(error: e, description: p("error_description")?.replacingOccurrences(of: "+", with: " ")) }
        guard let code = p("code") else { throw IdentviaError.invalidState("No code in the authorization response.") }
        let t = try await tokenRequest([
            ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", tx.redirectURI.absoluteString),
            ("code_verifier", tx.codeVerifier), ("client_id", clientId),
        ])
        guard let idToken = t.idToken else { throw IdentviaError.validation("The token response has no id_token.") }
        let claims = try await validateIDToken(idToken, nonce: tx.nonce, maxAge: tx.maxAge, accessToken: t.accessToken)
        return IdentviaSession(user: IdentviaUser(claims: claims), tokens: t)
    }

    /// Opens the system browser, signs the user in and stores the session.
    @discardableResult
    public func signIn(
        scopes extra: [String]? = nil, prompt: String? = nil, maxAge: Int? = nil, loginHint: String? = nil,
        uiLocales: [String]? = nil, authorizationDetails: [AuthorizationDetail]? = nil
    ) async throws -> IdentviaSession {
        guard !signingIn else { throw IdentviaError.configuration("A sign-in is already in progress.") }
        signingIn = true
        defer { signingIn = false }
        let (url, tx) = try await makeAuthorizationRequest(scopes: extra, prompt: prompt, maxAge: maxAge, loginHint: loginHint, uiLocales: uiLocales, authorizationDetails: authorizationDetails)
        let back = try await presenter.authenticate(url: url, redirectURI: redirectURI, ephemeral: ephemeralSession)
        let s = try await completeAuthorization(callback: back, transaction: tx)
        try await save(s)
        return s
    }

    // MARK: - Session

    private func key(_ n: String) -> String { "identvia.\(clientId).\(n)" }

    /// The stored session, if any. Doesn't hit the network.
    public func currentSession() async throws -> IdentviaSession? {
        if let cached { return cached }
        guard let json = try await store.get(key("session")), var s = try? JSONDecoder().decode(IdentviaSession.self, from: Data(json.utf8)) else {
            cached = .some(nil)
            return nil
        }
        s.tokens.refreshToken = try await store.get(key("rt"))
        cached = s
        return s
    }

    private func save(_ s: IdentviaSession?) async throws {
        cached = .some(s)
        if var s {
            if let rt = s.tokens.refreshToken { try await store.set(key("rt"), rt) } else { try await store.delete(key("rt")) }
            s.tokens.refreshToken = nil  // the refresh token lives in its own item
            try await store.set(key("session"), String(decoding: try JSONEncoder().encode(s), as: UTF8.self))
        } else {
            try await store.delete(key("session"))
            try await store.delete(key("rt"))
        }
        for c in continuations.values { c.yield(s) }
    }

    /// Emits the session whenever it changes (sign-in, refresh, sign-out).
    public func sessionUpdates() -> AsyncStream<IdentviaSession?> {
        let id = UUID()
        let (stream, c) = AsyncStream<IdentviaSession?>.makeStream()
        continuations[id] = c
        c.onTermination = { [weak self] _ in
            guard let self else { return }
            Task { await self.removeContinuation(id) }
        }
        return stream
    }

    private func removeContinuation(_ id: UUID) { continuations[id] = nil }

    /// A valid access token, refreshed (and the refresh token rotated) when it's about to expire.
    /// Concurrent callers share one refresh. Throws `.loginRequired` when the session has ended.
    public func accessToken(forceRefresh: Bool = false) async throws -> String {
        guard let s = try await currentSession() else { throw IdentviaError.loginRequired }
        if !forceRefresh && s.tokens.expiresAt.timeIntervalSince(clock()) > refreshLeeway { return s.tokens.accessToken }
        return try await refresh(s).tokens.accessToken
    }

    private func refresh(_ s: IdentviaSession) async throws -> IdentviaSession {
        if let refreshTask { return try await refreshTask.value }
        let task = Task { () throws -> IdentviaSession in
            guard let rt = s.tokens.refreshToken else {
                try await self.save(nil)
                throw IdentviaError.loginRequired
            }
            let t: TokenSet
            do {
                t = try await self.tokenRequest([("grant_type", "refresh_token"), ("refresh_token", rt), ("client_id", self.clientId)])
            } catch IdentviaError.token(let e, _, _) where e == "invalid_grant" {
                // Expired, revoked, or reused (Identvia then revokes the whole token family).
                try await self.save(nil)
                throw IdentviaError.loginRequired
            }
            var user = s.user
            if let id = t.idToken {
                let c = try await self.validateIDToken(id, nonce: nil, maxAge: nil, accessToken: t.accessToken)
                guard c["sub"]?.stringValue == s.user.sub else { throw IdentviaError.validation("Refreshed ID token is for a different user.") }
                user = IdentviaUser(claims: c)
            }
            let merged = TokenSet(accessToken: t.accessToken, tokenType: t.tokenType, expiresAt: t.expiresAt,
                                  refreshToken: t.refreshToken ?? rt, idToken: t.idToken ?? s.tokens.idToken,
                                  scope: t.scope ?? s.tokens.scope, authorizationDetails: t.authorizationDetails ?? s.tokens.authorizationDetails)
            let n = IdentviaSession(user: user, tokens: merged)
            try await self.save(n)
            return n
        }
        refreshTask = task
        defer { refreshTask = nil }
        return try await task.value
    }

    /// Calls the userinfo endpoint with the current access token and checks `sub`.
    public func userinfo() async throws -> [String: JSONValue] {
        let m = try await discovery()
        let at = try await accessToken()
        var r = URLRequest(url: try endpointURL(m.userinfoEndpoint))
        r.setValue("Bearer \(at)", forHTTPHeaderField: "Authorization")
        let (status, data) = try await send(r)
        guard let o = decodeObject(data) else { throw IdentviaError.network("userinfo returned invalid JSON (\(status)).") }
        guard status == 200 else { throw IdentviaError.token(error: o["error"]?.stringValue ?? "http_\(status)", description: o["error_description"]?.stringValue, status: status) }
        let s = try await currentSession()
        guard let sub = o["sub"]?.stringValue, s == nil || constantTimeEquals(sub, s!.user.sub) else { throw IdentviaError.validation("userinfo is for a different user.") }
        return o
    }

    /// Deletes the local session and revokes the refresh token. `federated: true` also ends the Identvia
    /// browser session (RP-initiated logout), which opens the browser sheet briefly.
    public func signOut(federated: Bool = false, postLogoutRedirectURI: String? = nil) async throws {
        let s = try await currentSession()
        try await save(nil)
        let m = try await discovery()
        if let s, let rev = m.revocationEndpoint, let url = try? endpointURL(rev) {
            let tok = s.tokens.refreshToken ?? s.tokens.accessToken
            var r = URLRequest(url: url)
            r.httpMethod = "POST"
            r.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            r.httpBody = formEncode([("token", tok), ("token_type_hint", s.tokens.refreshToken != nil ? "refresh_token" : "access_token"), ("client_id", clientId)])
            _ = try? await send(r)
        }
        if federated, let es = m.endSessionEndpoint {
            let back = try RedirectURI.validate(postLogoutRedirectURI ?? redirectURI.absoluteString)
            var c = URLComponents(url: try endpointURL(es), resolvingAgainstBaseURL: false)!
            var q = [URLQueryItem(name: "client_id", value: clientId), URLQueryItem(name: "post_logout_redirect_uri", value: back.absoluteString)]
            if let id = s?.tokens.idToken { q.append(.init(name: "id_token_hint", value: id)) }
            c.queryItems = q
            _ = try? await presenter.authenticate(url: c.url!, redirectURI: back, ephemeral: ephemeralSession)
        }
    }

    // MARK: - HTTP

    private func validateIDToken(_ t: String, nonce: String?, maxAge: Int?, accessToken: String?) async throws -> [String: JSONValue] {
        _ = try await discovery()
        let cache = jwks!
        let o = IDTokenValidationOptions(issuer: issuer, clientId: clientId, nonce: nonce, maxAge: maxAge, accessToken: accessToken, now: clock())
        return try await IDTokenValidator.validate(t, o) { kid, alg in try await cache.key(kid: kid, alg: alg) }
    }

    private func tokenRequest(_ fields: [(String, String)]) async throws -> TokenSet {
        let m = try await discovery()
        var r = URLRequest(url: try endpointURL(m.tokenEndpoint))
        r.httpMethod = "POST"
        r.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        r.httpBody = formEncode(fields)
        let (status, data) = try await send(r)
        guard let o = decodeObject(data) else { throw IdentviaError.network("Token endpoint returned invalid JSON (\(status)).") }
        guard status == 200 else {
            throw IdentviaError.token(error: o["error"]?.stringValue ?? "http_\(status)", description: o["error_description"]?.stringValue, status: status)
        }
        guard let at = o["access_token"]?.stringValue, o["token_type"]?.stringValue?.lowercased() == "bearer" else {
            throw IdentviaError.validation("Token response has no Bearer access_token.")
        }
        return TokenSet(accessToken: at, tokenType: "Bearer", expiresAt: clock().addingTimeInterval(o["expires_in"]?.doubleValue ?? 600),
                        refreshToken: o["refresh_token"]?.stringValue, idToken: o["id_token"]?.stringValue, scope: o["scope"]?.stringValue,
                        authorizationDetails: o["authorization_details"]?.arrayValue)
    }

    private func request(_ url: URL) async throws -> (Int, Data) {
        var r = URLRequest(url: url)
        return try await send(r.accepting())
    }

    private func send(_ r: URLRequest) async throws -> (Int, Data) {
        var r = r
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        r.cachePolicy = .reloadIgnoringLocalCacheData
        let (d, res) = try await transport.send(r)
        return (res.statusCode, d)
    }
}

private extension URLRequest {
    mutating func accepting() -> URLRequest { setValue("application/json", forHTTPHeaderField: "Accept"); return self }
}
