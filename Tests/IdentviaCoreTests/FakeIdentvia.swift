import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto
import _CryptoExtras
@testable import IdentviaCore

let testIssuer = "https://id.identvia.test"
let testClientId = "oid_swift_test"
let testRedirect = "com.example.notes:/oauth/identvia"

/// Reads INTEGERs out of a PKCS#1 RSAPublicKey (test helper).
func rsaPrimitives(_ der: Data) -> (n: Data, e: Data) {
    var i = der.startIndex
    func len() -> Int {
        let b = Int(der[i]); i += 1
        if b < 0x80 { return b }
        var l = 0
        for _ in 0..<(b & 0x7f) { l = (l << 8) | Int(der[i]); i += 1 }
        return l
    }
    precondition(der[i] == 0x30); i += 1; _ = len()
    var out: [Data] = []
    for _ in 0..<2 { precondition(der[i] == 0x02); i += 1; let l = len(); out.append(Data(der[i..<(i + l)]).drop(while: { $0 == 0 })); i += l }
    return (Data(out[0]), Data(out[1]))
}

func b64(_ o: Any) -> String { try! JSONSerialization.data(withJSONObject: o, options: [.sortedKeys]).base64URLEncodedString() }

func signRS256(_ header: [String: Any], _ claims: [String: Any], _ key: _RSA.Signing.PrivateKey) -> String {
    let input = "\(b64(header)).\(b64(claims))"
    let sig = try! key.signature(for: SHA256.hash(data: Data(input.utf8)), padding: .insecurePKCS1v1_5)
    return "\(input).\(sig.rawRepresentation.base64URLEncodedString())"
}

func signES256(_ header: [String: Any], _ claims: [String: Any], _ key: P256.Signing.PrivateKey) -> String {
    let input = "\(b64(header)).\(b64(claims))"
    let sig = try! key.signature(for: Data(input.utf8))
    return "\(input).\(sig.rawRepresentation.base64URLEncodedString())"
}

let sharedRSA = try! _RSA.Signing.PrivateKey(keySize: .bits2048)

/// An in-memory Identvia that enforces the real server's rules.
final class FakeIdentvia: HTTPTransport, @unchecked Sendable {
    let lock = NSLock()
    var rsa = sharedRSA
    var ec: P256.Signing.PrivateKey?
    var kid = "k1"
    var stage5 = false
    var redirectURIs = [testRedirect]
    var forceNonce: String?
    var wrongIss = false, omitIss = false
    var idTokenOverride: (([String: Any]) -> String)?
    let userSub = "pw_" + randomToken(bytes: 9)
    var codes: [String: [String: Any]] = [:]
    var refresh: [String: [String: Any]] = [:]
    var revokedFamilies = Set<String>()
    var access: [String: String] = [:]  // at -> family
    var requests: [(String, String, String)] = []  // method, path, body
    var jwksFetches = 0
    var tokenDelay: UInt64 = 0

    var discovery: [String: Any] {
        var d: [String: Any] = [
            "issuer": testIssuer,
            "authorization_endpoint": "\(testIssuer)/oauth/authorize",
            "token_endpoint": "\(testIssuer)/oauth/token",
            "userinfo_endpoint": "\(testIssuer)/oauth/userinfo",
            "jwks_uri": "\(testIssuer)/oauth/jwks.json",
            "revocation_endpoint": "\(testIssuer)/oauth/revoke",
            "end_session_endpoint": "\(testIssuer)/oauth/logout",
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "authorization_response_iss_parameter_supported": true,
            "subject_types_supported": ["pairwise"],
        ]
        if stage5 { d["authorization_details_types_supported"] = ["agent_task"] }
        return d
    }

    var jwks: [String: Any] {
        let p = rsaPrimitives(rsa.publicKey.pkcs1DERRepresentation)
        var keys: [[String: Any]] = [["kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": p.n.base64URLEncodedString(), "e": p.e.base64URLEncodedString()]]
        if let ec {
            let raw = ec.publicKey.rawRepresentation
            keys.append(["kty": "EC", "kid": "ec1", "use": "sig", "alg": "ES256", "crv": "P-256", "x": raw.prefix(32).base64URLEncodedString(), "y": raw.suffix(32).base64URLEncodedString()])
        }
        return ["keys": keys]
    }

    func idToken(sub: String, nonce: String?, at: String) -> String {
        let now = Int(Date().timeIntervalSince1970)
        var c: [String: Any] = ["iss": testIssuer, "sub": sub, "aud": testClientId, "azp": testClientId, "iat": now, "exp": now + 600, "auth_time": now,
                                "email": "ada@example.com", "email_verified": true, "name": "Ada",
                                "at_hash": Data(SHA256.hash(data: Data(at.utf8))).prefix(16).base64URLEncodedString()]
        if let nonce { c["nonce"] = nonce }
        if let o = idTokenOverride { return o(c) }
        return signRS256(["alg": "RS256", "kid": kid, "typ": "JWT"], c, rsa)
    }

    private func issue(sub: String, scope: String, nonce: String?, family: String? = nil) -> [String: Any] {
        let at = "at_" + randomToken(bytes: 18)
        var out: [String: Any] = ["token_type": "Bearer", "access_token": at, "expires_in": 600, "scope": scope]
        let scopes = scope.split(separator: " ")
        if scopes.contains("openid") && family == nil { out["id_token"] = idToken(sub: sub, nonce: nonce, at: at) }
        var fam = family ?? ""
        if scopes.contains("offline_access") {
            if fam.isEmpty { fam = randomToken(bytes: 6) }
            let rt = "rt_" + randomToken(bytes: 18)
            refresh[rt] = ["family": fam, "used": false, "sub": sub, "scope": scope]
            out["refresh_token"] = rt
        }
        access[at] = fam
        return out
    }

    func form(_ body: Data?) -> [String: String] {
        var out: [String: String] = [:]
        for pair in String(decoding: body ?? Data(), as: UTF8.self).split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1).map { String($0).removingPercentEncoding ?? "" }
            out[kv[0]] = kv.count > 1 ? kv[1] : ""
        }
        return out
    }

    func send(_ r: URLRequest) async throws -> (Data, HTTPURLResponse) {
        if r.url?.path == "/oauth/token", tokenDelay > 0 { try await Task.sleep(nanoseconds: tokenDelay) }
        lock.lock(); defer { lock.unlock() }
        let (status, body) = handle(r)
        let data = (body as? Data) ?? (try! JSONSerialization.data(withJSONObject: body))
        return (data, HTTPURLResponse(url: r.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!)
    }

    private func handle(_ r: URLRequest) -> (Int, Any) {
        let path = r.url!.path
        let f = form(r.httpBody)
        requests.append((r.httpMethod ?? "GET", path, String(decoding: r.httpBody ?? Data(), as: UTF8.self)))
        switch path {
        case "/.well-known/openid-configuration": return (200, discovery)
        case "/oauth/jwks.json": jwksFetches += 1; return (200, jwks)
        case "/oauth/token":
            guard f["client_id"] == testClientId, f["client_secret"] == nil else { return (401, ["error": "invalid_client"]) }
            if f["grant_type"] == "authorization_code" {
                guard let code = f["code"], var c = codes[code], c["used"] as? Bool == false else { return (400, ["error": "invalid_grant"]) }
                c["used"] = true; codes[code] = c
                guard c["redirect_uri"] as? String == f["redirect_uri"] else { return (400, ["error": "invalid_grant"]) }
                guard Data(SHA256.hash(data: Data((f["code_verifier"] ?? "").utf8))).base64URLEncodedString() == c["challenge"] as? String else {
                    return (400, ["error": "invalid_grant", "error_description": "PKCE verification failed"])
                }
                var out = issue(sub: c["sub"] as! String, scope: c["scope"] as! String, nonce: c["nonce"] as? String)
                if let d = c["details"] { out["authorization_details"] = d }
                return (200, out)
            }
            if f["grant_type"] == "refresh_token" {
                guard let rt = f["refresh_token"], var x = refresh[rt], !revokedFamilies.contains(x["family"] as! String) else { return (400, ["error": "invalid_grant"]) }
                if x["used"] as! Bool { revokedFamilies.insert(x["family"] as! String); return (400, ["error": "invalid_grant", "error_description": "Refresh token reuse detected"]) }
                x["used"] = true; refresh[rt] = x
                return (200, issue(sub: x["sub"] as! String, scope: x["scope"] as! String, nonce: nil, family: x["family"] as? String))
            }
            return (400, ["error": "unsupported_grant_type"])
        case "/oauth/userinfo":
            let at = (r.value(forHTTPHeaderField: "Authorization") ?? "").replacingOccurrences(of: "Bearer ", with: "")
            guard let fam = access[at], !revokedFamilies.contains(fam) else { return (401, ["error": "invalid_token"]) }
            return (200, ["sub": userSub, "email": "ada@example.com"])
        case "/oauth/revoke":
            if let t = f["token"], let x = refresh[t] { revokedFamilies.insert(x["family"] as! String) }
            return (200, Data())
        default: return (404, ["error": "not_found"])
        }
    }

    /// The user signs in and approves; returns the redirect Identvia would send.
    func authorize(_ url: URL, deny: Bool = false) throws -> URL {
        lock.lock(); defer { lock.unlock() }
        let q = Dictionary(uniqueKeysWithValues: (URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        guard let ru = q["redirect_uri"], redirectURIs.contains(ru) else { throw IdentviaError.configuration("Invalid redirect") }
        guard q["code_challenge_method"] == "S256", q["nonce"] != nil, let state = q["state"] else { throw IdentviaError.configuration("bad request") }
        var items = [URLQueryItem(name: "state", value: state)]
        if !omitIss { items.append(.init(name: "iss", value: wrongIss ? "https://evil.example" : testIssuer)) }
        if deny {
            items.append(.init(name: "error", value: "access_denied"))
            items.append(.init(name: "error_description", value: "The+user+denied+access"))
        } else {
            let code = "c_" + randomToken(bytes: 18)
            var c: [String: Any] = ["challenge": q["code_challenge"]!, "redirect_uri": ru, "nonce": forceNonce ?? q["nonce"]!, "scope": q["scope"]!, "sub": userSub, "used": false]
            if let d = q["authorization_details"] { c["details"] = try! JSONSerialization.jsonObject(with: Data(d.utf8)) }
            codes[code] = c
            items.append(.init(name: "code", value: code))
        }
        var c = URLComponents(string: ru)!
        c.queryItems = items
        return c.url!
    }
}

final class FakePresenter: AuthSessionPresenter, @unchecked Sendable {
    let idp: FakeIdentvia
    var deny = false, cancel = false
    var tamper: ((URL) -> URL)?
    var opened: [URL] = []
    init(_ idp: FakeIdentvia) { self.idp = idp }

    func authenticate(url: URL, redirectURI: URL, ephemeral: Bool) async throws -> URL {
        opened.append(url)
        if cancel { throw IdentviaError.cancelled }
        if url.path == "/oauth/logout" { return redirectURI }
        let cb = try idp.authorize(url, deny: deny)
        return tamper?(cb) ?? cb
    }
}
