import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto
import _CryptoExtras
@testable import IdentviaCore

final class PKCETests: XCTestCase {
    func testRFC7636Vector() throws {
        XCTAssertEqual(try PKCE.challenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }
    func testGenerateIsRandomAndValid() throws {
        let a = PKCE.generate(), b = PKCE.generate()
        XCTAssertEqual(a.verifier.count, 43)
        XCTAssertNotEqual(a.verifier, b.verifier)
        XCTAssertEqual(a.challenge, try PKCE.challenge(for: a.verifier))
        XCTAssertThrowsError(try PKCE.challenge(for: "too-short"))
        XCTAssertThrowsError(try PKCE.challenge(for: String(repeating: "a", count: 42) + "!"))
    }
    func testBase64URL() {
        XCTAssertEqual(Data([0xfb, 0xff]).base64URLEncodedString(), "-_8")
        XCTAssertEqual(Data(base64URLEncoded: "-_8"), Data([0xfb, 0xff]))
        XCTAssertNil(Data(base64URLEncoded: "a+b="))
    }
}

final class ConfigTests: XCTestCase {
    func testRedirectRules() throws {
        XCTAssertNoThrow(try RedirectURI.validate("com.example.app:/cb"))
        XCTAssertNoThrow(try RedirectURI.validate("https://app.example.com/cb"))
        XCTAssertNoThrow(try RedirectURI.validate("http://127.0.0.1:8123/cb"))
        for bad in ["myapp://cb", "http://app.example.com/cb", "com.example.app:/cb#x", "javascript:alert(1)", "not a url"] {
            XCTAssertThrowsError(try RedirectURI.validate(bad), bad)
        }
        XCTAssertTrue(RedirectURI.matches(URL(string: "com.example.app:/cb?code=1")!, URL(string: "com.example.app:/cb")!))
        XCTAssertFalse(RedirectURI.matches(URL(string: "com.example.app:/cb2?code=1")!, URL(string: "com.example.app:/cb")!))
        XCTAssertFalse(RedirectURI.matches(URL(string: "https://evil.example/cb")!, URL(string: "https://app.example.com/cb")!))
    }
    func testIssuerAndClient() {
        let p = FakePresenter(FakeIdentvia())
        XCTAssertThrowsError(try IdentviaClient(issuer: "http://id.identvia.com", clientId: "x", redirectURI: testRedirect, presenter: p, store: InMemoryTokenStore()))
        XCTAssertThrowsError(try IdentviaClient(clientId: " ", redirectURI: testRedirect, presenter: p, store: InMemoryTokenStore()))
        XCTAssertEqual(try IdentviaClient(issuer: "https://id.identvia.com/", clientId: "x", redirectURI: testRedirect, presenter: p, store: InMemoryTokenStore()).issuer, "https://id.identvia.com")
    }
}

func make(_ idp: FakeIdentvia = FakeIdentvia(), leeway: TimeInterval = 60) throws -> (IdentviaClient, FakeIdentvia, FakePresenter, InMemoryTokenStore) {
    let p = FakePresenter(idp), s = InMemoryTokenStore()
    let c = try IdentviaClient(issuer: testIssuer, clientId: testClientId, redirectURI: testRedirect, presenter: p, store: s, transport: idp, refreshLeeway: leeway)
    return (c, idp, p, s)
}

func assertThrows<T>(_ f: () async throws -> T, _ check: (IdentviaError) -> Bool, file: StaticString = #filePath, line: UInt = #line) async {
    do { _ = try await f(); XCTFail("expected an error", file: file, line: line) }
    catch let e as IdentviaError { XCTAssertTrue(check(e), "unexpected \(e)", file: file, line: line) }
    catch { XCTFail("unexpected \(error)", file: file, line: line) }
}

func validation(_ needle: String) -> (IdentviaError) -> Bool { { if case .validation(let m) = $0 { return m.contains(needle) }; return false } }
func invalidState(_ e: IdentviaError) -> Bool { if case .invalidState = e { return true }; return false }

final class SignInTests: XCTestCase {
    func testFullFlow() async throws {
        let (c, idp, p, store) = try make()
        let s = try await c.signIn(prompt: "login")
        XCTAssertEqual(s.user.sub, idp.userSub)
        XCTAssertEqual(s.user.email, "ada@example.com")
        let q = Dictionary(uniqueKeysWithValues: URLComponents(url: p.opened[0], resolvingAgainstBaseURL: false)!.queryItems!.map { ($0.name, $0.value!) })
        XCTAssertEqual(q["code_challenge_method"], "S256")
        XCTAssertEqual(q["scope"], "openid email profile offline_access")
        XCTAssertEqual(q["prompt"], "login")
        let values = await store.values
        XCTAssertEqual(Set(values.keys), ["identvia.\(testClientId).session", "identvia.\(testClientId).rt"])
        XCTAssertFalse(values["identvia.\(testClientId).session"]!.contains("rt_"))
        XCTAssertFalse(idp.requests.contains { $0.2.contains("client_secret") })
    }
    func testCancelled() async throws {
        let (c, _, p, store) = try make(); p.cancel = true
        await assertThrows({ try await c.signIn() }) { $0 == .cancelled }
        let v = await store.values; XCTAssertTrue(v.isEmpty)
    }
    func testAccessDenied() async throws {
        let (c, _, p, _) = try make(); p.deny = true
        await assertThrows({ try await c.signIn() }) { $0 == .authorization(error: "access_denied", description: "The user denied access") }
    }
    func testForgedState() async throws {
        let (c, _, p, _) = try make()
        p.tamper = { u in var x = URLComponents(url: u, resolvingAgainstBaseURL: false)!; x.queryItems = x.queryItems!.map { $0.name == "state" ? .init(name: "state", value: "forged") : $0 }; return x.url! }
        await assertThrows({ try await c.signIn() }, invalidState)
    }
    func testOtherRedirect() async throws {
        let (c, _, p, _) = try make()
        p.tamper = { URL(string: $0.absoluteString.replacingOccurrences(of: "com.example.notes:", with: "com.evil.app:"))! }
        await assertThrows({ try await c.signIn() }, invalidState)
    }
    func testIssMixUp() async throws {
        let a = FakeIdentvia(); a.wrongIss = true
        await assertThrows({ try await make(a).0.signIn() }, invalidState)
        let b = FakeIdentvia(); b.omitIss = true
        await assertThrows({ try await make(b).0.signIn() }, invalidState)
    }
    func testNonceReplay() async throws {
        let idp = FakeIdentvia(); idp.forceNonce = "attacker"
        await assertThrows({ try await make(idp).0.signIn() }, validation("nonce"))
    }
    func testCodeReplayFails() async throws {
        let (c, idp, _, _) = try make()
        let (url, tx) = try await c.makeAuthorizationRequest()
        let cb = try idp.authorize(url)
        _ = try await c.completeAuthorization(callback: cb, transaction: tx)
        await assertThrows({ try await c.completeAuthorization(callback: cb, transaction: tx) }) { if case .token(let e, _, 400) = $0 { return e == "invalid_grant" }; return false }
    }
    func testWrongVerifierFails() async throws {
        let (c, idp, _, _) = try make()
        let (url, tx) = try await c.makeAuthorizationRequest()
        let cb = try idp.authorize(url)
        let bad = AuthorizationTransaction(state: tx.state, nonce: tx.nonce, codeVerifier: PKCE.generate().verifier, redirectURI: tx.redirectURI, maxAge: nil)
        await assertThrows({ try await c.completeAuthorization(callback: cb, transaction: bad) }) { if case .token(_, let d, _) = $0 { return d?.contains("PKCE") == true }; return false }
    }
}

final class IDTokenTests: XCTestCase {
    func reject(_ needle: String, header: [String: Any] = ["alg": "RS256", "kid": "k1"], key: _RSA.Signing.PrivateKey? = nil, _ patch: @escaping ([String: Any]) -> [String: Any] = { $0 }) async throws {
        let idp = FakeIdentvia()
        idp.idTokenOverride = { c in signRS256(header, patch(c), key ?? idp.rsa) }
        await assertThrows({ try await make(idp).0.signIn() }, validation(needle))
    }
    func testWrongIssuer() async throws { try await reject("issuer") { var c = $0; c["iss"] = "https://evil.example"; return c } }
    func testWrongAudience() async throws { try await reject("aud") { var c = $0; c["aud"] = "other"; c["azp"] = "other"; return c } }
    func testMultiAudNeedsAzp() async throws { try await reject("azp") { var c = $0; c["aud"] = [testClientId, "other"]; c.removeValue(forKey: "azp"); return c } }
    func testExpired() async throws { try await reject("expired") { var c = $0; c["exp"] = 1000; c["iat"] = 900; return c } }
    func testFutureIat() async throws { try await reject("future") { var c = $0; c["iat"] = Int(Date().timeIntervalSince1970) + 3600; return c } }
    func testMissingSub() async throws { try await reject("sub") { var c = $0; c.removeValue(forKey: "sub"); return c } }
    func testAtHash() async throws { try await reject("at_hash") { var c = $0; c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA"; return c } }
    func testOtherKey() async throws { try await reject("signature", key: try _RSA.Signing.PrivateKey(keySize: .bits2048)) }
    func testUnknownKid() async throws { try await reject("unknown key", header: ["alg": "RS256", "kid": "nope"]) }
    func testAlgNone() async throws {
        let idp = FakeIdentvia()
        idp.idTokenOverride = { c in "\(b64(["alg": "none", "kid": "k1"])).\(b64(c))." }
        await assertThrows({ try await make(idp).0.signIn() }, validation("none"))
    }
    func testHS256Confusion() async throws {
        let idp = FakeIdentvia()
        idp.idTokenOverride = { c in
            let input = "\(b64(["alg": "HS256", "kid": "k1"])).\(b64(c))"
            let p = rsaPrimitives(idp.rsa.publicKey.pkcs1DERRepresentation)
            let mac = HMAC<SHA256>.authenticationCode(for: Data(input.utf8), using: SymmetricKey(data: p.n))
            return "\(input).\(Data(mac).base64URLEncodedString())"
        }
        await assertThrows({ try await make(idp).0.signIn() }, validation("HS256"))
    }
    func testES256Accepted() async throws {
        let idp = FakeIdentvia()
        let ec = P256.Signing.PrivateKey()
        idp.ec = ec
        idp.idTokenOverride = { c in signES256(["alg": "ES256", "kid": "ec1"], c, ec) }
        let s = try await make(idp).0.signIn()
        XCTAssertEqual(s.user.sub, idp.userSub)
    }
    func testKeyRotationRefetchIsRateLimited() async throws {
        let idp = FakeIdentvia()
        let (c, _, _, _) = try make(idp)
        _ = try await c.signIn()
        XCTAssertEqual(idp.jwksFetches, 1)
        // Rotate: new key, new kid. The first unknown kid triggers a refetch (well, rate-limited to 30 s).
        idp.rsa = try _RSA.Signing.PrivateKey(keySize: .bits2048); idp.kid = "k2"
        await assertThrows({ try await c.signIn() }, validation("unknown key"))
        XCTAssertEqual(idp.jwksFetches, 1, "refetch is rate limited within 30 s")
        let (fresh, _, _, _) = try make(idp)
        _ = try await fresh.signIn()
    }
    func testMaxAge() async throws {
        let idp = FakeIdentvia()
        idp.idTokenOverride = { c in var c = c; c["auth_time"] = Int(Date().timeIntervalSince1970) - 7200; return signRS256(["alg": "RS256", "kid": "k1"], c, idp.rsa) }
        await assertThrows({ try await make(idp).0.signIn(maxAge: 60) }, validation("max_age"))
    }
}

final class TokenTests: XCTestCase {
    func testRotationSingleFlight() async throws {
        let (c, idp, _, store) = try make(leeway: 3600)
        _ = try await c.signIn()
        let rt1 = await store.values["identvia.\(testClientId).rt"]
        idp.tokenDelay = 50_000_000
        async let a = c.accessToken(), b = c.accessToken(), d = c.accessToken()
        let r = try await [a, b, d]
        XCTAssertEqual(Set(r).count, 1)
        XCTAssertEqual(idp.requests.filter { $0.1 == "/oauth/token" && $0.2.contains("grant_type=refresh_token") }.count, 1)
        let rt2 = await store.values["identvia.\(testClientId).rt"]
        XCTAssertNotEqual(rt1, rt2)
    }
    func testReuseDetectionSignsOut() async throws {
        let (c, idp, _, store) = try make(leeway: 3600)
        _ = try await c.signIn()
        let old = await store.values["identvia.\(testClientId).rt"]!
        _ = try await c.accessToken()
        // An attacker replays the old refresh token: Identvia revokes the whole family.
        var r = URLRequest(url: URL(string: "\(testIssuer)/oauth/token")!); r.httpMethod = "POST"
        r.httpBody = Data("grant_type=refresh_token&refresh_token=\(old)&client_id=\(testClientId)".utf8)
        _ = try await idp.send(r)
        await assertThrows({ try await c.accessToken() }) { $0 == .loginRequired }
        let v = await store.values; XCTAssertTrue(v.isEmpty)
        let s = try await c.currentSession(); XCTAssertNil(s)
    }
    func testFreshTokenNoRefresh() async throws {
        let (c, idp, _, _) = try make()
        let s = try await c.signIn()
        let at = try await c.accessToken()
        XCTAssertEqual(at, s.tokens.accessToken)
        XCTAssertEqual(idp.requests.filter { $0.1 == "/oauth/token" }.count, 1)
    }
    func testRestoreAndUserinfo() async throws {
        let (c, idp, p, store) = try make()
        _ = try await c.signIn()
        let again = try IdentviaClient(issuer: testIssuer, clientId: testClientId, redirectURI: testRedirect, presenter: p, store: store, transport: idp)
        let s = try await again.currentSession()
        XCTAssertEqual(s?.user.sub, idp.userSub)
        XCTAssertNotNil(s?.tokens.refreshToken)
        let info = try await again.userinfo()
        XCTAssertEqual(info["sub"]?.stringValue, idp.userSub)
    }
    func testSignOut() async throws {
        let (c, idp, p, store) = try make()
        _ = try await c.signIn()
        try await c.signOut(federated: true)
        XCTAssertEqual(idp.revokedFamilies.count, 1)
        let v = await store.values; XCTAssertTrue(v.isEmpty)
        let q = Dictionary(uniqueKeysWithValues: URLComponents(url: p.opened.last!, resolvingAgainstBaseURL: false)!.queryItems!.map { ($0.name, $0.value!) })
        XCTAssertNotNil(q["id_token_hint"])
        XCTAssertEqual(q["post_logout_redirect_uri"], testRedirect)
    }
    func testSessionUpdates() async throws {
        let (c, _, _, _) = try make()
        let stream = await c.sessionUpdates()
        var it = stream.makeAsyncIterator()
        _ = try await c.signIn()
        let first = await it.next()
        XCTAssertNotNil(first!)
        try await c.signOut()
        let second = await it.next()
        XCTAssertNil(second!)
    }
    func testRARNeedsStage5() async throws {
        await assertThrows({ try await make().0.signIn(authorizationDetails: [.agentTask("x")]) }) { if case .unsupported(let m) = $0 { return m.contains("2026-10-21_5") }; return false }
        let idp = FakeIdentvia(); idp.stage5 = true
        let s = try await make(idp).0.signIn(authorizationDetails: [.agentTask("Order groceries", actions: ["order"])])
        XCTAssertEqual(s.tokens.authorizationDetails?.first?["type"]?.stringValue, "agent_task")
        XCTAssertEqual(s.tokens.authorizationDetails?.first?["actions"], ["order"])
    }
}
