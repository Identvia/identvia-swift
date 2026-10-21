import Foundation

/// The signed-in user, from the validated ID token. `sub` is pairwise: stable for your app, different in other apps.
public struct IdentviaUser: Codable, Sendable, Equatable {
    public let sub: String
    public let email: String?
    public let emailVerified: Bool?
    public let name: String?
    public let givenName: String?
    public let familyName: String?
    public let picture: String?
    public let locale: String?
    public let authTime: Date?
    /// All ID token claims.
    public let claims: [String: JSONValue]

    init(claims c: [String: JSONValue]) {
        sub = c["sub"]?.stringValue ?? ""
        email = c["email"]?.stringValue
        emailVerified = c["email_verified"]?.boolValue
        name = c["name"]?.stringValue
        givenName = c["given_name"]?.stringValue
        familyName = c["family_name"]?.stringValue
        picture = c["picture"]?.stringValue
        locale = c["locale"]?.stringValue
        authTime = c["auth_time"]?.doubleValue.map { Date(timeIntervalSince1970: $0) }
        claims = c
    }
}

public struct IDTokenValidationOptions: Sendable {
    public var issuer: String
    public var clientId: String
    public var nonce: String?
    public var maxAge: Int?
    public var accessToken: String?
    public var leeway: TimeInterval = 60
    public var now: Date
}

/// OIDC Core §3.1.3.7 ID token validation.
public enum IDTokenValidator {
    static func validate(_ token: String, _ o: IDTokenValidationOptions, key: (String?, String) async throws -> JWK?) async throws -> [String: JSONValue] {
        let jws = try CompactJWS(token)
        guard let alg = jws.header["alg"]?.stringValue else { throw IdentviaError.validation("ID token has no alg.") }
        guard JWSVerifier.allowed.contains(alg) else { throw IdentviaError.validation("ID token alg \(alg) is not allowed (expected RS256 or ES256; never none or HS*).") }
        if let crit = jws.header["crit"], crit != .null { throw IdentviaError.validation("Unsupported crit header.") }
        let kid = jws.header["kid"]?.stringValue
        guard let k = try await key(kid, alg) else { throw IdentviaError.validation("ID token is signed with an unknown key (kid \(kid ?? "none")).") }
        guard try JWSVerifier.verify(jws, alg: alg, key: k) else { throw IdentviaError.validation("ID token signature is invalid.") }

        let c = jws.payload
        guard c["iss"]?.stringValue == o.issuer else { throw IdentviaError.validation("ID token issuer \(c["iss"]?.stringValue ?? "none") is not \(o.issuer).") }
        guard let sub = c["sub"]?.stringValue, !sub.isEmpty else { throw IdentviaError.validation("ID token has no sub.") }
        let aud: [String]
        switch c["aud"] {
        case .string(let s): aud = [s]
        case .array(let a): aud = a.compactMap(\.stringValue)
        default: aud = []
        }
        guard aud.contains(o.clientId) else { throw IdentviaError.validation("ID token aud does not include this client.") }
        let azp = c["azp"]?.stringValue
        if aud.count > 1 && azp == nil { throw IdentviaError.validation("ID token with several audiences needs azp.") }
        if let azp, azp != o.clientId { throw IdentviaError.validation("ID token azp is another client.") }
        let now = o.now.timeIntervalSince1970
        guard let exp = c["exp"]?.doubleValue else { throw IdentviaError.validation("ID token has no exp.") }
        guard now < exp + o.leeway else { throw IdentviaError.validation("ID token expired.") }
        guard let iat = c["iat"]?.doubleValue else { throw IdentviaError.validation("ID token has no iat.") }
        guard iat <= now + o.leeway else { throw IdentviaError.validation("ID token was issued in the future.") }
        if let expected = o.nonce {
            guard let n = c["nonce"]?.stringValue, constantTimeEquals(n, expected) else { throw IdentviaError.validation("ID token nonce does not match (replay?).") }
        }
        if let maxAge = o.maxAge {
            guard let at = c["auth_time"]?.doubleValue else { throw IdentviaError.validation("max_age was requested but auth_time is missing.") }
            guard now <= at + Double(maxAge) + o.leeway else { throw IdentviaError.validation("auth_time is older than max_age.") }
        }
        if let h = c["at_hash"]?.stringValue, let at = o.accessToken {
            let want = Data(sha256(at).prefix(16)).base64URLEncodedString()
            guard constantTimeEquals(h, want) else { throw IdentviaError.validation("ID token at_hash does not match the access token.") }
        }
        return c
    }
}
