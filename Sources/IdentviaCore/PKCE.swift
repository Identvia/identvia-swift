import Foundation

/// Proof Key for Code Exchange (RFC 7636), S256 only. Identvia rejects `plain`.
public struct PKCE: Sendable, Equatable, Codable {
    public let verifier: String
    public let challenge: String
    public var method: String { "S256" }

    /// A fresh verifier with 256 bits of entropy (43 chars).
    public static func generate() -> PKCE {
        let v = randomToken(bytes: 32)
        return PKCE(verifier: v, challenge: try! challenge(for: v))
    }

    public static func challenge(for verifier: String) throws -> String {
        let ok = verifier.utf8.allSatisfy { c in
            (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2D || c == 0x2E || c == 0x5F || c == 0x7E
        }
        guard ok, (43...128).contains(verifier.utf8.count) else {
            throw IdentviaError.configuration("A PKCE verifier must be 43-128 unreserved characters.")
        }
        return sha256(verifier).base64URLEncodedString()
    }
}
