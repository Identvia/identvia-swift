import Foundation
import Crypto

extension Data {
    /// RFC 4648 §5 base64url without padding.
    public func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    public init?(base64URLEncoded s: String) {
        guard s.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        if b.count % 4 == 1 { return nil }
        while b.count % 4 != 0 { b += "=" }
        self.init(base64Encoded: b)
    }
}

/// `n` bytes from the system CSPRNG, base64url encoded.
public func randomToken(bytes n: Int = 32) -> String {
    var g = SystemRandomNumberGenerator()
    return Data((0..<n).map { _ in UInt8.random(in: .min ... .max, using: &g) }).base64URLEncodedString()
}

/// Constant-time string comparison (for state, nonce, at_hash).
func constantTimeEquals(_ a: String, _ b: String) -> Bool {
    let x = Array(a.utf8), y = Array(b.utf8)
    guard x.count == y.count else { return false }
    var d: UInt8 = 0
    for i in 0..<x.count { d |= x[i] ^ y[i] }
    return d == 0
}

func sha256(_ s: String) -> Data { Data(SHA256.hash(data: Data(s.utf8))) }

/// application/x-www-form-urlencoded body.
func formEncode(_ fields: [(String, String)]) -> Data {
    var allowed = CharacterSet.alphanumerics
    allowed.insert(charactersIn: "-._~")
    func e(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: allowed) ?? "" }
    return Data(fields.map { "\(e($0.0))=\(e($0.1))" }.joined(separator: "&").utf8)
}
