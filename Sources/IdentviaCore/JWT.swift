import Foundation
import Crypto
import _CryptoExtras
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A JSON Web Key from the Identvia JWKS.
public struct JWK: Codable, Sendable, Equatable {
    public let kty: String
    public let kid: String?
    public let use: String?
    public let alg: String?
    public let n: String?
    public let e: String?
    public let crv: String?
    public let x: String?
    public let y: String?

    public init(kty: String, kid: String?, use: String? = "sig", alg: String?, n: String? = nil, e: String? = nil, crv: String? = nil, x: String? = nil, y: String? = nil) {
        self.kty = kty; self.kid = kid; self.use = use; self.alg = alg; self.n = n; self.e = e; self.crv = crv; self.x = x; self.y = y
    }
}

struct JWKSet: Codable { let keys: [JWK] }

/// A compact JWS split into its parts. Doesn't verify anything.
struct CompactJWS {
    let header: JSONObject
    let payload: JSONObject
    let signingInput: Data
    let signature: Data

    init(_ token: String) throws {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { throw IdentviaError.validation("ID token is not a compact JWS.") }
        guard let h = Data(base64URLEncoded: parts[0]).flatMap(decodeObject),
              let p = Data(base64URLEncoded: parts[1]).flatMap(decodeObject),
              let s = Data(base64URLEncoded: parts[2]) else {
            throw IdentviaError.validation("ID token is malformed.")
        }
        header = h; payload = p; signature = s
        signingInput = Data("\(parts[0]).\(parts[1])".utf8)
    }
}

enum JWSVerifier {
    static let allowed: Set<String> = ["RS256", "ES256"]

    static func verify(_ jws: CompactJWS, alg: String, key: JWK) throws -> Bool {
        if let a = key.alg, a != alg { throw IdentviaError.validation("Key \(key.kid ?? "?") is for \(a), not \(alg).") }
        if let u = key.use, u != "sig" { throw IdentviaError.validation("Key is not a signing key.") }
        let digest = SHA256.hash(data: jws.signingInput)
        switch alg {
        case "RS256":
            guard key.kty == "RSA", let n = key.n.flatMap({ Data(base64URLEncoded: $0) }), let e = key.e.flatMap({ Data(base64URLEncoded: $0) }) else {
                throw IdentviaError.validation("RS256 needs an RSA key.")
            }
            let pk = try _RSA.Signing.PublicKey(derRepresentation: pkcs1PublicKeyDER(n: n, e: e))
            return pk.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: jws.signature), for: digest, padding: .insecurePKCS1v1_5)
        case "ES256":
            guard key.kty == "EC", key.crv == "P-256", let x = key.x.flatMap({ Data(base64URLEncoded: $0) }), let y = key.y.flatMap({ Data(base64URLEncoded: $0) }),
                  x.count == 32, y.count == 32 else { throw IdentviaError.validation("ES256 needs a P-256 key.") }
            let pk = try P256.Signing.PublicKey(rawRepresentation: x + y)
            guard jws.signature.count == 64, let sig = try? P256.Signing.ECDSASignature(rawRepresentation: jws.signature) else { return false }
            return pk.isValidSignature(sig, for: digest)
        default:
            throw IdentviaError.validation("alg \(alg) is not allowed.")
        }
    }

    /// DER for PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
    static func pkcs1PublicKeyDER(n: Data, e: Data) -> Data {
        func len(_ l: Int) -> Data {
            if l < 0x80 { return Data([UInt8(l)]) }
            var b: [UInt8] = []; var v = l
            while v > 0 { b.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
            return Data([0x80 | UInt8(b.count)] + b)
        }
        func int(_ d: Data) -> Data {
            var v = Data(d.drop(while: { $0 == 0 }))
            if v.isEmpty { v = Data([0]) }
            if v.first! & 0x80 != 0 { v.insert(0, at: 0) }
            return Data([0x02]) + len(v.count) + v
        }
        let body = int(n) + int(e)
        return Data([0x30]) + len(body.count) + body
    }
}

/// Fetches and caches the JWKS. An unknown `kid` triggers one refetch, at most every 30 seconds (key rotation).
actor JWKSCache {
    private let url: URL
    private let transport: HTTPTransport
    private let clock: @Sendable () -> Date
    private var keys: [JWK]?
    private var lastFetch: Date?
    private(set) var fetchCount = 0

    init(url: URL, transport: HTTPTransport, clock: @escaping @Sendable () -> Date) {
        self.url = url; self.transport = transport; self.clock = clock
    }

    func key(kid: String?, alg: String) async throws -> JWK? {
        if keys == nil { try await load() }
        if let k = find(kid, alg) { return k }
        if let l = lastFetch, clock().timeIntervalSince(l) < 30 { return nil }
        try await load()
        return find(kid, alg)
    }

    private func find(_ kid: String?, _ alg: String) -> JWK? {
        let kty = alg.hasPrefix("ES") ? "EC" : "RSA"
        let c = (keys ?? []).filter { $0.kty == kty && ($0.use == nil || $0.use == "sig") }
        if let kid { return c.first { $0.kid == kid } }
        return c.count == 1 ? c[0] : nil
    }

    private func load() async throws {
        var r = URLRequest(url: url)
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, res) = try await transport.send(r)
        fetchCount += 1
        lastFetch = clock()
        guard res.statusCode == 200, let set = try? JSONDecoder().decode(JWKSet.self, from: data) else {
            throw IdentviaError.network("Could not load the JWKS (\(res.statusCode)).")
        }
        keys = set.keys
    }
}
