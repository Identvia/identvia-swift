import Foundation

/// Opens the authorization URL in a **system** browser session and returns the URL Identvia redirected to.
/// Throw `IdentviaError.cancelled` when the user closes it. Never use an embedded web view (RFC 8252 §8.12).
public protocol AuthSessionPresenter: Sendable {
    func authenticate(url: URL, redirectURI: URL, ephemeral: Bool) async throws -> URL
}

/// Secure storage for the session. On Apple platforms use `KeychainTokenStore`.
public protocol TokenStore: Sendable {
    func get(_ key: String) async throws -> String?
    func set(_ key: String, _ value: String) async throws
    func delete(_ key: String) async throws
}

/// For tests and previews. Not persistent.
public actor InMemoryTokenStore: TokenStore {
    public private(set) var values: [String: String] = [:]
    public init() {}
    public func get(_ key: String) -> String? { values[key] }
    public func set(_ key: String, _ value: String) { values[key] = value }
    public func delete(_ key: String) { values[key] = nil }
}

public struct TokenSet: Codable, Sendable, Equatable {
    public let accessToken: String
    public let tokenType: String
    public let expiresAt: Date
    public internal(set) var refreshToken: String?
    public let idToken: String?
    public let scope: String?
    /// RFC 9396 details the user approved (server 2026-10-21_5+).
    public let authorizationDetails: [JSONValue]?
}

public struct IdentviaSession: Codable, Sendable, Equatable {
    public let user: IdentviaUser
    public internal(set) var tokens: TokenSet
}

/// One RFC 9396 authorization detail. Requires server 2026-10-21_5+.
public struct AuthorizationDetail: Sendable, Equatable, Encodable {
    public let type: String
    public let fields: [String: JSONValue]
    public init(type: String, fields: [String: JSONValue] = [:]) { self.type = type; self.fields = fields }

    /// An `agent_task` detail, shown to the user on the consent screen.
    public static func agentTask(_ description: String, actions: [String]? = nil, locations: [String]? = nil) -> AuthorizationDetail {
        var f: [String: JSONValue] = ["description": .string(description)]
        if let actions { f["actions"] = .array(actions.map { .string($0) }) }
        if let locations { f["locations"] = .array(locations.map { .string($0) }) }
        return AuthorizationDetail(type: "agent_task", fields: f)
    }

    public func encode(to encoder: Encoder) throws {
        var o = fields
        o["type"] = .string(type)
        try JSONValue.object(o).encode(to: encoder)
    }
}

/// What one sign-in attempt must remember between opening the browser and handling the redirect.
public struct AuthorizationTransaction: Codable, Sendable, Equatable {
    public let state: String
    public let nonce: String
    public let codeVerifier: String
    public let redirectURI: URL
    public let maxAge: Int?
}
