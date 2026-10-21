import Foundation

/// The parts of `/.well-known/openid-configuration` the SDK uses.
public struct ProviderMetadata: Codable, Sendable, Equatable {
    public let issuer: String
    public let authorizationEndpoint: String
    public let tokenEndpoint: String
    public let userinfoEndpoint: String?
    public let jwksUri: String
    public let revocationEndpoint: String?
    public let endSessionEndpoint: String?
    public let codeChallengeMethodsSupported: [String]?
    public let grantTypesSupported: [String]?
    public let idTokenSigningAlgValuesSupported: [String]?
    public let authorizationResponseIssParameterSupported: Bool?
    /// Stage 5 (server 2026-10-21_5+): RFC 9396 types such as `agent_task`.
    public let authorizationDetailsTypesSupported: [String]?
    public let backchannelAuthenticationEndpoint: String?
}

let snakeDecoder: JSONDecoder = {
    let d = JSONDecoder()
    d.keyDecodingStrategy = .convertFromSnakeCase
    return d
}()
