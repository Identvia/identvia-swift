#if canImport(Security) && canImport(AuthenticationServices)
import Foundation
import Security
import IdentviaCore

/// Stores the session in the Keychain, readable after first unlock, never synced to iCloud or restored to another device.
public struct KeychainTokenStore: TokenStore {
    public let service: String
    public let accessGroup: String?

    public init(service: String = "com.identvia.session", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func base(_ key: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: false,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        #if os(macOS)
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }

    public func get(_ key: String) async throws -> String? {
        var q = base(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let d = out as? Data else { throw IdentviaError.configuration("Keychain read failed (\(status)).") }
        return String(decoding: d, as: UTF8.self)
    }

    public func set(_ key: String, _ value: String) async throws {
        let data = Data(value.utf8)
        let update: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var status = SecItemUpdate(base(key) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = base(key)
            add.merge(update) { $1 }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw IdentviaError.configuration("Keychain write failed (\(status)).") }
    }

    public func delete(_ key: String) async throws {
        let status = SecItemDelete(base(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw IdentviaError.configuration("Keychain delete failed (\(status)).") }
    }
}

public extension IdentviaClient {
    /// The usual setup on Apple platforms: ASWebAuthenticationSession + Keychain.
    init(issuer: String = defaultIssuer, clientId: String, redirectURI: String,
         scopes: [String] = ["email", "profile", "offline_access"], ephemeralSession: Bool = false) throws {
        try self.init(issuer: issuer, clientId: clientId, redirectURI: redirectURI, scopes: scopes,
                      presenter: WebAuthenticationSessionPresenter(), store: KeychainTokenStore(service: "com.identvia.\(clientId)"),
                      ephemeralSession: ephemeralSession)
    }
}
#endif
