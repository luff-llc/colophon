import Foundation
import Security

/// Where the 32-byte device-held key that seals saved state lives (spec §17.2). It is a cache key, not
/// an identity: losing it makes the engine replay the history. It must never leave this device.
public protocol DeviceSecretStore: Sendable {
    /// The key for `account`, created on first use. Returned as secret memory (`Data.secret`).
    func key(for account: String) throws -> Data
    func remove(account: String) throws
}

/// A process-lifetime store for tests and previews.
public final class MemoryDeviceSecrets: DeviceSecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: Data] = [:]
    public init() {}
    public func key(for account: String) throws -> Data {
        try lock.withLock {
            if let existing = keys[account] { return Data.secret(existing) }
            let fresh = try colophonEntropy(32)
            keys[account] = Data(fresh)
            return fresh
        }
    }
    public func remove(account: String) throws { lock.withLock { keys[account] = nil } }
}

/// A generic-password Keychain item per account: `ThisDeviceOnly`, not synchronised, not in backups.
public struct KeychainDeviceSecrets: DeviceSecretStore {
    public let service: String
    public init(service: String = "org.luff.colophon.device-key") { self.service = service }
    public func key(for account: String) throws -> Data {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false]
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 { return Data.secret(data) }
        guard status == errSecItemNotFound else { throw StorageError.unavailable("Keychain: \(status)") }
        let fresh = try colophonEntropy(32)
        var add = query
        add[kSecValueData as String] = Data(fresh)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let created = SecItemAdd(add as CFDictionary, nil)
        if created == errSecDuplicateItem { return try key(for: account) }
        guard created == errSecSuccess else { throw StorageError.unavailable("Keychain: \(created)") }
        return fresh
    }
    public func remove(account: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw StorageError.unavailable("Keychain: \(status)") }
    }
}
