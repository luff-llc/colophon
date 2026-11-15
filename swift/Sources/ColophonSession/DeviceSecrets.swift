import Foundation
import Security

/// Where the 32-byte device-held key that seals saved state lives (spec §17.2). It is a cache key, not
/// an identity: losing it makes the engine replay the history. It must never leave this device.
public protocol DeviceSecretStore: Sendable {
    /// The key for `account`, created on first use, in memory the SDK owns and zeroes.
    func key(for account: String) throws -> SecretBytes
    func remove(account: String) throws
}

/// A process-lifetime store for tests and previews.
public final class MemoryDeviceSecrets: DeviceSecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: SecretBytes] = [:]
    public init() {}
    public func key(for account: String) throws -> SecretBytes {
        try lock.withLock {
            if let existing = keys[account] { return existing }
            let fresh = try SecretBytes.random(count: 32)
            keys[account] = fresh
            return fresh
        }
    }
    public func remove(account: String) throws { lock.withLock { keys[account] = nil } }
}

/// A generic-password Keychain item per account: `ThisDeviceOnly`, not synchronised, not in backups.
///
/// The class is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, on purpose: the key only seals a cache of
/// what the engine can rebuild from the records (losing it costs a replay, never data), and a session must open
/// for background work (an exchange pass, an App Intent, a share extension) while the device is locked after its
/// first unlock. `WhenUnlocked` would make every background open replay the history; `ThisDeviceOnly` keeps it
/// out of backups and off other devices, which is what protects it.
///
/// Copies the SDK cannot reach: on a read, the `CFData` that `SecItemCopyMatching` returns (it is copied into
/// `SecretBytes` at once and released, not zeroed: Security owns it); on a write, the Keychain's own buffers.
/// The new key itself is generated straight into `SecretBytes` and handed to the Keychain without a copy
/// (`CFDataCreateWithBytesNoCopy` over the owned memory, for the duration of `SecItemAdd`).
public struct KeychainDeviceSecrets: DeviceSecretStore {
    public let service: String
    public init(service: String = "org.luff.colophon.device-key") { self.service = service }
    public func key(for account: String) throws -> SecretBytes {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false]
        if let existing = try KeychainSecret.read(query) {
            guard existing.count == 32 else { throw StorageError.unavailable("Keychain: the device key has the wrong length") }
            return existing
        }
        let fresh = try SecretBytes.random(count: 32)
        let created = KeychainSecret.add(query, secret: fresh, accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
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

/// The narrowest Keychain calls for a secret value.
enum KeychainSecret {
    /// The item's data copied into `SecretBytes` straight from the returned `CFData`; nil when there is no item.
    static func read(_ query: [String: Any]) throws -> SecretBytes? {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let value = result, CFGetTypeID(value) == CFDataGetTypeID() else {
            throw StorageError.unavailable("Keychain: \(status)")
        }
        let data = unsafeDowncast(value, to: CFData.self)
        let length = CFDataGetLength(data)
        guard length > 0, let bytes = CFDataGetBytePtr(data) else { return SecretBytes(count: 0) { _ in } }
        return SecretBytes(copying: UnsafeRawBufferPointer(start: bytes, count: length))
    }
    /// Adds an item whose data is `secret`, lent without a copy for the duration of the call.
    static func add(_ query: [String: Any], secret: SecretBytes, accessible: CFString) -> OSStatus {
        secret.withUnsafeBytes { buffer -> OSStatus in
            guard let base = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                  let data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, base, buffer.count, kCFAllocatorNull) else { return errSecParam }
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = accessible
            return SecItemAdd(add as CFDictionary, nil)
        }
    }
}
