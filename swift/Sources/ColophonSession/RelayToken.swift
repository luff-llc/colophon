import Foundation
import Security

/// Stores a relay storage token in a process-private, ThisDeviceOnly Keychain item.
/// The token only lets this device read and write ciphertext in one relay slot.
public enum RelayToken {
    public static func load(service: String, account: String = "relay") throws -> String? {
        var query = base(service, account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, let token = String(data: data, encoding: .utf8) else {
            throw StorageError.unavailable("Keychain: \(status)")
        }
        return token
    }
    public static func save(_ token: String, service: String, account: String = "relay") throws {
        let query = base(service, account)
        let data = Data(token.utf8)
        let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw StorageError.unavailable("Keychain: \(update)") }
        var addition = query
        addition[kSecValueData as String] = data
        addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(addition as CFDictionary, nil)
        guard status == errSecSuccess else { throw StorageError.unavailable("Keychain: \(status)") }
    }
    public static func remove(service: String, account: String = "relay") throws {
        let status = SecItemDelete(base(service, account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw StorageError.unavailable("Keychain: \(status)") }
    }
    private static func base(_ service: String, _ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }
}
