import CryptoKit
import Foundation
import LocalAuthentication

/// The identity an app uses on this device: Secure Enclave when there is one, software otherwise.
/// Stored in the app's own storage; nothing here is shared with any other app.
public enum DeviceIdentity: Codable, Sendable, Identity {
  case enclave(SecureEnclaveIdentity)
  case software(SoftwareIdentity)

  /// Loads the identity at `url`, or creates and saves one.
  public static func loadOrCreate(at url: URL, requiresPresence: Bool = false) throws -> DeviceIdentity {
    try loadOrCreate(at: url, requiresPresence: requiresPresence, readData: { try Data(contentsOf: $0) })
  }

  static func loadOrCreate(at url: URL, requiresPresence: Bool,
    readData: (URL) throws -> Data,
    createIdentity: (Bool) throws -> DeviceIdentity = Self.makeIdentity) throws -> DeviceIdentity
  {
    do {
      let identity = try Canonical.decode(DeviceIdentity.self, from: readData(url))
      // Identities saved before backups were excluded are moved out of future backups too.
      excludeFromBackup(url)
      return identity
    } catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile {
      // Only a genuinely absent identity permits creation. A protected or unreadable
      // existing file must never be replaced with a different member identity.
    }
    let identity = try createIdentity(requiresPresence)
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try PrivateAtomicFile.write(Canonical.encode(identity), to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    excludeFromBackup(url)
    return identity
  }

  /// A device identity belongs to this device. An enclave handle restored onto another device is
  /// dead, and a copied software key would make two devices one member. Left out of backups, a
  /// restored or migrated device finds no identity, makes its own and asks to join again.
  /// Best effort: a file the system won't mark is still a working identity.
  static func excludeFromBackup(_ url: URL) {
    var url = url
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try? url.setResourceValues(values)
  }

  private static func makeIdentity(requiresPresence: Bool) throws -> DeviceIdentity {
    // Presence needs a passcode the system can check. Without one (or in the Simulator), the
    // key still lives in the enclave but signs without asking.
    let presence = requiresPresence && Self.canCheckPresence
    return SecureEnclaveIdentity.isAvailable && !Self.forceSoftware
      ? .enclave(try SecureEnclaveIdentity(requiresPresence: presence))
      : .software(SoftwareIdentity())
  }

  static var canCheckPresence: Bool {
    #if targetEnvironment(simulator)
      false
    #else
      LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    #endif
  }

  /// Whether signing with this identity asks for the person.
  public var requiresPresence: Bool {
    if case .enclave(let enclave) = self { enclave.requiresPresence } else { false }
  }

  /// Tests and unsigned command-line runs can't use the enclave's keychain-backed keys.
  static var forceSoftware: Bool { ProcessInfo.processInfo.environment["COLOPHON_SOFTWARE_KEYS"] == "1" }

  private var base: any Identity {
    switch self {
    case .enclave(let identity): identity
    case .software(let identity): identity
    }
  }

  public var publicIdentity: PublicIdentity { base.publicIdentity }
  public func availablePublicIdentity() throws -> PublicIdentity { try base.availablePublicIdentity() }
  public var custody: KeyCustody { base.custody }
  public func sign(_ bytes: Data) throws -> Data { try base.sign(bytes) }
  public func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
    try base.sharedSecret(with: peer)
  }
}
