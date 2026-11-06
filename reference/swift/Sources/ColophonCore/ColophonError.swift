import Foundation

public enum ColophonError: Error, Equatable, Sendable, LocalizedError {
  case malformed(String)
  case notALibrary
  case badSignature(String)
  case brokenAuthorityChain(Int)
  case notAMember
  case revoked
  case expired
  case noAccess(String)
  case notTheRoot
  case wrongRecoveryKit
  case alreadyExists(String)
  case unavailable(String)
  /// The bytes exist but are still downloading. Retry; this is not an absent file.
  case pending(String)
  /// A newer app wrote this authority entry in a form this version can't check. Reading on could
  /// grant or hide the wrong things, so the library stays closed until the app is updated.
  case newerAuthority(Int)
  /// This key cannot unwrap the library vault.
  case vaultLocked
  /// The library's keys don't allow this step from here. The message is a complete sentence.
  case keysCantDoThis(String)

  public var errorDescription: String? {
    switch self {
    case .malformed(let what): String(localized: "Malformed \(what).")
    case .notALibrary: String(localized: "This folder doesn't contain a library.")
    case .badSignature(let what): String(localized: "The signature on \(what) doesn't verify.")
    case .brokenAuthorityChain(let seq): String(localized: "The library's authority history is broken at entry \(seq).")
    case .notAMember: String(localized: "This app hasn't been approved for the library yet.")
    case .revoked: String(localized: "Access for this app was revoked.")
    case .expired: String(localized: "This app's access has expired.")
    case .noAccess(let namespace): String(localized: "This app has no access to \(namespace).")
    case .notTheRoot: String(localized: "This device doesn't hold the library's root.")
    case .wrongRecoveryKit: String(localized: "That recovery kit doesn't open this library.")
    case .alreadyExists(let what): String(localized: "\(what) already exists.")
    case .unavailable(let what): String(localized: "\(what) isn't available yet.")
    case .pending(let what): String(localized: "\(what) is still downloading from iCloud.")
    case .newerAuthority: String(localized: "A newer version of one of your apps updated this library. Update this app to keep using it.")
    case .vaultLocked: String(localized: "This key can't open the library's vault.")
    case .keysCantDoThis(let sentence): sentence
    }
  }
}
