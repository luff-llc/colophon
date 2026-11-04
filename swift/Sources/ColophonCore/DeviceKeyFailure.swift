import CryptoTokenKit
import Foundation

/// A device-key failure that needs deliberate recovery, rather than an automatic retry or
/// replacement identity. No key material or arbitrary system error descriptions are retained.
public enum DeviceKeyFailure: Error, Equatable, Sendable, LocalizedError {
  case invalidated

  public init?(_ error: any Error) {
    if let failure = error as? Self { self = failure; return }
    var current = error as NSError
    // CryptoKit can preserve a token error as an underlying error. Keep inspection bounded
    // and require the exact domain as well as the code; -10 alone is not a key diagnosis.
    for _ in 0..<8 {
      // TKErrorCodeInvalidatedDeviceKey is named in the OS 27 SDK. Its wire value can be
      // received independently of this process's minimum deployment target.
      if current.domain == TKErrorDomain, current.code == -10 {
        self = .invalidated
        return
      }
      guard let underlying = current.userInfo[NSUnderlyingErrorKey] as? NSError,
        underlying !== current else { return nil }
      current = underlying
    }
    return nil
  }

  public var errorDescription: String? {
    String(localized: "This app’s device key is no longer valid, so this change couldn’t be saved. Don’t delete the app or reset your library. Access recovery needs the library owner or a recovery kit.")
  }
}
