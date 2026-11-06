import Foundation
import Security

/// A temporarily inaccessible key. This never authorizes creating or replacing an identity.
public enum ProtectedDataFailure {
  public static func matches(_ error: any Error) -> Bool {
    guard DeviceKeyFailure(error) == nil else { return false }
    var current = error as NSError
    for _ in 0..<8 {
      if current.domain == NSOSStatusErrorDomain,
        current.code == Int(errSecInteractionNotAllowed) { return true }
      guard let underlying = current.userInfo[NSUnderlyingErrorKey] as? NSError,
        underlying !== current else { return false }
      current = underlying
    }
    return false
  }
}
