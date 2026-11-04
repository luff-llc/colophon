import CryptoKit
import CryptoTokenKit
import Foundation

/// Only fixed vocabulary and numeric codes enter support logs. Never add content or identities here.
public struct SupportEvent: Codable, Sendable, Equatable, Identifiable {
  public enum Stage: String, Codable, Sendable, CaseIterable {
    case applicationLaunch, save, playback, download, sync
    case discovery, start, open, membership, refresh, sourceExtraction, identityMatching
    case publication, presentation, feedAcquisition, retry
  }
  public enum Outcome: String, Codable, Sendable {
    case started, succeeded, failed, unavailable, pending, member, revoked, noLibrary
  }
  public struct Failure: Codable, Sendable, Equatable {
    public enum Category: String, Codable, Sendable { case colophon, cocoa, url, posix, cancellation, keychain, deviceKey, cryptoKit, cryptoTokenKit, decoding, encoding, publicationRejected, unknown }
    public let category: Category
    public let code: Int?

    public init(category: Category, code: Int? = nil) {
      self.category = category; self.code = code
    }

    public init(_ error: any Error) {
      if DeviceKeyFailure(error) != nil { category = .deviceKey; code = -10; return }
      if ProtectedDataFailure.matches(error) { category = .keychain; code = -25308; return }
      if let crypto = error as? CryptoKitError {
        category = .cryptoKit
        // CoreCrypto's native numeric code is retained. Other cases use this fixed vocabulary.
        code = switch crypto {
        case .underlyingCoreCryptoError(let value): Int(value)
        case .incorrectKeySize: 1
        case .incorrectParameterSize: 2
        case .authenticationFailure: 3
        case .wrapFailure: 4
        case .unwrapFailure: 5
        case .invalidParameter: 6
        @unknown default: nil
        }
        return
      }
      if error is DecodingError { category = .decoding; code = nil; return }
      if error is EncodingError { category = .encoding; code = nil; return }
      if error is CancellationError { category = .cancellation; code = nil; return }
      if let error = error as? ColophonError {
        category = .colophon
        code = switch error {
        case .malformed: 1
        case .notALibrary: 2
        case .badSignature: 3
        case .brokenAuthorityChain: 4
        case .notAMember: 5
        case .revoked: 6
        case .expired: 7
        case .noAccess: 8
        case .notTheRoot: 9
        case .wrongRecoveryKit: 10
        case .alreadyExists: 11
        case .unavailable: 12
        case .pending: 16
        case .newerAuthority: 13
        case .vaultLocked: 14
        case .keysCantDoThis: 15
        }
        return
      }
      var value = error as NSError
      for _ in 0..<8 {
        if let crypto = value as? CryptoKitError {
          let failure = Self(crypto)
          category = failure.category; code = failure.code; return
        }
        switch value.domain {
        case NSOSStatusErrorDomain: category = .keychain; code = value.code; return
        case TKErrorDomain: category = .cryptoTokenKit; code = value.code; return
        case NSCocoaErrorDomain: category = .cocoa; code = value.code; return
        case NSURLErrorDomain: category = .url; code = value.code; return
        case NSPOSIXErrorDomain: category = .posix; code = value.code; return
        default: break
        }
        guard let underlying = value.userInfo[NSUnderlyingErrorKey] as? NSError,
          underlying !== value else { break }
        value = underlying
      }
      category = .unknown; code = nil
    }
  }
  public let id: UUID
  public let date: Date
  public let stage: Stage
  public let outcome: Outcome
  public let failure: Failure?

  public init(stage: Stage, outcome: Outcome, error: (any Error)? = nil, date: Date = Date()) {
    id = UUID(); self.date = date; self.stage = stage; self.outcome = outcome
    failure = error.map(Failure.init)
  }

  public init(stage: Stage, outcome: Outcome, failure: Failure?, date: Date = Date()) {
    id = UUID(); self.date = date; self.stage = stage; self.outcome = outcome
    self.failure = failure
  }
}
