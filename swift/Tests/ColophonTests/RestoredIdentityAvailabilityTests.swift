import CryptoKit
import CryptoTokenKit
import Foundation
import Security
import Testing
@testable import ColophonCore

struct RestoredIdentityAvailabilityTests {
  private enum Stage: Sendable { case signing, agreement }
  private enum Failure: Sendable, CaseIterable {
    case invalidated, locked, missing

    var error: NSError {
      switch self {
      case .invalidated: NSError(domain: TKErrorDomain, code: -10)
      case .locked: NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed))
      case .missing: NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))
      }
    }
  }

  /// Exercises protocol dispatch without touching Secure Enclave or Keychain services.
  private struct FailedLookup: Identity {
    let failure: Failure
    var custody: KeyCustody { .hardware }
    var publicIdentity: PublicIdentity { PublicIdentity(signing: Data(), agreement: Data()) }
    func availablePublicIdentity() throws -> PublicIdentity { throw failure.error }
    func sign(_ bytes: Data) throws -> Data { throw failure.error }
    func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret { throw failure.error }
  }

  @Test(arguments: Failure.allCases)
  private func erasedIdentityPreservesTheSpecificKeyFailure(failure: Failure) throws {
    let identity: any Identity = FailedLookup(failure: failure)
    do {
      _ = try identity.availablePublicIdentity()
      Issue.record("A failed lookup must not become an empty or replacement identity")
    } catch {
      let actual = error as NSError
      #expect(actual.domain == failure.error.domain)
      #expect(actual.code == failure.error.code)
      #expect((DeviceKeyFailure(error) == .invalidated) == (failure == .invalidated))
    }
  }

  @Test private func softwareAndErasedDeviceIdentitiesStillResolveNormally() throws {
    let software = SoftwareIdentity()
    let identity: any Identity = DeviceIdentity.software(software)
    let resolved = try identity.availablePublicIdentity()
    #expect(resolved == software.publicIdentity)
  }

  @Test(arguments: [Stage.signing, .agreement], Failure.allCases)
  private func restoredOpaqueHandlesAndLibrarySelectionRemainIntact(stage: Stage, failure: Failure) throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "restored-key-fixture-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    // These are deliberately synthetic bytes, not a hardware key's representation.
    let signing = Data("synthetic-restored-signing-handle".utf8)
    let agreement = Data("synthetic-restored-agreement-handle".utf8)
    let enclaveBytes = try JSONSerialization.data(withJSONObject: [
      "signingHandle": signing.base64EncodedString(),
      "agreementHandle": agreement.base64EncodedString(),
      "requiresPresence": false,
    ], options: [.sortedKeys])
    let restored = try Canonical.decode(SecureEnclaveIdentity.self, from: enclaveBytes)
    let member = DeviceIdentity.enclave(restored)
    let oldIdentity = try Canonical.encode(member)
    let retained = ["identity.json": oldIdentity, "root.json": oldIdentity,
      "library.bookmark": Data("synthetic-retained-bookmark".utf8),
      "retained-ciphertext.fixture": Data("synthetic-encrypted-library-data".utf8)]
    for (name, bytes) in retained { try bytes.write(to: directory.appending(path: name)) }
    let loaded = try DeviceIdentity.loadOrCreate(at: directory.appending(path: "identity.json"),
      requiresPresence: false, readData: { try Data(contentsOf: $0) },
      createIdentity: { _ in
        Issue.record("A restored identity file must never trigger automatic identity creation")
        throw failure.error
      })
    guard case .enclave(let handle) = loaded else {
      Issue.record("A restored enclave identity must not become a software identity")
      return
    }
    for _ in 0..<2 {
      do {
        _ = try SecureEnclaveIdentity.readPublicIdentity(signing: {
          #expect(handle.signingHandle == signing)
          if stage == .signing { throw failure.error }
          return Data("synthetic-public-signing-key".utf8)
        }, agreement: {
          #expect(handle.agreementHandle == agreement)
          throw failure.error
        })
        Issue.record("A failed restored key lookup must not claim access was recovered")
      } catch {
        if failure == .invalidated {
          #expect(DeviceKeyFailure(error) == .invalidated)
        } else {
          let actual = error as NSError
          #expect(actual.domain == failure.error.domain)
          #expect(actual.code == failure.error.code)
        }
      }
      let stillEncoded = try Canonical.encode(loaded)
      #expect(stillEncoded == oldIdentity)
      for (name, bytes) in retained {
        let actual = try Data(contentsOf: directory.appending(path: name))
        #expect(actual == bytes)
      }
    }
  }
}
