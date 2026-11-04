import ColophonCore
import CryptoTokenKit
import Foundation
import Testing

struct DeviceKeyFailureTests {
  @Test func invalidatedKeyHasActionableMessageAndContentFreeDiagnostics() throws {
    let secret = "synthetic-private-description-and-path"
    let error = NSError(domain: TKErrorDomain, code: -10,
      userInfo: [NSLocalizedDescriptionKey: secret, NSFilePathErrorKey: secret])
    let classified = try #require(DeviceKeyFailure(error))
    #expect(classified == .invalidated)
    #expect(classified.localizedDescription.contains(secret) == false)
    #expect(classified.localizedDescription.contains("CryptoTokenKit") == false)
    let event = SupportEvent(stage: .save, outcome: .failed, error: error)
    #expect(event.failure?.category == .deviceKey)
    #expect(event.failure?.code == -10)
    let encoded = String(decoding: try JSONEncoder().encode(event), as: UTF8.self)
    #expect(encoded.contains(secret) == false)
    #expect(encoded.contains("save"))
    #expect(encoded.contains("deviceKey"))
  }

  @Test(arguments: [NSOSStatusErrorDomain, NSCocoaErrorDomain, "synthetic-other-domain"])
  func matchingCodeInAnotherDomainIsNotInvalidation(domain: String) {
    let error = NSError(domain: domain, code: -10)
    #expect(DeviceKeyFailure(error) == nil)
  }

  @Test(arguments: [-9, -5, -25308])
  func otherTokenFailuresAreNotInvalidation(code: Int) {
    #expect(DeviceKeyFailure(NSError(domain: TKErrorDomain, code: code)) == nil)
  }

  @Test func underlyingTokenFailureIsRecognizedWithoutExportingTheWrapper() throws {
    let inner = NSError(domain: TKErrorDomain, code: -10)
    let wrapper = NSError(domain: "private-wrapper-description", code: 41,
      userInfo: [NSUnderlyingErrorKey: inner, NSLocalizedDescriptionKey: "private wrapper"])
    #expect(DeviceKeyFailure(wrapper) == .invalidated)
    let failure = SupportEvent.Failure(wrapper)
    #expect(failure.category == .deviceKey)
    #expect(failure.code == -10)
    let encoded = String(decoding: try JSONEncoder().encode(failure), as: UTF8.self)
    #expect(encoded.contains("private") == false)
    #expect(DeviceKeyFailure(DeviceKeyFailure.invalidated) == .invalidated)
  }
}
