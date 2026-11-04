import ColophonCore
import CryptoKit
import CryptoTokenKit
import Foundation
import Testing

struct ProtectedDataFailureTests {
  @Test func lockedKeychainAndWrappedErrorsRetainTheirCategory() {
    let locked = NSError(domain: NSOSStatusErrorDomain, code: -25308)
    let wrapped = NSError(domain: "PrivateWrapper", code: 1, userInfo: [NSUnderlyingErrorKey: locked])
    #expect(ProtectedDataFailure.matches(locked))
    #expect(ProtectedDataFailure.matches(wrapped))
    let failure = SupportEvent.Failure(wrapped)
    #expect(failure.category == .keychain)
    #expect(failure.code == -25308)
    let other = NSError(domain: "Unrelated", code: -25308)
    #expect(!ProtectedDataFailure.matches(other))
  }

  @Test func invalidatedDeviceKeyTakesPrecedenceOverTemporaryWrapper() {
    let invalidated = NSError(domain: TKErrorDomain, code: -10)
    let wrapper = NSError(domain: NSOSStatusErrorDomain, code: -25308,
      userInfo: [NSUnderlyingErrorKey: invalidated])
    #expect(!ProtectedDataFailure.matches(wrapper))
    let failure = SupportEvent.Failure(wrapper)
    #expect(failure.category == .deviceKey)
    #expect(failure.code == -10)
  }

  @Test func cryptoFailuresRetainFixedCategoriesAndNativeCodes() {
    let crypto = SupportEvent.Failure(CryptoKitError.underlyingCoreCryptoError(error: -4300))
    #expect(crypto.category == .cryptoKit)
    #expect(crypto.code == -4300)
    let authentication = SupportEvent.Failure(CryptoKitError.authenticationFailure)
    #expect(authentication.category == .cryptoKit)
    #expect(authentication.code == 3)
    let wrapper = NSError(domain: "PrivateWrapper", code: 1,
      userInfo: [NSUnderlyingErrorKey: CryptoKitError.authenticationFailure])
    let wrappedCrypto = SupportEvent.Failure(wrapper)
    #expect(wrappedCrypto.category == .cryptoKit)
    #expect(wrappedCrypto.code == 3)
    let token = SupportEvent.Failure(NSError(domain: TKErrorDomain, code: -5))
    #expect(token.category == .cryptoTokenKit)
    #expect(token.code == -5)
  }
}
