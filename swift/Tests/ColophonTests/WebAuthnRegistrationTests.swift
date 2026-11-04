import ColophonAuthority
import ColophonCore
import CryptoKit
import Foundation
import Testing

@Suite struct WebAuthnRegistrationTests {
  @Test func parsesSyntheticAttestation() throws {
    let key = P256.Signing.PrivateKey()
    let credential = Data(repeating: 0x11, count: 16)
    let cose = try WebAuthnRegistration.es256COSE(x963: key.publicKey.x963Representation)
    let authData = WebAuthnRegistration.attestedAuthenticatorData(rpID: "id.luff.works", flags: 0x05,
      credentialID: credential, coseKey: cose)
    let object = WebAuthnRegistration.formatNone(authData: authData)
    let parsed = try WebAuthnRegistration.parse(attestationObject: object)
    #expect(parsed.credentialID == credential)
    #expect(parsed.coseKey == cose)
    let controller = try Controller.webauthn(coseKey: parsed.coseKey, rpID: "id.luff.works", credential: parsed.credentialID,
      label: "Passkey", roles: ["approve", "recover"], verification: true)
    #expect(controller.key == key.publicKey.x963Representation)
  }

  @Test func sliceWithANonZeroStartIndexParses() throws {
    let object = try sample()
    let padded = Data([0x00]) + object
    let slice = padded.dropFirst()
    let sliceStartsLater = slice.startIndex != 0
    #expect(sliceStartsLater)
    let parsed = try WebAuthnRegistration.parse(attestationObject: slice)
    let direct = try WebAuthnRegistration.parse(attestationObject: object)
    #expect(parsed.credentialID == direct.credentialID)
    #expect(parsed.coseKey == direct.coseKey)
    let key = P256.Signing.PrivateKey()
    let x963 = key.publicKey.x963Representation
    let keySlice = (Data([0x00]) + x963).dropFirst()
    let fromSlice = try WebAuthnRegistration.es256COSE(x963: keySlice)
    let fromKey = try WebAuthnRegistration.es256COSE(x963: x963)
    #expect(fromSlice == fromKey)
  }

  @Test func truncatedAttestationIsRejected() throws {
    let object = try sample()
    let truncated = object.dropLast()
    #expect(throws: ColophonError.self) {
      try WebAuthnRegistration.parse(attestationObject: truncated)
    }
  }

  @Test func missingAttestedCredentialFlagIsRejected() throws {
    let key = P256.Signing.PrivateKey()
    let cose = try WebAuthnRegistration.es256COSE(x963: key.publicKey.x963Representation)
    var authData = Data(SHA256.hash(data: Data("id.luff.works".utf8)))
    authData.append(0x01)
    authData.append(contentsOf: [0, 0, 0, 0])
    let object = WebAuthnRegistration.formatNone(authData: authData + cose)
    #expect(throws: ColophonError.self) {
      try WebAuthnRegistration.parse(attestationObject: object)
    }
  }

  private func sample() throws -> Data {
    let key = P256.Signing.PrivateKey()
    let cose = try WebAuthnRegistration.es256COSE(x963: key.publicKey.x963Representation)
    let authData = WebAuthnRegistration.attestedAuthenticatorData(rpID: "id.luff.works", flags: 0x45,
      credentialID: Data([1, 2, 3, 4]), coseKey: cose)
    return WebAuthnRegistration.formatNone(authData: authData)
  }
}
