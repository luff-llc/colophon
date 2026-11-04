import ColophonCore
import CryptoKit
import Foundation

/// A controller that can sign authority entries. WebAuthn signers also return the assertion.
public protocol ControllerSigner: Sendable {
  var controller: Controller { get }
  func sign(_ body: Data) throws -> (signature: Data, assertion: Assertion?)
}

/// Signs with an app owner key. The identity's signing key is the controller's key.
public struct P256ControllerSigner: ControllerSigner {
  public let identity: any Identity
  public let controller: Controller

  public init(identity: any Identity, controller: Controller) throws {
    guard controller.kind == "p256", controller.key == identity.publicIdentity.signing else {
      throw ColophonError.malformed("controller")
    }
    self.identity = identity
    self.controller = controller
  }

  public func sign(_ body: Data) throws -> (signature: Data, assertion: Assertion?) {
    (try identity.sign(body), nil)
  }
}

/// Asks an authenticator to sign. `assert` receives SHA-256(body), the WebAuthn challenge bytes.
public struct WebAuthnControllerSigner: ControllerSigner {
  public let controller: Controller
  private let assert: @Sendable (Data) throws -> (signature: Data, authenticatorData: Data, clientData: Data)

  public init(controller: Controller,
    assert: @escaping @Sendable (Data) throws -> (signature: Data, authenticatorData: Data, clientData: Data)) throws
  {
    guard controller.kind == "webauthn" else { throw ColophonError.malformed("controller") }
    self.controller = controller
    self.assert = assert
  }

  public func sign(_ body: Data) throws -> (signature: Data, assertion: Assertion?) {
    let challenge = Data(SHA256.hash(data: body))
    let result = try assert(challenge)
    return (result.signature, Assertion(authenticatorData: result.authenticatorData, clientData: result.clientData))
  }
}
