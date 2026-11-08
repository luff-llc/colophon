import AuthenticationServices
import CryptoKit
import Foundation
#if os(macOS)
  import AppKit
#else
  import UIKit
#endif

/// Passkeys and security keys through AuthenticationServices.
/// PRF is requested only during get, with platform availability checked before presenting UI.
public struct SystemWebAuthnCeremonies: WebAuthnCeremonies {
  /// Creates the platform ceremony adapter.
  public init() {}

  /// Security keys are never available on visionOS.
  public var supportsSecurityKeys: Bool {
    #if os(visionOS)
      false
    #else
      true
    #endif
  }

  /// Checks runtime PRF availability without presenting a ceremony.
  public func supportsPRF(kind: CredentialKind) -> Bool {
    switch kind {
    case .passkey:
      if #available(iOS 18, macOS 15, visionOS 2, *) { return true }
      return false
    case .securityKey:
      #if os(visionOS)
      return false
      #else
      if #available(iOS 26.4, macOS 26.4, *) { return true }
      return false
      #endif
    }
  }

  /// Registers ES256 without requesting or returning registration PRF material.
  public func register(kind: CredentialKind, rpID: String, userID: Data, userName: String, challenge: Data)
    async throws -> Registration
  {
    switch kind {
    case .passkey:
      let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
      let request = provider.createCredentialRegistrationRequest(challenge: challenge, name: userName, userID: userID)
      request.userVerificationPreference = .required
      let authorization = try await Self.authorize(request)
      guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
        let attestation = credential.rawAttestationObject else { throw KeyProviderError.credentialMissing }
      return Registration(credentialID: credential.credentialID, attestationObject: attestation)
    case .securityKey:
      #if os(visionOS)
        throw KeyProviderError.unsupportedHere
      #else
      let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
      let request = provider.createCredentialRegistrationRequest(challenge: challenge, displayName: userName, name: userName,
        userID: userID)
      request.credentialParameters = [ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)]
      request.attestationPreference = .none
      request.userVerificationPreference = .required
      request.residentKeyPreference = .discouraged
      let authorization = try await Self.authorize(request)
      guard let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration,
        let attestation = credential.rawAttestationObject else { throw KeyProviderError.credentialMissing }
      return Registration(credentialID: credential.credentialID, attestationObject: attestation)
      #endif
    }
  }

  /// Gets exactly the selected credential and passes signed bytes through unchanged.
  public func assert(kind: CredentialKind, rpID: String, credential: Data, challenge: Data, prfSalt: Data?,
    requireVerification: Bool) async throws -> AssertionResult
  {
    if prfSalt != nil, !supportsPRF(kind: kind) { throw KeyProviderError.unsupportedHere }
    switch kind {
    case .passkey:
      let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
      let request = provider.createCredentialAssertionRequest(challenge: challenge)
      request.allowedCredentials = [ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credential)]
      request.userVerificationPreference = requireVerification ? .required : .preferred
      if #available(iOS 18, macOS 15, visionOS 2, *), let prfSalt {
        let values = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(saltInput1: prfSalt)
        var perCredential: [Data: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues] = [:]
        perCredential[credential] = values
        request.prf = .inputValues(values, perCredentialInputValues: perCredential.isEmpty ? nil : perCredential)
      }
      let authorization = try await Self.authorize(request)
      guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
        throw KeyProviderError.credentialMissing
      }
      var output: Data?
      if #available(iOS 18, macOS 15, visionOS 2, *) {
        output = credential.prf?.first.withUnsafeBytes { Data($0) }
        if output?.isEmpty == true { output = nil }
      }
      return AssertionResult(credentialID: credential.credentialID, signature: credential.signature,
        authenticatorData: credential.rawAuthenticatorData, clientData: credential.rawClientDataJSON, prfOutput: output)
    case .securityKey:
      #if os(visionOS)
        throw KeyProviderError.unsupportedHere
      #else
      let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
      let request = provider.createCredentialAssertionRequest(challenge: challenge)
      request.allowedCredentials = [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: credential, transports: [])]
      request.userVerificationPreference = requireVerification ? .required : .preferred
      if #available(iOS 26.4, macOS 26.4, *), let prfSalt {
        let values = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(saltInput1: prfSalt)
        request.prf = .inputValues(values, perCredentialInputValues: [credential: values])
      }
      let authorization = try await Self.authorize(request)
      guard let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion else {
        throw KeyProviderError.credentialMissing
      }
      var output: Data?
      if #available(iOS 26.4, macOS 26.4, *) {
        output = credential.prf?.first.withUnsafeBytes { Data($0) }
      }
      return AssertionResult(credentialID: credential.credentialID, signature: credential.signature,
        authenticatorData: credential.rawAuthenticatorData, clientData: credential.rawClientDataJSON, prfOutput: output)
      #endif
    }
  }

  @MainActor private static func authorize(_ request: ASAuthorizationRequest) async throws -> ASAuthorization {
    guard let presentation = WebAuthnPresentationContext.current else {
      throw KeyProviderError.unsupportedHere
    }
    let window = try presentation.capturedWindow()
    let coordinator = Coordinator(presentationWindow: window)
    let controller = ASAuthorizationController(authorizationRequests: [request])
    coordinator.controller = controller
    controller.delegate = coordinator
    controller.presentationContextProvider = coordinator
    coordinator.keepAlive = coordinator
    var observer: UUID?
    var pendingPresentation: UUID?
    defer {
      if let observer { presentation.removeInvalidationObserver(observer) }
      if let pendingPresentation { presentation.removePendingPresentation(pendingPresentation) }
    }
    let authorization: ASAuthorization = try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        coordinator.continuation = continuation
        observer = presentation.observeInvalidation { [weak coordinator] in coordinator?.cancel() }
        guard coordinator.continuation != nil else { return }
        if Task.isCancelled { coordinator.cancel(); return }
        pendingPresentation = presentation.enqueuePresentation({ [weak coordinator] in
          guard coordinator?.continuation != nil else { return }
          controller.performRequests()
        }, onFailure: { [weak coordinator] error in coordinator?.fail(error) })
      }
    } onCancel: {
      Task { @MainActor in coordinator.cancel() }
    }
    try presentation.checkCurrent()
    return authorization
  }
}

@MainActor private final class Coordinator: NSObject, ASAuthorizationControllerDelegate,
  ASAuthorizationControllerPresentationContextProviding
{
  var continuation: CheckedContinuation<ASAuthorization, Error>?
  var controller: ASAuthorizationController?
  var keepAlive: Coordinator?
  private let presentationWindow: ASPresentationAnchor

  init(presentationWindow: ASPresentationAnchor) {
    self.presentationWindow = presentationWindow
    super.init()
  }

  func cancel() {
    controller?.cancel()
    finish(.failure(CancellationError()))
  }

  func fail(_ error: Error) { finish(.failure(error)) }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    finish(.success(authorization))
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
    finish(.failure(KeyProviderError.map(error)))
  }

  func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
    presentationWindow
  }

  private func finish(_ result: Result<ASAuthorization, Error>) {
    let continuation = continuation
    self.continuation = nil
    keepAlive = nil
    switch result {
    case .success(let authorization): continuation?.resume(returning: authorization)
    case .failure(let error): continuation?.resume(throwing: error)
    }
  }

}
