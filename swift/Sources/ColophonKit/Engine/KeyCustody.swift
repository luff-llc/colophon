import Foundation

/// The host's key custody for one engine operation: the providers the host holds, found by key ID.
///
/// The engine never calls a key provider (docs/bindings-05.md §8). It returns exact bodies to sign,
/// PRF requests, unlock inputs and epoch agreements, and the host answers them. This type does the
/// answering through `AsyncKeyProvider`s, so that raw keys (device keys, Secure Enclave keys, a
/// recovery kit) and WebAuthn passkeys are driven the same way.
public struct KeyCustody: Sendable {
    /// Providers by key ID (the first 32 hex characters of SHA-256 of the signing point).
    public let providers: [String: any AsyncKeyProvider]

    public init(providers: [String: any AsyncKeyProvider]) { self.providers = providers }

    /// Reads each provider's public key to find its ID.
    public init(_ list: [any AsyncKeyProvider]) async throws {
        var byId: [String: any AsyncKeyProvider] = [:]
        for provider in list { byId[try await Self.keyID(of: provider)] = provider }
        providers = byId
    }

    public static func keyID(of spec: ControllerSpec) throws -> String { try accountKeyId(signing: spec.key.signing) }

    public static func keyID(of provider: any AsyncKeyProvider) async throws -> String {
        try accountKeyId(signing: try await provider.publicKeys().signing)
    }

    public func provider(for id: String) throws -> any AsyncKeyProvider {
        guard let provider = providers[id] else { throw KeyCustodyError.noKey(id) }
        return provider
    }
    public func holds(_ id: String) -> Bool { providers[id] != nil }

    /// One signature per step, in order: raw `r||s` from `sign(body:)`, or the WebAuthn assertion for
    /// the step's challenge. A step whose signer is not held is `KeyCustodyError.noKey`.
    public func sign(_ steps: [AccountSigningStep]) async throws -> [Signature] {
        var out: [Signature] = []
        for step in steps {
            try Task.checkCancellation()
            let provider = try provider(for: step.signer)
            switch step.form {
            case .raw:
                out.append(Signature(signature: try await provider.sign(body: step.body), authenticatorData: nil, clientData: nil))
            case .webauthn:
                guard let challenge = step.challenge else { throw KeyCustodyError.missingChallenge }
                guard let result = try await provider.assert(challenge: challenge, prfSalt: nil) else { throw KeyCustodyError.unsupported }
                out.append(result.signatureValue)
            case .unknown:
                throw KeyCustodyError.unsupported
            }
        }
        return out
    }

    /// One assertion per request, evaluating the request's salt: `results.first` is the PRF output.
    public func answer(_ requests: [PrfRequest]) async throws -> [HostPrfAnswer] {
        var out: [HostPrfAnswer] = []
        for request in requests {
            try Task.checkCancellation()
            let provider = try provider(for: request.controller)
            let challenge = Self.base64url(request.challenge)
            guard let result = try await provider.assert(challenge: challenge, prfSalt: request.salt),
                  let prf = result.prf, prf.count == 32 else { throw KeyCustodyError.unsupported }
            out.append(HostPrfAnswer(authenticatorData: result.authenticatorData, clientData: result.clientData,
                                     signature: result.signature, output: prf))
        }
        return out
    }

    /// The raw results of a slot's routes, in input order: ECDH against `enc`, or the PRF of `salt`.
    public func answer(unlock inputs: [UnlockInput]) async throws -> [HostUnlockSecret] {
        var out: [HostUnlockSecret] = []
        for input in inputs {
            try Task.checkCancellation()
            let provider = try provider(for: input.controller)
            switch input.kind {
            case .ecdh: out.append(HostUnlockSecret(kind: .ecdh, secret: try await provider.sharedSecret(peer: input.enc)))
            case .prf:
                guard let prf = try await provider.prf(salt: input.salt), prf.count == 32 else { throw KeyCustodyError.unsupported }
                out.append(HostUnlockSecret(kind: .prf, secret: prf))
            }
        }
        return out
    }

    /// The ECDH results a member's host performs to open its epoch shares.
    public func answer(epochs agreements: [EpochAgreement]) async throws -> [HostEpochAnswer] {
        var out: [HostEpochAnswer] = []
        for agreement in agreements {
            try Task.checkCancellation()
            let provider = try provider(for: agreement.recipient)
            out.append(HostEpochAnswer(namespace: agreement.namespace, epoch: agreement.epoch,
                                       shared: try await provider.sharedSecret(peer: agreement.peer)))
        }
        return out
    }

    static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public enum KeyCustodyError: Error, Equatable, Sendable {
    /// The engine asked for a key this host does not hold (its ID is the payload; an ID is public).
    case noKey(String)
    case missingChallenge
    /// The provider cannot do what was asked (no PRF, no assertion, an unknown signing form).
    case unsupported
}
extension KeyCustodyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noKey(let id): "This device does not hold the key \(id)."
        case .missingChallenge: "A WebAuthn step carried no challenge."
        case .unsupported: "This key cannot perform the requested ceremony."
        }
    }
}

/// The host's answer to a `PrfRequest`, its output held as `SecretBytes` until the one export call that takes it.
public struct HostPrfAnswer: Sendable, CustomStringConvertible {
    public let authenticatorData: Data
    public let clientData: Data
    public let signature: Data
    public let output: SecretBytes
    public init(authenticatorData: Data, clientData: Data, signature: Data, output: SecretBytes) {
        self.authenticatorData = authenticatorData; self.clientData = clientData; self.signature = signature; self.output = output
    }
    public var description: String { "HostPrfAnswer(redacted)" }
}

/// One slot route's raw secret, held as `SecretBytes` until `finish_unlock_slot`.
public struct HostUnlockSecret: Sendable, CustomStringConvertible {
    public let kind: UnlockKind
    public let secret: SecretBytes
    public init(kind: UnlockKind, secret: SecretBytes) { self.kind = kind; self.secret = secret }
    public var description: String { "HostUnlockSecret(redacted)" }
}

/// One epoch share's ECDH result, held as `SecretBytes` until `finish_unlock_epochs`.
public struct HostEpochAnswer: Sendable, CustomStringConvertible {
    public let namespace: String
    public let epoch: UInt64
    public let shared: SecretBytes
    public init(namespace: String, epoch: UInt64, shared: SecretBytes) { self.namespace = namespace; self.epoch = epoch; self.shared = shared }
    public var description: String { "HostEpochAnswer(redacted)" }
}

/// Lending the secrets to the generated records for exactly one export call. The records refer to the owned memory
/// (no Swift copy); they must not escape `body`.
extension Array where Element == HostPrfAnswer {
    public func withRecords<R>(_ body: ([PrfAnswer]) throws -> R) throws -> R {
        try withUnsafeData(map(\.output)) { outputs in
            try body(zip(self, outputs).map { PrfAnswer(authenticatorData: $0.authenticatorData, clientData: $0.clientData, signature: $0.signature, output: $1) })
        }
    }
}
extension Array where Element == HostUnlockSecret {
    public func withRecords<R>(_ body: ([UnlockSecret]) throws -> R) throws -> R {
        try withUnsafeData(map(\.secret)) { secrets in try body(zip(self, secrets).map { UnlockSecret(kind: $0.kind, secret: $1) }) }
    }
}
extension Array where Element == HostEpochAnswer {
    public func withRecords<R>(_ body: ([EpochAnswer]) throws -> R) throws -> R {
        try withUnsafeData(map(\.shared)) { shares in try body(zip(self, shares).map { EpochAnswer(namespace: $0.namespace, epoch: $0.epoch, shared: $1) }) }
    }
}
