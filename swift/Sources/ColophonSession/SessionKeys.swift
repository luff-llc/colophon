import Foundation
import ColophonKit

public struct SessionKeyFailure: Error, Sendable, LocalizedError {
    public let detail: String
    public var errorDescription: String? { detail }
}
/// Classifies provider failures at their origin, preserving storage/core errors separately.
struct SessionKeys: AsyncKeyProvider {
    let base: any AsyncKeyProvider
    var form: KeyForm { base.form }
    func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion? {
        do { return try await base.assert(challenge: challenge, prfSalt: prfSalt) }
        catch is CancellationError { throw CancellationError() }
        catch { throw SessionKeyFailure(detail: error.localizedDescription) }
    }
    func prf(salt: Data) async throws -> SecretBytes? {
        do { return try await base.prf(salt: salt) }
        catch is CancellationError { throw CancellationError() }
        catch { throw SessionKeyFailure(detail: error.localizedDescription) }
    }
    func publicKeys() async throws -> PublicKeys {
        do { return try await base.publicKeys() }
        catch is CancellationError { throw CancellationError() }
        catch { throw SessionKeyFailure(detail: error.localizedDescription) }
    }
    func sign(body: Data) async throws -> Data {
        do { return try await base.sign(body: body) }
        catch is CancellationError { throw CancellationError() }
        catch { throw SessionKeyFailure(detail: error.localizedDescription) }
    }
    func keyDescriptor() async throws -> KeyDescriptorView {
        do { return try await base.keyDescriptor() }
        catch is CancellationError { throw CancellationError() }
        catch { throw SessionKeyFailure(detail: error.localizedDescription) }
    }
    func sharedSecret(peer: Data) async throws -> SecretBytes {
        do { return try await base.sharedSecret(peer: peer) }
        catch is CancellationError { throw CancellationError() }
        catch { throw SessionKeyFailure(detail: error.localizedDescription) }
    }
}
