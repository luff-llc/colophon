import Foundation
import ColophonKit

struct SessionKeyFailure: Error, Sendable { let detail: String }
/// Classifies provider failures at their origin, preserving storage/core errors separately.
struct SessionKeys: AsyncKeyProvider {
    let base: any AsyncKeyProvider
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
    func agree(peer: Data) async throws -> Data {
        do { return try await base.agree(peer: peer) }
        catch is CancellationError { throw CancellationError() }
        catch { throw SessionKeyFailure(detail: error.localizedDescription) }
    }
}
