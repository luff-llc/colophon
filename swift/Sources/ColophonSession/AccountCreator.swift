import Foundation

/// Drives `AccountCreation` through its stages with the host's key custody: PRF answers for the new
/// slots, then the signatures of the genesis and the first rekey.
enum AccountCreator {
    @concurrent static func create(params: CreateParams, identity: AccountIdentity, custody: KeyCustody, nowMs: Int64) async throws -> Created {
        do {
            let creation = try AccountCreation.begin(params: params, identity: identity, nowMs: nowMs, entropy: try colophonEntropy(96))
            let requests = try creation.prfRequests()
            if !requests.isEmpty { try creation.providePrf(results: try await custody.answer(requests)) }
            for _ in 0..<8 {
                let steps = try creation.steps()
                if try creation.provideSignatures(signatures: try await custody.sign(steps)) == .done { return try creation.takeResult() }
            }
            throw ColophonError.internalFailure(code: "internal", detail: "the creation did not finish")
        } catch { throw ColophonError.wrap(error) }
    }
}
