import Foundation

/// Drives `AccountCreation` through its stages with the host's key custody: PRF answers for the new
/// slots, then the signatures of the genesis and the first rekey. Returns the creation with its result: the
/// caller stores the result and opens the session over it with `ColophonEngine.openCreated`, unlocked.
enum AccountCreator {
    @concurrent static func create(params: CreateParams, identity: AccountIdentity, custody: KeyCustody, nowMs: Int64) async throws -> (AccountCreation, Created) {
        do {
            let creation = try withEntropy(96) { try AccountCreation.begin(params: params, identity: identity, nowMs: nowMs, entropy: $0) }
            let requests = try creation.prfRequests()
            if !requests.isEmpty {
                let answers = try await custody.answer(requests)
                try answers.withRecords { try creation.providePrf(results: $0) }
            }
            for _ in 0..<8 {
                let steps = try creation.steps()
                if try creation.provideSignatures(signatures: try await custody.sign(steps)) == .done { return (creation, try creation.takeResult()) }
            }
            throw ColophonError.internalFailure(code: "internal", detail: "the creation did not finish")
        } catch { throw ColophonError.wrap(error) }
    }
}
