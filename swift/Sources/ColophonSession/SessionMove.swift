import Foundation

/// The session-level steps of the 0.5 move of a Swift-keyring library (docs/bindings-05.md §7). The successor
/// genesis (`SwiftSuccessorCreation`), the record copy (`SwiftCopyPlan` with the app's own translator) and the
/// migration need the app's own record translators and an app update that can write the freezing entry to the
/// predecessor library, so they are not built here: an app drives those generated objects itself and then opens
/// this session over the stored objects. What a session can do with the account that exists is below.
extension SessionWorker {
    func swiftSuccession() async throws -> SwiftSuccession {
        try await requireEngine().run { try $0.swiftSuccession() }
    }

    /// Signs a veto of the succession with the owner controller, stores it and returns what the move produced.
    func vetoSwiftSuccession() async throws -> MoveResult {
        try await inGate {
            try await withOwnerForMove { owner, custody, ownerID in
                let signers = try await owner.run { try $0.suggestSigners(available: [ownerID], need: .veto) }
                let issued = Int64((configuration.now().timeIntervalSince1970 * 1000).rounded())
                let who = signers.isEmpty ? [ownerID] : signers
                let move = try await owner.run { try $0.beginSwiftVeto(issuedMs: issued, signers: who) }
                let signatures = try await custody.sign(try move.steps())
                let result = try await owner.run { try $0.finishMove(step: move, signatures: signatures) }
                try await persistStores(result.stores)
                return result
            }
        }
    }

    func acceptPredecessorEntry(_ entry: Data) async throws {
        try await inGate {
            let at = Int64((configuration.now().timeIntervalSince1970 * 1000).rounded())
            _ = try await requireEngine().run { try $0.acceptPredecessorEntry(entry: entry, nowMs: at) }
        }
    }
}

extension ColophonSession {
    /// Where the account's claimed Swift succession stands (§15.1): window, veto deadline, due time, verified or not.
    /// The engine decides every field.
    public func swiftSuccession() async throws -> SwiftSuccession { await restore(); return try await worker.swiftSuccession() }

    /// One call to veto a succession during its wait: the owner signs, the veto is stored at `vetoes/<digest>.json`,
    /// and the next exchange submits it to every home. Returns the veto bytes and path the move produced.
    public func vetoSwiftSuccession() async throws -> MoveResult {
        await restore()
        do { let result = try await worker.vetoSwiftSuccession(); await refresh(); return result }
        catch { throw error }
    }

    /// Another device takes in the freezing entry the freezing device appended to the Swift library (`MoveResult.frozenEntry`).
    public func acceptPredecessorEntry(_ entry: Data) async throws {
        await restore(); try await worker.acceptPredecessorEntry(entry); await refresh()
    }
}
