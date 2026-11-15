import Foundation
import ColophonSession

/// What the host does next in the move of a Swift-keyring library to a 0.5 account, from the engine's own
/// `SwiftSuccession.stage` (docs/bindings-05.md §7). Nothing here decides: the stage is the engine's.
public struct SwiftMoveNextStep: Equatable, Sendable {
    public enum Action: Equatable, Sendable {
        /// The succession window has not opened: nothing to do.
        case wait
        /// The veto window runs: show its deadline and offer `ColophonSession.vetoSwiftSuccession()`.
        case offerVeto
        /// It is due: the freezing device signs F (`begin_swift_freeze`, `AccountMove`, `finish_move`), appends
        /// `MoveResult.frozenEntry` to the Swift library and stores `MoveResult.stores`.
        case freeze
        /// F is written: other devices call `ColophonSession.acceptPredecessorEntry(_:)`; a copying member then
        /// runs the copy with the app's translator (`SwiftCopyPlan`) and the migration.
        case copyAndMigrate
        /// Vetoed: stop. The predecessor library is still the library.
        case vetoed
        /// Done: the account is the library.
        case migrated
    }
    public let action: Action
    public let succession: SwiftSuccession
    public init(_ succession: SwiftSuccession) {
        self.succession = succession
        switch succession.stage {
        case .windowNotOpen: action = .wait
        case .waiting: action = .offerVeto
        case .due: action = .freeze
        case .frozen, .verified: action = .copyAndMigrate
        case .vetoed: action = .vetoed
        case .migrated: action = .migrated
        }
    }
}

extension ColophonSession {
    /// The engine's succession claim and what to do next.
    public func swiftMoveNextStep() async throws -> SwiftMoveNextStep { SwiftMoveNextStep(try await swiftSuccession()) }
}
