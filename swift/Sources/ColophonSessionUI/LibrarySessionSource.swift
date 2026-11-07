import ColophonSession
import Foundation

/// Observable session surface shared by production, previews and deterministic UI-model tests.
/// Conforming sources must publish cached values on the main actor; getters perform no I/O.
@MainActor public protocol LibrarySessionSource: AnyObject {
    var phase: SessionPhase { get }
    var hasUsableContent: Bool { get }
    var context: UUID { get }
    var revision: UInt64 { get }
    var members: [Member] { get }
    var requests: [AccessRequest] { get }
    var ledger: [LedgerEntry] { get }
    func restore() async
    func refresh() async
    func retry() async
    func create() async
    func leave() async throws
    func rejoin(keys: any AsyncKeyProvider) async
    func importRequest(from url: URL) async throws
    func approve(_ request: AccessRequest, grant: GrantOptions?) async throws
    func revoke(memberID: String) async throws
}

extension ColophonSession: LibrarySessionSource {}

extension LibrarySessionSource { public var hasUsableContent: Bool { phase == .ready || phase == .refreshing } }
