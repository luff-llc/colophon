import ColophonSession
import Foundation

/// Observable session surface shared by production, previews and deterministic UI-model tests.
/// Conforming sources must publish cached values on the main actor; getters perform no I/O.
@MainActor public protocol LibrarySessionSource: AnyObject {
    var phase: SessionPhase { get }
    var hasUsableContent: Bool { get }
    var context: UUID { get }
    var revision: UInt64 { get }
    var members: [AccountMember] { get }
    var requests: [AccessRequest] { get }
    /// New in 0.5: what a person must be shown that is not content (pending changes, unseen activations, no home).
    var notices: SessionNotices { get }
    func restore() async
    func refresh() async
    func retry() async
    func create() async
    func leave() async throws
    func rejoin(keys: any AsyncKeyProvider) async
    func importRequest(from url: URL) async throws
    func approve(_ request: AccessRequest, grant: GrantOptions?) async throws
    func revoke(memberID: String) async throws
    /// New in 0.5: one call to veto a pending change; the session stores it and submits it to every home.
    func veto(_ transition: String) async throws
    /// New in 0.5: the person saw one activation. Pending transitions are not affected.
    func acknowledgeActivation(seq: UInt64) async
    /// New in 0.5: opens a locked session again.
    func unlock() async
    /// New in 0.5: hides the content and drops every secret the engine holds (the gate calls it when the scene leaves).
    func lock() async
    /// New in 0.5: what the host must do and say beyond `notices` (§17.5).
    var duties: HostDuties { get }
    /// New in 0.5: signs a dead transition this device signed again.
    @discardableResult func resign(_ transition: String) async throws -> String
}

extension ColophonSession: LibrarySessionSource {}

extension LibrarySessionSource { public var hasUsableContent: Bool { [SessionPhase.ready, .refreshing, .waitingForDownload, .retry].contains(phase) } }
