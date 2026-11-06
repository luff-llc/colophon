import ColophonSession
import Foundation
import Observation

@Observable @MainActor public final class MemberAccessModel {
    public let member: Member
    public let action = LibraryActionModel()
    private let context: UUID
    private let revision: UInt64
    public init(member: Member, session: any LibrarySessionSource) {
        self.member = member; context = session.context; revision = session.revision
    }
    public func revoke(session: any LibrarySessionSource) async -> Bool {
        await action.run {
            await session.refresh()
            try Task.checkCancellation()
            guard session.context == context else { throw SessionError.destinationChanged }
            guard session.revision == revision, session.members.contains(member) else { throw SessionError.staleRevision }
            guard session.phase == .ready else { throw SessionError.notReady }
            guard member.grant != nil, member.revokedAt == nil else {
                throw LibraryUIError.unavailable("This member’s access cannot be ended here.")
            }
            try await session.revoke(memberID: member.id)
        }
    }
}
