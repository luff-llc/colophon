import ColophonSession
import Foundation
import Observation

@Observable @MainActor public final class ApprovalModel {
    public let request: AccessRequest
    public var namespaces: Set<String>
    public var readOnly: Bool
    public var codeMatches = false
    public var limitsExpiry = false
    public var expires: Date
    public var limitsBudget = false
    public var budget = "100"
    public let action = LibraryActionModel()
    private let context: UUID
    private let revision: UInt64
    public init(request: AccessRequest, session: any LibrarySessionSource, now: Date = .now) {
        self.request = request; namespaces = Set(request.namespaces)
        readOnly = !request.access.contains(.write)
        expires = now.addingTimeInterval(7 * 86400)
        context = session.context; revision = session.revision
    }
    public func grant(now: Date = .now) throws -> GrantOptions {
        guard codeMatches else { throw LibraryUIError.unavailable("Compare the code on both devices before approving.") }
        guard !namespaces.isEmpty, namespaces.isSubset(of: Set(request.namespaces)) else {
            throw LibraryUIError.unavailable("Choose at least one of the requested areas.")
        }
        let access = request.access.filter { !readOnly || $0 == .read }
        guard !access.isEmpty else { throw LibraryUIError.unavailable("The selected access was not requested.") }
        guard !limitsExpiry || expires > now else { throw LibraryUIError.unavailable("Choose an expiry in the future.") }
        var writeBudget: UInt64?
        if limitsBudget && access.contains(.write) {
            guard let value = UInt64(budget), value > 0 else { throw LibraryUIError.unavailable("Enter a whole number of changes greater than zero.") }
            writeBudget = value
        }
        return GrantOptions(namespaces: request.namespaces.filter(namespaces.contains), access: access,
                            expires: limitsExpiry ? expires.ISO8601Format() : nil, writeBudget: writeBudget)
    }
    public func approve(session: any LibrarySessionSource, now: Date = .now) async -> Bool {
        await action.run {
            let options = try grant(now: now)
            await session.refresh()
            try Task.checkCancellation()
            guard session.context == context else { throw SessionError.destinationChanged }
            guard session.revision == revision, session.requests.contains(request) else { throw SessionError.staleRevision }
            guard session.phase == .ready else { throw SessionError.notReady }
            try await session.approve(request, grant: options)
        }
    }
}
