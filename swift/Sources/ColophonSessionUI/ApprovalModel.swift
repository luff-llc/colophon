import ColophonSession
import Foundation
import Observation

/// Reviewing one request before approving it. Approval spends a pairing for exactly this request's key (spec §9.1):
/// either the request was scanned from the joining device's screen (`code == nil`: the pairing is confirmed already),
/// or the two devices ran the six-digit code (`code` is the approving device's digits, and the person confirms that
/// the joining device shows the same before anything is approved).
@Observable @MainActor public final class ApprovalModel {
    public let request: AccessRequest
    /// The six digits to compare, when the devices paired by the code; `nil` when the request was scanned.
    public let code: String?
    public var namespaces: Set<String>
    public var readOnly: Bool
    public var codeMatches = false
    public var limitsExpiry = false
    public var expires: Date
    public var limitsBudget = false
    public var budget = "100"
    public let action = LibraryActionModel()
    private let pairing: AccountPairing
    private let context: UUID
    private let revision: UInt64
    public init(request: AccessRequest, pairing: AccountPairing, code: String?, session: any LibrarySessionSource, now: Date = .now) {
        self.request = request; self.pairing = pairing; self.code = code
        namespaces = Set(request.namespaces)
        readOnly = !request.access.contains(.write)
        expires = now.addingTimeInterval(7 * 86400)
        context = session.context; revision = session.revision
    }
    /// A request scanned from the joining device's screen.
    public convenience init(scanned: ScannedRequest, session: any LibrarySessionSource, now: Date = .now) {
        self.init(request: scanned.request, pairing: scanned.pairing, code: nil, session: session, now: now)
    }
    public func grant(now: Date = .now) throws -> GrantOptions {
        guard code == nil || codeMatches else { throw LibraryUIError.unavailable("Compare the code on both devices before approving.") }
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
            guard session.revision == revision else { throw SessionError.staleRevision }
            guard session.phase == .ready else { throw SessionError.notReady }
            // The person said both screens show the same digits: only now is the pairing confirmed.
            if code != nil, try pairing.stage() != .confirmed { try pairing.confirm() }
            try await session.approve(request, pairing: pairing, grant: options)
        }
    }
    /// The codes differ: the pairing ends here (a failure the limiter counts) and nothing is approved. The joining
    /// device must abort too; a new attempt starts with fresh nonces.
    public func codesDiffer(session: any LibrarySessionSource) async -> Bool {
        await action.run { try await session.rejectPairing(pairing) }
    }
}
