import ColophonSession
import Foundation
import Observation

/// Serializes user gestures and preserves errors without automatic retries of authority actions.
@Observable @MainActor public final class LibraryActionModel {
    public private(set) var isWorking = false
    public private(set) var error: String?
    public init() {}
    public func clearError() { error = nil }
    public func report(_ failure: any Error) {
        let cocoa = failure as NSError
        if failure is CancellationError || (cocoa.domain == NSCocoaErrorDomain && cocoa.code == NSUserCancelledError) { return }
        error = failure.localizedDescription
    }
    @discardableResult public func run(_ operation: @MainActor () async throws -> Void) async -> Bool {
        guard !isWorking else { return false }
        isWorking = true; error = nil
        defer { isWorking = false }
        do { try Task.checkCancellation(); try await operation(); return true }
        catch { report(error); return false }
    }
    public func rejoin(session: any LibrarySessionSource, host: LibraryHostActions) async -> Bool {
        await run {
            guard let provider = host.rejoinKeys else { throw LibraryUIError.unavailable("Rejoining is not configured in this app.") }
            let keys = try await provider()
            try Task.checkCancellation()
            await session.rejoin(keys: keys)
            switch session.phase {
            case .failed(let failure): throw LibraryUIError.unavailable(failure.message)
            case .unavailable(let reason): throw LibraryUIError.unavailable(reason)
            case .denied: throw LibraryUIError.unavailable("This identity no longer has access. Rejoin with a new, saved identity and ask for approval.")
            default: break
            }
        }
    }
}

enum LibraryUIError: LocalizedError {
    case unavailable(String)
    var errorDescription: String? { switch self { case .unavailable(let message): message } }
}
