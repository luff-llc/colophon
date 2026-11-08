import Foundation
import Observation

/// Secrets remain transient. Neither kit text nor arbitrary provider errors enter diagnostics.
@Observable @MainActor public final class RecoveryKitModel {
    public var input = ""
    public var kept = false
    public private(set) var exported: String?
    public private(set) var imported = false
    public let action = LibraryActionModel()
    private var generation = UUID()
    public init() {}
    public func clear() { generation = UUID(); input = ""; exported = nil; kept = false }
    public func prepare(host: LibraryHostActions) async {
        let lease = generation
        await action.run {
            guard let export = host.exportRecoveryKit else { throw LibraryUIError.unavailable("Recovery kit export is not available in this app.") }
            let text: String
            do { text = try await export() }
            catch is CancellationError { throw CancellationError() }
            catch { throw LibraryUIError.unavailable("The recovery kit could not be prepared. Check key access and try again.") }
            try Task.checkCancellation()
            guard generation == lease else { throw CancellationError() }
            guard !text.isEmpty, text.utf8.count <= 64 * 1024 else { throw LibraryUIError.unavailable("The recovery kit is empty or too large.") }
            exported = text; kept = false
        }
    }
    /// Ask the host to decode its kit and restore this device through the library's keyring.
    public func restoreDevice(host: LibraryHostActions) async {
        let secret = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let lease = generation
        await action.run {
            imported = false
            guard let recover = host.importRecoveryKit else { throw LibraryUIError.unavailable("Recovery kit import is not available in this app.") }
            guard !secret.isEmpty, secret.utf8.count <= 64 * 1024 else { throw LibraryUIError.unavailable("Enter a valid recovery kit.") }
            do { try await recover(secret) }
            catch is CancellationError { throw CancellationError() }
            catch { throw LibraryUIError.unavailable("This kit could not recover the library. Check the kit and selected library, then try again.") }
            guard generation == lease else { return }
            input = ""; imported = true
        }
    }
}
