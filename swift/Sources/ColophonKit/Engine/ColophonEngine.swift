import Dispatch
import Foundation

/// One engine on one serial executor.
///
/// Every `AccountEngine` call is synchronous and may be slow (a resumed open of 10,000 records is
/// about 0.7 s), and the host's record source callback runs inside it. This actor owns the engine and
/// runs each call on its own `DispatchSerialQueue`, never on the main actor and never on the
/// cooperative pool, so a long call blocks neither. The queue is the executor of the actor: calls to
/// one engine are strictly ordered.
///
/// Threads and callbacks (docs/bindings-05.md §3a): a `HostSource` callback runs on this queue while
/// the engine is inside a call. It must do its own I/O and return; it must not call back into this
/// actor, and must not wait on anything that does (a main-actor hop, a lock held by a task awaiting
/// this actor). A callback that re-enters on the same thread is the typed error `.reentered`.
///
/// Lifecycle: `lock()` before the last reference goes. Dropping an engine erases its keys on a
/// best-effort basis (the box below locks it), but only `lock()` clears the opened plaintext at a
/// moment you choose.
public actor ColophonEngine {
    private let queue: DispatchSerialQueue
    private let box = EngineBox()

    public nonisolated var unownedExecutor: UnownedSerialExecutor { queue.asUnownedSerialExecutor() }

    /// The engine's own account ID, set at open.
    public nonisolated let account: String
    public nonisolated let identity: AccountIdentity

    /// Opens the engine over `source` on its own queue. See `AccountEngine.open` for the arguments.
    /// `key` is the 32-byte device-held key that seals saved state; it is consumed (the bindings wipe
    /// their copy), so pass a `Data.secret` value.
    public static func open(label: String = "org.luff.colophon.engine", source: any HostSource, listing: [ListedPath],
                            identity: AccountIdentity, account: String, namespaces: [String] = [], batch: UInt64 = 0,
                            saved: SavedState? = nil, deviceKey: Data, nowMs: Int64) async throws -> ColophonEngine {
        let engine = ColophonEngine(label: label, account: account, identity: identity)
        try await engine.start(source: source, listing: listing, namespaces: namespaces, batch: batch, saved: saved, deviceKey: deviceKey, nowMs: nowMs)
        return engine
    }

    private init(label: String, account: String, identity: AccountIdentity) {
        queue = DispatchSerialQueue(label: label, qos: .userInitiated)
        self.account = account; self.identity = identity
    }

    private func start(source: any HostSource, listing: [ListedPath], namespaces: [String], batch: UInt64, saved: SavedState?,
                       deviceKey: Data, nowMs: Int64) throws {
        do {
            box.engine = try AccountEngine.open(source: source, listing: listing, identity: identity, account: account,
                namespaces: namespaces, batch: batch, saved: saved ?? SavedState(verifier: Data(), checkpoint: Data(), parts: []),
                key: deviceKey, nowMs: nowMs)
        } catch { throw ColophonError.wrap(error) }
    }

    /// Runs `body` on the engine's queue with the engine. Errors from the bindings arrive as
    /// `ColophonError`. A locked or discarded engine is `ColophonError.locked`.
    public func run<T: Sendable>(_ body: @Sendable (AccountEngine) throws -> T) throws -> T {
        guard let engine = box.engine else {
            throw ColophonError.locked(code: "locked", detail: "this engine was locked or discarded; open a new one")
        }
        do { return try body(engine) } catch { throw ColophonError.wrap(error) }
    }

    public var isLocked: Bool { box.engine == nil }

    /// Overwrites the engine's keys and opened plaintext and releases it. Further calls are `.locked`.
    public func lock() {
        guard let engine = box.engine else { return }
        _ = try? engine.lock()
        box.engine = nil
    }

    /// Drops the engine after the call that ended in `.integrity` (it is unusable; do not call `lock`).
    public func discard() { box.engine = nil }

    // MARK: Prepare, sign, finish

    /// An action from `begin` to `Written`: prepare, answer PRF requests, sign every step, finish.
    ///
    /// The calls into the engine run on its queue; the key ceremonies in between (a passkey prompt, a
    /// Secure Enclave signature) run in `custody` outside it, so a person's pause never holds the
    /// engine. Between the steps other calls may interleave: callers that must not interleave (a write
    /// followed by persisting its stores) serialise above this type, as the session worker does.
    ///
    /// A write refused for access reasons throws `ColophonError.denied` (the denial is a value in the
    /// bindings; here it is an error). A failed finish changes nothing and consumes the action.
    public func execute(custody: KeyCustody, _ begin: @Sendable (AccountEngine) throws -> AccountAction) async throws -> Written {
        let action = try run(begin)
        if let denial = try action.denial() {
            throw ColophonError.denied(code: "denied:" + denial.reasonRaw.orEmpty(String(describing: denial.reason)),
                                       reason: denial.reason, reasonRaw: denial.reasonRaw, detail: denial.detail)
        }
        let requests = try action.prfRequests()
        if !requests.isEmpty {
            let answers = try await custody.answer(requests)
            try run { try $0.providePrf(action: action, results: answers) }
        }
        let signatures = try await custody.sign(try action.steps())
        return try run { try $0.finish(action: action, signatures: signatures) }
    }
}

private extension Optional where Wrapped == String {
    func orEmpty(_ fallback: String) -> String { self ?? fallback }
}

/// Holds the engine so that dropping the last reference locks it.
private final class EngineBox: @unchecked Sendable {
    var engine: AccountEngine?
    deinit { if let engine { _ = try? engine.lock() } }
}
