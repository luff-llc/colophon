import Foundation
import os
import Security
import ColophonSession

/// A command the host refused or could not run.
public struct CellHostError: Error, Equatable, Sendable, CustomStringConvertible {
    public enum Code: String, Sendable { case closed, failed, commandQueueFull, notRun, timeout, superseded }
    public let code: Code
    public let message: String
    public init(_ code: Code, _ message: String) { self.code = code; self.message = message }
    public var description: String { "\(code.rawValue): \(message)" }
}

/// Why an endpoint was made again.
public enum RebuildReason: String, Sendable { case clockBackwards, wrongView, sessionChanged }
/// Why a cell host stopped acting: `store` (its writes or fence checks kept failing), `rebuild` (a new endpoint could not
/// be made), `superseded` (the store holds another instance's fence: it owns the cell now).
public enum FailReason: String, Sendable { case store, rebuild, superseded }
/// An input the endpoint kept behind the `Persist` being written.
public enum KeptInput: String, Sendable { case frame, tick, link }

/// What a cell host reports. Session events and sent frames carry application state: show them, never log them.
public enum CellHostEvent: Sendable {
    /// An `Event` effect: the event's tag and the core's event JSON.
    case session(event: String, json: String)
    /// A frame was handed to the carrier (`frame` is the sealed text, `kind` its plaintext kind).
    case sent(kind: String, frame: String)
    /// A frame was not sent: the core could not seal it (`reason` its code), or the carrier was down (`carrier`, with the
    /// sealed `frame`).
    case unsent(kind: String, reason: String, frame: String?)
    /// A received frame was dropped (the §S3 code; `queueFull` when it could not be kept behind a write).
    case drop(reason: String, helloTo: String?)
    /// Effects decided under an older authority head were dropped instead of released.
    case discarded(count: UInt32)
    /// An input was kept behind the `Persist` being written.
    case queued(input: KeptInput)
    /// A `Persist` write started, completed (and was acknowledged), or failed (and will be retried).
    case persist(phase: PersistPhase, ack: UInt64, error: String?)
    /// A command waits for the write in progress (`session:persistPending`).
    case commandHeld(command: String)
    /// The endpoint's view was older than the engine's head (`session:staleAccount`).
    case stale
    /// A new view was installed: what this member may do now.
    case account(entitled: Bool, canWrite: Bool, seq: UInt64)
    /// The endpoint was made again from the stored claim.
    case rebuilt(reason: RebuildReason)
    /// A frame arrived while the endpoint was being made again: not judged (loss).
    case missed
    /// The cell stopped acting: its endpoint is gone, it sends nothing and is detached, and every held or new command is
    /// refused. Open a new host to take part again (from the last stored claim, so the restart rules apply).
    case failed(reason: FailReason, error: String?)
    /// Something the host could not do (`code` as the core spells it).
    case error(code: String, during: String)

    public enum PersistPhase: String, Sendable { case started, stored, failed }
}

/// How a cell host is made.
public struct CellHostOptions: Sendable {
    public var account: any HostAccount
    public var carrier: any CellCarrier
    public var namespace: String
    public var cell: String
    /// Where the claim lives: a fenced `ClaimStore` (`MemoryClaimStore`, `SQLiteClaimStore`).
    public var store: any ClaimStore
    /// The §S1 policy as JSON (default `session_default_policy()`); every member of a cell uses the same one.
    public var policy: String?
    public var clock: any HostClock = SystemClock()
    /// The application's state for the cell, given with `join` (a restarted holder retakes with it, §S6).
    public var state: @Sendable () -> Data? = { nil }
    /// How long a delegation is valid (at most 86,400,000 ms; default that). It is renewed an hour before it ends.
    public var delegationMs: Int64 = 86_400_000
    /// How long to wait before writing a `Persist` again after its write failed.
    public var persistRetryMs: Int64 = 250
    /// Consecutive failed or overdue attempts of one write after which the cell fails.
    public var persistAttempts: Int = 20
    /// How long one write may take before it counts as failed; a late success is not acknowledged.
    public var persistTimeoutMs: Int64 = 10_000
    /// Consecutive failed or unanswered fence checks (one a beat) after which the cell fails closed.
    public var fenceCheckMisses: Int = 3
    /// The most commands held at once; one more is refused with `commandQueueFull`.
    public var maxCommands: Int = 64
    /// Host randomness (default `SecRandomCopyBytes`). The session key and the `fresh` seed are new on every start.
    public var random: @Sendable (Int) -> Data = { count in
        var bytes = Data(count: count)
        let ok = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        precondition(ok == errSecSuccess, "the system random number generator failed")
        return bytes
    }
    public init(account: any HostAccount, carrier: any CellCarrier, namespace: String, cell: String, store: any ClaimStore) {
        self.account = account; self.carrier = carrier; self.namespace = namespace; self.cell = cell; self.store = store
    }
}

/// A command admitted to a cell host; `value()` waits until the endpoint ran it (or it was refused).
public struct CellCommand: Sendable {
    fileprivate let outcome: OneShot<Result<Void, CellCommandFailure>>
    /// Returns once the endpoint has run the command; throws the endpoint's refusal or a `CellHostError`.
    public func value() async throws {
        if case .failure(let failure) = await outcome.wait() { throw failure.error }
    }
}
struct CellCommandFailure: Error { let error: any Error }

/// The Swift host of one 0.6 session cell: it owns a `SessionEndpoint` and runs the reference host loop of
/// docs/bindings-05.md §10 exactly.
///
/// - Every input (a frame, a timer at the step's `next_deadline`, a carrier change, an application command, a completed
///   write, a delegation renewal) is one job on one serial queue: jobs run one at a time, in admission order, and a job
///   that suspends (to read the engine) is never interleaved with another, so nothing touches the endpoint outside the
///   job that owns it. Listeners hear events only between jobs, and anything a listener, store, socket or timer does
///   becomes a later job: nothing re-enters the endpoint.
/// - The step a call returns is carried out in order: `Send` to the carrier, `Event` to the application, `Persist` to the
///   store. A `Persist` is acknowledged (`persisted`) only when its durable write has completed, as a later job.
/// - `session:staleAccount` installs a fresh view of the engine (`set_account`) and the input is run again.
/// - `session:persistPending` keeps the command, in order, until the write completes. Admission is bounded.
/// - `session:clockBackwards` and a view of another engine (`session:wrongView`) discard the endpoint and make a new one
///   from the last claim the store holds, so the restart rules apply (sessions §S6).
/// - Drops, discarded effects and unsent frames are reported, never thrown away silently.
///
/// Frames reach `receive` as the text the carrier delivered, unchanged. Every timing decision is the core's: the host
/// only calls `tick` at the deadline the latest step carries. See docs/hosts-06.md §6 for the store, fencing and failure
/// rules (one save in flight, a write deadline, bounded attempts, a fence check every beat).
public actor SessionCellHost: StreamCell {
    public nonisolated let namespace: String
    public nonisolated let cell: String
    public nonisolated let me: String
    private let account: any HostAccount
    private let carrier: any CellCarrier
    private let store: any ClaimStore
    private let policy: String
    private let clock: any HostClock
    private let stateOf: @Sendable () -> Data?
    private let delegationMs: Int64
    private let persistRetryMs: Int64
    private let persistAttempts: Int
    private let persistTimeoutMs: Int64
    private let maxCommands: Int
    private let random: @Sendable (Int) -> Data
    private let watchMs: Int64
    private let watchMisses: Int

    public enum Phase: String, Sendable { case opening, open, rebuilding, failed, closed }
    private var phase: Phase = .opening
    private var endpoint: SessionEndpoint? { didSet { let e = endpoint; visible.withLock { $0 = e } } }
    /// The authority head (seq and digest) of the view installed last, and this member's session number in it.
    private var installed: (seq: UInt64, digest: String, session: UInt64?)?
    /// The last `persisted_json` whose durable write completed: what a new endpoint starts from.
    private var lastStored: String? { didSet { let s = lastStored; storedVisible.withLock { $0 = s } } }
    /// Settles when the write in progress has ended (stored, or given up); set before any store code runs.
    private var writing: OneShot<Void>?
    /// This instance's fencing generation (above what the store held when it opened or rebuilt) and its save count.
    private var generation: Int64 = 1
    private var seq: Int64 = 0
    /// The fence this instance last saw held: what every save it makes expects (compare-and-set).
    private var heldFence: Fence?
    private var tickTimer = Deadline()
    private var renewTimer = Deadline()
    /// Timers that close and failure cancel (retry waits, write deadlines, beats).
    private var waits: [UUID: (OneShot<Waited>, HostTimer)] = [:]
    /// Commands that wait, in admission order: one the endpoint refused with `persistPending`, and every later one.
    private var held: [Held] = []
    /// The carrier's link as last reported, applied to every new endpoint.
    private var carrierUp = false
    private var attached = false
    private var passToken: ListenerToken?
    private var outbox: [CellHostEvent] = []
    private var inJob = false
    /// Commands a job settled: their callers resume after the job's events were reported.
    private var settled: [(OneShot<Result<Void, CellCommandFailure>>, Result<Void, CellCommandFailure>)] = []

    /// Read without entering the actor: the endpoint (for its read-only calls), the stored claim, admitted commands,
    /// listeners, and whether the host has ended.
    private nonisolated let visible = OSAllocatedUnfairLock<SessionEndpoint?>(initialState: nil)
    private nonisolated let storedVisible = OSAllocatedUnfairLock<String?>(initialState: nil)
    private nonisolated let gate = OSAllocatedUnfairLock<Gate>(initialState: Gate())
    private nonisolated let listeners = OSAllocatedUnfairLock<[UUID: @Sendable (CellHostEvent) -> Void]>(initialState: [:])
    private nonisolated let jobs: AsyncStream<Job>.Continuation

    /// Statistics for tests and diagnostics.
    public struct Stats: Sendable { public var calls = 0, queued = 0, drops = 0, stale = 0, rebuilt = 0, persisted = 0, held = 0 }
    public private(set) var stats = Stats()

    private struct Gate {
        /// Closed or failed: every new command is refused with this.
        var over: CellHostError?
        var admitted: [UUID: Held] = [:]
    }
    fileprivate struct Held: Sendable {
        let id: UUID
        let name: String
        let json: String
        let outcome: OneShot<Result<Void, CellCommandFailure>>?
    }
    private enum Waited: Sendable { case fired, cancelled }
    private enum SaveResult: Sendable { case stored, stale, failed(String) }
    private enum Job: Sendable {
        case command(Held), frame(String), linkUp, linkDown, accountChanged, close
        case tick(UInt64), renew(UInt64)
        case stored(ack: UInt64, endpoint: ObjectIdentifier)
        case writeEnded(fail: FailReason?, error: String?)
        case rebuilt(failure: FailReason?, error: String?)
        case renewed(body: Data, signature: Data, endpoint: ObjectIdentifier, expires: Int64)
        case fail(FailReason, error: String?)
    }

    private init(_ options: CellHostOptions) {
        account = options.account; carrier = options.carrier; namespace = options.namespace; cell = options.cell
        me = options.account.member; store = options.store
        policy = options.policy ?? ((try? sessionDefaultPolicy()) ?? "{}")
        clock = options.clock; stateOf = options.state
        delegationMs = min(max(options.delegationMs, 1), Self.day)
        persistRetryMs = max(0, options.persistRetryMs)
        persistAttempts = max(1, options.persistAttempts)
        persistTimeoutMs = max(1, options.persistTimeoutMs)
        maxCommands = max(1, options.maxCommands)
        random = options.random
        var beat: Int64 = 5_000
        if let object = try? JSONSerialization.jsonObject(with: Data(policy.utf8)) as? [String: Any], let b = object["beatMs"] as? NSNumber, b.int64Value > 0 { beat = b.int64Value }
        watchMs = beat
        watchMisses = max(1, options.fenceCheckMisses)
        let (stream, continuation) = AsyncStream<Job>.makeStream()
        jobs = continuation
        Task { [weak self] in
            for await job in stream {
                guard let self else { return }
                await self.perform(job)
            }
        }
    }
    deinit { jobs.finish() }

    private static let day: Int64 = 86_400_000
    private static let renewBefore: Int64 = 3_600_000

    /// Starts a session for this member in the cell: loads the stored claim, reserves this instance's fence, makes the
    /// endpoint, has the member key sign its delegation, attaches to the carrier and joins with the application's state.
    /// If any of that fails the host is closed (detached, its endpoint dropped) and the error is thrown.
    public static func open(_ options: CellHostOptions, listener: (@Sendable (CellHostEvent) -> Void)? = nil) async throws -> SessionCellHost {
        let host = SessionCellHost(options)
        if let listener { _ = host.on(listener) }
        do {
            try await host.opening()
            try await host.command("join", json: await host.joinJSON())
        } catch {
            await host.end(.closed, CellHostError(.closed, "the cell host is closed"))
            throw error
        }
        return host
    }
    private func opening() async throws {
        let held = try await store.load()
        lastStored = held?.claim
        heldFence = held?.fence
        generation = held?.fence.generation ?? 0
        // Reserve this instance's generation by compare-and-set before any claim is saved under it.
        try await reserve(held?.claim)
        try await build()
        guard phase == .opening, !isOver else { throw CellHostError(.closed, "the cell host was closed while it opened") }
        phase = .open
        attached = true
        try await carrier.attach(self)
        passToken = await carrier.onPass { [weak self] in self?.accountChanged() }
        armTick(try? endpoint?.nextDeadline())
        watch()
    }
    private func joinJSON() -> String { Self.json(["command": "join", "state": stateValue()]) }

    /// Calls `listener` with every event, between jobs. Listeners may call any of this host's `nonisolated` calls
    /// (commands, inputs); each becomes a later job.
    public nonisolated func on(_ listener: @escaping @Sendable (CellHostEvent) -> Void) -> ListenerToken {
        let id = UUID()
        listeners.withLock { $0[id] = listener }
        return ListenerToken { [listeners] in listeners.withLock { $0[id] = nil } }
    }

    /// The endpoint, for its read-only calls (`isHolder`, `gated`, `viewJson`, ...), or nil while it is being made again
    /// (or after the host ended).
    public nonisolated var current: SessionEndpoint? { visible.withLock { $0 } }
    /// The claim the store last confirmed, as JSON.
    public nonisolated var storedClaim: String? { storedVisible.withLock { $0 } }
    /// Whether a `Persist` write is in progress.
    public var writePending: Bool { writing != nil }
    public var state: Phase { phase }

    // MARK: Inputs (from anywhere, in order)

    /// Admits an application command (§S10) as the core's JSON, tagged by `command`, at its place in the input queue now.
    /// Refused at once when the host is closed or failed, or when `maxCommands` are already admitted and unsettled.
    public nonisolated func submit(_ name: String, json: String) -> CellCommand {
        let outcome = OneShot<Result<Void, CellCommandFailure>>()
        let held = Held(id: UUID(), name: name, json: json, outcome: outcome)
        let refusal: CellHostError? = gate.withLock { g in
            if let over = g.over { return over }
            if g.admitted.count >= maxCommands { return CellHostError(.commandQueueFull, "\(maxCommands) commands are already waiting") }
            g.admitted[held.id] = held
            return nil
        }
        if let refusal { outcome.resolve(.failure(CellCommandFailure(error: refusal))) } else { jobs.yield(.command(held)) }
        return CellCommand(outcome: outcome)
    }
    /// An application command; returns once the endpoint has run it.
    public nonisolated func command(_ name: String, json: String) async throws { try await submit(name, json: json).value() }
    public nonisolated func deliver(_ frame: String) { jobs.yield(.frame(frame)) }
    public nonisolated func linkUp() { jobs.yield(.linkUp) }
    public nonisolated func linkDown() { jobs.yield(.linkDown) }
    /// The account's verified head may have moved (after an exchange pass): install a fresh view if it did.
    public nonisolated func accountChanged() { jobs.yield(.accountChanged) }
    /// Stops at once, as a process that ends would: no `leave`; the stored claim is what a restart starts from.
    public nonisolated func close() {
        let why = CellHostError(.closed, "the cell host is closed")
        gate.withLock { g in if g.over == nil { g.over = why } }
        jobs.yield(.close)
    }
    /// Ends this member's part: `leave` (a holder releases the role), then closes, which drops the endpoint and its key.
    public func leave() async throws {
        defer { close() }
        try await command("leave", json: Self.json(["command": "leave"]))
    }

    // MARK: The queue

    private var isOver: Bool { phase == .closed || phase == .failed || gate.withLock { $0.over != nil } }
    private var isOpen: Bool { phase == .open && endpoint != nil && !isOver }

    private func perform(_ job: Job) async {
        inJob = true
        await body(job)
        inJob = false
        flush()
        let done = settled; settled.removeAll()
        for (outcome, result) in done { outcome.resolve(result) }
    }
    private func body(_ job: Job) async {
        if case .close = job { await end(.closed, CellHostError(.closed, "the cell host is closed")); return }
        if gate.withLock({ $0.over?.code == .closed }), phase != .closed { await end(.closed, CellHostError(.closed, "the cell host is closed")) }
        switch job {
        case .command(let c): await admit(c)
        case .frame(let frame):
            if phase == .rebuilding { emit(.missed); return }
            guard isOpen else { return }
            let bytes = Data(frame.utf8)
            _ = try? await run("receive", input: .frame) { try $0.receive(bytes: bytes, engine: $1, clock: $2) }
        case .linkUp:
            carrierUp = true
            guard isOpen else { return }
            _ = try? await run("linkUp", input: .link) { try $0.linkUp(engine: $1, clock: $2) }
        case .linkDown:
            carrierUp = false
            guard isOpen else { return }
            _ = try? await run("linkDown", input: .link) { try $0.linkDown(engine: $1, clock: $2) }
        case .tick(let token):
            guard tickTimer.fired(token), isOpen else { return }
            _ = try? await run("tick", input: .tick) { try $0.tick(engine: $1, clock: $2) }
        case .renew(let token):
            guard renewTimer.fired(token), isOpen else { return }
            renew()
        case .accountChanged:
            guard isOpen else { return }
            let head: (UInt64, String)
            do { let engine = try await account.engine(); head = (try engine.headSeq(), try engine.headDigest()) } catch {
                emit(.error(code: codeOf(error), during: "accountChanged")); return
            }
            if let installed, installed.seq == head.0, installed.digest == head.1 { return }
            _ = await install()
            await drainCommands()
        case .stored(let ack, let id):
            writing?.resolve(()); writing = nil
            guard let e = endpoint, ObjectIdentifier(e) == id, phase == .open, !isOver else { return }
            stats.persisted += 1
            emit(.persist(phase: .stored, ack: ack, error: nil))
            do { _ = try await run("persisted", input: nil) { try $0.persisted(ack: ack, engine: $1, clock: $2) } }
            catch { emit(.error(code: codeOf(error), during: "persisted")) }
            await drainCommands()
        case .writeEnded(let reason, let error):
            writing?.resolve(()); writing = nil
            if let reason { await fail(reason, error: error) }
        case .rebuilt(let failure, let error):
            guard phase == .rebuilding else { return }
            if let failure { await fail(failure, error: error); return }
            phase = .open
            held.insert(Held(id: UUID(), name: "join", json: joinJSON(), outcome: nil), at: 0)
            armTick(try? endpoint?.nextDeadline())
            if carrierUp { _ = try? await run("linkUp", input: .link) { try $0.linkUp(engine: $1, clock: $2) } }
            await drainCommands()
        case .renewed(let body, let signature, let id, let expires):
            guard let e = endpoint, ObjectIdentifier(e) == id, isOpen else { return }
            do { try e.finishDelegation(body: body, signature: signature, clock: clockNow()); armRenewal(expires) }
            catch { emit(.error(code: codeOf(error), during: "delegation")) }
        case .fail(let reason, let error): await fail(reason, error: error)
        case .close: return
        }
    }

    private func emit(_ event: CellHostEvent) {
        outbox.append(event)
        if !inJob { flush() }
    }
    /// Reports what was produced, between jobs.
    private func flush() {
        while !outbox.isEmpty {
            let events = outbox; outbox.removeAll()
            let current = Array(listeners.withLock { $0 }.values)
            for event in events { for listener in current { listener(event) } }
        }
    }
    /// Settles a command. Inside a job its caller resumes only after the job's events reached the listeners, so a caller
    /// that awaited a command sees what the command did.
    private func settle(_ c: Held, _ result: Result<Void, any Error>) {
        gate.withLock { _ = $0.admitted.removeValue(forKey: c.id) }
        guard let outcome = c.outcome else { return }
        let r = result.mapError { CellCommandFailure(error: $0) }
        if inJob { settled.append((outcome, r)) } else { outcome.resolve(r) }
    }

    // MARK: Ending

    /// Stops acting: timers and waits cancelled, detached, every held and admitted command refused, the endpoint dropped.
    private func end(_ to: Phase, _ why: CellHostError) async {
        guard phase != .closed, phase != .failed else { return }
        phase = to
        let pending: [Held] = gate.withLock { g in
            if g.over == nil || to == .failed { g.over = why }
            let all = Array(g.admitted.values); g.admitted.removeAll(); return all
        }
        tickTimer.clear(); renewTimer.clear()
        for (shot, timer) in waits.values { timer.cancel(); shot.resolve(.cancelled) }
        waits.removeAll()
        passToken?.cancel(); passToken = nil
        held.removeAll()
        for c in pending { settle(c, .failure(why)) }
        endpoint = nil
        if attached { attached = false; await carrier.detach(self) }
    }
    private func fail(_ reason: FailReason, error: String? = nil) async {
        guard phase != .closed, phase != .failed else { return }
        await end(.failed, CellHostError(.failed, "the cell host failed (\(reason.rawValue))"))
        emit(.failed(reason: reason, error: error))
    }

    // MARK: The loop (inside jobs only)

    private func clockNow() -> SessionClock { SessionClock(monoMs: UInt64(max(0, clock.monoMs())), wallMs: clock.wallMs()) }
    private func armTick(_ due: UInt64?) {
        guard phase == .open, endpoint != nil else { tickTimer.clear(); return }
        let jobs = jobs
        tickTimer.at(due.map { Int64(clamping: $0) }, clock: clock) { jobs.yield(.tick($0)) }
    }

    /// One endpoint call and its step. `session:staleAccount` installs a fresh view and runs the input once more; a
    /// backwards clock or another engine's view makes the endpoint again. A command's other errors are thrown to its
    /// caller; an input's are reported. Returns whether the input ran.
    private func run(_ during: String, input: KeptInput?, again: Bool = true,
                     _ call: (SessionEndpoint, AccountEngine, SessionClock) throws -> SessionStep) async throws -> Bool {
        guard let e = endpoint, phase == .open else { return false }
        let engine: AccountEngine
        do { engine = try await account.engine() } catch { emit(.error(code: codeOf(error), during: during)); return false }
        // Nothing else ran meanwhile (this is the only job), but the host may have been closed from outside.
        guard endpoint === e, phase == .open, !isOver else { return false }
        let step: SessionStep
        do {
            stats.calls += 1
            step = try call(e, engine, clockNow())
        } catch {
            let c = codeOf(error)
            if c == "session:staleAccount", again {
                stats.stale += 1
                emit(.stale)
                guard await install() else { return false }
                return try await run(during, input: input, again: false, call)
            }
            if c == "session:clockBackwards" { rebuild(.clockBackwards); return false }
            if c == "session:wrongView" { rebuild(.wrongView); return false }
            if input == nil, during != "persisted" { throw error }
            emit(.error(code: c, during: during))
            return false
        }
        if let input, step.queued { stats.queued += 1; emit(.queued(input: input)) }
        await handle(step)
        return true
    }

    /// Carries out a step's effects in order, reports its drops and discards, and arms the timer from it.
    private func handle(_ step: SessionStep) async {
        for effect in step.effects {
            switch effect.kind {
            case .send:
                let frame = String(decoding: effect.bytes, as: UTF8.self)
                let kind = effect.frameKind ?? ""
                let sent = await carrier.sendSession(frame)
                emit(sent ? .sent(kind: kind, frame: frame) : .unsent(kind: kind, reason: "carrier", frame: frame))
            case .event:
                emit(.session(event: effect.event ?? "unknown", json: effect.eventJson ?? "{}"))
            case .persist:
                // A step's effects end at its first Persist; its acknowledgement ID is the step's.
                if let json = effect.persistedJson, let ack = step.awaitingPersist { write(json, ack: ack) }
            case .unsent:
                emit(.unsent(kind: effect.frameKind ?? "", reason: effect.unsent ?? "unknown", frame: nil))
            }
        }
        for d in step.drops { stats.drops += 1; emit(.drop(reason: d.reason, helloTo: d.helloTo)) }
        if step.discarded > 0 { emit(.discarded(count: step.discarded)) }
        // While a Persist is outstanding the step carries no deadline: nothing to tick until its acknowledgement.
        armTick(step.nextDeadline)
    }

    // MARK: Writes and fences

    /// The durable write of one `Persist`; only its completion, as a later job, acknowledges it. One save is in flight at
    /// a time: an attempt that passes its deadline counts as failed, and the next one starts only once it has settled (a
    /// save that never settles uses up the attempts and fails the cell without another save being issued). A save that
    /// succeeds only after its deadline is not acknowledged: the claim is saved again under the next fence.
    private func write(_ json: String, ack: UInt64) {
        guard let endpoint else { return }
        let id = ObjectIdentifier(endpoint)
        // Marked before any store code runs, so nothing can see "no write" while this one is under way.
        writing = OneShot<Void>()
        emit(.persist(phase: .started, ack: ack, error: nil))
        Task { await self.writeLoop(json, ack: ack, endpoint: id) }
    }
    private func writeLoop(_ json: String, ack: UInt64, endpoint id: ObjectIdentifier) async {
        var failures = 0
        func failed(_ error: String) -> Bool {
            failures += 1
            emit(.persist(phase: .failed, ack: ack, error: error))
            if failures < persistAttempts { return false }
            jobs.yield(.writeEnded(fail: .store, error: error))
            return true
        }
        while true {
            if isOver { jobs.yield(.writeEnded(fail: nil, error: nil)); return }
            seq += 1
            guard let fence = try? Fence(generation: generation, seq: seq) else { jobs.yield(.writeEnded(fail: .store, error: "the fence is exhausted")); return }
            let saving = OneShot<SaveResult>()
            let record = StoredClaim(claim: json, fence: fence)
            Task { saving.resolve(await self.save(record)) }
            var late = false
            var result: SaveResult
            while true {
                let deadline = wait(persistTimeoutMs)
                let first = await Self.first(saving, deadline.shot)
                deadline.cancel()
                switch first {
                case .left(let r): result = r
                case .right(.cancelled): jobs.yield(.writeEnded(fail: nil, error: nil)); return
                case .right(.fired):
                    late = true
                    if failed("timeout: the store did not finish a write within \(persistTimeoutMs) ms") { return }
                    continue
                }
                break
            }
            switch result {
            case .failed(let error):
                // A failed write may still have been written: what is held now is read before the next attempt.
                _ = await adopt()
                if failed(error) { return }
                if await wait(persistRetryMs).shot.wait() == .cancelled { jobs.yield(.writeEnded(fail: nil, error: nil)); return }
                continue
            case .stale:
                // Stale against this instance's own earlier save (one it could not see complete) is adopted and saved
                // again; anything else means another instance holds the cell.
                if await adopt() { continue }
                jobs.yield(.writeEnded(fail: .superseded, error: nil))
                return
            case .stored:
                if late { continue }
            }
            break
        }
        // Stored: a restart starts from it, whatever happens to this endpoint.
        lastStored = json
        jobs.yield(.stored(ack: ack, endpoint: id))
    }
    /// Takes the next generation by compare-and-set from the fence last seen held, saving `claim` under
    /// `{generation, 0}`. Another instance that reserved first makes it stale: `superseded`.
    private func reserve(_ claim: String?) async throws {
        let next = generation + 1
        guard let fence = try? Fence(generation: next, seq: 0) else { throw CellHostError(.failed, "the fence generation is exhausted") }
        generation = next; seq = 0
        let saving = OneShot<SaveResult>()
        Task { saving.resolve(await self.save(StoredClaim(claim: claim, fence: fence))) }
        let deadline = wait(persistTimeoutMs)
        let first = await Self.first(saving, deadline.shot)
        deadline.cancel()
        switch first {
        case .right: throw CellHostError(.timeout, "the store did not reserve this host's fence in time")
        case .left(.failed(let error)): throw CellHostError(.failed, "the store could not reserve this host's fence: \(error)")
        case .left(.stale): throw CellHostError(.superseded, "another instance of this cell reserved the fence first")
        case .left(.stored): return
        }
    }
    /// One compare-and-set save from the fence last seen held; never throws. A stored save moves that fence.
    private func save(_ record: StoredClaim) async -> SaveResult {
        let expected = heldFence
        do {
            switch try await store.save(record, expected: expected) {
            case .stored: heldFence = record.fence; return .stored
            case .stale: return .stale
            }
        } catch { return .failed(String(describing: error)) }
    }
    /// Reads the held fence after a save this instance could not see complete. True when it is one of this instance's
    /// own (adopted as the fence to expect), or the one it already expected; false when another instance's.
    private func adopt() async -> Bool {
        let now: StoredClaim?
        do { now = try await store.load() } catch { return true }
        guard let f = now?.fence else { return heldFence == nil }
        if f.generation == generation, f.seq <= seq { heldFence = f; return true }
        return f == heldFence
    }
    /// Checks, every beat, that the store still holds this instance's fence, by reading the fence alone. It is never
    /// skipped: while a write is in flight the held fence may be that write's (one of this instance's own fences, which
    /// counts as its own). Another instance's fence fails the cell as `superseded` within one beat. One read starts each
    /// beat and must answer within it; after `fenceCheckMisses` consecutive beats whose read failed or did not answer,
    /// the cell fails closed (`store`): a host that cannot tell whether it still holds the cell stops acting.
    private func watch() {
        Task { await self.watchLoop() }
    }
    private func watchLoop() async {
        var misses = 0
        if await wait(watchMs).shot.wait() == .cancelled { return }
        // One read per beat: each read must answer within its beat, and the next starts when that beat ends.
        while !isOver {
            let beat = wait(watchMs)
            let reading = OneShot<Result<Fence?, CellCommandFailure>>()
            let store = store
            Task { do { reading.resolve(.success(try await store.fence())) } catch { reading.resolve(.failure(CellCommandFailure(error: error))) } }
            let first = await Self.first(reading, beat.shot)
            if isOver { beat.cancel(); return }
            switch first {
            case .right(.cancelled): return
            case .left(.success(let f)):
                misses = 0
                if !mine(f) { beat.cancel(); jobs.yield(.fail(.superseded, error: nil)); return }
            case .left(.failure), .right(.fired):
                misses += 1
                if misses >= watchMisses {
                    beat.cancel()
                    let error: String
                    if case .left(.failure(let failure)) = first { error = String(describing: failure.error) } else { error = "timeout: the store did not answer a fence check in time" }
                    jobs.yield(.fail(.store, error: error))
                    return
                }
            }
            if case .right(.fired) = first { continue }
            if await beat.shot.wait() == .cancelled { return }
        }
    }
    /// Whether `f` is a fence this instance saved (the one it last saw held, or one of its current generation's).
    private func mine(_ f: Fence?) -> Bool {
        guard let f else { return false }
        if f == heldFence { return true }
        return f.generation == generation && f.seq <= seq
    }
    /// A timer that close and failure cancel.
    private func wait(_ ms: Int64) -> (shot: OneShot<Waited>, cancel: @Sendable () -> Void) {
        let shot = OneShot<Waited>()
        if isOver { shot.resolve(.cancelled); return (shot, {}) }
        waits = waits.filter { $0.value.0.value == nil }
        let id = UUID()
        let timer = clock.schedule(after: ms) { shot.resolve(.fired) }
        waits[id] = (shot, timer)
        return (shot, { timer.cancel(); shot.resolve(.cancelled) })
    }
    private enum Either<A: Sendable, B: Sendable>: Sendable { case left(A), right(B) }
    /// Whichever of two one-shots resolves first.
    private static func first<A: Sendable, B: Sendable>(_ a: OneShot<A>, _ b: OneShot<B>) async -> Either<A, B> {
        let either = OneShot<Either<A, B>>()
        Task { either.resolve(.left(await a.wait())) }
        Task { either.resolve(.right(await b.wait())) }
        return await either.wait()
    }

    // MARK: Commands

    /// A command at its place in the input queue: run now, or held behind an earlier held command.
    private func admit(_ c: Held) async {
        guard c.outcome?.value == nil else { return }
        if isOver {
            let why = gate.withLock { $0.over } ?? CellHostError(.closed, "the cell host is closed")
            settle(c, .failure(why)); return
        }
        held.append(c)
        if held.count == 1 { await drainCommands() }
    }
    /// Runs held commands in order; one refused with `session:persistPending` waits for the write to complete.
    private func drainCommands() async {
        while let c = held.first, isOpen {
            let ran: Bool
            do {
                ran = try await run("command", input: nil) { try $0.command(commandJson: c.json, engine: $1, clock: $2) }
            } catch {
                if codeOf(error) == "session:persistPending" { stats.held += 1; emit(.commandHeld(command: c.name)); return }
                held.removeFirst()
                settle(c, .failure(ColophonError.wrap(error)))
                continue
            }
            // Not run because the endpoint is being made again (or the host ended): it stays first in line, or was refused.
            if !ran, phase != .open { return }
            if !held.isEmpty { held.removeFirst() }
            settle(c, ran ? .success(()) : .failure(CellHostError(.notRun, "the \(c.name) command could not be run")))
        }
    }

    // MARK: Views, delegation and rebuilding

    /// Installs the engine's current view (`set_account`). False when the endpoint is being made again instead.
    private func install() async -> Bool {
        guard let e = endpoint else { return false }
        let engine: AccountEngine, view: SessionAccountView
        do {
            engine = try await account.engine()
            view = try engine.sessionAccount(namespace: namespace, atMs: clock.wallMs())
        } catch { emit(.error(code: codeOf(error), during: "install")); return false }
        guard endpoint === e else { return false }
        do {
            let session = view.sessionOf(member: me)
            let seq = try engine.headSeq(), digest = try engine.headDigest()
            // A new session number needs a new session key (sessions §S2): a new endpoint.
            if let installed, let was = installed.session, let session, session != was { rebuild(.sessionChanged); return false }
            let step: SessionStep
            do { step = try e.setAccount(view: view, engine: engine, clock: clockNow()) } catch {
                let c = codeOf(error)
                if c == "session:clockBackwards" { rebuild(.clockBackwards); return false }
                if c == "session:wrongView" { rebuild(.wrongView); return false }
                emit(.error(code: c, during: "install"))
                return false
            }
            installed = (seq, digest, session ?? installed?.session)
            await handle(step)
            emit(.account(entitled: (try? e.entitled()) ?? false, canWrite: (try? e.canWrite()) ?? false, seq: seq))
            return true
        } catch {
            emit(.error(code: codeOf(error), during: "install"))
            return false
        }
    }

    /// Makes the endpoint from the stored claim with new randomness, and installs a signed delegation.
    private func build() async throws {
        let engine = try await account.engine()
        let view = try engine.sessionAccount(namespace: namespace, atMs: clock.wallMs())
        var keyRandom = random(32), seed = random(16)
        defer { keyRandom.resetBytes(in: 0..<keyRandom.count); seed.resetBytes(in: 0..<seed.count) }
        let made = try SessionEndpoint(account: account.account, namespace: namespace, cell: cell, me: me, policyJson: policy,
                                       persistedJson: lastStored, view: view, keyRandom: keyRandom, freshSeed: seed, clock: clockNow())
        installed = (try engine.headSeq(), try engine.headDigest(), view.sessionOf(member: me))
        endpoint = made
        let notBefore = clock.wallMs() - 60_000
        let body = try made.beginDelegation(notBeforeMs: notBefore, expiresMs: notBefore + delegationMs)
        let signature = try await account.signRaw(body)
        guard endpoint === made else { throw CellHostError(.closed, "the cell host ended while its delegation was signed") }
        try made.finishDelegation(body: body, signature: signature, clock: clockNow())
        armRenewal(notBefore + delegationMs)
    }
    private func armRenewal(_ expires: Int64) {
        let jobs = jobs
        renewTimer.at(clock.monoMs() + max(60_000, expires - clock.wallMs() - Self.renewBefore), clock: clock) { jobs.yield(.renew($0)) }
    }
    /// Signs a new delegation for the same session key before the old one ends.
    private func renew() {
        guard let e = endpoint else { return }
        let notBefore = clock.wallMs() - 60_000, expires = notBefore + delegationMs
        let body: Data
        do { body = try e.beginDelegation(notBeforeMs: notBefore, expiresMs: expires) } catch { emit(.error(code: codeOf(error), during: "delegation")); return }
        let account = account, jobs = jobs, id = ObjectIdentifier(e)
        Task {
            do { jobs.yield(.renewed(body: body, signature: try await account.signRaw(body), endpoint: id, expires: expires)) }
            catch { await self.report(.error(code: codeOf(error), during: "delegation")) }
        }
    }
    private func report(_ event: CellHostEvent) { emit(event) }

    /// Discards the endpoint and makes a new one from the last stored claim (after the write in progress, if any, ends),
    /// then joins again with the application's state. Frames that arrive meanwhile are not judged (`missed`). If the new
    /// endpoint cannot be made, the cell fails.
    private func rebuild(_ reason: RebuildReason) {
        guard phase == .open else { return }
        phase = .rebuilding
        stats.rebuilt += 1
        emit(.rebuilt(reason: reason))
        tickTimer.clear(); renewTimer.clear()
        endpoint = nil
        let writing = writing
        Task { await self.rebuilding(after: writing) }
    }
    private func rebuilding(after writing: OneShot<Void>?) async {
        do {
            if let writing { await writing.wait() }
            guard phase == .rebuilding, !isOver else { return }
            // The new endpoint takes a new generation by compare-and-set, like an open.
            try await reserve(lastStored)
            try await build()
        } catch {
            let superseded = (error as? CellHostError)?.code == .superseded
            jobs.yield(.rebuilt(failure: superseded ? .superseded : .rebuild, error: String(describing: error)))
            return
        }
        jobs.yield(.rebuilt(failure: nil, error: nil))
    }

    private func stateValue() -> Any {
        guard let s = stateOf() else { return NSNull() }
        return s.base64EncodedString()
    }
    static func json(_ object: [String: Any]) -> String {
        // Commands are flat objects of strings and nulls; the core compares values, not spelling.
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}
