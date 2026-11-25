import Foundation
import os
import Testing
@testable import ColophonHosts
import ColophonSession

// Fakes for the host unit tests: a manual clock with timers, scripted sockets, a ticket transport, a fake engine, and
// claim stores whose writes the test completes, delays or fails (the counterparts of js/test06/fakes.ts).

/// Lets the hosts' queues, their store tasks and the timers' continuations run. The hosts run on actors and tasks, so
/// "nothing left to do" is a short real pause after yielding; every assertion that something happens waits for it with
/// `eventually`.
func settle(_ rounds: Int = 3, isolation: isolated (any Actor)? = #isolation) async {
    for _ in 0..<rounds {
        for _ in 0..<50 { await Task.yield() }
        try? await Task.sleep(for: .milliseconds(2))
    }
}

/// Waits (up to `seconds`, polling) until `condition` holds; records an issue when it does not.
@discardableResult
func eventually(_ what: String = "the condition", seconds: Double = 10, isolation: isolated (any Actor)? = #isolation,
                sourceLocation: SourceLocation = #_sourceLocation, _ condition: () async throws -> Bool) async rethrows -> Bool {
    let end = ContinuousClock.now + .milliseconds(Int(seconds * 1000))
    while ContinuousClock.now < end {
        if try await condition() { return true }
        try? await Task.sleep(for: .milliseconds(5))
    }
    if try await condition() { return true }
    Issue.record("\(what) did not happen within \(seconds) s", sourceLocation: sourceLocation)
    return false
}

/// A clock the test moves. Timers fire, in due order, only inside `advance`.
final class ManualClock: HostClock {
    private struct Timer { let at: Int64; let id: Int; let run: @Sendable () -> Void }
    private struct State { var mono: Int64 = 10_000; var wall = Int64(Date().timeIntervalSince1970 * 1000); var timers: [Timer] = []; var next = 0 }
    private let state = OSAllocatedUnfairLock(initialState: State())
    func monoMs() -> Int64 { state.withLock { $0.mono } }
    func wallMs() -> Int64 { state.withLock { $0.wall } }
    func schedule(after ms: Int64, _ run: @escaping @Sendable () -> Void) -> HostTimer {
        let id = state.withLock { s -> Int in
            let id = s.next; s.next += 1
            s.timers.append(Timer(at: s.mono + max(0, ms), id: id, run: run))
            return id
        }
        return HostTimer { [state] in state.withLock { $0.timers.removeAll { $0.id == id } } }
    }
    var mono: Int64 { monoMs() }
    /// Moves both clocks by `ms`, firing every timer that falls due on the way and letting the hosts react to each.
    func advance(_ ms: Int64) async {
        let end = monoMs() + ms
        while true {
            let due: Timer? = state.withLock { s in
                s.timers.sort { $0.at != $1.at ? $0.at < $1.at : $0.id < $1.id }
                guard let t = s.timers.first, t.at <= end else { return nil }
                s.timers.removeFirst()
                s.wall += t.at - s.mono; s.mono = t.at
                return t
            }
            guard let due else { break }
            due.run()
            await settle()
        }
        state.withLock { s in s.wall += end - s.mono; s.mono = end }
        await settle()
    }
    /// Sets the monotonic clock without firing anything (a reset clock may go back).
    func jump(to mono: Int64) { state.withLock { $0.mono = mono } }
    var pending: Int { state.withLock { $0.timers.count } }
}

/// Collects what a listener heard, from any thread.
final class Log<Event: Sendable>: Sendable {
    private let items = OSAllocatedUnfairLock<[Event]>(initialState: [])
    func append(_ e: Event) { items.withLock { $0.append(e) } }
    var all: [Event] { items.withLock { $0 } }
    var count: Int { items.withLock { $0.count } }
    func since(_ mark: Int) -> [Event] { Array(all.dropFirst(mark)) }
}

final class FakeSocket: HostSocket {
    let url: String
    let handlers: SocketHandlers
    private let state = OSAllocatedUnfairLock<(sent: [String], closed: UInt32?)>(initialState: ([], nil))
    init(url: String, handlers: SocketHandlers) { self.url = url; self.handlers = handlers }
    func send(_ text: String) { state.withLock { $0.sent.append(text) } }
    func close(code: UInt32) { state.withLock { $0.closed = code } }
    var sent: [String] { state.withLock { $0.sent } }
    var closedWith: UInt32? { state.withLock { $0.closed } }
    func sentTypes() -> [String] { sent.compactMap { (try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any])?["type"] as? String } }
}
/// Records every socket the host opens; the test drives them.
final class Sockets: Sendable {
    private let made = OSAllocatedUnfairLock<[FakeSocket]>(initialState: [])
    let hook = OSAllocatedUnfairLock<(@Sendable (FakeSocket) -> Void)?>(initialState: nil)
    var factory: SocketFactory {
        { [made, hook] url, handlers in
            let s = FakeSocket(url: url, handlers: handlers)
            made.withLock { $0.append(s) }
            hook.withLock { $0 }?(s)
            return s
        }
    }
    var all: [FakeSocket] { made.withLock { $0 } }
    var last: FakeSocket? { all.last }
}

/// The home's frames as the stream numbers them.
final class Frames {
    private var n = 0
    func hello(_ extra: [String: Any] = [:]) -> String {
        n = 0
        var hello: [String: Any] = ["type": "hello", "protocol": "colophon/home-stream/6", "account": String(repeating: "a", count: 64), "home": "h",
                                    "instance": "i1", "cursor": "i1.0", "head": NSNull(), "notice": 0, "principal": "m", "expiresAt": NSNull(),
                                    "namespaces": ["listening.podcasts"], "limits": ["pingMs": 20_000, "idleMs": 60_000]]
        hello.merge(extra) { $1 }
        return frame(hello)
    }
    func frame(_ fields: [String: Any]) -> String {
        n += 1
        var f = fields; f["n"] = n
        return String(decoding: try! JSONSerialization.data(withJSONObject: f, options: [.sortedKeys]), as: UTF8.self)
    }
    func next() -> Int { n += 1; return n }
}

let ticket = String(repeating: "T", count: 43)
func answer(_ status: UInt32, _ body: [String: Any] = [:], headers: [Header] = []) -> HttpAnswer {
    HttpAnswer(status: status, headers: headers, body: try! JSONSerialization.data(withJSONObject: body))
}
/// Answers the ticket request with `answer` (default: a ticket) and records what was asked.
final class TicketTransport: HomeTransport {
    private let state = OSAllocatedUnfairLock<(requests: [HttpRequest], answer: @Sendable () -> HttpAnswer)>(initialState: ([], {
        ColophonHostsTests.answer(200, ["ticket": ticket, "path": "/stream", "expires": "2030-01-01T00:00:00Z"])
    }))
    func send(_ request: HttpRequest) async throws -> HttpAnswer {
        state.withLock { $0.requests.append(request); return $0.answer }()
    }
    var requests: [HttpRequest] { state.withLock { $0.requests } }
    func answer(_ make: @escaping @Sendable () -> HttpAnswer) { state.withLock { $0.answer = make } }
}

/// An engine that only knows its head (the stream host asks it after every pass).
final class HeadEngine: AccountEngine {
    private let seq = OSAllocatedUnfairLock<UInt64>(initialState: 5)
    init() { super.init(noHandle: NoHandle()) }
    required init(unsafeFromHandle handle: UInt64) { fatalError("not used") }
    override func headSeq() throws -> UInt64 { seq.withLock { $0 } }
    func set(_ s: UInt64) { seq.withLock { $0 = s } }
}

/// A host account whose engine, call, exchange and key the test scripts.
final class ScriptedAccount: HostAccount {
    let account = String(repeating: "a", count: 64)
    let member = "m"
    let head = HeadEngine()
    private let state = OSAllocatedUnfairLock<(passes: [Int64], call: @Sendable () async throws -> Data, exchange: @Sendable () async throws -> Void)>(
        initialState: ([], { Data(#"{"a call":1}"#.utf8) }, {}))
    let clock: ManualClock
    init(clock: ManualClock) { self.clock = clock }
    func engine() async throws -> AccountEngine { head }
    func streamCall(home: String) async throws -> Data { try await state.withLock { $0.call }() }
    func exchange() async throws {
        let (run, mono) = state.withLock { ($0.exchange, clock.mono) }
        try await run()
        state.withLock { $0.passes.append(mono) }
    }
    func signRaw(_ body: Data) async throws -> Data { Data(count: 64) }
    var passes: [Int64] { state.withLock { $0.passes } }
    func call(_ make: @escaping @Sendable () async throws -> Data) { state.withLock { $0.call = make } }
    func exchanging(_ run: @escaping @Sendable () async throws -> Void) { state.withLock { $0.exchange = run } }
}

/// A claim store whose writes complete when the test says (`hold`, `hang`), after a delay, or fail. It applies the
/// compare-and-set when a write lands, as the contract requires, and records how many saves were ever in flight at once.
final class TestStore: ClaimStore {
    struct State {
        var value: String?
        var heldFence: Fence?
        var fenceFailures = 0
        var fenceHang = false
        var fenceReads = 0
        var writes: [String] = []
        var fences: [Fence] = []
        var hold = false
        var delayMs: Int64 = 0
        var failures = 0
        var hang = 0
        var inflight = 0
        var maxInflight = 0
        var refused = 0
        var waiting: [CheckedContinuation<Void, Never>] = []
        var hung: [CheckedContinuation<Void, Never>] = []
    }
    let state = OSAllocatedUnfairLock(initialState: State())
    /// Runs the store's delays (a manual clock's timers, or real time).
    private let delay: @Sendable (Int64) async -> Void
    init(_ initial: StoredClaim? = nil, delay: @escaping @Sendable (Int64) async -> Void = { try? await Task.sleep(for: .milliseconds($0)) }) {
        self.delay = delay
        state.withLock { $0.value = initial?.claim; $0.heldFence = initial?.fence }
    }
    /// A store whose delays run on `clock`.
    convenience init(clock: ManualClock) {
        self.init(delay: { ms in await withCheckedContinuation { c in _ = clock.schedule(after: ms) { c.resume() } } })
    }
    func load() async throws -> StoredClaim? { state.withLock { s in s.heldFence.map { StoredClaim(claim: s.value, fence: $0) } } }
    func fence() async throws -> Fence? {
        let (fail, hang, fence) = state.withLock { s -> (Bool, Bool, Fence?) in
            s.fenceReads += 1
            if s.fenceFailures > 0 { s.fenceFailures -= 1; return (true, false, nil) }
            return (false, s.fenceHang, s.heldFence)
        }
        if fail { throw ClaimStoreError.storage("the disk is busy") }
        if hang { await withCheckedContinuation { (_: CheckedContinuation<Void, Never>) in } }
        return fence
    }
    func save(_ record: StoredClaim, expected: Fence?) async throws -> SaveOutcome {
        let (fail, hang) = state.withLock { s -> (Bool, Bool) in
            s.inflight += 1; s.maxInflight = max(s.maxInflight, s.inflight)
            if let claim = record.claim { s.writes.append(claim) }
            s.fences.append(record.fence)
            if s.failures > 0 { s.failures -= 1; return (true, false) }
            if s.hang > 0 { s.hang -= 1; return (false, true) }
            return (false, false)
        }
        defer { state.withLock { $0.inflight -= 1 } }
        if fail { throw ClaimStoreError.storage("the disk is full") }
        if hang { await withCheckedContinuation { c in state.withLock { $0.hung.append(c) } } }
        if state.withLock({ $0.hold }) {
            await withCheckedContinuation { c in
                let resume = state.withLock { s -> Bool in if s.hold { s.waiting.append(c); return false }; return true }
                if resume { c.resume() }
            }
        }
        let ms = state.withLock { $0.delayMs }
        if ms > 0 { await delay(ms) }
        // The compare-and-set, applied when the write lands.
        return state.withLock { s in
            let held = s.heldFence.map { StoredClaim(claim: s.value, fence: $0) }
            guard let next = compareAndSet(held: held, record: record, expected: expected) else { s.refused += 1; return .stale }
            s.value = next.claim; s.heldFence = next.fence
            return .stored
        }
    }
    func set(_ change: @Sendable (inout State) -> Void) { state.withLock { change(&$0) } }
    var value: String? { state.withLock { $0.value } }
    var maxInflight: Int { state.withLock { $0.maxInflight } }
    var heldWrites: Int { state.withLock { $0.waiting.count } }
    /// Completes every held write.
    func release() {
        let waiting = state.withLock { s -> [CheckedContinuation<Void, Never>] in s.hold = false; let w = s.waiting; s.waiting = []; return w }
        for w in waiting { w.resume() }
    }
    /// Lets the oldest hung save continue.
    func releaseHung() { state.withLock { $0.hung.isEmpty ? nil : $0.hung.removeFirst() }?.resume() }
}
