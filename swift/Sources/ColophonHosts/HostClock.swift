import Foundation
import os

/// The clocks and timers a 0.6 host drives the core with. Both state machines take time as an argument and keep no
/// timer of their own, so the host owns these; tests inject a manual clock and step it.
public protocol HostClock: Sendable {
    /// Monotonic milliseconds: never goes back while the process runs (every stream and session timer).
    func monoMs() -> Int64
    /// Wall-clock milliseconds since the Unix epoch (delegation windows, member expiry, account views).
    func wallMs() -> Int64
    /// Runs `run` once, `ms` from now on the monotonic clock. Cancelling the returned timer stops it.
    func schedule(after ms: Int64, _ run: @escaping @Sendable () -> Void) -> HostTimer
}

/// A timer `HostClock.schedule` returned.
public struct HostTimer: Sendable {
    private let stop: @Sendable () -> Void
    public init(cancel: @escaping @Sendable () -> Void) { stop = cancel }
    /// Stops the timer if it has not fired; does nothing afterwards.
    public func cancel() { stop() }
}

/// The system's clocks: `CLOCK_MONOTONIC` (it keeps counting while the device sleeps, so a timeout measured across a
/// suspension is its true length), the wall clock, and timers on the continuous clock.
public struct SystemClock: HostClock {
    public init() {}
    public func monoMs() -> Int64 { Int64(clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1_000_000) }
    public func wallMs() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) }
    public func schedule(after ms: Int64, _ run: @escaping @Sendable () -> Void) -> HostTimer {
        let delay = max(0, min(ms, Int64(Int32.max)))
        let task = Task {
            try? await Task.sleep(for: .milliseconds(delay), clock: .continuous)
            if !Task.isCancelled { run() }
        }
        return HostTimer { task.cancel() }
    }
}

/// One timer that is always set to the latest deadline it was given: `at` replaces whatever was scheduled before, and
/// `clear` cancels it. The owner (an actor) calls it from its own isolation only; `fire` is how the timer reaches back.
struct Deadline {
    private(set) var due: Int64?
    private var timer: HostTimer?
    private var generation: UInt64 = 0

    /// Arms the timer at monotonic `due` (at once if it has passed), or clears it for none. `fire` receives a token that
    /// the owner passes to `fired(_:)` to learn whether this arming is still the current one.
    mutating func at(_ due: Int64?, clock: any HostClock, fire: @escaping @Sendable (UInt64) -> Void) {
        if due == self.due, timer != nil { return }
        clear()
        guard let due else { return }
        self.due = due
        let token = generation
        timer = clock.schedule(after: max(0, due - clock.monoMs())) { fire(token) }
    }
    /// True when `token` is the current arming (and consumes it); false for a timer that was replaced or cleared.
    mutating func fired(_ token: UInt64) -> Bool {
        guard token == generation, timer != nil else { return false }
        timer = nil; due = nil; generation &+= 1
        return true
    }
    mutating func clear() { timer?.cancel(); timer = nil; due = nil; generation &+= 1 }
}

/// A one-shot value that several tasks can wait for, resolved at most once (by a result, a timer or a cancellation).
final class OneShot<Value: Sendable>: Sendable {
    private let state = OSAllocatedUnfairLock<(value: Value?, waiters: [CheckedContinuation<Value, Never>])>(initialState: (nil, []))
    /// Resolves it; later calls do nothing. Returns whether this call resolved it.
    @discardableResult func resolve(_ value: Value) -> Bool {
        let waiters: [CheckedContinuation<Value, Never>]? = state.withLock { s in
            if s.value != nil { return nil }
            s.value = value
            let w = s.waiters; s.waiters = []; return w
        }
        guard let waiters else { return false }
        for w in waiters { w.resume(returning: value) }
        return true
    }
    var value: Value? { state.withLock { $0.value } }
    func wait() async -> Value {
        await withCheckedContinuation { continuation in
            let ready: Value? = state.withLock { s in
                if let v = s.value { return v }
                s.waiters.append(continuation); return nil
            }
            if let ready { continuation.resume(returning: ready) }
        }
    }
}
