import Foundation
import os
import Testing
@testable import ColophonHosts
import ColophonSession

/// The cell host's reference loop against real endpoints of two members of a local account, over an in-memory
/// carrier, with a manual clock and stores whose writes the test completes: effects in order, the acknowledgement only
/// after the durable write, inputs kept and commands held while a write is in progress, a failed write retried, a stale
/// view replaced, a backwards clock recovered from the stored claim, frames handed on as their own text, bounded and
/// ordered admission, write deadlines and failure bounds, fenced saves and the per-beat fence check
/// (js/test06/cell-host.test.ts).
@MainActor @Suite(.serialized) struct CellHostTests {
    struct Pair {
        let clock: ManualClock
        let carrier: LoopCarrier
        let stores: (a: TestStore, b: TestStore)
        let logs: (a: Log<CellHostEvent>, b: Log<CellHostEvent>)
        let a: SessionCellHost
        let b: SessionCellHost
        let first: Device
        let second: Device
        func close() async {
            a.close(); b.close()
            await settle()
            #expect(stores.a.maxInflight <= 1 && stores.b.maxInflight <= 1, "never two saves of one cell in flight")
        }
    }
    func pair(_ clock: ManualClock = ManualClock(), _ configure: (inout CellHostOptions) -> Void = { _ in }) async throws -> Pair {
        let (first, second) = try await LocalAccount.pair()
        let carrier = LoopCarrier()
        let stores = (a: TestStore(clock: clock), b: TestStore(clock: clock))
        let logs = (a: Log<CellHostEvent>(), b: Log<CellHostEvent>())
        var oa = CellHostOptions(source: try first.account(), carrier: carrier.view(), namespace: listening, cell: nowPlaying, store: stores.a)
        oa.clock = clock
        configure(&oa)
        var ob = CellHostOptions(source: try second.account(), carrier: carrier.view(), namespace: listening, cell: nowPlaying, store: stores.b)
        ob.clock = clock
        let a = try await SessionCellHost.open(oa) { logs.a.append($0) }
        let b = try await SessionCellHost.open(ob) { logs.b.append($0) }
        await settle()
        return Pair(clock: clock, carrier: carrier, stores: stores, logs: logs, a: a, b: b, first: first, second: second)
    }
    func persists(_ log: Log<CellHostEvent>, _ phase: CellHostEvent.PersistPhase) -> Int {
        log.all.filter { if case .persist(phase, _, _) = $0 { true } else { false } }.count
    }
    func sent(_ log: Log<CellHostEvent>, _ kind: String) -> Bool { log.all.contains { if case .sent(kind, _) = $0 { true } else { false } } }
    func failedReason(_ log: Log<CellHostEvent>) -> FailReason? { log.all.lazy.compactMap { if case .failed(let r, _) = $0 { r } else { nil } }.first }
    func code(_ body: () async throws -> Void) async -> String? {
        do { try await body(); return nil } catch let e as CellHostError { return e.code.rawValue } catch { return codeOf(error) }
    }

    @Test func aPersistHoldsBackWhatFollowsItUntilItsDurableWriteCompletes() async throws {
        let r = try await pair()
        r.stores.a.set { $0.hold = true }
        let mark = r.logs.a.count
        try await r.a.command("take", json: json(["command": "take", "state": b64("anchor-0")]))
        await settle()
        #expect(r.logs.a.since(mark).map(shape) == ["persist:started"])
        #expect(r.stores.a.heldWrites == 1)
        #expect(try r.a.current?.awaitingPersist() != nil)
        r.stores.a.release()
        await eventually { persists(r.logs.a, .stored) == 1 && r.logs.a.all.contains { shape($0) == "event:becameHolder" } }
        let order = Array(r.logs.a.since(mark).map(shape).filter { $0 != "event:holderChanged" }.prefix(5))
        #expect(order == ["persist:started", "persist:stored", "sent:take", "sent:state", "event:becameHolder"])
        #expect(try r.a.current?.awaitingPersist() == nil)
        #expect(r.a.storedClaim == r.stores.a.value)
        await eventually { r.logs.b.all.contains { shape($0) == "event:holderChanged" } }
        await r.close()
    }

    @Test func whileAWriteIsInProgressFramesAndATickAreKeptAndACommandIsHeldAllRunAfterItInOrder() async throws {
        let r = try await pair()
        r.stores.a.set { $0.hold = true }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        // A frame from B arrives meanwhile, a tick falls due, and the app publishes.
        try await r.b.command("presence", json: json(["command": "presence", "payload": b64(#"{"label":"Kitchen"}"#)]))
        await settle()
        let publishing = r.a.submit("publish", json: json(["command": "publish", "id": "AAAAAAAAAAAAAAAAAAAAAA", "payload": b64("anchor-1")]))
        await settle()
        await r.clock.advance(6_000)
        let kept = r.logs.a.all.compactMap { if case .queued(let input) = $0 { input } else { nil } }
        #expect(kept.contains(.frame))
        #expect(kept.filter { $0 == .tick }.count <= 1)
        #expect(r.logs.a.all.contains { if case .commandHeld("publish") = $0 { true } else { false } })
        #expect(!sent(r.logs.a, "msg"))
        let mark = r.logs.a.count
        r.stores.a.release()
        try await publishing.value()
        await settle()
        let after = r.logs.a.since(mark).map(shape)
        #expect(after.firstIndex(of: "persist:stored") == 0)
        let became = try #require(after.firstIndex(of: "event:becameHolder")), presence = try #require(after.firstIndex(of: "event:presenceChanged"))
        let msg = try #require(after.firstIndex(of: "sent:msg"))
        #expect(became < presence && presence < msg)
        #expect(!r.logs.a.all.contains { shape($0) == "drop" })
        await r.close()
    }

    @Test func aFailedWriteIsRetriedAndNeverAcknowledgedUntilItSucceeds() async throws {
        let r = try await pair()
        r.stores.a.set { $0.failures = 2 }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        #expect(persists(r.logs.a, .failed) == 1)
        #expect(!sent(r.logs.a, "take"))
        await r.clock.advance(250)
        #expect(persists(r.logs.a, .failed) == 2)
        #expect(try r.a.current?.awaitingPersist() != nil)
        await r.clock.advance(250)
        #expect(persists(r.logs.a, .stored) == 1)
        #expect(sent(r.logs.a, "take"))
        #expect(r.stores.a.state.withLock { $0.writes.count } == 3)
        await r.close()
    }

    @Test func aStaleViewIsReplacedAndTheInputRuns() async throws {
        let r = try await pair()
        // A third member is approved on A's device: A's engine has a new authority head.
        let third = try await LocalAccount.third(r.first)
        defer { third.close() }
        let mark = r.logs.a.count
        try await r.b.command("presence", json: json(["command": "presence", "payload": b64(#"{"label":"Car"}"#)]))
        await eventually { r.logs.a.since(mark).contains { shape($0) == "event:presenceChanged" } }
        let after = r.logs.a.since(mark).map(shape)
        let stale = try #require(after.firstIndex(of: "stale")), account = try #require(after.firstIndex(of: "account"))
        #expect(stale < account)
        #expect(await r.a.stats.stale == 1)
        await r.close()
    }

    @Test func aClockThatGoesBackRebuildsTheEndpointFromTheStoredClaimARestartedHolderIsGated() async throws {
        let r = try await pair()
        try await r.a.command("take", json: json(["command": "take", "state": b64("anchor-0")]))
        await settle()
        #expect(try r.a.current?.isHolder() == true)
        let key = try #require(try r.a.current?.keyId())
        r.clock.jump(to: r.clock.mono - 5_000)
        try await r.b.command("presence", json: json(["command": "presence", "payload": b64("{}")]))
        await eventually("the rebuilt endpoint joins") { (try? r.a.current?.joined()) == true && (try? r.a.current?.keyId()) != key }
        #expect(r.logs.a.all.contains { if case .rebuilt(.clockBackwards) = $0 { true } else { false } })
        #expect(try r.a.current?.gated() == true)
        // It waits out askTimeoutMs, then retakes.
        await r.clock.advance(2_000)
        #expect(try r.a.current?.gated() == false)
        #expect(try r.a.current?.isHolder() == true)
        await r.close()
    }

    @Test func framesReachTheEndpointAsTheTextTheCarrierDeliveredAReserialisedFrameWouldDifferAndIsRefused() async throws {
        let r = try await pair()
        try await r.a.command("take", json: json(["command": "take", "state": b64("anchor-0")]))
        await settle()
        let frame = try #require(r.carrier.carried(from: r.a).last)
        #expect(SessionFrames.frameText(ofMessage: #"{"type":"session","frame":\#(frame),"retained":true}"#) == frame)
        #expect(SessionFrames.frameText(ofMessage: #"{"n":7, "type":"session", "frame" : \#(frame) }"#) == frame)
        #expect(SessionFrames.frameText(ofMessage: #"{"type":"session","frame":\#(frame),"frame":\#(frame)}"#) == nil)
        // A frame whose text is not canonical (an escape a JSON parser decodes): re-serialising would hand the codec other
        // bytes than were carried, and would make it canonical. The host hands on the carried text; the codec refuses it.
        let escaped = frame.replacingOccurrences(of: #""cell":"now-playing""#, with: #""cell":"now\u002dplaying""#)
        #expect(escaped != frame)
        let message = #"{"type":"session","frame":\#(escaped)}"#
        let carried = try #require(SessionFrames.frameText(ofMessage: message))
        #expect(carried == escaped)
        let parsed = try #require(try JSONSerialization.jsonObject(with: Data(message.utf8)) as? [String: Any])
        let reserialised = try JSONSerialization.data(withJSONObject: try #require(parsed["frame"]))
        #expect(String(decoding: reserialised, as: UTF8.self) != escaped, "re-serialising changes the bytes")
        let drops = await r.b.stats.drops
        r.b.deliver(carried)
        await eventually { await r.b.stats.drops == drops + 1 }
        await r.close()
    }

    @Test func listenersThatCallBackIntoTheHostFromEveryEventNeverReEnterTheEndpoint() async throws {
        let r = try await pair()
        let a = r.a, b = r.b, clock = r.clock
        let state = Log<String>()
        let lastFrame = OSAllocatedUnfairLockBox<String?>(nil)
        _ = a.on { e in
            // Everything a listener can do, synchronously, from every event: each becomes a later job.
            state.append("call")
            if case .sent(_, let frame) = e { lastFrame.set(frame) }
            a.accountChanged()
            a.linkUp()
            if let f = lastFrame.get(), state.count < 200 { b.deliver(f) }
            if state.count < 20 { _ = a.submit("presence", json: json(["command": "presence", "payload": b64("{}")])) }
            if case .persist(.started, _, _) = e {
                // A backwards clock and an input while the write is under way: the rebuild waits for that write.
                clock.jump(to: clock.mono - 1_000)
                a.deliver(lastFrame.get() ?? "{}")
            }
        }
        r.stores.a.set { $0.hold = true }
        try await a.command("take", json: json(["command": "take", "state": b64("anchor-0")]))
        await eventually { a.current == nil }
        #expect(await a.writePending)
        #expect(r.logs.a.all.contains { shape($0) == "rebuilt" })
        // Rebuilt only once the write completes, and from the claim it stored.
        r.stores.a.release()
        await eventually { await a.state == .open && a.current != nil }
        let stored = try #require(a.storedClaim)
        #expect(stored.contains(#""holder":"\#(r.first.id)""#))
        #expect(try a.current?.claimJson()?.contains(#""holder":"\#(r.first.id)""#) == true)
        #expect(!r.logs.a.all.contains { shape($0) == "error" })
        await r.close()
    }

    @Test func aDelegationThatCannotBeSignedFailsOpenAndNothingStaysAttached() async throws {
        let (first, _) = try await LocalAccount.pair()
        let carrier = LoopCarrier()
        var options = CellHostOptions(source: FlakyKey(try first.account(), failing: true), carrier: carrier.view(), namespace: listening, cell: nowPlaying, store: TestStore())
        options.clock = ManualClock()
        await #expect(throws: (any Error).self) { _ = try await SessionCellHost.open(options) }
        #expect(carrier.cellCount == 0)
    }

    @Test func aRebuildThatFailsLeavesTheCellFailedHeldAndNewCommandsAreRefused() async throws {
        let (first, _) = try await LocalAccount.pair()
        let key = FlakyKey(try first.account())
        let r = try await pair(ManualClock()) { $0.source = key }
        // The next delegation (the rebuild's) cannot be signed.
        key.failing.withLock { $0 = true }
        r.clock.jump(to: r.clock.mono - 1_000)
        let held = r.a.submit("presence", json: json(["command": "presence", "payload": b64("{}")]))
        await eventually { failedReason(r.logs.a) == .rebuild }
        #expect(await r.a.state == .failed)
        #expect(await code { try await held.value() } == "failed")
        #expect(await code { try await r.a.command("ask", json: json(["command": "ask"])) } == "failed")
        #expect(!r.carrier.has(r.a))
        key.failing.withLock { $0 = false }
        await r.close()
    }

    @Test func aStoreThatKeepsFailingFailsTheCellItStopsActingAndSaysSo() async throws {
        let r = try await pair(ManualClock()) { $0.persistAttempts = 3 }
        r.stores.a.set { $0.failures = 1_000 }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        let waiting = r.a.submit("publish", json: json(["command": "publish", "id": "AAAAAAAAAAAAAAAAAAAAAA", "payload": b64("x")]))
        await settle()
        await r.clock.advance(250)
        await r.clock.advance(250)
        #expect(persists(r.logs.a, .failed) == 3)
        await eventually { failedReason(r.logs.a) == .store }
        #expect(!sent(r.logs.a, "take"))
        #expect(await code { try await waiting.value() } == "failed")
        #expect(r.a.current == nil)
        await r.close()
    }

    @Test func commandAdmissionIsBoundedAndKeepsTheOrderOfWhatItAccepted() async throws {
        let r = try await pair(ManualClock()) { $0.maxCommands = 2 }
        r.stores.a.set { $0.hold = true }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        let one = r.a.submit("publish", json: json(["command": "publish", "id": "AAAAAAAAAAAAAAAAAAAAAA", "payload": b64("1")]))
        let two = r.a.submit("publish", json: json(["command": "publish", "id": "AQAAAAAAAAAAAAAAAAAAAA", "payload": b64("2")]))
        #expect(await code { try await r.a.command("publish", json: json(["command": "publish", "id": "AgAAAAAAAAAAAAAAAAAAAA", "payload": b64("3")])) } == "commandQueueFull")
        r.stores.a.release()
        try await one.value(); try await two.value()
        await settle()
        let messages = r.logs.a.all.compactMap { e -> String? in
            guard case .session("message", let json) = e, case .message(_, _, _, _, let payload) = CellEvent(event: "message", json: json) else { return nil }
            return String(decoding: payload, as: UTF8.self)
        }
        #expect(messages == ["1", "2"])
        await r.close()
    }

    // The receiver's side of revocation, at unit level (the end-to-end test shows it over the home's wire): a frame the
    // member sealed under the old head, arriving after the receiver installed the new one.
    @Test func afterANewHeadThatRemovesAMemberItsFramesAreDroppedAndChangeNothing() async throws {
        let r = try await pair()
        let third = try await LocalAccount.third(r.first)
        defer { third.close() }
        await r.second.session.refresh()
        var options = CellHostOptions(source: try third.account(), carrier: r.carrier.view(), namespace: listening, cell: nowPlaying, store: TestStore())
        options.clock = r.clock
        let thirdHost = try await SessionCellHost.open(options)
        await settle()
        r.carrier.pause()
        try await thirdHost.command("presence", json: json(["command": "presence", "payload": b64(#"{"label":"Old phone"}"#)]))
        let sealed = try #require(r.carrier.carried(from: thirdHost).last)
        thirdHost.close()
        try await r.first.session.revoke(memberID: third.id)
        await r.second.session.refresh()
        r.b.accountChanged()
        await eventually { r.logs.b.all.contains { shape($0) == "account" } }
        let mark = r.logs.b.count
        let view = try r.b.current?.viewJson()
        r.b.deliver(sealed)
        await eventually { r.logs.b.since(mark).contains { shape($0) == "drop" } }
        let judged = r.logs.b.since(mark).map(shape).filter { ["drop", "queued", "missed"].contains($0) || $0.hasPrefix("event:") }
        #expect(judged == ["drop"])
        #expect(try r.b.current?.viewJson() == view)
        await r.close()
    }

    @Test func inputsRunInAdmissionOrderACommandAFrameAndACommandAdmittedFromAListener() async throws {
        let r = try await pair()
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        // A frame from B, held back by the carrier so the test decides when it is delivered.
        r.carrier.pause()
        try await r.b.command("presence", json: json(["command": "presence", "payload": b64(#"{"label":"Hall"}"#)]))
        let frame = try #require(r.carrier.lastCarried)
        let a = r.a
        let fired = OSAllocatedUnfairLockBox(false)
        _ = a.on { e in
            guard case .sent("presence", _) = e, !fired.get() else { return }
            fired.set(true)
            _ = a.submit("publish", json: json(["command": "publish", "id": "AAAAAAAAAAAAAAAAAAAAAA", "payload": b64("1")]))
            a.deliver(frame)
            _ = a.submit("publish", json: json(["command": "publish", "id": "AQAAAAAAAAAAAAAAAAAAAA", "payload": b64("2")]))
        }
        let mark = r.logs.a.count
        try await a.command("presence", json: json(["command": "presence", "payload": b64(#"{"label":"Desk"}"#)]))
        await eventually { r.logs.a.since(mark).filter { shape($0) == "sent:msg" }.count == 2 }
        let order = r.logs.a.since(mark).map(shape).filter { $0 == "sent:msg" || $0 == "event:presenceChanged" }
        #expect(order == ["sent:msg", "event:presenceChanged", "sent:msg"])
        await r.close()
    }

    @Test func behindAWriteAHeldCommandKeepsItsPlaceAmongCommandsALaterFrameRunsAtTheAcknowledgement() async throws {
        let r = try await pair()
        r.carrier.pause()
        try await r.b.command("presence", json: json(["command": "presence", "payload": b64(#"{"label":"Hall"}"#)]))
        let frame = try #require(r.carrier.lastCarried)
        r.stores.a.set { $0.hold = true }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        let mark = r.logs.a.count
        let one = r.a.submit("publish", json: json(["command": "publish", "id": "AAAAAAAAAAAAAAAAAAAAAA", "payload": b64("1")]))
        r.a.deliver(frame)
        let two = r.a.submit("publish", json: json(["command": "publish", "id": "AQAAAAAAAAAAAAAAAAAAAA", "payload": b64("2")]))
        await settle()
        r.stores.a.release()
        try await one.value(); try await two.value()
        await settle()
        let keep = ["commandHeld", "queued", "persist:stored", "event:becameHolder", "event:presenceChanged", "sent:msg"]
        let order = r.logs.a.since(mark).map(shape).filter { keep.contains($0) }
        #expect(order == ["commandHeld", "queued", "persist:stored", "event:becameHolder", "event:presenceChanged", "sent:msg", "sent:msg"])
        await r.close()
    }

    @Test func aWriteThatNeverSettlesCountsAsFailedAtItsDeadlineAndTheCellFailsAfterTheAttempts() async throws {
        let clock = ManualClock()
        let r = try await pair(clock) { $0.persistAttempts = 3; $0.persistTimeoutMs = 1_000 }
        r.stores.a.set { $0.hang = 1_000 }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        await clock.advance(999)
        #expect(persists(r.logs.a, .failed) == 0)
        await clock.advance(1)
        let errors = r.logs.a.all.compactMap { if case .persist(.failed, _, let e) = $0 { e } else { nil } }
        #expect(errors.count == 1 && errors[0].hasPrefix("timeout"))
        await clock.advance(250 + 1_000 + 250 + 1_000)
        await eventually { failedReason(r.logs.a) == .store }
        #expect(!sent(r.logs.a, "take"))
        #expect(r.stores.a.state.withLock { $0.fences.count } == 2, "the reservation and one save: no second save while the first is in flight")
        await r.close()
    }

    @Test func oneSaveAtATimeAnOverdueAttemptIsWaitedForALateSuccessIsSavedAgainAndTheStoreEndsWithTheLatestClaim() async throws {
        let clock = ManualClock()
        let r = try await pair(clock) { $0.persistTimeoutMs = 1_000 }
        let store = r.stores.a
        let before = store.state.withLock { $0.writes.count }
        store.set { $0.hang = 1 }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        await clock.advance(1_000)
        // Attempt A is overdue: counted as failed, and no other save is issued while it is in flight.
        #expect(persists(r.logs.a, .failed) == 1)
        #expect(store.state.withLock { $0.writes.count } - before == 1)
        await clock.advance(3_000)
        #expect(store.state.withLock { $0.writes.count } - before == 1)
        // A settles late: not acknowledged; the claim is saved again (B) under the next fence, and B is acknowledged.
        store.releaseHung()
        await settle()
        await clock.advance(0)
        await eventually { persists(r.logs.a, .stored) == 1 }
        #expect(store.state.withLock { $0.writes.count } - before == 2)
        // A later claim C (the holder releases): the store ends with C, under the greatest fence.
        try await r.a.command("release", json: json(["command": "release"]))
        await eventually { store.value?.contains(#""released":true"#) == true }
        #expect(store.maxInflight == 1)
        let fences = store.state.withLock { $0.fences }
        #expect(zip(fences, fences.dropFirst()).allSatisfy { $0 < $1 }, "\(fences)")
        await r.close()
    }

    @Test func acrossAReplacementInstanceAnOldInstancesSaveThatSettlesLateIsRefusedAndTheNewerClaimStays() async throws {
        let (first, _) = try await LocalAccount.pair()
        let clock = ManualClock()
        let carrier = LoopCarrier()
        let store = TestStore(clock: clock)
        var options = CellHostOptions(source: try first.account(), carrier: carrier.view(), namespace: listening, cell: nowPlaying, store: store)
        options.clock = clock; options.persistTimeoutMs = 1_000
        let old = try await SessionCellHost.open(options)
        store.set { $0.hang = 1 }
        try await old.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        old.close()
        // A new instance opens from the same store while the old one's save is still pending.
        options.carrier = carrier.view()
        let replacement = try await SessionCellHost.open(options)
        try await replacement.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        await clock.advance(1_000)
        try await replacement.command("release", json: json(["command": "release"]))
        await eventually { store.value?.contains(#""released":true"#) == true }
        let newest = store.value
        store.releaseHung()
        await eventually { store.state.withLock { $0.refused } == 1 }
        #expect(store.value == newest)
        replacement.close()
    }

    @Test func anInstanceWhoseFenceReservationIsRefusedDoesNotOpen() async throws {
        let (first, _) = try await LocalAccount.pair()
        let carrier = LoopCarrier()
        var options = CellHostOptions(source: try first.account(), carrier: carrier.view(), namespace: listening, cell: nowPlaying, store: RefusingStore())
        options.clock = ManualClock()
        var refused: CellHostError?
        do { _ = try await SessionCellHost.open(options) } catch { refused = error as? CellHostError }
        #expect(refused?.code == .superseded)
        #expect(carrier.cellCount == 0)
    }

    @Test(arguments: ["close", "fail"]) func closeAndFailureCancelTheRetryAndDeadlineTimers(_ ending: String) async throws {
        let (first, _) = try await LocalAccount.pair()
        let clock = ManualClock()
        let store = TestStore(clock: clock)
        var options = CellHostOptions(source: try first.account(), carrier: LoopCarrier().view(), namespace: listening, cell: nowPlaying, store: store)
        options.clock = clock; options.persistAttempts = 2; options.persistTimeoutMs = 1_000
        let host = try await SessionCellHost.open(options)
        store.set { $0.failures = 1; $0.hang = 1 }
        try await host.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        // The first attempt failed: a retry timer waits; then the second hangs under a deadline.
        if ending == "close" {
            host.close()
            await settle()
        } else {
            await clock.advance(250)
            await clock.advance(1_000)
            await eventually { await host.state == .failed }
        }
        await settle()
        #expect(clock.pending == 0)
        #expect(store.maxInflight == 1)
        host.close()
        store.releaseHung()
    }

    @Test func theFenceCheckRunsEveryBeatEvenWhileAWriteIsInFlightAndAWriteOfItsOwnIsNotTakenForAnotherInstance() async throws {
        let clock = ManualClock()
        let r = try await pair(clock)
        r.stores.a.set { $0.hold = true }
        try await r.a.command("take", json: json(["command": "take", "state": NSNull()]))
        let reads = r.stores.a.state.withLock { $0.fenceReads }
        await clock.advance(5_000 * 3)
        #expect(r.stores.a.state.withLock { $0.fenceReads } - reads == 3)
        #expect(await r.a.state == .open)
        r.stores.a.release()
        await settle()
        await clock.advance(5_000)
        #expect(await r.a.state == .open)
        await r.close()
    }

    @Test(arguments: ["reject", "hang", "once"])
    func fenceChecksThatKeepFailingOrNeverAnswerFailTheCellClosedThreeBeatsAfterTheFirstMissOneMissAloneDoesNot(_ mode: String) async throws {
        let clock = ManualClock()
        let r = try await pair(clock)
        // The first check reads one beat after the open; from then on, one read a beat.
        let opened = clock.mono
        switch mode {
        case "reject": r.stores.a.set { $0.fenceFailures = 3 }
        case "once": r.stores.a.set { $0.fenceFailures = 1 }
        default: r.stores.a.set { $0.fenceHang = true }
        }
        let failedAt = OSAllocatedUnfairLockBox<Int64?>(nil)
        _ = r.a.on { e in if case .failed = e, failedAt.get() == nil { failedAt.set(clock.mono) } }
        for _ in 0..<48 { await clock.advance(1_000) }
        let reason = failedReason(r.logs.a)
        if mode == "once" { #expect(reason == nil); await r.close(); return }
        #expect(reason == .store)
        let firstRead = opened + 5_000
        // A rejected read is a miss at once (reads at beats 1, 2 and 3); an unanswered one at the end of its beat.
        #expect(failedAt.get().map { $0 - firstRead } == (mode == "hang" ? 15_000 : 10_000))
        await r.close()
    }
}

/// A store that refuses every save (another instance always reserved first).
final class RefusingStore: ClaimStore {
    func load() async throws -> StoredClaim? { nil }
    func fence() async throws -> Fence? { nil }
    func save(_ record: StoredClaim, expected: Fence?) async throws -> SaveOutcome { .stale }
}

/// A value shared with `@Sendable` closures, under a lock.
final class OSAllocatedUnfairLockBox<Value: Sendable>: Sendable {
    private let lock: OSAllocatedUnfairLock<Value>
    init(_ value: Value) { lock = OSAllocatedUnfairLock(initialState: value) }
    func get() -> Value { lock.withLock { $0 } }
    func set(_ value: Value) { lock.withLock { $0 = value } }
}
