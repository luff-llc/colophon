import Foundation
import Testing
@testable import ColophonHosts
import ColophonSession

/// The flagship behaviour of 0.6, end to end through the Swift hosts: two members of one account, each through its own
/// `HomeStreamHost` over a real WebSocket (`URLSessionWebSocketTask`) to a real home (relay/server.js on Bun with the
/// Rust home module), on loopback (js/test06/handoff.test.ts and scenarios.test.ts).
@MainActor @Suite(.serialized) struct EndToEndTests {
    func live(_ a: Member, _ b: Member) async throws {
        try await a.startStream(); try await b.startStream()
        try await a.when("A's stream is live") { await a.stream.live }
        try await b.when("B's stream is live") { await b.stream.live }
    }

    /// A plays and publishes its anchor; B, on its "play", asks, and A's application pauses and passes its stopped
    /// position; B becomes holder with exactly A's last state and plays on from it; A sees it is no longer holder and
    /// sends no holder frame afterwards (default policy).
    @Test func handoffOnNowPlayingBTakesOverFromAAtAsPositionAndAYieldsAndStops() async throws {
        let (relay, a, b) = try await world()
        defer { a.close(); b.close(); relay.stop() }
        try await live(a, b)
        try await a.join(); try await b.join()
        try await a.when("A says hello") { a.sentKinds(since: 0).contains("hello") }

        // A plays: it takes the cell and publishes its anchor on its own clock.
        let start = Anchor(episode: "ep-1", show: "show-1", positionMs: 1_234_567, ratePermille: 1250, playing: true, at: anchorNow())
        a.appState.set(start.data)
        try await a.cell.take(start.data)
        _ = try await a.until("becameHolder")
        #expect(a.cell.state.isHolder)
        _ = try await b.until("holderChanged") { if case .holderChanged(let c) = $0 { c?.holder == a.id } else { false } }
        var last = start; last.positionMs = 1_240_000; last.at = anchorNow()
        a.appState.set(last.data)
        try await a.cell.publish(last.data)
        _ = try await b.until("message") { if case .message(_, _, _, _, let p) = $0 { Anchor.read(p)?.positionMs == last.positionMs } else { false } }
        #expect(Anchor.read(b.cell.state.state) == last)

        // B measures its clock offset to A, to project A's position on its own clock.
        try await b.cell.ping(a.id)
        let offsetEvent = try await b.until("offsetChanged") { if case .offsetChanged(let peer, _, _) = $0 { peer == a.id } else { false } }
        guard case .offsetChanged(_, let offset, let error) = offsetEvent.event else { return }

        // A's application, as §S12 has it: when another device asks to play, A pauses and passes its stopped position.
        let stopped = OSAllocatedUnfairLockBox<Anchor?>(nil)
        let cellA = a.cell!, appA = a.appState
        _ = cellA.events { event in
            guard case .askReceived(let from) = event, cellA.state.isHolder, let playing = Anchor.read(appA.get()) else { return }
            let now = anchorNow()
            var paused = playing; paused.positionMs = playing.project(now: now, offset: 0); paused.playing = false; paused.at = now
            stopped.set(paused)
            appA.set(paused.data)
            Task { try? await cellA.pass(to: from, snapshot: paused.data) }
        }

        // B's "play": it asks the holder for the role (§S5: a take never displaces a holder that is live and answering).
        let pressed = nowMs()
        try await b.cell.ask()
        let held = try await b.until("becameHolder", since: pressed)
        let seen = try await a.until("yielded", since: pressed)
        let toHolding = held.at - pressed, toObserved = seen.at - pressed
        print("handoff (default policy, real home over URLSessionWebSocketTask): B's play (ask) -> A observes it is no longer holder \(String(format: "%.1f", toObserved)) ms; -> B holding \(String(format: "%.1f", toHolding)) ms")

        // B starts from exactly A's last state: A's stopped position, which B now plays on from.
        guard case .becameHolder(_, let snapshot, let via) = held.event else { return }
        #expect(via == "pass")
        let resumed = try #require(Anchor.read(snapshot))
        #expect(resumed == stopped.get())
        #expect(resumed.positionMs >= last.positionMs)
        #expect(b.cell.state.isHolder && b.cell.state.holder == b.id)
        var playingOnB = resumed; playingOnB.playing = true; playingOnB.at = anchorNow()
        b.appState.set(playingOnB.data)
        try await b.cell.publish(playingOnB.data)
        // A follows B's anchor and projects B's position on its own clock, within the offset's error bound.
        let followed = try await a.until("message", since: seen.at) { if case .message(_, _, _, _, let p) = $0 { Anchor.read(p)?.playing == true } else { false } }
        guard case .message(_, _, _, _, let payload) = followed.event, let onA = Anchor.read(payload) else { return }
        #expect(onA.positionMs == resumed.positionMs)
        #expect(onA.project(now: anchorNow(), offset: -offset) >= resumed.positionMs - 2 * (error + 1))

        // A is no longer holder and acts as none: no holder frame after it passed, other than resending its pass.
        #expect(!a.cell.state.isHolder)
        #expect(a.cell.state.holder == b.id)
        try await Task.sleep(for: .milliseconds(1_500))
        #expect(a.sentKinds(since: seen.at).filter { holderFrames.contains($0) && $0 != "pass" } == [])
        #expect(!a.log.all.contains { if case .drop = $0.event { true } else { false } })
        #expect(toHolding < 1_000)
        #expect(toObserved < 2_000)
    }

    /// A holder restarted from what it stored, a holder that goes offline past the holder timeout and returns, a pass
    /// while both stores are slow and frames keep arriving, and a member revoked mid-session (fast policy).
    @Test func restartOfflinePastTheTimeoutASlowStoreDuringAPassAndRevocationOverARealHome() async throws {
        let (relay, a, b) = try await world()
        defer { a.close(); b.close(); relay.stop() }
        let policy = try fastPolicy()
        let ask = 300.0
        try await live(a, b)
        try await a.join(policy: policy); try await b.join(policy: policy)

        // A plays.
        let first = Anchor(episode: "ep-2", show: "show-1", positionMs: 60_000, ratePermille: 1000, playing: true, at: anchorNow())
        a.appState.set(first.data)
        try await a.cell.take(first.data)
        _ = try await a.until("becameHolder")
        _ = try await b.until("holderChanged") { if case .holderChanged(let c) = $0 { c?.holder == a.id } else { false } }

        // 1. A restarts from its stored claim (a new endpoint, session key and randomness). It holds locally, gated, sends
        //    no holder frame, waits out askTimeoutMs, then retakes with the state its application kept (§S6).
        #expect(a.store.value?.contains(#""holder":"\#(a.id)""#) == true)
        a.cell.close()
        try await a.when("A's cell detaches") { await a.cell.host.state == .closed }
        let restarted = nowMs()
        try await a.join(policy: policy)
        #expect(a.cell.state.gated)
        let retook = try await a.until("becameHolder", since: restarted)
        guard case .becameHolder(_, let retakenState, let retakenVia) = retook.event else { return }
        #expect(retakenVia == "take")
        #expect(!a.cell.state.gated)
        #expect(retook.at - restarted >= ask)
        let takeSent = try #require(a.log.all.first { $0.at >= restarted && { if case .sent("take", _) = $0 { true } else { false } }($0.event) })
        #expect(takeSent.at - restarted >= ask)
        #expect(a.sentKinds(since: restarted, to: takeSent.at).filter { holderFrames.contains($0) } == [])
        #expect(Anchor.read(retakenState) == first)
        _ = try await b.until("holderChanged", since: restarted) { if case .holderChanged(let c) = $0 { c?.holder == a.id && (c?.term ?? 0) > 1 } else { false } }
        print("restart: A rejoined from its stored claim and retook after \(Int(retook.at - restarted)) ms (askTimeoutMs \(Int(ask)))")

        // 2. A goes offline while holder, past the holder timeout. B sees the holder lapse and takes; A returns, says it
        //    was out of contact, and yields to B's greater claim without acting as holder.
        let offline = nowMs()
        a.network.down()
        let lapsed = try await b.until("holderLapsed", since: offline) { if case .holderLapsed(let h) = $0 { h == a.id } else { false } }
        #expect(lapsed.at - offline >= 1_400)
        let pressed = nowMs()
        try await b.cell.take()
        let tookOver = try await b.until("becameHolder", since: pressed)
        print("lapse: B saw A lapse \(Int(lapsed.at - offline)) ms after A went offline; B's take -> B holding \(String(format: "%.1f", tookOver.at - pressed)) ms")
        guard case .becameHolder(_, let takenState, let takenVia) = tookOver.event else { return }
        #expect(takenVia == "take")
        #expect(Anchor.read(takenState) == first)
        // A, cut off, still acts locally as holder (sessions §S0 rule 1).
        #expect(a.cell.state.isHolder)
        try await Task.sleep(for: .milliseconds(500))
        a.network.restore()
        let back = nowMs()
        a.stream.retryNow()
        let yielded = try await a.until("yielded", since: back, seconds: 15)
        #expect(a.sentKinds(since: back).filter { holderFrames.contains($0) } == [])
        #expect(!a.cell.state.isHolder)
        #expect(a.cell.state.holder == b.id)
        #expect(a.sentKinds(since: back).contains("hello"))
        // What A held reaches B's application (G11).
        _ = try await b.until("displaced", since: back) { if case .displaced(let from, _, _, _) = $0 { from == a.id } else { false } }
        print("return: A yielded \(Int(yielded.at - back)) ms after its network came back, sending no holder frame")

        // 3. A pass while both stores take 250 ms per write, with frames arriving during the writes. B's application passes
        //    to A when A asks; nothing a Persist holds back is released before its write completes. The write is kept
        //    under askTimeoutMs (300 here): B sends nothing as holder while its pass is being written, so a longer write
        //    would let A take on its own after askTimeoutMs (§S5, take after an unanswered ask) and receive the pass late.
        // From a quiet cell: the writes of the return have completed.
        try await a.when("A's writes complete") { await !a.cell.host.writePending }
        try await b.when("B's writes complete") { await !b.cell.host.writePending }
        try await Task.sleep(for: .milliseconds(300))
        let slow: Int64 = 250
        a.store.set { $0.delayMs = slow }; b.store.set { $0.delayMs = slow }
        var bPlaying = first; bPlaying.positionMs = 90_000; bPlaying.at = anchorNow()
        b.appState.set(bPlaying.data)
        let passedAt = OSAllocatedUnfairLockBox<Double>(0)
        let cellB = b.cell!, appB = b.appState
        _ = cellB.events { event in
            guard case .askReceived(let from) = event, cellB.state.isHolder, passedAt.get() == 0, let playing = Anchor.read(appB.get()) else { return }
            passedAt.set(nowMs())
            let now = anchorNow()
            var paused = playing; paused.positionMs = playing.project(now: now, offset: 0); paused.playing = false; paused.at = now
            appB.set(paused.data)
            // Admitted in this order now: the pass, then a command while that pass is being written (it waits for the write).
            let pass = cellB.host.submit("pass", json: json(["command": "pass", "to": from, "snapshot": Base64.encode(paused.data)]))
            let presence = cellB.host.submit("presence", json: json(["command": "presence", "payload": b64(#"{"label":"Kitchen","playing":false}"#)]))
            Task { try? await pass.value(); try? await presence.value() }
        }
        let asked = nowMs()
        try await a.cell.ask()
        let gotIt = try await a.until("becameHolder", since: asked, seconds: 15)
        guard case .becameHolder(_, let passedState, let passedVia) = gotIt.event else { return }
        #expect(passedVia == "pass")
        #expect(passedState == b.appState.get())
        let passed = passedAt.get()
        func at(_ m: Member, from: Double, _ match: (CellHostEvent) -> Bool) throws -> Double { try #require(m.log.all.first { $0.at >= from && match($0.event) }).at }
        let bPersist = try at(b, from: passed) { if case .persist(.started, _, _) = $0 { true } else { false } }
        let bStored = try at(b, from: bPersist) { if case .persist(.stored, _, _) = $0 { true } else { false } }
        let bPassSent = try at(b, from: passed) { if case .sent("pass", _) = $0 { true } else { false } }
        #expect(bStored - bPersist >= Double(slow) - 10)
        #expect(bPassSent >= bStored)
        let aPersist = try at(a, from: asked) { if case .persist(.started, _, _) = $0 { true } else { false } }
        let aStored = try at(a, from: aPersist) { if case .persist(.stored, _, _) = $0 { true } else { false } }
        let aAck = try at(a, from: aPersist) { if case .sent("ack", _) = $0 { true } else { false } }
        #expect(aAck >= aStored)
        func kept(_ m: Member, _ from: Double, _ to: Double) -> [KeptInput] {
            m.log.all.filter { $0.at >= from && $0.at <= to }.compactMap { if case .queued(let i) = $0.event { i } else { nil } }
        }
        let keptA = kept(a, aPersist, aStored), keptB = kept(b, bPersist, bStored)
        let describe = { (k: [KeptInput]) in [KeptInput.frame, .tick, .link].map { i in "\(k.filter { $0 == i }.count) \(i.rawValue)" }.joined(separator: ", ") }
        let heldCommands = b.log.all.filter { $0.at >= passed && { if case .commandHeld = $0 { true } else { false } }($0.event) }.count
        print("slow store: B's pass waited \(Int(bPassSent - bPersist)) ms for its write; inputs kept behind the writes: A \(describe(keptA)); B \(describe(keptB)); commands held: \(heldCommands); A holding \(Int(gotIt.at - asked)) ms after asking")
        #expect(keptA.filter { $0 == .frame }.count + keptB.filter { $0 == .frame }.count > 0)
        #expect(heldCommands > 0)
        try await b.when("B's held presence ran") { b.sentKinds(since: passed).contains("presence") }
        #expect(!(a.log.all + b.log.all).contains { if case .drop("queueFull", _) = $0.event { true } else { false } })
        #expect(!b.cell.state.isHolder)
        a.store.set { $0.delayMs = 0 }; b.store.set { $0.delayMs = 0 }
        try await Task.sleep(for: .milliseconds(300))

        // 4. B revokes A mid-session (A holds the cell), by a real authority change on B's device. Nothing is injected:
        //    a. B holds the new head before the home does. A, which has not seen it, still sends over its socket; the home
        //       still carries the frame, and B's endpoint, under the new head, drops it on arrival, changing nothing.
        //    b. Once the home holds the revocation it ends A's stream: A's frames no longer leave the device.
        //    c. A's own poll brings the revocation in: its endpoint reports the stale view and, with the new one
        //       installed, A is no longer entitled.
        let revoking = nowMs()
        try await b.device.session.revoke(memberID: a.id)
        b.cell.host.accountChanged()
        try await b.when("B installs the new head") { b.log.all.contains { $0.at >= revoking && { if case .account = $0 { true } else { false } }($0.event) } }
        #expect(await a.stream.live)
        let dropsBefore = await b.cell.host.stats.drops
        let viewBefore = try b.cell.host.current?.viewJson()
        let overTheWire = nowMs()
        var late = first; late.positionMs = 95_000; late.at = anchorNow()
        try await a.cell.publish(late.data)
        #expect(a.sentKinds(since: overTheWire).contains("msg"))
        try await b.when("B drops A's frame") { await b.cell.host.stats.drops > dropsBefore }
        let refusal = b.log.all.filter { $0.at >= overTheWire }.compactMap { if case .drop(let r, _) = $0.event { r } else { nil } }
        #expect(try b.cell.host.current?.viewJson() == viewBefore)
        #expect(!b.events.all.contains { $0.at >= overTheWire && $0.event.name == "message" })
        // b. The home learns the revocation and ends A's stream.
        #expect(await syncUntilClean(b.device))
        try await a.when("A's stream stops being live", seconds: 15) { await !a.stream.live }
        let streamStatus = await a.stream.status
        let afterHome = nowMs()
        var later = first; later.positionMs = 97_000; later.at = anchorNow()
        try await a.cell.publish(later.data)
        #expect(a.sentKinds(since: afterHome).isEmpty)
        #expect(a.log.all.contains { $0.at >= afterHome && { if case .unsent(_, "carrier", _) = $0 { true } else { false } }($0.event) })
        // c. A's poll (the app's own timer; the stream is not live) brings the revocation in.
        let polled = nowMs()
        _ = await a.device.session.syncNow()
        var last = first; last.positionMs = 99_000; last.at = anchorNow()
        _ = try? await a.cell.publish(last.data)
        let stale = a.log.all.first { $0.at >= polled && { if case .stale = $0 { true } else { false } }($0.event) }
        let account = a.log.all.first { $0.at >= polled && { if case .account = $0 { true } else { false } }($0.event) }
        #expect(stale != nil)
        #expect(account != nil)
        if let stale, let account { #expect(account.at >= stale.at) }
        var entitled: Bool?
        if case .account(let e, _, _)? = account?.event { entitled = e }
        #expect(entitled == false)
        #expect(!a.cell.state.entitled)
        print("revocation: A's frame crossed the home and B dropped it (\(refusal.joined(separator: ","))); then the home ended A's stream (\(streamStatus.map { "\($0.kind)\($0.blocked.map { "/\($0)" } ?? "")" } ?? "-")); A reported stale, then entitled=\(entitled.map(String.init) ?? "-")")
    }

    /// What `URLSessionWebSocketTask` shows of a refused upgrade, against the real home: the HTTP status (here 401 or
    /// 403 for a ticket the home never issued), reported with `refused`, not as a bare transport failure.
    @Test func aRefusedUpgradeIsReportedWithItsStatus() async throws {
        let (relay, a, b) = try await world()
        defer { a.close(); b.close(); relay.stop() }
        let url = "ws://\(relay.local)/stream?ticket=\(String(repeating: "x", count: 43))"
        let seen = Log<String>()
        let socket = try URLSessionSocketFactory(allowingLoopback: true).factory(url, SocketHandlers(
            open: { seen.append("open") }, message: { _ in seen.append("message") },
            refused: { answer in seen.append("refused \(answer.status)") }, closed: { code in seen.append("closed \(code.map(String.init) ?? "none")") }))
        defer { socket.close(code: 1000) }
        try await a.when("the socket ends") { !seen.all.isEmpty }
        let first = try #require(seen.all.first)
        print("refused upgrade: URLSessionWebSocketTask reported '\(first)'")
        #expect(first.hasPrefix("refused 4"), "\(seen.all)")
    }
}
