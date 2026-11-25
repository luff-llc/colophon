import Foundation
import Testing
@testable import ColophonHosts
import ColophonSession

/// The stream host against the core's real `HomeStream` (made directly, no engine), with a fake socket, ticket transport
/// and clock: every step kind, refusals and close codes, the polling fallback, session routing, and that no ticket
/// leaves except in the socket URL (js/test06/stream-host.test.ts).
@Suite struct StreamHostTests {
    static let base = "https://home.test/v1/accounts/x"

    struct Rig {
        let clock = ManualClock()
        let sockets = Sockets()
        let transport = TicketTransport()
        let account: ScriptedAccount
        let host: HomeStreamHost
        let events = Log<StreamHostEvent>()
        let cursors = Log<String?>()
        let frames = Frames()

        init(cursor: String? = nil) async throws {
            account = ScriptedAccount(clock: clock)
            let cursors = cursors
            host = try await HomeStreamHost(account: account, home: "h", transport: transport, socket: sockets.factory, clock: clock,
                                            saveCursor: { cursors.append($0) },
                                            client: try HomeStream(home: "h", base: StreamHostTests.base, config: streamDefaultConfig(), cursor: cursor))
            let events = events
            _ = host.on { events.append($0) }
        }
        var kinds: [StreamEventKind] { events.all.compactMap { if case .event(let e) = $0 { e.kind } else { nil } } }
        var socket: FakeSocket { get throws { try #require(sockets.last) } }
        /// Mints, connects and says hello.
        func live() async throws {
            await settle()
            let s = try socket
            s.handlers.open()
            s.handlers.message(frames.hello())
            await settle()
        }
        func status() async -> StreamStatus? { await host.status }
        func until() async -> Int64 { Int64(await host.status?.until ?? 0) }
    }

    @Test func needTicketCallConnectWakeMintsConnectsWithTheTicketAndWakesAPassOnTheFirstHello() async throws {
        let r = try await Rig()
        #expect(await r.host.polling)
        r.host.start()
        await settle()
        #expect(r.transport.requests.count == 1)
        let request = try #require(r.transport.requests.first)
        #expect(request.method == .post && request.url == "\(Self.base)/stream/ticket")
        #expect(r.sockets.all.count == 1)
        #expect(try r.socket.url == "wss://home.test/v1/accounts/x/stream?ticket=\(ticket)")
        let connect = r.events.all.compactMap { if case .connect(let url) = $0 { url } else { nil } }
        #expect(connect.count == 1 && !connect[0].contains(ticket), "only the redacted URL is reported")
        try r.socket.handlers.open()
        try r.socket.handlers.message(r.frames.hello())
        await settle()
        #expect(await r.host.live)
        #expect(await !r.host.polling)
        #expect(r.kinds.contains(.connected))
        // The first hello wakes a pass, coalesced over 250 ms; then `on_history`.
        #expect(r.account.passes.isEmpty)
        await r.clock.advance(250)
        #expect(r.account.passes.count == 1)
        #expect(r.events.all.contains { if case .pass(let seq, nil) = $0 { seq == 5 } else { false } })
        // No event, status or log line carries the ticket.
        #expect(!r.events.all.map { String(describing: $0) }.joined().contains(ticket))
        r.host.stop()
    }

    @Test func sendPingsAfterPingMsAndCloses1001AfterIdleMsThenBacksOffAndMintsAgain() async throws {
        let r = try await Rig()
        r.host.start()
        try await r.live()
        await r.clock.advance(20_000)
        #expect(try r.socket.sentTypes().contains("ping"))
        await r.clock.advance(40_001)
        #expect(try r.socket.closedWith == 1001)
        #expect(await r.status()?.kind == .backoff)
        #expect(await r.host.polling)
        // Sleep until the backoff ends, then mint again (the core's schedule, not the host's).
        let until = await r.until()
        #expect(until > r.clock.mono)
        await r.clock.advance(until - r.clock.mono)
        #expect(r.transport.requests.count == 2)
        #expect(r.sockets.all.count == 2)
        r.host.stop()
    }

    @Test func aGapInFrameNumbersClosesWith1002() async throws {
        let r = try await Rig()
        r.host.start()
        try await r.live()
        try r.socket.handlers.message(#"{"type":"head","home":"h","seq":9,"digest":"d","n":5}"#)
        await settle()
        #expect(r.kinds.contains(.violation))
        #expect(try r.socket.closedWith == 1002)
        r.host.stop()
    }

    @Test func closeCodes1008BlocksUntilTheHistoryChanges1012And1000BackOff() async throws {
        let r = try await Rig()
        r.host.start()
        try await r.live()
        try r.socket.handlers.closed(1008)
        await settle()
        #expect(await r.status()?.kind == .blocked)
        #expect(await r.status()?.blocked == .accessEnded)
        #expect(await r.host.polling)
        await r.clock.advance(600_000)
        #expect(r.transport.requests.count == 1)
        // The same history: still blocked. A changed one: tried again.
        r.host.historyChanged()
        await settle()
        #expect(r.transport.requests.count == 1)
        r.account.head.set(6)
        r.host.historyChanged()
        await settle()
        #expect(r.transport.requests.count == 2)
        try await r.live()
        try r.socket.handlers.closed(1012)
        await settle()
        #expect(await r.status()?.kind == .backoff)
        await r.clock.advance(await r.until() - r.clock.mono)
        #expect(r.transport.requests.count == 3)
        try await r.live()
        try r.socket.handlers.closed(1000)
        await settle()
        #expect(await r.status()?.kind == .backoff)
        r.host.stop()
    }

    @Test func aTransportFailureWithNoCloseCodeBacksOff() async throws {
        let r = try await Rig()
        r.host.start()
        await settle()
        try r.socket.handlers.closed(nil)
        await settle()
        #expect(await r.status()?.kind == .backoff)
        #expect(r.kinds.contains(.down))
        r.host.stop()
    }

    @Test func refusalsA429BacksOffAtLeastRetryAfterA403RefusedRevokedEndsAccess() async throws {
        let r = try await Rig()
        r.host.start()
        await settle()
        try r.socket.handlers.refused(answer(429, ["result": "refused:rateLimited"], headers: [Header(name: "retry-after", value: "30")]))
        await settle()
        #expect(await r.status()?.kind == .backoff)
        #expect(await r.until() - r.clock.mono >= 30_000)
        await r.clock.advance(await r.until() - r.clock.mono)
        try r.socket.handlers.refused(answer(403, ["result": "refused:revoked"]))
        await settle()
        #expect(await r.status()?.blocked == .accessEnded)
        // What URLSession can report of a refused upgrade: the status and headers, no body. A 403 without its body is an
        // unrecognised refusal: backed off, not blocked.
        let s = try await Rig()
        s.host.start()
        await settle()
        try s.socket.handlers.refused(HttpAnswer(status: 403, headers: [], body: Data()))
        await settle()
        #expect(await s.status()?.kind == .backoff)
        r.host.stop(); s.host.stop()
    }

    @Test func ticketAnswers404IsUnsupported403IsRefusedAFailedCallBacksOff() async throws {
        let unsupported = try await Rig()
        unsupported.transport.answer { answer(404) }
        unsupported.host.start()
        await settle()
        #expect(await unsupported.status()?.blocked == .unsupported)
        #expect(await unsupported.host.polling)
        #expect(unsupported.sockets.all.isEmpty)
        unsupported.host.stop()

        let refused = try await Rig()
        refused.transport.answer { answer(403, ["result": "refused:revoked"]) }
        refused.host.start()
        await settle()
        #expect(await refused.status()?.blocked == .refused)
        #expect(await refused.status()?.refused == "refused:revoked")
        refused.host.stop()

        let failing = try await Rig()
        failing.account.call { throw ColophonError.unavailable(code: "unavailable", detail: "no fresh head") }
        failing.host.start()
        await settle()
        #expect(failing.events.all.contains { if case .ticketCallFailed("unavailable") = $0 { true } else { false } })
        #expect(await failing.status()?.kind == .backoff)
        #expect(failing.transport.requests.isEmpty)
        failing.host.stop()
    }

    @Test func needTicketCallRepeatsWhileTheCallIsSignedTheHostSignsOnce() async throws {
        let r = try await Rig()
        let signing = Signing()
        r.account.call { await signing.wait() }
        r.host.start()
        await settle()
        await r.clock.advance(5_000)
        #expect(await signing.calls == 1)
        #expect(r.transport.requests.isEmpty)
        await signing.sign(Data(#"{"a call":1}"#.utf8))
        await settle()
        #expect(await signing.calls == 1)
        #expect(r.transport.requests.count == 1)
        #expect(r.sockets.all.count == 1)
        r.host.stop()
    }

    @Test func waitingArmsTheTimerFromWakeAtACallNeverSignedCountsAsFailedAfterTheCoresTimeout() async throws {
        let r = try await Rig()
        let signing = Signing()
        r.account.call { await signing.wait() }
        r.host.start()
        await settle()
        #expect(await r.status()?.kind == .connecting)
        await r.clock.advance(59_000)
        #expect(await r.status()?.kind == .connecting)
        await r.clock.advance(1_100)
        #expect(await signing.calls == 1)
        #expect(await r.status()?.kind == .backoff)
        r.host.stop()
    }

    @Test func stopFromAListenerOrFromInsideTheSocketFactoryLeavesNoTicketBearingSocketOpen() async throws {
        let r = try await Rig()
        let host = r.host
        _ = host.on { if case .connect = $0 { host.stop() } }
        r.host.start()
        await settle()
        #expect(r.sockets.all.count == 1)
        #expect(try r.socket.closedWith == 1000)
        await r.clock.advance(120_000)
        #expect(r.sockets.all.count == 1)

        // Stopped from inside the socket factory, before the factory returned.
        let s = try await Rig()
        let inner = s.host
        s.sockets.hook.withLock { $0 = { _ in inner.stop() } }
        s.host.start()
        await settle()
        #expect(try s.socket.closedWith == 1000)
        #expect(!s.events.all.contains { if case .connect = $0 { true } else { false } })
        await s.clock.advance(120_000)
        #expect(s.sockets.all.count == 1)
    }

    @Test func listenersThatCallBackIntoTheHostFromEveryEventDoNotBreakTheLoop() async throws {
        let r = try await Rig()
        let host = r.host
        _ = host.on { _ in host.historyChanged(); host.retryNow() }
        r.host.start()
        try await r.live()
        await r.clock.advance(250)
        #expect(await r.host.live)
        #expect(!r.account.passes.isEmpty)
        r.host.stop()
    }

    @Test func cursorsAreSavedAndPresentedOnReconnect() async throws {
        let r = try await Rig(cursor: "i1.3")
        r.host.start()
        await settle()
        #expect(try r.socket.url.contains("after=i1.3"))
        try r.socket.handlers.open()
        try r.socket.handlers.message(r.frames.hello())
        try r.socket.handlers.message(r.frames.frame(["type": "change", "cursor": "i1.4",
                                                      "entry": ["path": "records/x", "size": 1, "sha256": String(repeating: "0", count: 64)]]))
        await settle()
        #expect(r.cursors.all.contains("i1.4"))
        #expect(await r.host.cursor == "i1.4")
        r.host.stop()
    }

    @Test func cellsAreSubscribedWhenLiveLinkUpOnTheAckFramesRoutedAsTheirOwnTextLinkDownWhenTheSocketEnds() async throws {
        let r = try await Rig()
        let cell = RecordingCell(namespace: "listening.podcasts", cell: "now-playing")
        try await r.host.attach(cell)
        #expect(await !r.host.sendSession("{}"))
        r.host.start()
        try await r.live()
        let subscribe = try r.socket.sent.compactMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] }.first { $0["type"] as? String == "subscribe" }
        #expect(subscribe?["namespace"] as? String == "listening.podcasts" && subscribe?["cell"] as? String == "now-playing")
        #expect(cell.log.all.isEmpty)
        try r.socket.handlers.message(r.frames.frame(["type": "subscribed", "namespace": "listening.podcasts", "cell": "now-playing"]))
        await settle()
        #expect(cell.log.all == ["up"])
        // The frame inside the message, character for character, spacing and all.
        let frame = #"{"account":"\#(String(repeating: "a", count: 64))","cell":"now-playing","namespace":"listening.podcasts","n":1}"#
        try r.socket.handlers.message(#"{"type":"session","frame":\#(frame),"retained":true,"n":\#(r.frames.next())}"#)
        await settle()
        #expect(cell.delivered.all == [frame])
        // A frame for a cell nobody attached is reported, not delivered.
        try r.socket.handlers.message(r.frames.frame(["type": "session", "frame": ["namespace": "listening.podcasts", "cell": "other"]]))
        await settle()
        #expect(r.events.all.contains { if case .unrouted("noCell") = $0 { true } else { false } })
        #expect(await r.host.sendSession(frame))
        #expect(try r.socket.sent.last == #"{"type":"session","frame":\#(frame)}"#)
        try r.socket.handlers.closed(1011)
        await settle()
        #expect(cell.log.all == ["up", "down"])
        #expect(await !r.host.sendSession(frame))
        r.host.stop()
    }

    @Test func aPassWokenDuringAPassRunsOnceMoreAfterIt() async throws {
        let r = try await Rig()
        let gate = Gate()
        r.account.exchanging { await gate.enter() }
        r.host.start()
        try await r.live()
        await r.clock.advance(250)
        #expect(await gate.running == 1)
        try r.socket.handlers.message(r.frames.frame(["type": "head", "home": "h", "seq": 6, "digest": "d"]))
        await settle()
        await r.clock.advance(250)
        #expect(await gate.running == 1)
        await gate.release()
        await settle()
        #expect(await gate.running == 1)
        await gate.release()
        await settle()
        #expect(r.events.all.filter { if case .pass = $0 { true } else { false } }.count == 2)
        r.host.stop()
    }

    @Test func theSystemSocketFactoryOpensOnlyWssOrAnAllowedLoopbackWs() throws {
        let handlers = SocketHandlers(open: {}, message: { _ in }, refused: { _ in }, closed: { _ in })
        #expect(throws: HostError.insecureSocket) { _ = try URLSessionSocketFactory().factory("ws://home.test/stream?ticket=x", handlers) }
        #expect(throws: HostError.insecureSocket) { _ = try URLSessionSocketFactory().factory("ws://127.0.0.1:1/stream", handlers) }
        #expect(throws: HostError.insecureSocket) { _ = try URLSessionSocketFactory(allowingLoopback: true).factory("ws://home.test/stream", handlers) }
        #expect(throws: HostError.insecureSocket) { _ = try URLSessionSocketFactory().factory("https://home.test/stream", handlers) }
    }
}

/// A ticket call the test signs when it wants.
actor Signing {
    private(set) var calls = 0
    private var waiters: [CheckedContinuation<Data, Never>] = []
    func wait() async -> Data { calls += 1; return await withCheckedContinuation { waiters.append($0) } }
    func sign(_ call: Data) { for w in waiters { w.resume(returning: call) }; waiters.removeAll() }
}
/// An exchange the test lets finish, one at a time.
actor Gate {
    private(set) var running = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func enter() async { running += 1; await withCheckedContinuation { waiters.append($0) } }
    func release() { guard !waiters.isEmpty else { return }; running -= 1; waiters.removeFirst().resume() }
}
/// A stream cell that records what the stream did to it.
final class RecordingCell: StreamCell {
    let namespace: String
    let cell: String
    let log = Log<String>()
    let delivered = Log<String>()
    init(namespace: String, cell: String) { self.namespace = namespace; self.cell = cell }
    func deliver(_ frame: String) { delivered.append(frame) }
    func linkUp() { log.append("up") }
    func linkDown() { log.append("down") }
}
