import Foundation
import os
import ColophonSession

/// A session cell as the stream carries it (`SessionCellHost` implements it). Each call only hands the input to the
/// cell's own queue: none runs the cell's endpoint inside the caller.
public protocol StreamCell: AnyObject, Sendable {
    var namespace: String { get }
    var cell: String { get }
    /// A frame for this cell, as the text the home carried.
    func deliver(_ frame: String)
    /// The home carries this cell's frames to and from this device now (subscribed on a live stream).
    func linkUp()
    /// It no longer does.
    func linkDown()
}

/// What carries a cell's frames: a `HomeStreamHost`, or anything with the same calls.
public protocol CellCarrier: Sendable {
    func attach(_ cell: any StreamCell) async throws
    func detach(_ cell: any StreamCell) async
    /// Sends one sealed frame verbatim; false when it could not be sent now (loss, to the session).
    func sendSession(_ frame: String) async -> Bool
    /// Calls `listener` after every exchange pass the carrier ran (a `HomeStreamHost`'s `Wake`); returns what stops it.
    func onPass(_ listener: @escaping @Sendable () -> Void) async -> ListenerToken?
}

/// Returned by `on(_:)` and `onPass(_:)`; `cancel()` removes the listener.
public struct ListenerToken: Sendable {
    private let stop: @Sendable () -> Void
    init(_ stop: @escaping @Sendable () -> Void) { self.stop = stop }
    public func cancel() { stop() }
}

/// What a `HomeStreamHost` reports. None of these carries a ticket, an unredacted URL or a frame.
public enum StreamHostEvent: Sendable {
    /// An event the core returned, in order (`session` included, after it was routed).
    case event(StreamEvent)
    /// The stream's status changed.
    case status(StreamStatus)
    /// A socket is being opened; `url` is the core's redacted form.
    case connect(url: String)
    /// An exchange pass the stream woke finished (`seq`: the verified head after it), or failed (`error`: its code).
    case pass(seq: UInt64?, error: String?)
    /// The ticket call could not be made or signed; the core was told (`ticket_call_failed`).
    case ticketCallFailed(code: String)
    /// A `session` message whose frame could not be taken out (`noFrame`), or that names no attached cell (`noCell`).
    case unrouted(reason: String)
    /// A core call failed where the core gives no step (a defect, reported, never retried by the host).
    case error(code: String, during: String)
}

/// The Swift host of the 0.6 home stream (docs/colophon-0.6-sync-stream.md §2): one per home. It owns the socket, the
/// ticket request and the timer, and does exactly what the core's `HomeStream` says, step by step. Every policy (when to
/// mint, how long to back off, when to ping, when to wake a pass, when to give up) is the core's; nothing here retries,
/// waits or caps on its own.
///
/// Every input (a socket's open, message or end, a signed call, a ticket answer, a timer, a finished pass, `start`,
/// `stop`, `retryNow`) is handled as one job, in arrival order, on the actor; a job never suspends, so nothing
/// interleaves with the core's state. Listeners hear the events of a job after it ends.
///
/// A frame is a hint: `Wake` runs an ordinary exchange pass through the account, and nothing a frame carries reaches the
/// engine. Session cells attach here: the host subscribes them while the stream is live, routes the home's `session`
/// messages to them as the frame's own text, and sends their frames.
public actor HomeStreamHost: CellCarrier {
    public nonisolated let home: String
    private let account: any HostAccount
    private var client: HomeStream?
    private let transport: any HomeTransport
    private let openSocket: SocketFactory
    private let clock: any HostClock
    private let saveCursor: (@Sendable (String?) async -> Void)?
    private var timer = Deadline()
    private var listeners: [UUID: @Sendable (StreamHostEvent) -> Void] = [:]
    private var cells: [String: any StreamCell] = [:]
    /// Cells the home acknowledged a subscription for on the current connection.
    private var subscribed: Set<String> = []
    private var socket: (any HostSocket)?
    /// Bumped whenever the current socket is replaced or closed: events from an older socket are ignored.
    private var generation: UInt64 = 0
    private var started = false
    private var passing = false
    private var passAgain = false
    private var lastStatus: StreamStatusKind?
    private var outbox: [StreamHostEvent] = []
    private var work: [UUID: Task<Void, Never>] = [:]
    /// Set by `stop()` at once, from any thread: no socket is opened or kept after it.
    private nonisolated let stopped = OSAllocatedUnfairLock(initialState: false)
    private nonisolated let inputs: AsyncStream<Input>.Continuation

    private enum Input: Sendable {
        case start, stop, retryNow, history(UInt64?)
        case timer(UInt64)
        case minted(Data?, failure: String?)
        case ticket(HttpAnswer?)
        case socket(UInt64, SocketEvent)
        case passed(UInt64?, failure: String?)
        case listener(UUID, (@Sendable (StreamHostEvent) -> Void)?)
    }
    private enum SocketEvent: Sendable { case open, message(String), refused(HttpAnswer), closed(UInt32?) }

    /// - Parameters:
    ///   - account: the account; its engine makes the client (`stream_client`), its key signs the ticket call.
    ///   - home: the home's member ID.
    ///   - transport: where ticket requests go: the transport the session uses for this home.
    ///   - socket: opens the WebSocket (default `URLSessionSocketFactory`).
    ///   - configure: adjusts the documented configuration (`stream_default_config`) before the client is made.
    ///   - cursor: the resume cursor saved from an earlier `Cursor` event; `saveCursor` persists each new one.
    ///   - client: the client, when the host does not make it from the engine (tests).
    public init(account: any HostAccount, home: String, transport: any HomeTransport, socket: SocketFactory? = nil,
                clock: any HostClock = SystemClock(), configure: (@Sendable (inout StreamConfig) -> Void)? = nil, cursor: String? = nil,
                saveCursor: (@Sendable (String?) async -> Void)? = nil, client: HomeStream? = nil) async throws {
        let made: HomeStream
        if let client {
            made = client
        } else {
            var config = streamDefaultConfig()
            configure?(&config)
            made = try await account.engine().streamClient(home: home, config: config, cursor: cursor)
        }
        self.init(account: account, home: home, transport: transport, socket: socket ?? URLSessionSocketFactory().factory, clock: clock,
                  saveCursor: saveCursor, made: made)
    }
    private init(account: any HostAccount, home: String, transport: any HomeTransport, socket: @escaping SocketFactory, clock: any HostClock,
                 saveCursor: (@Sendable (String?) async -> Void)?, made: HomeStream) {
        self.home = home; self.account = account; self.transport = transport; openSocket = socket; self.clock = clock
        self.saveCursor = saveCursor; client = made
        let (stream, continuation) = AsyncStream<Input>.makeStream()
        inputs = continuation
        Task { [weak self] in
            for await input in stream {
                guard let self else { return }
                await self.run(input)
            }
        }
    }

    // MARK: Control (from anywhere)

    /// Starts driving the stream.
    public nonisolated func start() { inputs.yield(.start) }
    /// Stops: closes the socket (1000), cancels the timer and the call in flight, and drops the client. From this call
    /// on no socket is opened, and one being opened is closed before anything hears of it.
    public nonisolated func stop() {
        stopped.withLock { $0 = true }
        inputs.yield(.stop)
    }
    /// Try again now: foreground entry, a network change or an explicit user action, never a timer (the core bounds it).
    public nonisolated func retryNow() { inputs.yield(.retryNow) }
    /// The account's verified history moved outside a pass this host woke (the app's own poll): tell the core.
    public nonisolated func historyChanged() {
        let account = account, inputs = inputs
        Task { inputs.yield(.history(try? await account.engine().headSeq())) }
    }
    /// Calls `listener` with every event, after the job that produced it. Listeners may call any of this host's
    /// `nonisolated` calls; each becomes a later job.
    public nonisolated func on(_ listener: @escaping @Sendable (StreamHostEvent) -> Void) -> ListenerToken {
        let id = UUID(), inputs = inputs
        inputs.yield(.listener(id, listener))
        return ListenerToken { inputs.yield(.listener(id, nil)) }
    }
    /// Calls `listener` after every exchange pass this host ran (cells install a new view from it).
    public func onPass(_ listener: @escaping @Sendable () -> Void) -> ListenerToken? {
        let id = UUID(), inputs = inputs
        listeners[id] = { event in if case .pass = event { listener() } }
        return ListenerToken { inputs.yield(.listener(id, nil)) }
    }

    // MARK: State

    /// Where the stream stands.
    public var status: StreamStatus? { try? client?.status() }
    /// Whether the app's ordinary poll timer should run (always, unless the stream is live).
    public var polling: Bool { (try? client?.polling()) ?? true }
    /// The resume cursor held now.
    public var cursor: String? { (try? client?.cursor()) ?? nil }
    public var live: Bool { status?.kind == .live }

    // MARK: Cells

    /// Carries `cell` on this stream: subscribed whenever the stream is live, its frames delivered to it.
    public func attach(_ cell: any StreamCell) throws {
        let k = Self.key(cell.namespace, cell.cell)
        guard cells[k] == nil else { throw CellHostError(.closed, "a cell \(cell.namespace)/\(cell.cell) is already attached") }
        cells[k] = cell
        if live { sendClient { try $0.subscribe(namespace: cell.namespace, cell: cell.cell, id: nil) } }
    }
    /// Stops carrying `cell` (unsubscribes when live).
    public func detach(_ cell: any StreamCell) {
        let k = Self.key(cell.namespace, cell.cell)
        guard let held = cells[k], held === cell else { return }
        cells[k] = nil
        if subscribed.remove(k) != nil { cell.linkDown() }
        if live { sendClient { try $0.unsubscribe(namespace: cell.namespace, cell: cell.cell, id: nil) } }
    }
    /// Sends one sealed session frame (a `Send` effect's bytes as text), carried verbatim. False when the stream is not
    /// live or the frame was refused before sending: to the session that is loss, which its own rules repair.
    public func sendSession(_ frame: String) -> Bool {
        guard live, socket != nil else { return false }
        return sendClient { try $0.sessionFrame(frame: frame, id: nil) }
    }
    @discardableResult private func sendClient(_ build: (HomeStream) throws -> String) -> Bool {
        guard let socket, let client, let text = try? build(client) else { return false }
        socket.send(text)
        return true
    }

    // MARK: The loop

    private static func key(_ namespace: String, _ cell: String) -> String { namespace + "\n" + cell }
    private var now: Int64 { clock.monoMs() }
    private var isStopped: Bool { stopped.withLock { $0 } }

    private func run(_ input: Input) {
        defer { flush() }
        if case .listener(let id, let listener) = input { listeners[id] = listener; return }
        if case .stop = input { shutDown(); return }
        guard !isStopped, client != nil else { return }
        switch input {
        case .start:
            guard !started else { return }
            started = true
        case .retryNow: try? client?.retryNow()
        case .history(let seq): if let seq { try? client?.onHistory(seq: seq) }
        case .timer(let token): guard timer.fired(token) else { return }
        case .minted(let call, let failure): minted(call, failure: failure)
        case .ticket(let answer): handle { try $0.onTicket(answer: answer, nowMs: now) }
        case .socket(let at, let event):
            guard at == generation else { return }
            socketEvent(event)
        case .passed(let seq, let failure):
            if let seq { try? client?.onHistory(seq: seq) }
            passing = false
            emit(.pass(seq: seq, error: failure))
            if passAgain { passAgain = false; runPass() }
        case .stop, .listener: return
        }
        pump()
    }

    /// Asks the core what to do, does it, and asks again, until it says to wait or sleep.
    private func pump() {
        guard started, !isStopped else { return }
        // Every step but Waiting and Sleep changes the core's state, so this ends; the bound only guards a defect.
        for _ in 0..<1000 {
            guard !isStopped, let client else { return }
            let step: StreamStep
            do { step = try client.next(nowMs: now) } catch { emit(.error(code: codeOf(error), during: "next")); return }
            switch step.kind {
            case .wake: runPass()
            case .needTicketCall: mint()
            case .connect: connect(url: step.url ?? "", logUrl: step.logUrl ?? "")
            case .send: if let text = step.text { sendClient { _ in text } }
            case .close: close(code: step.code ?? 1000)
            // Both carry `wake_at`, when to ask again at the latest (a coalesced wake while a call is signed, say).
            case .waiting: arm(step.wakeAt); checkStatus(); return
            case .sleep: arm([step.until, step.wakeAt].compactMap { $0 }.min()); checkStatus(); return
            }
            checkStatus()
        }
    }
    private func arm(_ due: Int64?) {
        let inputs = inputs
        timer.at(due, clock: clock) { inputs.yield(.timer($0)) }
    }

    /// `NeedTicketCall`: sign the call; `minted` sends the ticket request and hands the core the answer.
    private func mint() {
        let account = account, home = home, inputs = inputs
        track {
            do { inputs.yield(.minted(try await account.streamCall(home: home), failure: nil)) }
            catch { inputs.yield(.minted(nil, failure: codeOf(error))) }
        }
    }
    private func minted(_ call: Data?, failure: String?) {
        guard let client else { return }
        let request: HttpRequest
        do {
            guard let call else { throw CellHostError(.notRun, failure ?? "unknown") }
            request = try client.ticketRequest(call: call, nowMs: now)
        } catch {
            // The call could not be signed, or the core refused to build the request: it is told the call failed.
            handle { try $0.ticketCallFailed(nowMs: now) }
            emit(.ticketCallFailed(code: call == nil ? (failure ?? "unknown") : codeOf(error)))
            return
        }
        let transport = transport, inputs = inputs
        track { inputs.yield(.ticket(try? await transport.send(request))) }
    }

    /// `Connect`: open the socket at `url` (never logged) and report what it does.
    private func connect(url: String, logUrl: String) {
        generation += 1
        let at = generation, inputs = inputs, stopped = stopped
        let report: @Sendable (SocketEvent) -> Void = { event in if !stopped.withLock({ $0 }) { inputs.yield(.socket(at, event)) } }
        let handlers = SocketHandlers(open: { report(.open) }, message: { report(.message($0)) },
                                      refused: { report(.refused($0)) }, closed: { report(.closed($0)) })
        let made: any HostSocket
        do { made = try openSocket(url, handlers) } catch {
            // A socket that cannot even be made is a transport failure, reported as a later input like any other.
            inputs.yield(.socket(at, .closed(nil)))
            return
        }
        // The socket carries the ticket: it is owned (kept, or closed at once) before any listener hears of it.
        if isStopped { made.close(code: 1000); return }
        socket = made
        emit(.connect(url: logUrl))
    }
    private func socketEvent(_ event: SocketEvent) {
        switch event {
        case .open: try? client?.onOpen(nowMs: now)
        case .message(let text): handle { try $0.onFrame(text: text, nowMs: now) }
        case .refused(let answer): ended(); handle { try $0.onRefused(answer: answer, nowMs: now) }
        case .closed(let code): ended(); handle { try $0.onClosed(code: code, nowMs: now) }
        }
    }
    private func ended() { socket = nil; generation += 1; allDown() }

    /// `Close`: close the socket, then tell the core.
    private func close(code: UInt32) {
        let s = socket
        socket = nil; generation += 1
        s?.close(code: code)
        allDown()
        handle { try $0.onClosed(code: code, nowMs: now) }
    }

    /// `Wake`: one ordinary exchange pass, then `on_history`. A wake during a pass runs one more after it.
    private func runPass() {
        if passing { passAgain = true; return }
        passing = true
        let account = account, inputs = inputs
        track {
            var failure: String?
            do { try await account.exchange() } catch { failure = codeOf(error) }
            var seq: UInt64?
            do { seq = try await account.engine().headSeq() } catch { failure = failure ?? codeOf(error) }
            inputs.yield(.passed(seq, failure: failure))
        }
    }

    /// The core's events, in order.
    private func handle(_ call: (HomeStream) throws -> [StreamEvent]) {
        guard let client else { return }
        let events: [StreamEvent]
        do { events = try call(client) } catch { emit(.error(code: codeOf(error), during: "stream")); return }
        for event in events {
            switch event.kind {
            case .connected:
                // The hello arrived: the stream is live. Subscribe every attached cell.
                subscribed.removeAll()
                for cell in cells.values { sendClient { try $0.subscribe(namespace: cell.namespace, cell: cell.cell, id: nil) } }
            case .cursor:
                if let saveCursor { let cursor = event.cursor; track { await saveCursor(cursor) } }
            case .session: route(event.text ?? "")
            case .ack: acknowledged(event.json)
            default: break
            }
            emit(.event(event))
        }
    }
    private func acknowledged(_ json: String?) {
        guard let json, let v = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
              let namespace = v["namespace"] as? String, let cellName = v["cell"] as? String else { return }
        let k = Self.key(namespace, cellName)
        guard let cell = cells[k] else { return }
        let type = v["type"] as? String
        if type == "subscribed", !subscribed.contains(k) { subscribed.insert(k); cell.linkUp() }
        if type == "unsubscribed", subscribed.remove(k) != nil { cell.linkDown() }
    }
    /// A `session` message: its frame's own text to the cell it names.
    private func route(_ message: String) {
        guard let frame = SessionFrames.frameText(ofMessage: message) else { emit(.unrouted(reason: "noFrame")); return }
        guard let at = SessionFrames.cell(ofFrame: frame), let cell = cells[Self.key(at.namespace, at.cell)] else {
            emit(.unrouted(reason: "noCell")); return
        }
        cell.deliver(frame)
    }

    private func allDown() {
        let up = subscribed
        subscribed.removeAll()
        for k in up { cells[k]?.linkDown() }
    }
    private func checkStatus() {
        guard !isStopped, let status else { return }
        guard status.kind != lastStatus else { return }
        lastStatus = status.kind
        if status.kind != .live { allDown() }
        emit(.status(status))
    }
    private func shutDown() {
        guard client != nil else { return }
        timer.clear()
        let s = socket
        socket = nil; generation += 1
        s?.close(code: 1000)
        allDown()
        for task in work.values { task.cancel() }
        work.removeAll()
        client = nil
        inputs.finish()
    }

    private func emit(_ event: StreamHostEvent) { outbox.append(event) }
    /// Reports what the last job produced, after it ended.
    private func flush() {
        while !outbox.isEmpty {
            let events = outbox; outbox.removeAll()
            let current = Array(listeners.values)
            for event in events { for listener in current { listener(event) } }
        }
    }
    /// Runs `body` as a task this host cancels when it stops.
    private func track(_ body: @escaping @Sendable () async -> Void) {
        let id = UUID()
        work[id] = Task { [weak self] in
            await body()
            await self?.finished(id)
        }
    }
    private func finished(_ id: UUID) { work[id] = nil }
}
