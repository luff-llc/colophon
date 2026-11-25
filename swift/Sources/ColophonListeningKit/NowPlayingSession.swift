import Foundation
import Observation
import os
import ColophonHosts

/// The `listening.podcasts/now-playing` cell for a player (sessions §S12, docs/now-playing.md): this device is playing
/// episode E at position P; another device can continue from exactly there, and this one pauses.
///
/// It is a thin layer over a `CellSession`: it decides nothing the core decides (who holds, when a take is allowed,
/// when a restarted holder retakes), and adds only what §S12 leaves to the application: the anchor, its translation to
/// this device's clock, when to publish, what the holder does with an ask, and one pause event per loss of the role.
///
/// Everything runs on the main actor. Events from the cell reach it through one ordered queue; commands go to the cell
/// host in the order the app's calls make them. Local playback is never blocked: when the stream, the cell or the
/// account does not allow handoff, `requestPlayback()` answers `playLocally` at once and `update` keeps working.
@MainActor @Observable public final class NowPlayingSession {
    /// The cell's namespace and name.
    public nonisolated static let namespace = "listening.podcasts"
    public nonisolated static let cellName = "now-playing"
    /// The claim store's record name for this cell (one SQLite file may hold several cells).
    public nonisolated static let storeName = "listening.podcasts/now-playing"

    /// What the app can show.
    public private(set) var state = NowPlayingState()
    /// Called with every event, on the main actor, in order. `pause` is called before the role is handed over. Events
    /// that happen before it is set (while the session opens, for example a restarted holder that yields at once) are
    /// kept and delivered, in order, when it is set.
    @ObservationIgnored public var onEvent: (@MainActor (NowPlayingEvent) -> Void)? {
        didSet {
            guard let onEvent else { return }
            let kept = undelivered
            undelivered = []
            for event in kept { onEvent(event) }
        }
    }
    @ObservationIgnored private var undelivered: [NowPlayingEvent] = []
    /// What this device does when another device asks (it may be changed at any time).
    @ObservationIgnored public var handoffPolicy: NowPlayingHandoffPolicy
    /// This device's member ID.
    public nonisolated let member: String

    private enum Input: Sendable { case cell(CellEvent), failed(FailReason), cellState, stream(Bool), tick, commandFailed(String, String) }

    @ObservationIgnored private let options: NowPlayingOptions
    @ObservationIgnored private let clock: any HostClock
    @ObservationIgnored private let make: @Sendable () async throws -> CellHostOptions
    @ObservationIgnored private let local: OSAllocatedUnfairLock<NowPlayingAnchor?>
    @ObservationIgnored private let inputs: AsyncStream<Input>.Continuation
    @ObservationIgnored private var loop: Task<Void, Never>?
    @ObservationIgnored private var cell: CellSession?
    @ObservationIgnored private var tokens: [ListenerToken] = []
    @ObservationIgnored private var streamToken: ListenerToken?
    @ObservationIgnored private var timer: HostTimer?
    @ObservationIgnored private var joining = false
    @ObservationIgnored private var closed = false
    /// This device holds the role, as the app has been told (false from the moment a pass begins).
    @ObservationIgnored private var holdsRole = false
    @ObservationIgnored private var passingTo: String?
    @ObservationIgnored private var streamLive: Bool
    @ObservationIgnored private var failure: NowPlayingUnavailable?
    @ObservationIgnored private var waiting: [CheckedContinuation<NowPlayingRequestOutcome, Never>] = []
    /// The state supplied with this device's pending take (a re-stamped anchor on this device's clock).
    @ObservationIgnored private var takeState: Data?
    /// The member whose clock `state.lastAnchor` is on.
    @ObservationIgnored private var lastAnchorClock: String?
    /// The last other member seen holding.
    @ObservationIgnored private var followed: String?
    @ObservationIgnored private var offsets: [String: (offset: Int64, error: Int64, since: Int64)] = [:]
    @ObservationIgnored private var labels: [String: String] = [:]
    @ObservationIgnored private var lastPing: [String: Int64] = [:]
    @ObservationIgnored private var lastPublished: Int64 = .min / 2
    @ObservationIgnored private var lastPresence: Int64 = .min / 2
    @ObservationIgnored private var holderTimeoutMs: Int64 = 15_000
    @ObservationIgnored private var presenceTimeoutMs: Int64 = 15_000

    // MARK: Opening

    /// Opens the cell for `session` over `stream`, with its claim kept durably in the SQLite database at
    /// `claimsDatabase` (created if needed; it may hold other cells' claims, and nothing else). It never throws: if the
    /// cell cannot be joined the session reports why (`state.availability`) and local playback goes on; `retry()`
    /// tries again.
    public static func open(session: ColophonSession, stream: HomeStreamHost, claimsDatabase: URL,
                            options: NowPlayingOptions) async -> NowPlayingSession {
        do {
            return await open(account: try ColophonHostAccount(session: session), stream: stream, claimsDatabase: claimsDatabase, options: options)
        } catch {
            let s = NowPlayingSession(member: session.memberID ?? "", clock: SystemClock(), streamLive: false, options: options) {
                throw error
            }
            s.failure = .couldNotJoin(String(describing: error))
            s.refresh()
            return s
        }
    }

    /// Opens the cell for `account` over `stream`, with its claim in the SQLite database at `claimsDatabase`.
    public static func open(account: ColophonHostAccount, stream: HomeStreamHost, claimsDatabase: URL,
                            options: NowPlayingOptions) async -> NowPlayingSession {
        let s = NowPlayingSession(member: account.member, clock: SystemClock(), streamLive: await stream.live, options: options) {
            let store = try await SQLiteClaimStore(path: claimsDatabase, name: NowPlayingSession.storeName)
            return CellHostOptions(account: account, carrier: stream, namespace: NowPlayingSession.namespace, cell: NowPlayingSession.cellName, store: store)
        }
        let inputs = s.inputs
        s.streamToken = stream.on { event in
            if case .status(let status) = event { inputs.yield(.stream(status.kind == .live)) }
        }
        // A status that changed between reading `live` and listening is read again.
        inputs.yield(.stream(await stream.live))
        await s.join()
        return s
    }

    /// For tests: any carrier and store, a given clock and stream state.
    static func open(member: String, clock: any HostClock, streamLive: Bool, options: NowPlayingOptions,
                     make: @escaping @Sendable () async throws -> CellHostOptions) async -> NowPlayingSession {
        let s = NowPlayingSession(member: member, clock: clock, streamLive: streamLive, options: options, make: make)
        await s.join()
        return s
    }
    /// For tests: the stream's state changed.
    func streamChanged(live: Bool) { inputs.yield(.stream(live)) }
    /// For tests: the cell host, and the offset measured to `peer`.
    var hostForTests: SessionCellHost? { cell?.host }
    func offsetForTests(_ peer: String) -> (offset: Int64, error: Int64)? { offsets[peer].map { ($0.offset, $0.error) } }

    private init(member: String, clock: any HostClock, streamLive: Bool, options: NowPlayingOptions,
                 make: @escaping @Sendable () async throws -> CellHostOptions) {
        self.member = member; self.clock = clock; self.options = options; self.make = make
        self.streamLive = streamLive
        handoffPolicy = options.handoffPolicy
        local = OSAllocatedUnfairLock(initialState: options.restoredAnchor)
        let (stream, continuation) = AsyncStream<Input>.makeStream()
        inputs = continuation
        state.localAnchor = options.restoredAnchor
        loop = Task { @MainActor [weak self] in
            for await input in stream {
                guard let self else { return }
                self.handle(input)
            }
        }
    }
    deinit { inputs.finish() }

    private var maximumProjectionMs: Int64 { options.maximumProjectionMs ?? NowPlayingAnchor.defaultMaximumProjectionMs(holderTimeoutMs: holderTimeoutMs) }

    private func join() async {
        guard !closed, !joining, cell == nil else { return }
        joining = true
        defer { joining = false }
        do {
            var o = try await make()
            o.namespace = Self.namespace; o.cell = Self.cellName; o.clock = clock
            if let policy = options.cellPolicy { o.policy = policy }
            let local = local
            o.state = { local.withLock { $0?.encoded } }
            readPolicy(o.policy ?? ((try? sessionDefaultPolicy()) ?? "{}"))
            // A device restarting as the holder of its stored claim holds the role from the start (§S6): if it yields
            // before this session hears of it, it is still told to pause.
            let restoredHolder = Self.storedHolder(try? await o.store.load()) == member
            let joined = try await CellSession.join(o)
            guard !closed else { joined.close(); return }
            let inputs = inputs
            tokens = [
                joined.events { inputs.yield(.cell($0)) },
                joined.host.on { if case .failed(let reason, _) = $0 { inputs.yield(.failed(reason)) } },
                joined.subscribe { _ in inputs.yield(.cellState) },
            ]
            cell = joined
            failure = nil
            // Baseline after listening: a restarted holder holds (gated) without an event.
            let now = joined.state
            holdsRole = restoredHolder || now.isHolder
            if holdsRole, !now.isHolder { loseRole(.displaced(by: now.holder.map(memberValue))) }
            if let anchor = now.state.flatMap({ try? NowPlayingAnchor(decoding: $0) }) {
                state.lastAnchor = anchor
                lastAnchorClock = now.claim?.holder
            }
            if let h = now.holder, h != member { followed = h; ping(h) }
            sendPresence()
            arm()
        } catch {
            failure = .couldNotJoin(String(describing: error))
        }
        refresh()
    }
    /// The holder of a stored claim (`{"claim":{…},"released":…}`) that was not released.
    private static func storedHolder(_ stored: StoredClaim?) -> String? {
        guard let text = stored?.claim, let p = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
              (p["released"] as? Bool) != true, let claim = p["claim"] as? [String: Any] else { return nil }
        return claim["holder"] as? String
    }
    private func readPolicy(_ json: String) {
        guard let p = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else { return }
        if let v = (p["holderTimeoutMs"] as? NSNumber)?.int64Value, v > 0 { holderTimeoutMs = v }
        if let v = (p["presenceTimeoutMs"] as? NSNumber)?.int64Value, v > 0 { presenceTimeoutMs = v }
    }

    /// Opens the cell again after it failed or could not be joined (from the last stored claim: the restart rules apply).
    public func retry() async {
        guard !closed, cell == nil || failure != nil else { return }
        dropCell()
        failure = nil
        await join()
    }
    /// Gives the role up (a holder releases it, so nobody holds) and leaves the session.
    public func leave() async {
        guard let cell else { close(); return }
        holdsRole = false
        try? await cell.leave()
        close()
    }
    /// Stops at once, as a process that ends would: the stored claim is what the next start begins from.
    public func close() {
        guard !closed else { return }
        closed = true
        resolve(.playLocally(.closed, nil))
        dropCell()
        streamToken?.cancel(); streamToken = nil
        inputs.finish()
        refresh()
    }
    private func dropCell() {
        timer?.cancel(); timer = nil
        for t in tokens { t.cancel() }
        tokens = []
        cell?.close()
        cell = nil
    }

    // MARK: What the app calls

    /// Reports this device's playback: on play, pause, seek, rate change and episode change (and after a stall, so the
    /// anchor stays true). The holder publishes it; any other device only keeps it. Stamped with this device's clock.
    public func update(episode: String, show: String, positionMs: Int64, ratePermille: Int64 = 1_000, playing: Bool) throws(NowPlayingCodingError) {
        let anchor = try NowPlayingAnchor(episode: episode, show: show, positionMs: positionMs, ratePermille: ratePermille, playing: playing,
                                          at: clock.monoMs())
        let wasPlaying = state.localAnchor?.playing
        setLocal(anchor)
        if holdsRole, passingTo == nil { publish(anchor) }
        if wasPlaying != playing { sendPresence() }
        refresh()
    }

    /// The user pressed Play on this device. If this device holds the role, or handoff is unavailable, it answers at
    /// once. Otherwise it asks the holder (§S5); the holder passes (`play`, from the holder's stopped position, exact),
    /// declines, or has lapsed (then this device takes, from the last anchor it knew, projected). A holder that is live
    /// and answering is never displaced: between two live devices handoff is ask and pass.
    public func requestPlayback() async -> NowPlayingRequestOutcome {
        if let reason = unavailable { return .playLocally(reason, best(.local)) }
        guard let cell else { return .playLocally(.starting, best(.local)) }
        if holdsRole {
            let start = best(.held)
            startPlaying(start)
            return .play(start)
        }
        if !waiting.isEmpty { return await withCheckedContinuation { waiting.append($0) } }
        // The state a take starts from: the last anchor known, re-stamped on this clock (§S5 lets the take carry it).
        let restamped = best(.local).map { s -> NowPlayingAnchor in
            (try? NowPlayingAnchor(episode: s.anchor.episode, show: s.anchor.show, positionMs: s.positionMs, ratePermille: s.anchor.ratePermille,
                                   playing: s.anchor.playing, at: clock.monoMs())) ?? s.anchor
        }
        takeState = restamped?.encoded
        let take: [String: Any] = ["state": takeState.map { Base64.encode($0) as Any } ?? NSNull()]
        if cell.state.holder == nil {
            send("take", take)
        } else {
            // `ask` first: it records the ask; `take` then only gives the want its state (a take that §S5 does not
            // allow yet waits, and a pass that arrives wins).
            send("ask", [:])
            send("take", take)
        }
        refresh()
        return await withCheckedContinuation { waiting.append($0); state.requesting = true }
    }

    /// Stops waiting for the holder. The ask cannot be withdrawn: if the holder passes anyway, this device becomes holder
    /// paused at the passed position (it publishes it, so no position is lost).
    public func cancelRequest() {
        takeState = nil
        resolve(.cancelled)
    }

    /// (`prompt`) Passes the role to `member`, whose ask is waiting: pauses here (the `pause` event), then hands over the
    /// exact stopped position. False when this device no longer holds the role or that ask is not waiting.
    @discardableResult public func pass(to member: String) -> Bool {
        guard state.asks.contains(where: { $0.id == member }) else { return false }
        return passTo(member)
    }
    /// (`prompt`) Declines `member`'s ask.
    public func decline(_ member: String) {
        state.asks.removeAll { $0.id == member }
        send("decline", ["to": member])
        refresh()
    }

    // MARK: Inputs (on the main actor, in order)

    private func handle(_ input: Input) {
        guard !closed else { return }
        switch input {
        case .cell(let event): cellEvent(event)
        case .failed(let reason):
            failure = .cellFailed(reason.rawValue)
            loseRole(reason == .superseded ? .superseded : .failed(reason.rawValue))
            resolve(.playLocally(.cellFailed(reason.rawValue), best(.local)))
            timer?.cancel(); timer = nil
        case .cellState: break
        case .stream(let live):
            streamLive = live
            if !live, !waiting.isEmpty { resolve(.playLocally(.streamDown, best(.local))) }
            if live { sendPresence() }
        case .tick: tick()
        case .commandFailed(let name, let reason):
            if name == "pass", let to = passingTo { passRefused(to: to, reason: reason) }
            if name == "ask" || name == "take", !waiting.isEmpty { resolve(.playLocally(.cellFailed(reason), best(.local))) }
        }
        refresh()
    }

    private func cellEvent(_ event: CellEvent) {
        switch event {
        case .becameHolder(let claim, let snapshot, let via):
            state.holderLapsed = false
            let anchor = try? NowPlayingAnchor(decoding: snapshot)
            let publisher: String?
            if via == "pass" { publisher = claim.via } else if let takeState, takeState == snapshot { publisher = member } else { publisher = lastAnchorClock }
            if let anchor { state.lastAnchor = anchor; lastAnchorClock = publisher }
            holdsRole = true
            passingTo = nil
            state.asks = []
            takeState = nil
            if !waiting.isEmpty {
                let source: NowPlayingStart.Source = via == "pass" ? .passed(from: claim.via ?? "") : .taken(from: followed)
                let start = anchor.map { makeStart(of: $0, publisher: publisher, source: source) }
                startPlaying(start)
                resolve(.play(start))
            } else {
                // Not asked for here (a restarted holder retaking, a pass after `cancelRequest`): publish what this device
                // is actually doing, so the cell's state is true.
                if let mine = local.withLock({ $0 }) {
                    publish(mine.restamped(nowMs: clock.monoMs(), maximumProjectionMs: maximumProjectionMs))
                } else if let anchor {
                    let s = makeStart(of: anchor, publisher: publisher, source: .local)
                    if let paused = try? NowPlayingAnchor(episode: anchor.episode, show: anchor.show, positionMs: s.positionMs,
                                                          ratePermille: anchor.ratePermille, playing: false, at: clock.monoMs()) {
                        setLocal(paused); publish(paused)
                    }
                }
            }
        case .yielded(let to):
            let other = memberValue(to.holder)
            loseRole(to.rank == 1 && to.via == member ? .passed(to: other) : .displaced(by: other))
            passingTo = nil
        case .holderChanged(let claim):
            state.holderLapsed = false
            if let h = claim?.holder, h != member {
                if followed != h { followed = h; ping(h) }
            }
        case .askReceived(let from):
            guard holdsRole, passingTo == nil else { return }
            switch handoffPolicy {
            case .automatic: passTo(from)
            case .never: send("decline", ["to": from])
            case .prompt:
                guard !state.asks.contains(where: { $0.id == from }) else { return }
                let asker = memberValue(from)
                state.asks.append(asker)
                emit(.askReceived(asker))
            }
        case .declined(let from):
            takeState = nil
            resolve(.declined(by: memberValue(from)))
        case .message(let claim, _, _, _, let payload):
            state.holderLapsed = false
            if let anchor = try? NowPlayingAnchor(decoding: payload) { state.lastAnchor = anchor; lastAnchorClock = claim.holder }
            if claim.holder != member, offsets[claim.holder] == nil { ping(claim.holder) }
        case .snapshot(let claim, let seq, let snapshot):
            state.holderLapsed = false
            if let anchor = try? NowPlayingAnchor(decoding: snapshot) {
                state.lastAnchor = anchor
                // A passed claim's first state is the passer's stopped anchor, on the passer's clock.
                lastAnchorClock = claim.rank == 1 && seq == 0 ? (claim.via ?? claim.holder) : claim.holder
            }
        case .presenceChanged(let from, let payload):
            let known = labels[from] != nil
            labels[from] = payload.flatMap { try? NowPlayingPresence(decoding: $0) }?.label
            // A member heard for the first time may have joined after this device's last presence: answer it once.
            if !known, labels[from] != nil { sendPresence() }
        case .holderLapsed: state.holderLapsed = true
        case .offsetChanged(let peer, let offset, let error):
            let now = clock.monoMs()
            if let o = offsets[peer], o.offset == offset, o.error == error { break }
            offsets[peer] = (offset, error, now)
        case .latePass(let from, _, let snapshot), .displaced(let from, _, _, let snapshot):
            emit(.otherState(try? NowPlayingAnchor(decoding: snapshot), from: memberValue(from)))
        case .rejected(let command, let reason):
            if command == "pass", let to = passingTo { passRefused(to: to, reason: reason) }
            // The core refuses an ask or take from a member that may not hold (`not-allowed`).
            if command == "ask" || command == "take", !waiting.isEmpty {
                resolve(.playLocally(reason == "not-allowed" ? .readOnly : .cellFailed(reason), best(.local)))
            }
        case .refused, .submitFailed, .other: break
        }
    }

    // MARK: The role

    /// The pass of §S12: compute the stopped position, tell the app to pause (before anything is sent), then publish
    /// that final anchor and pass it as the snapshot. Commands are admitted in this order.
    @discardableResult private func passTo(_ to: String) -> Bool {
        guard holdsRole, passingTo == nil, cell != nil, failure == nil else { return false }
        let now = clock.monoMs()
        let final = (local.withLock { $0 } ?? state.lastAnchor)?.paused(nowMs: now, maximumProjectionMs: maximumProjectionMs)
        if let final { setLocal(final) }
        passingTo = to
        state.asks = []
        holdsRole = false
        emit(.pause(.passed(to: memberValue(to))))
        let snapshot = final?.encoded ?? Data()
        if let final { publish(final) }
        send("pass", ["to": to, "snapshot": Base64.encode(snapshot)])
        sendPresence()
        refresh()
        return true
    }
    private func passRefused(to: String, reason: String) {
        passingTo = nil
        if cell?.state.isHolder == true, failure == nil {
            holdsRole = true
            emit(.passFailed(to: memberValue(to), reason: reason))
        }
    }
    /// Once per loss of the role: the app pauses.
    private func loseRole(_ reason: NowPlayingPauseReason) {
        state.asks = []
        guard holdsRole else { return }
        holdsRole = false
        if let mine = local.withLock({ $0 }), mine.playing { setLocal(mine.paused(nowMs: clock.monoMs(), maximumProjectionMs: maximumProjectionMs)) }
        emit(.pause(reason))
        sendPresence()
    }
    /// This device starts playing as holder from `start`: its anchor is published as playing at that position.
    private func startPlaying(_ start: NowPlayingStart?) {
        guard let start,
              let anchor = try? NowPlayingAnchor(episode: start.anchor.episode, show: start.anchor.show, positionMs: start.positionMs,
                                                 ratePermille: start.anchor.ratePermille, playing: true, at: clock.monoMs()) else { return }
        setLocal(anchor)
        if holdsRole { publish(anchor) }
        sendPresence()
    }

    // MARK: Translation

    /// The best start this device knows for `source`: its own anchor when it holds the role or has one, else the cell's
    /// last anchor translated from its publisher's clock.
    private func best(_ source: NowPlayingStart.Source) -> NowPlayingStart? {
        if holdsRole || state.lastAnchor == nil, let mine = local.withLock({ $0 }) { return makeStart(of: mine, publisher: member, source: source) }
        if let anchor = state.lastAnchor { return makeStart(of: anchor, publisher: lastAnchorClock, source: source) }
        return local.withLock { $0 }.map { makeStart(of: $0, publisher: member, source: source) }
    }
    private func makeStart(of anchor: NowPlayingAnchor, publisher: String?, source: NowPlayingStart.Source) -> NowPlayingStart {
        let now = clock.monoMs()
        let offset: NowPlayingClockOffset?
        if publisher == member { offset = .local } else if let p = publisher, let o = offsets[p] {
            offset = NowPlayingClockOffset(offsetMs: o.offset, errorMs: o.error, sampleAgeMs: max(0, now - o.since))
        } else { offset = nil }
        return NowPlayingStart(source: source, anchor: anchor, publisher: publisher,
                               projection: offset.map { anchor.projected(nowMs: now, clock: $0, maximumProjectionMs: maximumProjectionMs) })
    }

    // MARK: Plumbing

    private var unavailable: NowPlayingUnavailable? {
        if closed { return .closed }
        if let failure { return failure }
        guard let cell else { return .starting }
        if !streamLive { return .streamDown }
        let s = cell.state
        if !s.entitled { return .notEntitled }
        if !s.canWrite { return .readOnly }
        return nil
    }
    private func memberValue(_ id: String) -> NowPlayingMember {
        NowPlayingMember(id: id, label: id == member ? options.label : labels[id], isThisDevice: id == member)
    }
    private func emit(_ event: NowPlayingEvent) {
        if let onEvent { onEvent(event) } else if undelivered.count < 64 { undelivered.append(event) }
    }
    private func resolve(_ outcome: NowPlayingRequestOutcome) {
        let all = waiting
        waiting = []
        state.requesting = false
        for c in all { c.resume(returning: outcome) }
    }
    private func setLocal(_ anchor: NowPlayingAnchor) {
        local.withLock { $0 = anchor }
        state.localAnchor = anchor
    }
    private func publish(_ anchor: NowPlayingAnchor) {
        guard cell != nil, failure == nil else { return }
        send("publish", ["id": Base64.url(CellSession.randomID()), "payload": Base64.encode(anchor.encoded)])
        lastPublished = clock.monoMs()
        state.lastAnchor = anchor
        lastAnchorClock = member
    }
    private func sendPresence() {
        guard cell != nil, failure == nil, let p = try? NowPlayingPresence(label: options.label, playing: holdsRole && state.localAnchor?.playing == true)
        else { return }
        send("presence", ["payload": Base64.encode(p.encoded)])
        lastPresence = clock.monoMs()
    }
    private func ping(_ to: String) {
        guard cell != nil, failure == nil else { return }
        send("ping", ["to": to])
        lastPing[to] = clock.monoMs()
    }
    /// Admits one command to the cell host now, so commands keep the order of the calls that made them.
    private func send(_ name: String, _ fields: [String: Any]) {
        guard let cell, failure == nil else { return }
        var object = fields
        object["command"] = name
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return }
        let command = cell.host.submit(name, json: String(decoding: data, as: UTF8.self))
        let inputs = inputs
        Task {
            do { try await command.value() } catch { inputs.yield(.commandFailed(name, String(describing: error))) }
        }
    }

    /// Housekeeping every third of `presenceTimeoutMs` (at least 1 s): presence before it expires, the anchor while
    /// playing at least every `republishMs`, and the clock offset to the holder every `pingMs`.
    private func arm() {
        timer?.cancel()
        let inputs = inputs
        timer = clock.schedule(after: max(1_000, presenceTimeoutMs / 3)) { inputs.yield(.tick) }
    }
    private func tick() {
        guard cell != nil, failure == nil else { return }
        let now = clock.monoMs()
        sendPresence()
        if holdsRole, passingTo == nil, let mine = local.withLock({ $0 }), mine.playing, now - lastPublished >= options.republishMs {
            publish(mine.restamped(nowMs: now, maximumProjectionMs: maximumProjectionMs))
        }
        if let h = cell?.state.holder, h != member, now - (lastPing[h] ?? .min / 2) >= options.pingMs { ping(h) }
        arm()
    }

    private func refresh() {
        var next = state
        let cs = cell?.state
        next.isHolder = holdsRole
        next.gated = holdsRole && (cs?.gated ?? false)
        next.holder = cs?.holder.map(memberValue)
        next.availability = unavailable.map { .unavailable($0) } ?? .available
        if next.asks.contains(where: { $0.label == nil }) { next.asks = next.asks.map { memberValue($0.id) } }
        let changed = next.availability != state.availability
        if next != state { state = next }
        if changed { emit(.availabilityChanged(next.availability)) }
    }
}
