import Foundation
import os
import ColophonSession

/// A claim (§S4): taken (`rank` 0) or passed (`rank` 1, with `via`).
public struct Claim: Sendable, Hashable, Codable {
    public let term: Int64
    public let rank: Int
    public let holder: String
    public let via: String?
}

/// What the application sees of a cell. Replaced, never changed in place, on every change.
public struct CellState: Sendable, Equatable {
    /// The member has joined.
    public var joined = false
    /// This member's view of the holder (nil: no holder).
    public var holder: String?
    /// This member acts as holder (locally, even while `gated`).
    public var isHolder = false
    /// A holder that may not send holder frames yet: it restarted holding its stored claim, or came back after being out
    /// of contact, and waits out `askTimeoutMs` before it retakes or yields (sessions §S6). Show the role as held only
    /// when `isHolder` and not `gated`.
    public var gated = false
    /// The greatest claim this member accepted.
    public var claim: Claim?
    /// The cell's state as this member holds it (for `fold: latest`, the last payload or snapshot).
    public var state: Data?
    /// The position of `state` in the ordered lane.
    public var seq: Int64 = 0
    /// The member holds a `records` entry for the namespace (it may send).
    public var entitled = false
    /// The member may hold and submit (`write` access).
    public var canWrite = false
}

extension CellState {
    private struct ViewJSON: Decodable { let accepted: Claim?; let holder: String?; let seq: Int64; let state: String? }
    /// The state an endpoint's read-only calls report.
    init?(endpoint e: SessionEndpoint) {
        guard let text = try? e.viewJson(), let view = try? JSONDecoder().decode(ViewJSON.self, from: Data(text.utf8)) else { return nil }
        self.init(joined: (try? e.joined()) ?? false, holder: view.holder, isHolder: (try? e.isHolder()) ?? false, gated: (try? e.gated()) ?? false,
                  claim: view.accepted, state: view.state.flatMap(Base64.decode), seq: view.seq,
                  entitled: (try? e.entitled()) ?? false, canWrite: (try? e.canWrite()) ?? false)
    }
}

/// The core's events (§S10), typed, with bytes decoded.
public enum CellEvent: Sendable, Equatable {
    case becameHolder(claim: Claim, snapshot: Data, via: String)
    case yielded(to: Claim)
    case holderChanged(claim: Claim?)
    case askReceived(from: String)
    case declined(from: String)
    case message(claim: Claim, seq: Int64, origin: String, id: Data, payload: Data)
    case snapshot(claim: Claim, seq: Int64, snapshot: Data)
    case refused(id: Data, reason: String)
    case presenceChanged(member: String, payload: Data?)
    case holderLapsed(holder: String)
    case offsetChanged(peer: String, offset: Int64, error: Int64)
    case latePass(from: String, claim: Claim, snapshot: Data)
    case displaced(from: String, claim: Claim, seq: Int64, snapshot: Data)
    case submitFailed(id: Data)
    case rejected(command: String, reason: String)
    /// An event this version does not type: its tag and JSON.
    case other(event: String, json: String)

    /// The event's tag, as the core spells it.
    public var name: String {
        switch self {
        case .becameHolder: "becameHolder"
        case .yielded: "yielded"
        case .holderChanged: "holderChanged"
        case .askReceived: "askReceived"
        case .declined: "declined"
        case .message: "message"
        case .snapshot: "snapshot"
        case .refused: "refused"
        case .presenceChanged: "presenceChanged"
        case .holderLapsed: "holderLapsed"
        case .offsetChanged: "offsetChanged"
        case .latePass: "latePass"
        case .displaced: "displaced"
        case .submitFailed: "submitFailed"
        case .rejected: "rejected"
        case .other(let event, _): event
        }
    }

    /// The typed form of the core's event JSON.
    public init(event: String, json: String) {
        let object = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
        func string(_ k: String) -> String? { object[k] as? String }
        func int(_ k: String) -> Int64? { (object[k] as? NSNumber)?.int64Value }
        func bytes(_ k: String) -> Data? { string(k).flatMap(Base64.decode) }
        func claim(_ k: String) -> Claim? {
            guard let value = object[k], !(value is NSNull), let data = try? JSONSerialization.data(withJSONObject: value) else { return nil }
            return try? JSONDecoder().decode(Claim.self, from: data)
        }
        let typed: CellEvent?
        switch event {
        case "becameHolder": typed = claim("claim").map { .becameHolder(claim: $0, snapshot: bytes("snapshot") ?? Data(), via: string("via") ?? "") }
        case "yielded": typed = claim("to").map { .yielded(to: $0) }
        case "holderChanged": typed = .holderChanged(claim: claim("claim"))
        case "askReceived": typed = string("from").map { .askReceived(from: $0) }
        case "declined": typed = string("from").map { .declined(from: $0) }
        case "message":
            typed = claim("claim").map { .message(claim: $0, seq: int("seq") ?? 0, origin: string("origin") ?? "", id: bytes("id") ?? Data(), payload: bytes("payload") ?? Data()) }
        case "snapshot": typed = claim("claim").map { .snapshot(claim: $0, seq: int("seq") ?? 0, snapshot: bytes("snapshot") ?? Data()) }
        case "refused": typed = .refused(id: bytes("id") ?? Data(), reason: string("reason") ?? "")
        case "presenceChanged": typed = string("member").map { .presenceChanged(member: $0, payload: bytes("payload")) }
        case "holderLapsed": typed = string("holder").map { .holderLapsed(holder: $0) }
        case "offsetChanged": typed = string("peer").map { .offsetChanged(peer: $0, offset: int("offset") ?? 0, error: int("error") ?? 0) }
        case "latePass": typed = claim("claim").map { .latePass(from: string("from") ?? "", claim: $0, snapshot: bytes("snapshot") ?? Data()) }
        case "displaced":
            typed = claim("claim").map { .displaced(from: string("from") ?? "", claim: $0, seq: int("seq") ?? 0, snapshot: bytes("snapshot") ?? Data()) }
        case "submitFailed": typed = .submitFailed(id: bytes("id") ?? Data())
        case "rejected": typed = .rejected(command: string("command") ?? "", reason: string("reason") ?? "")
        default: typed = nil
        }
        self = typed ?? .other(event: event, json: json)
    }
}

/// A small typed API over one session cell for an application: join, observe the holder, the claim and the state,
/// take, ask, pass, publish, submit, leave. It decides nothing: every call is a core command, and what it publishes
/// comes from the endpoint.
public final class CellSession: Sendable {
    public let host: SessionCellHost
    private let current = OSAllocatedUnfairLock(initialState: CellState())
    private let stateListeners = OSAllocatedUnfairLock<[UUID: @Sendable (CellState) -> Void]>(initialState: [:])
    private let eventListeners = OSAllocatedUnfairLock<[UUID: @Sendable (CellEvent) -> Void]>(initialState: [:])

    private init(host: SessionCellHost) { self.host = host }

    /// Joins the cell (`SessionCellHost.open`) and starts publishing its state.
    public static func join(_ options: CellHostOptions) async throws -> CellSession {
        let box = OSAllocatedUnfairLock<CellSession?>(initialState: nil)
        let pending = OSAllocatedUnfairLock<[CellHostEvent]>(initialState: [])
        let host = try await SessionCellHost.open(options) { event in
            if let session = box.withLock({ $0 }) { session.hostEvent(event) } else { pending.withLock { $0.append(event) } }
        }
        let session = CellSession(host: host)
        box.withLock { $0 = session }
        for event in pending.withLock({ p -> [CellHostEvent] in let all = p; p = []; return all }) { session.hostEvent(event) }
        session.refresh()
        return session
    }

    /// The cell as this member sees it now.
    public var state: CellState { current.withLock { $0 } }
    /// Called after every change of `state`.
    public func subscribe(_ listener: @escaping @Sendable (CellState) -> Void) -> ListenerToken {
        let id = UUID()
        stateListeners.withLock { $0[id] = listener }
        return ListenerToken { [stateListeners] in stateListeners.withLock { $0[id] = nil } }
    }
    /// Called with every core event, in order.
    public func events(_ listener: @escaping @Sendable (CellEvent) -> Void) -> ListenerToken {
        let id = UUID()
        eventListeners.withLock { $0[id] = listener }
        return ListenerToken { [eventListeners] in eventListeners.withLock { $0[id] = nil } }
    }

    /// Takes the role as soon as §S5 allows (at once when there is no live holder), from `state` or the cell's own.
    public func take(_ state: Data? = nil) async throws { try await command(["command": "take", "state": state.map { Base64.encode($0) as Any } ?? NSNull()]) }
    /// Asks the holder for the role.
    public func ask() async throws { try await command(["command": "ask"]) }
    /// Passes the role to `to`, an asker, with the final state (the application stopped what the role controls first).
    public func pass(to: String, snapshot: Data) async throws { try await command(["command": "pass", "to": to, "snapshot": Base64.encode(snapshot)]) }
    /// Declines an asker.
    public func decline(_ to: String) async throws { try await command(["command": "decline", "to": to]) }
    /// Gives up the role without a successor.
    public func release() async throws { try await command(["command": "release"]) }
    /// Orders a message as holder (for `fold: latest`, the new state). Returns its id.
    @discardableResult public func publish(_ payload: Data, id: Data = CellSession.randomID()) async throws -> Data {
        try await command(["command": "publish", "id": Base64.url(id), "payload": Base64.encode(payload)])
        return id
    }
    /// Asks the holder to order a message (delivery is at least once). Returns its id.
    @discardableResult public func submit(_ payload: Data, id: Data = CellSession.randomID()) async throws -> Data {
        try await command(["command": "submit", "id": Base64.url(id), "payload": Base64.encode(payload)])
        return id
    }
    /// Publishes this member's presence.
    public func presence(_ payload: Data) async throws { try await command(["command": "presence", "payload": Base64.encode(payload)]) }
    /// Measures the round trip and clock offset to `to` (an `offsetChanged` event follows).
    public func ping(_ to: String) async throws { try await command(["command": "ping", "to": to]) }
    /// Leaves the session (a holder releases the role) and ends the endpoint.
    public func leave() async throws { try await host.leave() }
    /// Stops at once without leaving, as a process that ends would.
    public func close() { host.close() }

    private func command(_ object: [String: Any]) async throws {
        let name = object["command"] as? String ?? "command"
        try await host.command(name, json: SessionCellHost.json(object))
    }

    public static func randomID() -> Data { Data((0..<16).map { _ in UInt8.random(in: 0...255) }) }

    private func hostEvent(_ event: CellHostEvent) {
        switch event {
        case .session(let name, let json):
            let typed = CellEvent(event: name, json: json)
            for listener in eventListeners.withLock({ Array($0.values) }) { listener(typed) }
            refresh()
        case .account, .rebuilt, .persist: refresh()
        default: break
        }
    }
    private func refresh() {
        guard let next = host.snapshot else { return }
        let changed = current.withLock { s -> Bool in if s == next { return false }; s = next; return true }
        guard changed else { return }
        for listener in stateListeners.withLock({ Array($0.values) }) { listener(next) }
    }
}

/// Standard base64 with padding (`payload`, `snapshot`, `state`), and unpadded base64url (`id`, `fresh`), as the core
/// writes them.
public enum Base64 {
    public static func encode(_ data: Data) -> String { data.base64EncodedString() }
    public static func url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    /// Bytes of standard or URL-safe base64, padded or not.
    public static func decode(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        return Data(base64Encoded: s)
    }
}
