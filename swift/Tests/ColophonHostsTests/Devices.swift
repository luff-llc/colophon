import Foundation
import os
import Testing
@testable import ColophonHosts
import ColophonSession

let listening = "listening.podcasts"
let nowPlaying = "now-playing"

/// One device of a test account: a session over a medium, with software keys.
@MainActor final class Device {
    let medium: MemoryMedium
    let owner: SoftwareKeys
    let session: ColophonSession
    private let home: URL
    init(medium: MemoryMedium = MemoryMedium(), owner: SoftwareKeys = SoftwareKeys(), homes: [HomeConfiguration] = [], createWithoutHome: Bool = true,
         history: HistoryAccess? = nil, namespaces: [String] = [listening]) {
        self.medium = medium; self.owner = owner
        home = FileManager.default.temporaryDirectory.appendingPathComponent("colophon-hosts-\(UUID().uuidString)")
        session = ColophonSession(configuration: SessionConfiguration(memberLabel: "Test device", namespaces: namespaces, location: .memory(medium),
            privateContainer: home, keys: SoftwareKeys(), ownerController: owner, homes: homes, createWithoutHome: createWithoutHome,
            deviceSecrets: MemoryDeviceSecrets(), history: history))
    }
    var id: String { session.memberID ?? "" }
    func account() throws -> SessionHostAccount { try SessionHostAccount(session: session) }
    func close() { try? FileManager.default.removeItem(at: home) }
}

/// The scan path: the approving device scans the joining device's request and approves it.
@MainActor func approveByScan(joining: ColophonSession, approving: ColophonSession) async throws {
    let scanned = try await approving.scanRequest(try await joining.exportRequest())
    try await approving.approve(scanned.request, pairing: scanned.pairing)
}

/// A local account (no home) with two members entitled to write `listening.podcasts`, made once for the unit suites.
@MainActor enum LocalAccount {
    private static var made: (Device, Device)?
    static func pair() async throws -> (first: Device, second: Device) {
        if let made { return made }
        let first = Device()
        await first.session.create()
        try #require(first.session.phase == .ready)
        let second = Device(medium: first.medium)
        await second.session.restore()
        try await approveByScan(joining: second.session, approving: first.session)
        await second.session.refresh()
        try #require(second.session.phase == .ready)
        made = (first, second)
        return (first, second)
    }
    /// Another member approved on `first`'s device: the account's head moves.
    static func third(_ first: Device) async throws -> Device {
        let third = Device(medium: first.medium)
        await third.session.restore()
        try await approveByScan(joining: third.session, approving: first.session)
        await third.session.refresh()
        return third
    }
}

/// Every frame one cell sends reaches every other attached cell, in order; `paused` keeps them back.
final class LoopCarrier: Sendable {
    private struct State {
        var cells: [ObjectIdentifier: any StreamCell] = [:]
        var carried: [(from: ObjectIdentifier?, frame: String)] = []
        var paused = false
        var backlog: [(ObjectIdentifier?, String)] = []
    }
    private let state = OSAllocatedUnfairLock(initialState: State())
    /// A carrier view for one cell, so the carrier knows who sent each frame.
    func view() -> CellCarrier { View(loop: self) }
    var cellCount: Int { state.withLock { $0.cells.count } }
    func has(_ cell: AnyObject) -> Bool { let id = ObjectIdentifier(cell); return state.withLock { $0.cells[id] != nil } }
    func carried(from cell: AnyObject) -> [String] { let id = ObjectIdentifier(cell); return state.withLock { $0.carried.filter { $0.from == id }.map(\.frame) } }
    var lastCarried: String? { state.withLock { $0.carried.last?.frame } }
    func pause() { state.withLock { $0.paused = true } }
    func resume() {
        let backlog = state.withLock { s -> [(ObjectIdentifier?, String)] in s.paused = false; let b = s.backlog; s.backlog = []; return b }
        for (from, frame) in backlog { deliver(frame, from: from) }
    }
    fileprivate func add(_ cell: any StreamCell) { state.withLock { $0.cells[ObjectIdentifier(cell)] = cell } }
    fileprivate func remove(_ cell: any StreamCell) { state.withLock { _ = $0.cells.removeValue(forKey: ObjectIdentifier(cell)) } }
    fileprivate func send(_ frame: String, from: ObjectIdentifier?) {
        let paused = state.withLock { s -> Bool in
            s.carried.append((from, frame))
            if s.paused { s.backlog.append((from, frame)) }
            return s.paused
        }
        if !paused { deliver(frame, from: from) }
    }
    private func deliver(_ frame: String, from: ObjectIdentifier?) {
        for (id, cell) in state.withLock({ $0.cells }) where id != from { cell.deliver(frame) }
    }
    private struct View: CellCarrier {
        let loop: LoopCarrier
        let mine = OSAllocatedUnfairLock<ObjectIdentifier?>(initialState: nil)
        func attach(_ cell: any StreamCell) async throws { mine.withLock { $0 = ObjectIdentifier(cell) }; loop.add(cell); cell.linkUp() }
        func detach(_ cell: any StreamCell) async { loop.remove(cell) }
        func sendSession(_ frame: String) async -> Bool { loop.send(frame, from: mine.withLock { $0 }); return true }
        func onPass(_ listener: @escaping @Sendable () -> Void) async -> ListenerToken? { nil }
    }
}

/// A host account whose member key can be made to fail (a key that is unavailable).
final class FlakyKey: HostAccount {
    let inner: SessionHostAccount
    let failing = OSAllocatedUnfairLock(initialState: false)
    init(_ inner: SessionHostAccount, failing: Bool = false) { self.inner = inner; self.failing.withLock { $0 = failing } }
    var account: String { inner.account }
    var member: String { inner.member }
    func engine() async throws -> AccountEngine { try await inner.engine() }
    func streamCall(home: String) async throws -> Data { try await inner.streamCall(home: home) }
    func exchange() async throws { try await inner.exchange() }
    func signRaw(_ body: Data) async throws -> Data {
        if failing.withLock({ $0 }) { throw ClaimStoreError.storage("the key is unavailable") }
        return try await inner.signRaw(body)
    }
}

/// A short name for an event, for comparing orders.
func shape(_ e: CellHostEvent) -> String {
    switch e {
    case .session(let name, _): "event:\(name)"
    case .sent(let kind, _): "sent:\(kind)"
    case .persist(let phase, _, _): "persist:\(phase.rawValue)"
    case .unsent: "unsent"
    case .drop: "drop"
    case .discarded: "discarded"
    case .queued: "queued"
    case .commandHeld: "commandHeld"
    case .stale: "stale"
    case .account: "account"
    case .rebuilt: "rebuilt"
    case .missed: "missed"
    case .failed: "failed"
    case .error: "error"
    }
}
func b64(_ text: String) -> String { Data(text.utf8).base64EncodedString() }
func json(_ object: [String: Any]) -> String { SessionCellHost.json(object) }
