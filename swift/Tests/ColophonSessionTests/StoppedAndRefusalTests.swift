import CryptoKit
import Foundation
import Testing
import ColophonKeys
import ColophonSession

/// **Test-only, below the 0.5 builders**: a transition raising the account's layout to 3 (spec §20 "The upgrade door"),
/// signed by the owner controller and written to the device's store. 0.5's write side deliberately builds no `layout`
/// component, so this helper writes the canonical body itself (every value is plain ASCII, keys in order): the account,
/// the anchor (the verified head), the owner as `by` and only signer, the change, the clock. The session's own refresh then
/// records the `activate` (`record_due`), final at once in an account with no home: the device is stopped.
@MainActor func raiseLayout(_ device: Device, to layout: Int = 3, nowMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) async throws {
    let account = try #require(device.session.libraryID)
    let entries = try device.medium.listing().map(\.path).filter { $0.hasPrefix("authority/") }.sorted()
    let last = try #require(entries.last)
    let envelope = try #require(try JSONSerialization.jsonObject(with: device.medium.read(last)) as? [String: Any])
    let bodyText = try #require(envelope["body"] as? String)
    let headBody = try #require(Data(base64Encoded: bodyText))
    let seq = try #require(Int(last.dropFirst("authority/".count).prefix(8)))
    let owner = try accountKeyId(signing: try await device.owner.publicKeys().signing)
    let issued = try accountFormatDate(ms: nowMs)
    let body = Data(("{\"account\":\"\(account)\",\"anchor\":{\"digest\":\"\(hex(headBody))\",\"seq\":\(seq)},\"by\":\"\(owner)\","
        + "\"change\":{\"layout\":\(layout)},\"issued\":\"\(issued)\",\"protocol\":\"colophon/transition/5\",\"signers\":[\"\(owner)\"]}").utf8)
    let signature = try await device.owner.sign(body: body)
    let transition = Data("{\"body\":\"\(body.base64EncodedString())\",\"signature\":\"\(signature.base64EncodedString())\"}".utf8)
    try device.medium.write([MediumWrite(path: "transitions/\(hex(body)).json", bytes: transition)])
}
func hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

@MainActor struct StoppedAccountTests {
    private func savedItems(_ session: ColophonSession) async throws -> String {
        String(decoding: try await session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)), as: UTF8.self)
    }

    /// A final layout raise this device verified stops the account (spec §1 "A stop"): the phase says to update the app,
    /// what the device holds stays readable, nothing is written, no exchange runs, and it persists across relaunch; lock and
    /// sign-out still work.
    @Test func aFinalRaiseStopsTheAccountReadablyAndForGood() async throws {
        let home = SimHome()
        // A home is configured for the session (so a sync loop exists) but not appointed: the raise is final at once.
        let device = Device(homes: [HomeConfiguration(endpoint: URL(string: home.base + "/")!, transport: home)])
        await device.session.create()
        try #require(device.session.phase == .ready, "\(device.session.phase)")
        try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/before")!, title: "Before the stop"),
                                         observed: device.session.observedRevision)
        try #require(try await savedItems(device.session).contains("Before the stop"))
        let head = try device.medium.listing().filter { $0.path.hasPrefix("authority/") }.count

        try await raiseLayout(device)
        await device.session.flushExternalChanges()
        guard case .stopped(let seq, let layout) = device.session.phase else {
            Issue.record("expected stopped, got \(device.session.phase) \(device.session.lastError ?? "") pending \(device.session.notices.pending.map { "\($0.components) due \(String(describing: $0.dueMs)) full \(String(describing: $0.fullSet))" }) files \((try? device.medium.listing().map(\.path).filter { !$0.hasPrefix("ops/") }) ?? [])"); return
        }
        #expect(seq == UInt64(head + 1) && layout == 3, "the raising activation and its layout: \(seq) \(String(describing: layout))")
        #expect(device.session.lastError == nil, "no fault is shown: \(device.session.lastError ?? "")")
        // Reads go on, as of the stop.
        #expect(device.session.hasUsableContent)
        #expect(try await savedItems(device.session).contains("Before the stop"))
        // A write is refused, and the phase stays: the stop is not a new fault.
        await #expect(throws: (any Error).self) {
            try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/after")!, title: "After"),
                                             observed: device.session.observedRevision)
        }
        #expect(device.session.phase.isStopped, "\(device.session.phase)")
        #expect(try device.medium.listing().filter { $0.path.hasPrefix("ops/") }.count == 1, "nothing new was written")
        // No exchange runs: not a failure, and the home is never contacted.
        #expect(await device.session.syncNow())
        #expect(device.session.syncState == .disabled)
        #expect(home.requestLog.isEmpty, "\(home.requestLog)")

        // Lock and unlock: back to stopped.
        await device.session.lock()
        #expect(device.session.phase == .locked)
        await device.session.unlock()
        #expect(device.session.phase.isStopped, "\(device.session.phase)")

        // Relaunch: still stopped, still readable.
        device.session.stopSync()
        let relaunched = device.relaunch()
        await relaunched.restore()
        relaunched.stopSync()
        #expect(relaunched.phase == .stopped(seq: seq, layout: 3), "\(relaunched.phase)")
        #expect(try await savedItems(relaunched).contains("Before the stop"))
        // Sign-out works.
        try await relaunched.leave()
        #expect(relaunched.phase == .noLibrary)
    }

    /// A stop once verified survives its evidence going missing: the store loses the raising transition and its
    /// activate (a hostile shared folder), and a relaunch is still stopped and still writes nothing.
    @Test func aStopSurvivesItsEvidenceGoingMissing() async throws {
        let device = Device()
        await device.session.create()
        device.session.stopSync()
        try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/kept")!, title: "Kept"),
                                         observed: device.session.observedRevision)
        let before = Set(try device.medium.listing().map(\.path))
        try await raiseLayout(device)
        await device.session.flushExternalChanges()
        try #require(device.session.phase.isStopped, "\(device.session.phase)")
        // Remove every authority and pending file the raise added.
        for path in try device.medium.listing().map(\.path) where !before.contains(path)
            && (path.hasPrefix("authority/") || path.hasPrefix("transitions/")) { device.medium.remove(path) }
        let relaunched = device.relaunch()
        await relaunched.restore()
        relaunched.stopSync()
        #expect(relaunched.phase.isStopped, "\(relaunched.phase) \(relaunched.lastError ?? "")")
        await #expect(throws: (any Error).self) {
            try await relaunched.perform(try .saveLink(url: URL(string: "https://example.org/after")!, title: "After"),
                                         observed: relaunched.observedRevision)
        }
        #expect(try await relaunched.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)).count > 0)
        await relaunched.lock()
    }

    /// Nothing that arrives after the stop is admitted: a record written elsewhere under the old authority and put into
    /// the store afterwards does not change what the device shows, and the session does not refresh content while stopped.
    @Test func aRecordThatArrivesAfterTheStopIsNotAdmitted() async throws {
        let device = Device()
        await device.session.create()
        device.session.stopSync()
        try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/one")!, title: "One"),
                                         observed: device.session.observedRevision)
        // The same member on another copy of the store writes a second link that this device has not seen.
        var files: [String: Data] = [:]
        for path in try device.medium.listing().map(\.path) { files[path] = try device.medium.read(path) }
        let copy = Device(medium: MemoryMedium(files: files), member: device.member, owner: device.owner)
        await copy.session.restore()
        copy.session.stopSync()
        try #require(copy.session.phase == .ready, "\(copy.session.phase)")
        try await copy.session.perform(try .saveLink(url: URL(string: "https://example.org/late")!, title: "Late arrival"),
                                       observed: copy.session.observedRevision)
        let late = try copy.medium.listing().map(\.path).filter { $0.hasPrefix("ops/") && files[$0] == nil }
        try #require(late.count == 1)
        try await raiseLayout(device)
        await device.session.flushExternalChanges()
        try #require(device.session.phase.isStopped, "\(device.session.phase)")
        let shown = String(decoding: try await device.session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)), as: UTF8.self)
        try device.medium.write(late.map { MediumWrite(path: $0, bytes: try copy.medium.read($0)) })
        await device.session.flushExternalChanges()
        let after = String(decoding: try await device.session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)), as: UTF8.self)
        #expect(after == shown && !after.contains("Late arrival"), "\(after)")
        await copy.session.lock()
    }

    /// A raise that is only held (not activated) changes nothing.
    @Test func aRaiseThatIsNotYetRecordedStopsNothing() async throws {
        let device = Device()
        await device.session.create()
        device.session.stopSync()
        // Issued in the future: the transition is held, its activate not yet due.
        try await raiseLayout(device, nowMs: Int64(Date().timeIntervalSince1970 * 1000) + 3_600_000)
        await device.session.flushExternalChanges()
        #expect(!device.session.phase.isStopped, "\(device.session.phase)")
    }
}

/// A home's refusals, shown raw (spec §14, §19): an unknown `refused:` name, and the four reserved ones, refuse only that
/// request and are surfaced with their name as given, validated and bounded, never echoing the body; `Retry-After` is
/// honoured; `503 {"result":"unavailable"}` is the home being unavailable; none of them is a verified state of the account.
@MainActor struct HomeRefusalTests {
    private func device(_ home: SimHome) -> Device {
        let make: @Sendable (String) async throws -> Data = { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        }
        return Device(homes: [HomeConfiguration(endpoint: URL(string: home.base + "/")!, label: "Home", request: make, transport: home)],
                      createWithoutHome: false)
    }

    @Test func theResultGrammarIsBoundedAndNothingElseIsRead() {
        for good in ["refused:overQuota", "refused:noEntitlement", "refused:closed", "refused:notProvisioned", "refused:somethingNew2", "unavailable"] {
            #expect(HomeRefusal.isValid(good), "\(good)")
        }
        for bad in ["refused:", "refused:Upper", "refused:a-b", "refused:<script>", "refused:" + String(repeating: "a", count: 49), "nope", "refused:é"] {
            #expect(!HomeRefusal.isValid(bad), "\(bad)")
        }
        let refusal = HomeRefusal(status: 410, headers: [Header(name: "Retry-After", value: "30")], body: refusalBody("refused:closed"))
        #expect(refusal?.code == "refused:closed" && refusal?.retryAfterSeconds == 30)
        #expect(HomeRefusal(status: 410, headers: [], body: refusalBody("refused:<x>")) == nil, "an invalid result is not read")
        #expect(HomeRefusal(status: 200, headers: [], body: refusalBody("refused:closed")) == nil)
        #expect(HomeRefusal(status: 429, headers: [Header(name: "retry-after", value: "Tue, 1 Dec")], body: Data())?.retryAfterSeconds == nil)
    }

    /// Each reserved name, and one no version defines, refuses one request (a write), shows its name, and leaves the
    /// account ready; the rest of the pass goes on.
    @Test func unknownAndReservedRefusalsAreShownRawAndRefuseOnlyThatRequest() async throws {
        for (code, status) in [("refused:overQuota", UInt32(507)), ("refused:noEntitlement", 402), ("refused:closed", 410),
                               ("refused:somethingNew", 409)] {
            let home = SimHome()
            let device = device(home)
            await device.session.create()
            device.session.stopSync()
            try #require(await device.session.syncNow(), "first sync: \(device.session.homeIssues)")
            home.answer = { request in
                request.method == .put && request.url.contains("/records/ops/") ? HttpAnswer(status: status, headers: [], body: refusalBody(code)) : nil
            }
            try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/\(status)")!, title: "Refused"),
                                             observed: device.session.observedRevision)
            _ = await device.session.syncNow()
            #expect(device.session.homeIssues.contains { $0.problem == .remoteCallRefused(code: code) }, "\(code): \(device.session.homeIssues)")
            #expect(!device.session.homeIssues.description.contains("SECRET"), "the body is never echoed")
            #expect(device.session.phase == .ready, "\(code) is not a state of the account: \(device.session.phase)")
            #expect(home.requestLog.contains { $0.hasPrefix("GET /changes") || $0.hasPrefix("GET /records") || $0.hasPrefix("PUT /records/heads") }
                    || home.requestLog.count > 3, "the pass went on past the refused request")
        }
    }

    /// `refused:notProvisioned` (403) ends the pass, as a refused call does, and is still only the home's word.
    @Test func aRefusedCallIsTheHomesWordNotAState() async throws {
        let home = SimHome()
        let device = device(home)
        await device.session.create()
        device.session.stopSync()
        // One clean pass first: the background loop is stopped and nothing races the answers below.
        try #require(await device.session.syncNow(), "first sync: \(device.session.homeIssues)")
        home.answer = { request in request.url.hasSuffix("/head") ? nil : HttpAnswer(status: 403, headers: [], body: refusalBody("refused:notProvisioned")) }
        _ = await device.session.syncNow()
        #expect(device.session.homeIssues.contains { $0.problem == .remoteCallRefused(code: "refused:notProvisioned") }, "\(device.session.homeIssues) log \(home.requestLog) sync \(device.session.syncState)")
        // A refusal by name to a request that carried no call is not retried with a call.
        #expect(!device.session.homeIssues.contains { if case .callRefused = $0.problem { true } else { false } }, "\(device.session.homeIssues)")
        #expect(device.session.phase == .ready && device.session.hasUsableContent)
    }

    /// `Retry-After` is honoured: the home is not contacted again before then, and nothing loops.
    @Test func retryAfterIsHonoured() async throws {
        let home = SimHome()
        let device = device(home)
        await device.session.create()
        device.session.stopSync()
        // One clean pass first: the background loop is stopped and nothing races the answers below.
        try #require(await device.session.syncNow(), "first sync: \(device.session.homeIssues)")
        home.answer = { _ in HttpAnswer(status: 429, headers: [Header(name: "Retry-After", value: "120")], body: refusalBody("refused:window")) }
        _ = await device.session.syncNow()
        #expect(device.session.homeIssues.contains { $0.problem == .remoteCallRefused(code: "refused:window", retryAfterSeconds: 120) },
                "\(device.session.homeIssues) log \(home.requestLog) sync \(device.session.syncState) error \(device.session.lastError ?? "-")")
        let sent = home.requestLog.count
        _ = await device.session.syncNow()
        _ = await device.session.syncNow()
        #expect(home.requestLog.count == sent, "not contacted again before the time it asked for")
    }

    /// `503 {"result":"unavailable"}`: the home is not available, retried with backoff; never the device being stopped.
    @Test func anUnavailableHomeIsNotAStoppedDevice() async throws {
        let home = SimHome()
        let device = device(home)
        await device.session.create()
        device.session.stopSync()
        // One clean pass first: the background loop is stopped and nothing races the answers below.
        try #require(await device.session.syncNow(), "first sync: \(device.session.homeIssues)")
        home.answer = { _ in HttpAnswer(status: 503, headers: [], body: refusalBody("unavailable")) }
        #expect(await device.session.syncNow() == false, "a failure, so the loop backs off")
        #expect(device.session.syncState == .offline(reason: HomeWords.unavailable), "\(device.session.syncState)")
        #expect(device.session.homeIssues.contains { $0.problem == .homeUnavailable(retryAfterSeconds: nil) }, "\(device.session.homeIssues)")
        #expect(!device.session.phase.isStopped && device.session.hasUsableContent, "\(device.session.phase)")
        home.answer = nil
        #expect(await device.session.syncNow(), "it recovers when the home is back")
    }

    /// A device that asked to join and holds no grant for itself is waiting for approval, not revoked, when a home answers
    /// `refused:revoked` (the 0.5 result for a member no grant names). A member the account does name is shown the home's
    /// refusal as received.
    @Test func aJoiningDeviceIsWaitingForApprovalNotRevoked() async throws {
        let home = SimHome()
        let first = device(home)
        await first.session.create()
        first.session.stopSync()
        try #require(await first.session.syncNow())
        let joining = Device(medium: first.medium, homes: [HomeConfiguration(endpoint: URL(string: home.base + "/")!, transport: home)],
                             createWithoutHome: false)
        await joining.session.restore()
        joining.session.stopSync()
        try #require(joining.session.phase == .waitingForApproval, "\(joining.session.phase)")
        home.answer = { request in request.url.hasSuffix("/head") ? nil : HttpAnswer(status: 403, headers: [], body: refusalBody("refused:revoked")) }
        _ = await joining.session.syncNow()
        #expect(joining.session.homeIssues.contains { $0.problem == .waitingForApproval }, "\(joining.session.homeIssues)")
        #expect(!joining.session.homeIssues.contains { $0.problem == .remoteCallRefused(code: "refused:revoked") })
        #expect(joining.session.phase == .waitingForApproval)
        // The approved owner device, given the same answer, sees the home's refusal as received.
        _ = await first.session.syncNow()
        #expect(first.session.homeIssues.contains { $0.problem == .remoteCallRefused(code: "refused:revoked") }, "\(first.session.homeIssues)")
        #expect(first.session.phase == .ready)
    }
}

/// A home's error body: the result, and bytes a session must never echo.
func refusalBody(_ result: String) -> Data { Data("{\"result\":\"\(result)\",\"detail\":\"SECRET-BODY-BYTES\"}".utf8) }
