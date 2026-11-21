import CryptoKit
import Foundation
import Testing
import ColophonKit
import ColophonKeys
@testable import ColophonSession

/// Joining at an invite's head (0.5.2) against the REAL relay as the home (`relay/server.js` with the Rust home module,
/// history for members only): the joiner holds only the account ID, the home's base, the invite's head and its own keys.
/// It waits before approval, gets the history after, and the session opened from that history reuses the same request
/// and member. Refused: an invite head the home does not hold (another digest at the seq, a seq beyond), another account,
/// a history truncated at the invite's head or before the grant (the tip is not the signed head), a grant made from
/// another request, a signed head behind the history. A revoked member gets the home's same `refused:revoked`: not admitted.
/// The same journey runs in Kotlin (`ColophonJoinTest.kt`).
@MainActor @Suite(.serialized) struct ColophonJoinTests {
    private let base = "https://home-join.test/v1/accounts/swift"
    private let otherBase = "https://home-other.test/v1/accounts/swift"

    /// True the first time only.
    final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var used = false
        func take() -> Bool { lock.withLock { defer { used = true }; return !used } }
    }
    /// A home transport that lets a test rewrite what the home answers.
    final class Tamper: HomeTransport, @unchecked Sendable {
        let inner: any HomeTransport
        private let lock = NSLock()
        private var rewrite: (@Sendable (HttpRequest, HttpAnswer) -> HttpAnswer)?
        init(_ inner: any HomeTransport) { self.inner = inner }
        func set(_ f: (@Sendable (HttpRequest, HttpAnswer) -> HttpAnswer)?) { lock.withLock { rewrite = f } }
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            let answer = try await inner.send(request)
            let f = lock.withLock { rewrite }
            return f?(request, answer) ?? answer
        }
    }

    private func invite(_ medium: MemoryMedium) throws -> (UInt64, String) {
        let entries = medium.snapshot().filter { $0.key.hasPrefix("authority/") }.sorted { $0.key < $1.key }.map { ByteString(bytes: $0.value) }
        let report = try accountVerifyHistory(objects: AuthorityObjects(entries: entries, pending: [], heads: [], predecessor: []), nowMs: RelayHome.nowMs())
        try #require(report.code == "ok")
        return (UInt64(report.branch.count), report.branch.last!)
    }
    nonisolated private static func page(_ entries: [Data]) -> Data {
        let objects = entries.map { try! JSONSerialization.jsonObject(with: $0) }
        return try! JSONSerialization.data(withJSONObject: ["entries": objects, "receipts": [Any](), "more": false])
    }
    nonisolated private static func ok(_ body: Data) -> HttpAnswer { HttpAnswer(status: 200, headers: [], body: body) }
    nonisolated private static func isAuthority(_ r: HttpRequest) -> Bool { r.url.contains("/authority") }
    private func get(_ transport: any HomeTransport, _ url: String) async throws -> Data {
        try await transport.send(HttpRequest(ticket: 0, home: "", method: .get, url: url, headers: [], body: Data())).body
    }
    private func settle(_ device: Device) async throws {
        for _ in 0..<40 {
            if await device.session.syncNow(), device.session.homeIssues.isEmpty, device.session.homeFaults.isEmpty { return }
            try await Task.sleep(for: .milliseconds(150))
        }
        Issue.record("the device did not settle: \(device.session.phase) \(device.session.homeIssues)")
    }
    private func admitted(_ join: ColophonJoin) async throws -> AdmittedHistory? {
        for _ in 0..<60 {
            if case .admitted(let history) = try await join.fetchHistory() { return history }
            try await Task.sleep(for: .milliseconds(150))
        }
        Issue.record("the joiner was not admitted")
        return nil
    }
    private func rejected(_ code: String, _ body: () async throws -> Void) async {
        do { try await body(); Issue.record("expected \(code)") }
        catch let JoinError.rejected(c, d) { #expect(c == code || c.hasPrefix(code + ":"), "\(c) \(d)") }
        catch { Issue.record("expected \(code), got \(error)") }
    }
    private func refusedByHome(_ code: String, _ body: () async throws -> Void) async {
        do { try await body(); Issue.record("expected the home to refuse with \(code)") }
        catch let JoinError.refused(status, c) { #expect(status == 403 && c == code, "\(status) \(c ?? "-")") }
        catch { Issue.record("expected \(code), got \(error)") }
    }
    private func makeOwner(_ relay: RelayHome, _ base: String, passkey: TestPasskey? = nil) -> Device {
        Device(homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, request: { account in
            try relay.start(account: account)
            return try relay.memberRequest(account: account)
        }, transport: relay.transport())], createWithoutHome: false,
               additional: passkey.map { [AdditionalController(provider: $0, label: "Passkey")] } ?? [], history: .members)
    }
    /// A head envelope for `(seq, digest)` signed by `keys` as `by` (canonical: keys sorted).
    private func forgedHead(account: String, seq: UInt64, digest: String, by: String, keys: any AsyncKeyProvider) async throws -> Data {
        let issued = try accountFormatDate(ms: RelayHome.nowMs() - 1000)
        let body = Data("{\"account\":\"\(account)\",\"authority\":{\"digest\":\"\(digest)\",\"seq\":\(seq)},\"by\":\"\(by)\",\"issued\":\"\(issued)\",\"protocol\":\"colophon/head/5\"}".utf8)
        let signature = try await keys.sign(body: body)
        return Data("{\"body\":\"\(body.base64EncodedString())\",\"signature\":\"\(signature.base64EncodedString())\"}".utf8)
    }

    /// The paging bound, through the pure helper paging calls with its fixed limits: a home that pages forever fails.
    @Test func pagingStopsAtTheBound() throws {
        let page = Array(repeating: ByteString(bytes: Data(count: 100_000)), count: 16)
        var bytes = 0, count = 0
        let limit = 4 * 1024 * 1024
        do {
            while true { bytes = try ColophonJoin.bounded(bytes: bytes, count: count, page: page, maxBytes: limit, maxEntries: 1 << 18); count += page.count }
        } catch let JoinError.rejected(code, _) { #expect(code == "unavailable") }
        #expect(bytes <= limit, "nothing past the bound was kept")
        #expect(try ColophonJoin.bounded(bytes: 0, count: 0, page: page, maxBytes: ColophonJoin.maxHistoryBytes, maxEntries: ColophonJoin.maxEntries) == 1_600_000)
        #expect(throws: JoinError.self) {
            try ColophonJoin.bounded(bytes: 0, count: ColophonJoin.maxEntries, page: [page[0]], maxBytes: ColophonJoin.maxHistoryBytes, maxEntries: ColophonJoin.maxEntries)
        }
    }

    @Test(.timeLimit(.minutes(10))) func joinAtTheInviteHead() async throws {
        let relay = RelayHome(base: base, port: RelayHome.freePort())
        let other = RelayHome(base: otherBase, port: RelayHome.freePort())
        defer { relay.stop(); other.stop() }
        let passkey = TestPasskey()
        let owner = makeOwner(relay, base, passkey: passkey)
        await owner.session.create()
        owner.session.stopSync()
        try #require(owner.session.phase == .ready)
        try await owner.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: owner.session.observedRevision)
        try await settle(owner)
        let account = try #require(owner.session.libraryID)
        let (seq, head) = try invite(owner.medium)
        let headAtInvite = try await get(relay.transport(), base + "/head")

        let refusals = RelayHome.Refusals()
        let tamper = Tamper(relay.transport(refusals: refusals))
        let joiner = Device(homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, transport: tamper)], createWithoutHome: false)
        let join = ColophonJoin(configuration: joiner.configuration, account: account, home: URL(string: base + "/")!, seq: seq, head: head)

        // Before approval: the home refuses the member's read as from a non-member.
        let request = try await join.request()
        let memberID = try await join.memberID()
        let again = try await join.request()
        #expect(again == request, "the request is made once and reused")
        #expect(try joiner.medium.read("requests/\(memberID).json") == request, "stored where the session looks")
        let first = try await join.fetchHistory()
        #expect(first == .notAdmitted)
        #expect(refusals.all == ["refused:revoked"], "a key no grant names is refused:revoked")

        // An invite head the home does not hold, and another account: the home refuses.
        let home = URL(string: base)!
        await refusedByHome("refused:fork") { _ = try await ColophonJoin(configuration: joiner.configuration, account: account, home: home, seq: seq, head: String(repeating: "ab", count: 32)).fetchHistory() }
        await refusedByHome("unavailable") { _ = try await ColophonJoin(configuration: joiner.configuration, account: account, home: home, seq: seq + 10, head: head).fetchHistory() }
        let stranger = Device(homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, transport: relay.transport())], createWithoutHome: false)
        await refusedByHome("unavailable") { _ = try await ColophonJoin(configuration: stranger.configuration, account: String(repeating: "cd", count: 32), home: home, seq: seq, head: head).fetchHistory() }

        // The owner scans the request and approves it; the joiner is then admitted through the home.
        let scanned = try await owner.session.scanRequest(request)
        try await owner.session.approve(scanned.request, pairing: scanned.pairing)
        try await settle(owner)
        let history = try #require(try await admitted(join))
        let files = history.files
        #expect(files.keys.allSatisfy { $0.hasPrefix("authority/") } && UInt64(files.count) > seq)
        // The owner's passkey, read only from the accepted history (an AdmittedHistory, which only fetchHistory makes).
        #expect(try history.ownerDescriptor(keyID: String(repeating: "00", count: 16)) == nil, "no controller with this ID")
        #expect(try history.ownerDescriptor(keyID: try await KeyCustody.keyID(of: owner.owner)) == nil, "a raw controller is no passkey")
        let ownerPasskey = try #require(try history.ownerDescriptor(keyID: try await KeyCustody.keyID(of: passkey)))
        let descriptor = try KeyDescriptor(passkey: ownerPasskey)
        #expect(descriptor.relyingParty == passkey.rp && descriptor.credential == passkey.credential)
        #expect(descriptor.signing == passkey.key.publicKey.x963Representation)
        #expect(descriptor.view == ownerPasskey.view)
        // What the device stores after the join, restored at the next launch.
        let restored = try KeyDescriptor(stored: try descriptor.stored)
        #expect(restored == descriptor)

        // A history truncated at the invite's head, or before the grant: the tip is not the home's signed head.
        let full = files.sorted { $0.key < $1.key }.map(\.value)
        for cut in [Int(seq), full.count - 1] {
            let truncated = Self.page(Array(full.prefix(cut)))
            tamper.set { r, a in Self.isAuthority(r) && a.status == 200 ? Self.ok(truncated) : a }
            await rejected("refused:rollback") { _ = try await join.fetchHistory() }
        }
        // A head that moved past what was served once (the home recorded meanwhile): read again, then accepted.
        let shorter = Self.page(Array(full.prefix(full.count - 1)))
        let once = Once()
        tamper.set { r, a in Self.isAuthority(r) && a.status == 200 && once.take() ? Self.ok(shorter) : a }
        if case .admitted = try await join.fetchHistory() {} else { Issue.record("a head that moved once is read again") }
        // A head signed by a key the verified history names, but not as a current home (this member's own key).
        let tip = try invite(MemoryMedium(files: files))
        let forged = try await forgedHead(account: account, seq: tip.0, digest: tip.1, by: memberID, keys: joiner.member)
        tamper.set { r, a in r.url.hasSuffix("/head") ? Self.ok(forged) : a }
        await rejected("badSignature") { _ = try await join.fetchHistory() }
        // One entry over the authority envelope bound: malformed.
        let huge = try JSONSerialization.data(withJSONObject: ["entries": [["pad": String(repeating: "a", count: 2_200_000)]], "more": false])
        tamper.set { r, a in Self.isAuthority(r) && a.status == 200 ? Self.ok(huge) : a }
        await rejected("malformed") { _ = try await join.fetchHistory() }
        // A page that says more follows but brings nothing.
        tamper.set { r, a in Self.isAuthority(r) && a.status == 200 ? Self.ok(Data("{\"entries\":[],\"more\":true}".utf8)) : a }
        await rejected("malformed") { _ = try await join.fetchHistory() }
        // A signed head behind the history served (the head from the time of the invite).
        tamper.set { r, a in r.url.hasSuffix("/head") ? Self.ok(headAtInvite) : a }
        await rejected("unavailable") { _ = try await join.fetchHistory() }
        // Another account's history and head, served for this one.
        let otherOwner = makeOwner(other, otherBase)
        await otherOwner.session.create(); otherOwner.session.stopSync(); try await settle(otherOwner)
        let otherPage = Self.page(otherOwner.medium.snapshot().filter { $0.key.hasPrefix("authority/") }.sorted { $0.key < $1.key }.map(\.value))
        let otherHead = try await get(other.transport(), otherBase + "/head")
        tamper.set { r, a in
            if Self.isAuthority(r) && a.status == 200 { return Self.ok(otherPage) }
            if r.url.hasSuffix("/head") { return Self.ok(otherHead) }
            return a
        }
        await rejected("refused:fork") { _ = try await join.fetchHistory() }
        tamper.set(nil)

        // The session opened from the history reuses the request and the member.
        try joiner.medium.write(files.map { MediumWrite(path: $0.key, bytes: $0.value) })
        await joiner.session.restore()
        joiner.session.stopSync()
        #expect(joiner.session.memberID == memberID)
        let exported = try await joiner.session.exportRequest()
        #expect(exported == request, "the session reuses the request the owner approved")
        for _ in 0..<20 where joiner.session.phase != .ready {
            _ = await joiner.session.syncNow(); await joiner.session.refresh()
            try await Task.sleep(for: .milliseconds(100))
        }
        #expect(joiner.session.phase == .ready, "\(joiner.session.phase)")

        // A grant made from another request for the same key: refused:conflict.
        let keys = SoftwareKeys()
        let second = Device(member: keys, homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, transport: relay.transport())], createWithoutHome: false)
        let decoy = Device(member: keys, homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, transport: relay.transport())], createWithoutHome: false,
                           services: [ServiceTerms(audience: "https://service.test", purposes: ["decoy.read"])])
        let (seq2, head2) = try invite(owner.medium)
        let mine = ColophonJoin(configuration: second.configuration, account: account, home: home, seq: seq2, head: head2)
        let theirs = ColophonJoin(configuration: decoy.configuration, account: account, home: home, seq: seq2, head: head2)
        let mineID = try await mine.memberID(), theirsID = try await theirs.memberID()
        #expect(mineID == theirsID)
        _ = try await mine.request()
        let decoyScan = try await owner.session.scanRequest(try await theirs.request())
        try await owner.session.approve(decoyScan.request, pairing: decoyScan.pairing)
        try await settle(owner)
        let theirs1 = try await admitted(theirs)
        #expect(theirs1 != nil)
        await rejected("refused:conflict") { _ = try await mine.fetchHistory() }
        // This member's key reading with another current member's request on its medium: refused:conflict.
        let swapped = Device(medium: MemoryMedium(files: ["requests/\(memberID).json": try await theirs.request()]), member: joiner.member,
                             homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, transport: relay.transport())], createWithoutHome: false)
        await rejected("refused:conflict") {
            _ = try await ColophonJoin(configuration: swapped.configuration, account: account, home: home, seq: seq2, head: head2).fetchHistory()
        }

        // A revoked member: the home's answer is the same refused:revoked as before approval, so the joiner waits.
        try await owner.session.revoke(memberID: memberID)
        try await settle(owner)
        var notAdmitted = false
        for _ in 0..<40 where !notAdmitted {
            notAdmitted = try await join.fetchHistory() == .notAdmitted
            if !notAdmitted { try await Task.sleep(for: .milliseconds(150)) }
        }
        #expect(notAdmitted, "a revoked member is not admitted (no longer)")
        #expect(refusals.all.last == "refused:revoked")
    }
}
