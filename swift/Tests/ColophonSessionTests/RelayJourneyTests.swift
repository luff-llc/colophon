import Foundation
import Testing
import ColophonKit
import ColophonSavedKit
import ColophonSession

/// Two devices of one person, each running `ColophonSession`, syncing through the REAL relay as their home
/// (`relay/server.js` on Bun with the Rust home module, started by `RelayHome`), which requires a call for everything
/// spec §13.4 and §14 say needs one. No simulated home anywhere in these tests. The same journey runs through the Rust
/// exports in `crates/colophon-ffi/tests/v05_relay_journey.rs`.
///
/// The journey: an owner creates an account with the home and provisions the slot (the relay is started for the new
/// account ID when the session asks the home for its request); a second device holding a copy of the history from
/// before its approval (as a shared folder would deliver it; under `policy.history: members` a device with nothing
/// can fetch only the head) asks, is approved, learns its approval through the home and syncs; both write and read
/// through `ColophonSavedKit`, with a required and an optional blob; a third device is approved then revoked, reads
/// nothing new and is refused; a pending key change proposed on the first device is shown on the second (which holds
/// a control key) and vetoed there. Under `members` and `public`, and with two homes at `headQuorum` 2.
@MainActor @Suite(.serialized) struct RelayJourneyTests {
    private static func base(_ n: Int) -> String { "https://home-\(n).test/v1/accounts/swift" }

    /// The homes, their session configurations, and the relays they start when the owner creates the account.
    private func homes(_ count: Int) -> ([RelayHome], [HomeConfiguration]) {
        let relays = (0..<count).map { RelayHome(base: Self.base($0), port: RelayHome.freePort()) }
        let configs = relays.map { relay in
            HomeConfiguration(endpoint: URL(string: relay.base + "/")!, label: "Relay \(relay.base.prefix(14))", request: { account in
                try relay.start(account: account, peers: relays.filter { $0 !== relay })
                return try relay.memberRequest(account: account)
            }, transport: relay.transport())
        }
        return (relays, configs)
    }
    /// The same homes for a device that does not appoint them.
    private func joining(_ relays: [RelayHome], refusals: RelayHome.Refusals? = nil) -> [HomeConfiguration] {
        relays.map { HomeConfiguration(endpoint: URL(string: $0.base + "/")!, transport: $0.transport(refusals: refusals)) }
    }
    private func items(_ device: Device) async throws -> Int {
        try await SavedStore(session: device.session).load(ItemsQuery(limit: 50)).get().total
    }
    /// Sync until the session says nothing is wrong, at most `tries` times (a home records entries and forwards heads on
    /// its own schedule, every 50 ms here).
    private func settle(_ device: Device, tries: Int = 40) async -> Bool {
        for _ in 0..<tries {
            let ok = await device.session.syncNow()
            if ok, device.session.homeIssues.isEmpty, device.session.homeFaults.isEmpty { return true }
            try? await Task.sleep(for: .milliseconds(150))
        }
        return false
    }
    private func describe(_ device: Device) -> String {
        "phase \(device.session.phase) error \(device.session.lastError ?? "-") issues \(device.session.homeIssues) faults \(device.session.homeFaults.map { "\($0.fault.kind) \($0.fault.status.map(String.init) ?? "")" })"
    }

    private func journey(history: HistoryAccess, homeCount: Int) async throws {
        let (relays, configs) = homes(homeCount)
        defer { relays.forEach { $0.stop() } }
        let phoneOwner = SoftwareKeys()
        let first = Device(homes: configs, createWithoutHome: false, additional: [AdditionalController(provider: phoneOwner, label: "Phone owner key")],
                           history: history, headQuorum: homeCount)
        await first.session.create()
        first.session.stopSync()
        try #require(first.session.phase == .ready, "\(describe(first))")
        #expect(first.session.homes.count == homeCount, "the homes are appointed at creation")
        try await first.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: first.session.observedRevision)
        let required = Data((0..<90_000).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        let optional = Data((0..<20_000).map { UInt8(truncatingIfNeeded: $0 &* 13) })
        let a = try await first.session.putBlob(required, namespace: "reading.saved", mediaType: "text/plain", reference: "a", required: true)
        let b = try await first.session.putBlob(optional, namespace: "reading.saved", mediaType: "text/plain", reference: "b", required: false)
        #expect(await settle(first), "the first upload and the records reach the home: \(describe(first))")

        // The second device: a copy of the history from before its approval; it asks and is approved.
        let second = Device(medium: MemoryMedium(files: first.medium.snapshot().filter { $0.key.hasPrefix("authority/") }), owner: phoneOwner,
                            homes: joining(relays), createWithoutHome: false)
        await second.session.restore()
        second.session.stopSync()
        guard case .waitingForApproval = second.session.phase else { Issue.record("expected waiting, got \(describe(second))"); return }
        try await first.session.importRequest(try await second.session.exportRequest())
        try await first.session.approve(try #require(first.session.requests.first))
        #expect(await settle(first), "\(describe(first))")
        _ = await second.session.syncNow()
        await second.session.refresh()
        #expect(second.session.phase == .ready, "the phone learnt its approval through the home: \(describe(second))")
        #expect(await settle(second), "\(describe(second))")
        #expect(try await items(second) == 1, "the second device reads what the first wrote")
        #expect(await second.session.blobAvailability(namespace: "reading.saved", digest: a.digest) == .available, "a required blob comes with the sync")
        #expect(try await second.session.blobData(namespace: "reading.saved", digest: a.digest) == required)
        guard case .missing = await second.session.blobAvailability(namespace: "reading.saved", digest: b.digest) else {
            Issue.record("an optional blob is not downloaded before it is asked for"); return
        }
        try await second.session.prefetchBlob(namespace: "reading.saved", digest: b.digest)
        #expect(try await second.session.blobData(namespace: "reading.saved", digest: b.digest) == optional)
        try await second.session.perform(try .saveLink(id: "b", url: URL(string: "https://example.org/b")!, title: "B"), observed: second.session.observedRevision)
        #expect(await settle(second), "\(describe(second))")
        #expect(await settle(first), "\(describe(first))")
        #expect(try await items(first) == 2, "the first device reads what the second wrote")

        // A third device is approved, then revoked: it reads nothing new and the home refuses it.
        let thirdRefusals = RelayHome.Refusals()
        let third = Device(medium: MemoryMedium(files: first.medium.snapshot().filter { $0.key.hasPrefix("authority/") }),
                           homes: joining(relays, refusals: thirdRefusals), createWithoutHome: false)
        await third.session.restore()
        third.session.stopSync()
        try await first.session.importRequest(try await third.session.exportRequest())
        try await first.session.approve(try #require(first.session.requests.first))
        #expect(await settle(first), "\(describe(first))")
        _ = await third.session.syncNow()
        await third.session.refresh()
        #expect(third.session.phase == .ready, "\(describe(third))")
        #expect(await settle(third), "\(describe(third))")
        #expect(try await items(third) == 2)
        try await first.session.revoke(memberID: try #require(third.session.memberID))
        try await first.session.perform(try .saveLink(id: "c", url: URL(string: "https://example.org/c")!, title: "C"), observed: first.session.observedRevision)
        #expect(await settle(first), "\(describe(first))")
        thirdRefusals.clear()
        _ = await third.session.syncNow()
        // Under `members` the home refuses its call with `refused:revoked` (the home holds the revocation, the device
        // cannot fetch it); under `public` it may fetch the revocation without a call, and then its own check refuses
        // with the same code and sends nothing. Any other refusal fails the test.
        let byHome = third.session.homeFaults.contains { $0.fault.kind == .unauthorized }
        let byItself = third.session.homeIssues.contains { $0.problem == .callRefused(code: "refused:revoked") }
        #expect(byHome || byItself, "the revoked device is refused: \(describe(third)) home said \(thirdRefusals.all)")
        if byHome {
            #expect(!thirdRefusals.all.isEmpty && thirdRefusals.all.allSatisfy { $0 == "refused:revoked" },
                    "the home refuses it as revoked: \(thirdRefusals.all)")
        }
        if history == .members { #expect(byHome, "the home refuses the revoked device: \(describe(third))") }
        #expect(third.session.homeIssues.allSatisfy { if case .callRefused(let code) = $0.problem { code == "refused:revoked" } else { true } },
                "\(describe(third))")
        await third.session.refresh()
        // A device that holds its own revocation is `denied` and serves no query (`notReady`); one the home refused
        // before it could fetch the revocation still reads only what it had.
        if byItself { #expect(third.session.phase == .denied, "\(describe(third))") }
        if third.session.phase == .denied {
            await #expect(throws: SessionError.notReady) { try await items(third) }
        } else {
            #expect(try await items(third) <= 2, "the revoked device reads nothing new: \(describe(third))")
        }

        // A pending key change proposed on the first device is shown on the second and vetoed there.
        // A policy change (a longer recovery delay): a transition with a veto window, signed by the first device's owner.
        let change = "{\"policy\":{\"recoveryDelay\":7200}}"
        let digest = try await first.session.proposeTransition(change)
        #expect(await settle(first), "\(describe(first))")
        #expect(await settle(second), "\(describe(second))")
        let shown = try #require(second.session.notices.pending.first { $0.digest == digest }, "the second device shows the pending change")
        #expect(shown.vetoable, "the phone's owner key may veto it")
        try await second.session.veto(digest)
        #expect(await settle(second), "\(describe(second))")
        var gone = false
        for _ in 0..<60 where !gone {
            _ = await first.session.syncNow()
            gone = !first.session.notices.pending.contains { $0.digest == digest }
            if !gone { try? await Task.sleep(for: .milliseconds(150)) }
        }
        #expect(gone, "the home recorded the veto and the first device no longer shows the change: \(describe(first))")
        for device in [first, second, third] { device.session.stopSync() }
    }

    @Test func twoDevicesAndARealHomeWithTheHistoryForMembers() async throws {
        try await journey(history: .members, homeCount: 1)
    }
    @Test func twoDevicesAndARealHomeWithAPublicHistory() async throws {
        try await journey(history: .everyone, homeCount: 1)
    }
    @Test func twoDevicesAndTwoRealHomesAtQuorumTwo() async throws {
        try await journey(history: .members, homeCount: 2)
    }
}
