import Foundation
import Observation
import SwiftUI
import Testing
import ColophonSession
@testable import ColophonSessionUI

/// A deterministic session source: it never opens a file or a key, it only publishes values.
@Observable @MainActor private final class FakeSession: LibrarySessionSource {
    var phase: SessionPhase
    var context = UUID()
    var revision: UInt64 = 1
    var members: [AccountMember] = []
    var requests: [AccessRequest] = []
    var notices: SessionNotices = .empty
    var vetoed: [String] = []
    var acknowledged = 0
    var unlocked = 0
    init(_ phase: SessionPhase) { self.phase = phase }
    func restore() async {}
    func refresh() async { refreshed += 1 }
    func retry() async { retried += 1 }
    func create() async { created += 1 }
    func leave() async throws { left += 1 }
    func rejoin(keys: any AsyncKeyProvider) async {}
    func scanRequest(_ data: Data) async throws -> ScannedRequest { throw SessionError.notReady }
    func rejectPairing(_ pairing: AccountPairing) async throws {}
    func approve(_ request: AccessRequest, pairing: AccountPairing, grant: GrantOptions?) async throws {}
    func revoke(memberID: String) async throws {}
    func veto(_ transition: String) async throws { vetoed.append(transition) }
    func acknowledgeActivation(seq: UInt64) async { acknowledged += 1; notices = .empty }
    func unlock() async { unlocked += 1; phase = .ready }
    var locked = 0
    var resigned: [String] = []
    var created = 0
    var retried = 0
    var refreshed = 0
    var left = 0
    var duties: HostDuties = .none
    func lock() async { locked += 1; phase = .locked }
    func resign(_ transition: String) async throws -> String { resigned.append(transition); return transition }
    var removedFollowUps: [UInt64] = []
    var keptFollowUps: [UInt64] = []
    func removeFollowUp(seq: UInt64) async throws { removedFollowUps.append(seq); duties.removals.removeAll { $0.seq == seq } }
    func keepFollowUp(seq: UInt64) async throws { keptFollowUps.append(seq); duties.removals.removeAll { $0.seq == seq } }
}

private func pending(vetoable: Bool = true, digest: String = "ab") -> Pending {
    Pending(digest: String(repeating: digest, count: 32), by: "11111111111111111111111111111111",
            signers: [Signer(id: "22222222222222222222222222222222", label: "Laptop")], issuedMs: 1_000, anchorSeq: 4, firstSeenSeq: 4,
            dueMs: 260_000_000, vetoDeadlineMs: 259_000_000, fullSet: false, components: ["homes"], removes: [], adds: [], vetoes: [], vetoable: vetoable)
}
private func activation() -> SeenActivation {
    SeenActivation(seq: 7, transition: String(repeating: "cd", count: 32), signers: ["33333333333333333333333333333333"], components: ["keyring"],
                   receipted: [Receipted(home: "44444444444444444444444444444444", receivedMs: 5)])
}

@MainActor struct GateStateTests {
    private let presentation = LibraryPresentation(appName: "Later", promise: "Keep it.")
    private static let allPhases: [SessionPhase] = [.opening, .noLibrary, .creating, .migrating, .waitingForDownload, .waitingForApproval,
        .denied, .unavailable(reason: "offline"), .updateRequired, .ready, .refreshing, .retry, .locked,
        .failed(error: .keysUnavailable(detail: "locked")), .failed(error: .other(detail: "x"))]

    private func screen(_ phase: SessionPhase, rejoin: Bool = false, recovery: Bool = false) throws -> GateScreen {
        guard case .screen(let screen) = GateModel.content(phase: phase, usable: false, presentation: presentation,
                                                           capabilities: GateCapabilities(rejoin: rejoin, recovery: recovery)) else {
            throw GateTestFailure.notAScreen(phase)
        }
        return screen
    }
    private enum GateTestFailure: Error { case notAScreen(SessionPhase) }

    /// Every phase, without usable content, is a screen with a title, a stable identifier, the support report, and the
    /// controls that phase offers, exactly.
    @Test func everyPhaseIsAScreenWithExactlyItsControls() throws {
        let expected: [String: [GateAction]] = [
            "library.opening": [], "library.creating": [], "library.waitingForDownload": [], "library.refreshing": [],
            "library.noLibrary": [.create, .join], "library.locked": [.unlock], "library.retryPhase": [.retry],
            "library.updateRequired": [.retry], "library.migrating": [.retry], "library.waitingForApproval": [.checkAgain, .cancelPairing],
            "library.denied": [.retry], "library.unavailable": [.retry], "library.failed": [.retry],
        ]
        var seen: Set<String> = []
        for phase in Self.allPhases {
            let screen = try screen(phase)
            seen.insert(screen.identifier)
            #expect(!screen.title.isEmpty, "\(phase) has a title")
            #expect(screen.controls.last?.action == .supportReport, "\(phase) offers the support report")
            let actions = Array(screen.controls.dropLast().map(\.action))
            #expect(actions == expected[screen.identifier], "\(phase): \(actions)")
            #expect(Set(screen.controls.map(\.identifier)).count == screen.controls.count, "identifiers are unique on \(phase)")
        }
        #expect(seen == Set(expected.keys), "every screen was reached")
        // The host's capabilities add exactly their controls where they belong.
        #expect(try screen(.denied, rejoin: true, recovery: true).controls.map(\.action) == [.rejoin, .useRecoveryKit, .retry, .supportReport])
        #expect(try screen(.noLibrary, rejoin: true).controls.map(\.action) == [.create, .join, .rejoin, .supportReport])
        #expect(try screen(.waitingForApproval, recovery: true).controls.map(\.action) == [.checkAgain, .useRecoveryKit, .cancelPairing, .supportReport])
    }

    @Test func eachScreenSaysWhatThePersonNeeds() throws {
        let locked = try screen(.locked)
        #expect(locked.title == "Locked" && locked.message.contains("background"))
        #expect(locked.controls.first == GateControl(.unlock, "Unlock", "library.unlock", .prominent))
        let welcome = try screen(.noLibrary)
        #expect(welcome.title == "Welcome to Later" && welcome.message == "Keep it." && welcome.footnote == presentation.dataNote)
        #expect(welcome.controls.first?.title == "Get Started" && welcome.controls[1].title == "I Use Later on Another Device")
        let waiting = try screen(.waitingForApproval)
        // The joining device shows no code of its own (spec §9.1): the six digits appear only while it pairs.
        #expect(waiting.pairingCode == nil && waiting.message.contains("same code") && waiting.message.contains("scan"))
        #expect(try screen(.unavailable(reason: "The disk is gone")).message == "The disk is gone")
        #expect(try screen(.failed(error: .keysUnavailable(detail: "d"))).message.hasPrefix("Your identity keys are unavailable."))
        #expect(try screen(.updateRequired).message.contains("newer storage layout"))
        guard case .screen(let migrating) = GateModel.content(phase: .migrating, usable: false, presentation: presentation,
                                                              capabilities: .init(rejoin: false, recovery: false), migrationProgress: 1.7) else { Issue.record("migrating"); return }
        #expect(migrating.progress == .fraction("Upgrading library", 1), "progress is clamped")
    }

    /// With usable content the gate shows the content; a status line (never a blank) while it refreshes or retries.
    @Test func usableContentShowsTheContentAndAStatusWhileItIsNotReady() {
        let caps = GateCapabilities(rejoin: false, recovery: false)
        #expect(GateModel.content(phase: .ready, usable: true, presentation: presentation, capabilities: caps) == .content(status: nil, controls: []))
        #expect(GateModel.content(phase: .refreshing, usable: true, presentation: presentation, capabilities: caps) == .content(status: "Updating Your Library…", controls: []))
        #expect(GateModel.content(phase: .retry, usable: true, presentation: presentation, capabilities: caps)
                == .content(status: "Refresh failed", controls: [GateControl(.retry, "Retry", "library.retry")]))
    }

    /// The gate locks when the scene goes inactive or to the background, by default at once; one value delays or turns
    /// it off; returning unlocks a locked session and refreshes an open one.
    @Test func theSceneDecidesLockAndUnlock() {
        #expect(GateModel.sceneStep(.background, phase: .ready, policy: .immediately) == .lock(after: .zero))
        #expect(GateModel.sceneStep(.inactive, phase: .ready, policy: .immediately) == .lock(after: .zero))
        #expect(GateModel.sceneStep(.inactive, phase: .refreshing, policy: .after(.seconds(30))) == .lock(after: .seconds(30)))
        #expect(GateModel.sceneStep(.background, phase: .ready, policy: .never) == .nothing)
        #expect(GateModel.sceneStep(.background, phase: .locked, policy: .immediately) == .nothing)
        #expect(GateModel.sceneStep(.active, phase: .locked, policy: .immediately) == .unlock)
        #expect(GateModel.sceneStep(.active, phase: .ready, policy: .immediately) == .refresh)
    }

    /// Every control calls the session (or presents the sheet it names) through `GateModel.perform`, the one function
    /// the buttons call: the veto with the change's digest, unlock, acknowledge with the activation's seq, sign again.
    @Test func everyControlReachesTheSession() async throws {
        let session = FakeSession(.locked)
        let model = LibraryActionModel()
        var presented: [GateAction] = []
        func run(_ action: GateAction) async { await GateModel.perform(action, session: session, host: .init(), model: model) { presented.append($0) } }
        let unlock = try screen(.locked).controls[0]
        await run(unlock.action)
        #expect(session.unlocked == 1 && session.phase == .ready)
        let cards = GateModel.notices(SessionNotices(notices: Notices(pending: [pending()], activations: [activation()], owed: [], controllersWithoutSlot: [],
                                                                    vaultRetiring: false, noHome: false)))
        let veto = try #require(cards.flatMap(\.controls).first { if case .veto = $0.action { true } else { false } })
        #expect(veto.title == "Veto" && veto.weight == .destructive && veto.identifier == "library.notice.veto.abababab")
        await run(veto.action)
        #expect(session.vetoed == [pending().digest])
        let seen = try #require(cards.flatMap(\.controls).first { $0.title == "I’ve Seen This" })
        await run(seen.action)
        #expect(session.acknowledged == 1)
        for action: GateAction in [.create, .retry, .checkAgain, .cancelPairing, .resign("dd")] { await run(action) }
        #expect(session.created == 1 && session.retried == 1 && session.refreshed == 1 && session.left == 1 && session.resigned == ["dd"])
        for action: GateAction in [.join, .useRecoveryKit, .supportReport] { await run(action) }
        #expect(presented == [.join, .useRecoveryKit, .supportReport])
        #expect(model.error == nil)
    }

    /// The notices a person must see, as values: words, identifiers, controls.
    @Test func noticesSayWhatThePersonMustSeeAndOfferWhatTheyCanDo() {
        let notices = SessionNotices(notices: Notices(pending: [pending(), pending(vetoable: false, digest: "ef")], activations: [activation()], owed: [],
                                                      controllersWithoutSlot: [], vaultRetiring: false, noHome: true))
        var duties = HostDuties()
        duties.soleDevice = true
        duties.homeLabels = ["44444444444444444444444444444444": "My Home"]
        duties.routes = [RouteState(home: "4444", label: "My Home", registered: false, detail: "My Home does not offer notices yet.")]
        duties.submissions = [Submission(object: pending().digest, kind: .veto, receipted: 1, homes: 2, finished: true)]
        let cards = GateModel.notices(notices, duties: duties)
        #expect(cards.map(\.id) == ["library.notice.noHome", "library.notice.oneDevice", "library.notice.routes.4444", "library.notice.pending.abababab",
                                     "library.notice.pending.efefefef", "library.notice.activation.7"])
        #expect(cards[0].lines == [NoticeWords.noHome] && cards[1].lines == [NoticeWords.oneDevice])
        let waiting = cards[3]
        #expect(waiting.lines.contains("Signed by Laptop (22222222)") && waiting.lines.contains("First seen at history entry 4"))
        #expect(waiting.lines.contains { $0.hasPrefix("You can say no until") } && waiting.lines.last == NoticeWords.waiting)
        #expect(waiting.lines.contains("Only 1 of 2 homes receipted it within 5 minutes."))
        #expect(cards[4].controls.isEmpty, "a change this device cannot veto offers no veto")
        let took = cards[5]
        #expect(took.lines.contains { $0.hasPrefix("My Home receipted it ") }, "each home's receipt time is shown: \(took.lines)")
        // A dead transition replaces its pending card, and is offered to be signed again when this device kept it.
        duties.deadTransitions = [DeadTransition(digest: pending().digest, receipted: 0, quorum: 2, canResign: true)]
        let after = GateModel.notices(notices, duties: duties)
        #expect(!after.contains { $0.id == "library.notice.pending.abababab" })
        let dead = after.first { $0.id == "library.notice.dead.abababab" }
        #expect(dead?.lines == [NoticeWords.dead(receipted: 0, quorum: 2)] && dead?.controls.map(\.action) == [.resign(pending().digest)])
    }

    /// The removal follow-up (§17.5): when a controller's removal activated, what it admitted since the anchor is listed,
    /// with one action that removes it all and one that keeps it; each reaches the session with the activation's seq.
    @Test func aRemovalFollowUpListsWhatTheRemovedKeyAdmittedAndOffersOneAction() async throws {
        var duties = HostDuties()
        duties.removals = [RemovalFollowUp(seq: 12, removed: ["66666666666666666666666666666666"],
            members: [.init(id: "77777777777777777777777777777777", label: "Unknown phone")],
            controllers: [.init(id: "88888888888888888888888888888888", label: "Laptop")])]
        let cards = GateModel.notices(.empty, duties: duties)
        let card = try #require(cards.first { $0.id == "library.notice.removal.12" })
        #expect(card.lines.contains("Members: Unknown phone (77777777)") && card.lines.contains("Keys: Laptop (88888888)"))
        #expect(card.lines.first?.contains("66666666") == true)
        #expect(card.controls.map(\.action) == [.removeFollowUp(12), .keepFollowUp(12)])
        #expect(card.controls[0].weight == .destructive && card.controls[0].identifier == "library.notice.removeFollowUp.12")
        #expect(!GateModel.notices(.empty, duties: .none).contains { $0.id.hasPrefix("library.notice.removal") }, "no removal, no card")
        let session = FakeSession(.ready)
        session.duties = duties
        let model = LibraryActionModel()
        await GateModel.perform(card.controls[0].action, session: session, host: .init(), model: model) { _ in }
        #expect(session.removedFollowUps == [12] && session.duties.removals.isEmpty)
        session.duties = duties
        await GateModel.perform(card.controls[1].action, session: session, host: .init(), model: model) { _ in }
        #expect(session.keptFollowUps == [12])
        #expect(model.error == nil)
    }

    @Test func theWordsSayWhatTheSpecificationAsksTheHostToSay() {
        #expect(NoticeWords.noHome.contains("no home") && NoticeWords.noHome.contains("Add a home"))
        #expect(NoticeWords.waiting.hasPrefix("Waiting protects who controls your account."))
        #expect(NoticeWords.oneDevice.contains("stolen"))
        #expect(NoticeWords.vetoDeadline(nil).contains("not known"))
        #expect(NoticeWords.vetoDeadline(259_000_000).hasPrefix("You can say no until"))
    }

    @Test func aRequestShowsItsNamespacesAndAccessAndTheSupportReportNamesTheLockedPhase() throws {
        let request = AccessRequest(id: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", label: "iPad", kind: .device,
            termsJSON: #"{"records":[{"namespace":"reading.saved","access":"write"},{"namespace":"notes","access":"read"}]}"#, record: Data())
        #expect(request.namespaces == ["reading.saved", "notes"] && request.access == [.read, .write])
        let report = try SupportReport(session: FakeSession(.locked)).text()
        #expect(report.contains("\"phase\" : \"locked\""))
        #expect(!report.contains("5a5a"), "the report carries no identifiers")
    }

    @Test func memberWordsDescribeGrantsAndKinds() {
        let member = AccountMember(id: "m", label: "Mac", kind: .app, kindRaw: nil,
            grant: AccountGrant(namespaces: ["reading.saved"], access: [.read, .write], expires: nil, writeBudget: 5, import: false),
            since: 3, revokedAt: nil, writes: 2, expiresMs: nil, provisional: false, home: false, session: 0, grantedBy: [])
        #expect(LibraryWords.grant(member).contains("Read and change") && LibraryWords.grant(member).contains("Up to 5 changes; 2 made"))
        #expect(LibraryWords.kind(AccountMemberKind.unknown) == "Unknown kind")
    }
}
