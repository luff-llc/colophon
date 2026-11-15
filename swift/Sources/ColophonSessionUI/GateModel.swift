import ColophonSession
import Foundation

/// When the gate locks the session after the scene leaves the foreground.
public enum BackgroundLock: Equatable, Sendable {
    /// Lock this long after the scene goes inactive or to the background (`.zero`: at once). Returning first cancels it.
    case after(Duration)
    /// Never lock on scene changes (the host locks itself, or the content is not sensitive).
    case never
    /// The default: lock as soon as the scene goes inactive or to the background.
    public static let immediately = BackgroundLock.after(.zero)
}

/// The scene's phase as the gate reads it (SwiftUI's `ScenePhase`, without SwiftUI).
public enum GateScene: Equatable, Sendable { case active, inactive, background }

/// What the gate does when the scene changes.
public enum GateSceneStep: Equatable, Sendable {
    case lock(after: Duration)
    case unlock
    case refresh
    case nothing
}

/// What a control does. The view's buttons call `GateModel.perform` with it; nothing else is wired in the view.
public enum GateAction: Hashable, Sendable {
    case create, join, rejoin, useRecoveryKit, retry, checkAgain, cancelPairing, unlock, supportReport
    case veto(String)
    case acknowledgeActivation(UInt64)
    case resign(String)
    case removeFollowUp(UInt64)
    case keepFollowUp(UInt64)
}

/// One control the person can use: its words, its accessibility identifier, its weight, what it does.
public struct GateControl: Equatable, Identifiable, Sendable {
    public enum Weight: Equatable, Sendable { case prominent, normal, destructive, cancel }
    public let action: GateAction
    public let title: String
    public let identifier: String
    public let weight: Weight
    public var id: String { identifier }
    public init(_ action: GateAction, _ title: String, _ identifier: String, _ weight: Weight = .normal) {
        self.action = action; self.title = title; self.identifier = identifier; self.weight = weight
    }
}

/// A full-screen state of the gate (everything but ready content).
public struct GateScreen: Equatable, Sendable {
    public enum Progress: Equatable, Sendable { case indeterminate(String), fraction(String, Double) }
    public let title: String
    public let message: String
    public let identifier: String
    public var progress: Progress?
    public var pairingCode: String?
    public var footnote: String?
    public var controls: [GateControl]
}

/// What the gate shows: the content (with a status line while it refreshes or retries), or a screen.
public enum GateContent: Equatable, Sendable {
    case content(status: String?, controls: [GateControl])
    case screen(GateScreen)
}

/// A notice above the content (spec §17.5, §18; guide §5): one value per thing the person must see.
public struct NoticeCard: Equatable, Identifiable, Sendable {
    public let id: String
    public let title: String
    public let lines: [String]
    public let controls: [GateControl]
}

/// What the host can offer, from `LibraryHostActions`.
public struct GateCapabilities: Equatable, Sendable {
    public var rejoin: Bool
    public var recovery: Bool
    public init(rejoin: Bool, recovery: Bool) { self.rejoin = rejoin; self.recovery = recovery }
}

/// The gate as pure functions of the session's published state: every title, message and control a person can see or
/// use. `LibraryGate` and `NoticesView` render exactly these values; the tests check them exhaustively.
public enum GateModel {
    // MARK: Scene

    public static func sceneStep(_ scene: GateScene, phase: SessionPhase, policy: BackgroundLock) -> GateSceneStep {
        switch scene {
        case .active: return phase == .locked ? .unlock : .refresh
        case .inactive, .background:
            guard case .after(let delay) = policy, phase != .locked else { return .nothing }
            return .lock(after: delay)
        }
    }

    // MARK: Screens

    public static func content(phase: SessionPhase, usable: Bool, presentation: LibraryPresentation, capabilities: GateCapabilities,
                               migrationProgress: Double? = nil) -> GateContent {
        let retry = GateControl(.retry, "Retry", "library.retry")
        let rejoin = capabilities.rejoin ? [GateControl(.rejoin, "Rejoin Library", "library.rejoin")] : []
        let recovery = capabilities.recovery ? [GateControl(.useRecoveryKit, "Use Recovery Kit", "library.recoverFromPairing")] : []
        let support = GateControl(.supportReport, "Support Report", "library.bugReport")
        if usable {
            switch phase {
            case .ready: return .content(status: nil, controls: [])
            case .retry: return .content(status: "Refresh failed", controls: [retry])
            case .waitingForDownload: return .content(status: "Updating Your Library…", controls: [retry])
            default: return .content(status: "Updating Your Library…", controls: [])
            }
        }
        func screen(_ title: String, _ message: String, _ id: String, progress: GateScreen.Progress? = nil, code: String? = nil,
                    footnote: String? = nil, _ controls: [GateControl]) -> GateContent {
            .screen(GateScreen(title: title, message: message, identifier: id, progress: progress, pairingCode: code, footnote: footnote,
                               controls: controls + [support]))
        }
        switch phase {
        case .ready, .refreshing:
            return screen("Updating Your Library", "", "library.refreshing", progress: .indeterminate("Updating Your Library"), [])
        case .noLibrary:
            return screen(presentation.welcomeTitle, presentation.promise, "library.noLibrary", footnote: presentation.dataNote,
                          [GateControl(.create, presentation.createTitle, "library.createLocal", .prominent),
                           GateControl(.join, presentation.joinTitle, "library.join")] + rejoin)
        case .locked:
            return screen("Locked", "Your library is hidden while this app is in the background.", "library.locked",
                          [GateControl(.unlock, "Unlock", "library.unlock", .prominent)])
        case .opening: return screen("Opening Your Library", "", "library.opening", progress: .indeterminate("Opening Your Library"), [])
        case .waitingForDownload:
            return screen("Waiting for Your Library", "", "library.waitingForDownload", progress: .indeterminate("Waiting for Your Library"), [])
        case .creating: return screen("Creating Your Library", "", "library.creating", progress: .indeterminate("Creating Your Library"), [])
        case .retry: return screen("Couldn’t Open Your Library", "Retry to try again.", "library.retryPhase", [retry] + recovery)
        case .updateRequired:
            return screen("Update Required", "This library uses a newer storage layout. Update this app to open it. Your folder, identity and records are unchanged.",
                          "library.updateRequired", [retry])
        case .migrating:
            let progress: GateScreen.Progress = migrationProgress.flatMap { $0.isFinite ? .fraction("Upgrading library", min(1, max(0, $0))) : nil }
                ?? .indeterminate("Upgrading library")
            return screen("Your Library Is Being Upgraded", "Your existing library is kept while the upgrade completes.", "library.migrating",
                          progress: progress, [retry])
        case .waitingForApproval(let code):
            return screen("Waiting for Approval",
                          "On a device with access, open Library settings. Approve \(presentation.appName) only when both devices show the same code.",
                          "library.waitingForApproval", code: code,
                          [GateControl(.checkAgain, "Check Again", "library.retryPairing")] + recovery
                            + [GateControl(.cancelPairing, "Cancel Pairing", "library.cancelPairing", .cancel)])
        case .denied:
            return screen("Access Has Ended",
                          "This identity may have been revoked, expired, or not granted the access this app needs. Your past contributions stay attributed to you.",
                          "library.denied", rejoin + recovery + [retry])
        case .unavailable(let reason): return screen("Library Unavailable", reason, "library.unavailable", [retry] + recovery)
        case .failed(let error): return screen("Couldn’t Open Your Library", error.message, "library.failed", [retry] + recovery)
        }
    }

    // MARK: Notices

    /// Every notice, in the order a person should read them: the account has no home, it rests on one device, a change
    /// is waiting (with its one-tap veto), a change is dead, changes took effect.
    public static func notices(_ notices: SessionNotices, duties: HostDuties = .none, now: Date = Date()) -> [NoticeCard] {
        var cards: [NoticeCard] = []
        if notices.noHome { cards.append(NoticeCard(id: "library.notice.noHome", title: "No home", lines: [NoticeWords.noHome], controls: [])) }
        if duties.soleDevice {
            cards.append(NoticeCard(id: "library.notice.oneDevice", title: "One device", lines: [NoticeWords.oneDevice], controls: []))
        }
        for route in duties.routes where !route.registered {
            cards.append(NoticeCard(id: "library.notice.routes.\(route.home.prefix(8))", title: "Notices from \(route.label)",
                                    lines: [route.detail], controls: []))
        }
        let dead = Set(duties.deadTransitions.map(\.digest))
        for pending in notices.pending where !dead.contains(pending.digest) {
            var lines = ["Signed by " + pending.signers.map { "\($0.label) (\(String($0.id.prefix(8))))" }.joined(separator: ", ")]
            if let seen = pending.firstSeenSeq { lines.append("First seen at history entry \(seen)") }
            lines.append(NoticeWords.vetoDeadline(pending.vetoDeadlineMs))
            if !pending.adds.isEmpty { lines.append("Adds " + pending.adds.map { String($0.prefix(8)) }.joined(separator: ", ")) }
            if !pending.removes.isEmpty { lines.append("Removes " + pending.removes.map { String($0.prefix(8)) }.joined(separator: ", ")) }
            if let submission = duties.submissions.first(where: { $0.object == pending.digest }) { lines.append(submission.words) }
            lines.append(NoticeWords.waiting)
            let controls = pending.vetoable ? [GateControl(.veto(pending.digest), "Veto", "library.notice.veto.\(pending.digest.prefix(8))", .destructive)] : []
            cards.append(NoticeCard(id: "library.notice.pending.\(pending.digest.prefix(8))", title: "A change to your account is waiting",
                                    lines: lines, controls: controls))
        }
        for transition in duties.deadTransitions {
            cards.append(NoticeCard(id: "library.notice.dead.\(transition.digest.prefix(8))", title: "A change did not take hold",
                lines: [NoticeWords.dead(receipted: transition.receipted, quorum: transition.quorum)],
                controls: transition.canResign ? [GateControl(.resign(transition.digest), "Sign It Again", "library.notice.resign.\(transition.digest.prefix(8))", .prominent)] : []))
        }
        for removal in duties.removals {
            var lines = ["A key that was removed (\(removal.removed.map { String($0.prefix(8)) }.joined(separator: ", "))) had admitted others while its removal was pending."]
            if !removal.members.isEmpty { lines.append("Members: " + removal.members.map { "\($0.label) (\(String($0.id.prefix(8))))" }.joined(separator: ", ")) }
            if !removal.controllers.isEmpty { lines.append("Keys: " + removal.controllers.map { "\($0.label) (\(String($0.id.prefix(8))))" }.joined(separator: ", ")) }
            lines.append("Remove them unless you added them yourself.")
            cards.append(NoticeCard(id: "library.notice.removal.\(removal.seq)", title: "Remove what the removed key added?", lines: lines,
                controls: [GateControl(.removeFollowUp(removal.seq), "Remove Them", "library.notice.removeFollowUp.\(removal.seq)", .destructive),
                           GateControl(.keepFollowUp(removal.seq), "Keep Them", "library.notice.keepFollowUp.\(removal.seq)")]))
        }
        for activation in notices.unseenActivations {
            var lines = ["Entry \(activation.seq)", "Signed by " + activation.signers.map { String($0.prefix(8)) }.joined(separator: ", ")]
            if activation.receipted.isEmpty { lines.append("No home has receipted it.") }
            for receipt in activation.receipted.sorted(by: { $0.receivedMs < $1.receivedMs }) {
                let name = duties.homeLabels[receipt.home] ?? String(receipt.home.prefix(8))
                lines.append("\(name) receipted it " + Date(timeIntervalSince1970: Double(receipt.receivedMs) / 1000).formatted(date: .abbreviated, time: .standard) + ".")
            }
            lines.append(NoticeWords.waiting)
            cards.append(NoticeCard(id: "library.notice.activation.\(activation.seq)", title: "This change took effect, and no key on this device signed it",
                                    lines: lines, controls: [GateControl(.acknowledgeActivation(activation.seq), "I’ve Seen This", "library.notice.acknowledge.\(activation.seq)")]))
        }
        return cards
    }

    // MARK: Acting

    /// What every control does. The only place a gate control reaches the session or the host.
    @MainActor public static func perform(_ action: GateAction, session: any LibrarySessionSource, host: LibraryHostActions,
                                          model: LibraryActionModel, present: (GateAction) -> Void) async {
        switch action {
        case .create: await model.run { await session.create() }
        case .join, .useRecoveryKit, .supportReport: present(action)
        case .rejoin: _ = await model.rejoin(session: session, host: host)
        case .retry: await model.run { await session.retry() }
        case .checkAgain: await model.run { await session.refresh() }
        case .cancelPairing: await model.run { try await session.leave() }
        case .unlock: await model.run { await session.unlock() }
        case .veto(let digest): await model.run { try await session.veto(digest) }
        case .acknowledgeActivation(let seq): await model.run { await session.acknowledgeActivation(seq: seq) }
        case .resign(let digest): await model.run { try await session.resign(digest) }
        case .removeFollowUp(let seq): await model.run { try await session.removeFollowUp(seq: seq) }
        case .keepFollowUp(let seq): await model.run { try await session.keepFollowUp(seq: seq) }
        }
    }
}
