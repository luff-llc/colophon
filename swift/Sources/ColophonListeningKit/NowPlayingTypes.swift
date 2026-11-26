import Foundation

/// What the playing device does when another device asks to take over playback (docs/now-playing.md §4).
public enum NowPlayingHandoffPolicy: String, Sendable, Hashable, CaseIterable {
    /// Pass at once: pause here and hand over the exact position. The default.
    case automatic
    /// Report the ask (`NowPlayingEvent.askReceived`); the app calls `pass(to:)` or `decline(_:)`.
    case prompt
    /// Decline every ask.
    case never
}

/// How a `NowPlayingSession` is set up. The defaults suit a podcast player.
public struct NowPlayingOptions: Sendable {
    /// This device's name for other devices ("Kitchen iPad"), sent as its presence.
    public var label: String
    public var handoffPolicy: NowPlayingHandoffPolicy
    /// The anchor the app kept from its last run (§S12: a device SHOULD keep its last anchor), as it is now: paused
    /// unless audio is in fact playing. A restarted holder retakes the cell with it.
    public var restoredAnchor: NowPlayingAnchor?
    /// How far a playing anchor is projected at most (default `NowPlayingAnchor.defaultMaximumProjectionMs`).
    public var maximumProjectionMs: Int64?
    /// How often the holder re-publishes its anchor while playing. §S12 requires at least every 60 s: values are kept
    /// within 1 … 59 s.
    public var republishMs: Int64 = 30_000
    /// How long `requestPlayback()` waits for the holder before it answers `playLocally(.noAnswer, …)`. The default
    /// (nil) is the cell policy's `holderTimeoutMs` + 2 × `askTimeoutMs` (18 s with the default policy): every outcome
    /// the core decides on its own (a pass, a decline, a take after the ask timed out or after the holder lapsed) has
    /// happened by then, so what is left is a holder that is live but not answering (a person who has not decided
    /// under `prompt`).
    public var requestTimeoutMs: Int64?
    /// How often this device measures its clock offset to a holder it follows.
    public var pingMs: Int64 = 30_000
    /// The cell policy as JSON (internal: every member of the cell uses the same one; the default policy otherwise).
    var cellPolicy: String?
    public init(label: String, handoffPolicy: NowPlayingHandoffPolicy = .automatic, restoredAnchor: NowPlayingAnchor? = nil) {
        self.label = label; self.handoffPolicy = handoffPolicy; self.restoredAnchor = restoredAnchor
    }
}

/// A member of the cell as the app may show it.
public struct NowPlayingMember: Sendable, Hashable {
    /// The member ID.
    public let id: String
    /// Its presence label, when it sent one.
    public let label: String?
    /// The member is this device.
    public let isThisDevice: Bool
}

/// Why handoff is not available. Local playback is never blocked by any of these.
public enum NowPlayingUnavailable: Sendable, Hashable {
    /// The cell has not been joined yet.
    case starting
    /// The home stream is not live: other devices cannot be reached now.
    case streamDown
    /// This member has no `records` entry for `listening.podcasts`.
    case notEntitled
    /// This member may read but not write `listening.podcasts`: it can follow but not hold.
    case readOnly
    /// The cell could not be joined (the store could not be opened, the delegation could not be signed, …).
    case couldNotJoin(String)
    /// The cell stopped acting: its store kept failing (`store`), its endpoint could not be rebuilt (`rebuild`), or
    /// another instance of this app holds its store (`superseded`). `retry()` opens it again.
    case cellFailed(String)
    /// The app closed the session.
    case closed
    /// The holder did not answer within `requestTimeoutMs`.
    case noAnswer
}

public enum NowPlayingAvailability: Sendable, Hashable {
    case available
    case unavailable(NowPlayingUnavailable)
}

/// What the app can show. Replaced, never changed in place.
public struct NowPlayingState: Sendable, Hashable {
    public var availability: NowPlayingAvailability = .unavailable(.starting)
    /// Who holds the cell (nil: nobody).
    public var holder: NowPlayingMember?
    /// This device holds the role: it is the account's player. It is false from the moment this device starts to pass.
    public var isHolder = false
    /// This device holds the role locally but may not act as holder yet (it restarted, or came back after being out of
    /// contact); within `askTimeoutMs` it retakes or yields (§S6).
    public var gated = false
    /// The holder has not been heard from for `holderTimeoutMs` (cleared by its next anchor or a claim change).
    public var holderLapsed = false
    /// The cell's latest anchor: the holder's, on the clock of the member that published it.
    public var lastAnchor: NowPlayingAnchor?
    /// This device's own playback as the app last reported it, on this device's clock.
    public var localAnchor: NowPlayingAnchor?
    /// A `requestPlayback()` is waiting for the holder.
    public var requesting = false
    /// Asks waiting for the app's answer (`prompt` policy).
    public var asks: [NowPlayingMember] = []
    /// Whether this device should write passive `episode.position` progress (§S12: only the holder does; a device
    /// that cannot reach the others keeps writing its own).
    public var writesPassiveProgress: Bool { isHolder || availability != .available }
}

/// Where to start playback, and what that position rests on.
public struct NowPlayingStart: Sendable, Hashable {
    public enum Source: Sendable, Hashable {
        /// The holder passed the role: its stopped position, exact (§S12).
        case passed(from: String)
        /// This device took the role (nobody held it, or the holder had lapsed), from the last anchor it knew.
        case taken(from: String?)
        /// This device already held the role.
        case held
        /// Handoff was unavailable: this device's best knowledge.
        case local
    }
    public let source: Source
    /// The anchor as received, on its publisher's clock.
    public let anchor: NowPlayingAnchor
    /// The member whose clock `anchor.at` is on.
    public let publisher: String?
    /// The translation to this device's clock; nil when the offset to the publisher was never measured (then
    /// `positionMs` is the anchor's own position, not projected).
    public let projection: NowPlayingProjection?
    /// The position to start from now.
    public var positionMs: Int64 { projection?.positionMs ?? anchor.positionMs }
}

/// What `requestPlayback()` decided.
public enum NowPlayingRequestOutcome: Sendable, Hashable {
    /// This device holds the role: start the audio engine at `start` (nil: no anchor is known; play what the user
    /// chose and report it with `update`). The kit has already published `playing: true` at that position.
    case play(NowPlayingStart?)
    /// Handoff is unavailable: play here anyway, from `start` when one is known.
    case playLocally(NowPlayingUnavailable, NowPlayingStart?)
    /// The holder declined.
    case declined(by: NowPlayingMember)
    /// `cancelRequest()` was called, or the calling task was cancelled.
    case cancelled
}

/// Why this device must pause.
public enum NowPlayingPauseReason: Sendable, Hashable {
    /// It passed the role to another device, which starts from the exact position this device stopped at.
    case passed(to: NowPlayingMember)
    /// Another device holds the role now (it took after this device lapsed to it, or a greater claim won).
    case displaced(by: NowPlayingMember?)
    /// Another instance of this app holds the cell's store.
    case superseded
    /// The cell failed (its store kept failing, or its endpoint could not be rebuilt).
    case failed(String)
    /// The app closed or left the session while this device held the role.
    case ended
}

/// What the app must act on. Delivered on the main actor, in order, through `NowPlayingSession.onEvent`.
public enum NowPlayingEvent: Sendable, Hashable {
    /// Pause the audio engine now. Sent exactly once each time this device stops holding the role, before any frame
    /// that hands the role over leaves the device.
    case pause(NowPlayingPauseReason)
    /// (`prompt`) Another device asks to take over: call `pass(to:)` or `decline(_:)`.
    case askReceived(NowPlayingMember)
    /// A pass this device began was refused by the core (`reason` as the core spells it); it still holds the role,
    /// paused at the position it was going to pass.
    case passFailed(to: NowPlayingMember, reason: String)
    /// Another device's state this device did not start from (a displaced holder's last anchor, or a pass that came
    /// after this device took, §S5 / G11). The app may offer it ("Resume where Kitchen iPad stopped?").
    case otherState(NowPlayingAnchor?, from: NowPlayingMember)
    /// Handoff became available or unavailable.
    case availabilityChanged(NowPlayingAvailability)
}
