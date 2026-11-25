import Foundation

/// The measured relation between this device's clock and the clock an anchor was stamped on (sessions §S7):
/// `publisherClock ≈ localClock + offsetMs`, true within `errorMs` when it was measured, `sampleAgeMs` ago.
public struct NowPlayingClockOffset: Sendable, Hashable {
    public var offsetMs: Int64
    /// `ceil(rtt / 2)` of the sample the offset came from (§S7's error bound).
    public var errorMs: Int64
    /// How long ago, on this device's clock, that sample was taken.
    public var sampleAgeMs: Int64
    public init(offsetMs: Int64, errorMs: Int64, sampleAgeMs: Int64) {
        self.offsetMs = offsetMs; self.errorMs = errorMs; self.sampleAgeMs = sampleAgeMs
    }
    /// An anchor this device stamped itself: no offset and no error.
    public static let local = NowPlayingClockOffset(offsetMs: 0, errorMs: 0, sampleAgeMs: 0)
}

/// Where an anchor puts playback now, on this device's clock, and what that rests on.
public struct NowPlayingProjection: Sendable, Hashable {
    /// The position to start from now.
    public let positionMs: Int64
    /// The anchor's age on the publisher's clock (`now + offset − at`), clamped to ±(2^53 − 1). It may be negative
    /// when the offset's error exceeds the anchor's true age.
    public let ageMs: Int64
    /// The time projected forward: 0 for a paused anchor, else `ageMs` clamped to 0 … `maximumProjectionMs`.
    public let elapsedMs: Int64
    /// The anchor was playing and older than `maximumProjectionMs`: the projection stopped there.
    public let capped: Bool
    /// How far `positionMs` can be from the publisher's own projection at this instant, from the offset's error and
    /// the clocks' drift since it was measured (0 for a paused anchor). Not meaningful when `capped`.
    public let errorBoundMs: Int64
}

extension NowPlayingAnchor {
    /// The default `maximumProjectionMs` for a cell policy's `holderTimeoutMs`: the 60 s a playing holder may go between
    /// anchors (§S12) plus the time it takes to lapse. A playing anchor older than that cannot be the anchor of a holder
    /// that is still playing and reachable.
    public static func defaultMaximumProjectionMs(holderTimeoutMs: Int64 = 15_000) -> Int64 { 60_000 + max(0, holderTimeoutMs) }

    /// §S12's projected position, computed exactly in integers:
    ///
    /// - `ageMs = now + offset − at`, exact, then clamped to ±(2^53 − 1); `offset` is first clamped to ±(2^53 − 1);
    /// - paused: `positionMs`, with `elapsedMs` 0 and `errorBoundMs` 0;
    /// - playing: `elapsedMs = clamp(ageMs, 0, maximumProjectionMs)`, `capped = ageMs > maximumProjectionMs`, and
    ///   `positionMs + floor(ratePermille × elapsedMs / 1000)`, saturating at 2^53 − 1;
    /// - `errorBoundMs = ceil(ratePermille × (errorMs + ceil(sampleAgeMs / 1000)) / 1000)`, saturating at 2^53 − 1:
    ///   §S7's `ceil(rtt / 2)` plus 1 ms per second since the sample for two clocks each within 500 ppm (§S0).
    ///
    /// Negative `nowMs`, `errorMs`, `sampleAgeMs` or `maximumProjectionMs` count as 0. Clamping the elapsed time at 0
    /// departs from the formula only where the formula would put playback behind the anchor, which it never is.
    public func projected(nowMs: Int64, clock: NowPlayingClockOffset = .local, maximumProjectionMs: Int64) -> NowPlayingProjection {
        let max = Self.maximumInteger
        func clamp(_ v: Int64, _ lo: Int64, _ hi: Int64) -> Int64 { Swift.min(Swift.max(v, lo), hi) }
        let now = clamp(nowMs, 0, max), offset = clamp(clock.offsetMs, -max, max)
        // |now − at + offset| < 3 × 2^53: exact in 64 bits.
        let age = clamp(now - at + offset, -max, max)
        guard playing else { return NowPlayingProjection(positionMs: positionMs, ageMs: age, elapsedMs: 0, capped: false, errorBoundMs: 0) }
        let limit = clamp(maximumProjectionMs, 0, max)
        let elapsed = clamp(age, 0, limit)
        let advance = Self.mulDiv(UInt64(ratePermille), UInt64(elapsed), roundUp: false)
        let position = advance >= UInt64(max - positionMs) ? max : positionMs + Int64(advance)
        let drift = Self.ceilDiv(clamp(clock.sampleAgeMs, 0, max), 1_000)
        let error = clamp(clock.errorMs, 0, max) + drift
        let bound = Self.mulDiv(UInt64(ratePermille), UInt64(error), roundUp: true)
        return NowPlayingProjection(positionMs: position, ageMs: age, elapsedMs: elapsed, capped: age > limit,
                                    errorBoundMs: Int64(Swift.min(bound, UInt64(max))))
    }

    /// The same trajectory re-stamped on this device's clock at `nowMs`: the projected position, the same rate and
    /// playing flag, `at = nowMs`.
    public func restamped(nowMs: Int64, clock: NowPlayingClockOffset = .local, maximumProjectionMs: Int64) -> NowPlayingAnchor {
        let p = projected(nowMs: nowMs, clock: clock, maximumProjectionMs: maximumProjectionMs)
        return (try? NowPlayingAnchor(episode: episode, show: show, positionMs: p.positionMs, ratePermille: ratePermille, playing: playing,
                                      at: Swift.min(Swift.max(nowMs, 0), Self.maximumInteger))) ?? self
    }

    /// This anchor stopped at `nowMs`: its projected position, `playing: false`, `at = nowMs` (what a passing holder
    /// sends, §S12).
    public func paused(nowMs: Int64, maximumProjectionMs: Int64) -> NowPlayingAnchor {
        let p = projected(nowMs: nowMs, maximumProjectionMs: maximumProjectionMs)
        return (try? NowPlayingAnchor(episode: episode, show: show, positionMs: p.positionMs, ratePermille: ratePermille, playing: false,
                                      at: Swift.min(Swift.max(nowMs, 0), Self.maximumInteger))) ?? self
    }

    /// `floor` or `ceil` of `a × b / 1000` in 128 bits, saturating at `UInt64.max`.
    static func mulDiv(_ a: UInt64, _ b: UInt64, roundUp: Bool) -> UInt64 {
        let (high, low) = a.multipliedFullWidth(by: b)
        guard high < 1_000 else { return .max }
        let (q, r) = UInt64(1_000).dividingFullWidth((high, low))
        return roundUp && r > 0 ? (q == .max ? .max : q + 1) : q
    }
    static func ceilDiv(_ a: Int64, _ b: Int64) -> Int64 { a / b + (a % b > 0 ? 1 : 0) }
}

/// A member's presence in the `now-playing` cell (§S12): `{"label":…,"playing":…}`, canonical, strict like the anchor.
/// `label` follows the same text rule as an anchor's IDs.
public struct NowPlayingPresence: Sendable, Hashable {
    public let label: String
    public let playing: Bool
    public init(label: String, playing: Bool) throws(NowPlayingCodingError) {
        guard NowPlayingAnchor.validText(label) else { throw .badText }
        self.label = label; self.playing = playing
    }
    public var encoded: Data { Data("{\"label\":\(NowPlayingJSON.quoted(label)),\"playing\":\(playing)}".utf8) }
    public init(decoding data: Data) throws(NowPlayingCodingError) {
        let object = try NowPlayingAnchor.object(data, fields: ["label", "playing"])
        guard case .string(let label)? = object["label"], case .bool(let playing)? = object["playing"] else { throw .wrongType }
        try self.init(label: label, playing: playing)
        guard encoded == data else { throw .notCanonical }
    }
}
