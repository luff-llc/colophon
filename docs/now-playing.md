# The `now-playing` cell for players (Swift)

**Status:** Colophon 0.6, built on the Swift hosts of [hosts-06.md](hosts-06.md) §6. The cell is
`listening.podcasts/now-playing`, defined in [sessions §S12](../spec/colophon-0.6-sessions.md#s12-cell-listeningpodcastsnow-playing).

A podcast player calls this layer to say "this device is playing episode E at position P", and gets, on
another device, "continue from exactly there" while the first device is told to pause. It lives in
`ColophonListeningKit` as `NowPlayingSession`, a thin, main-actor layer over `CellSession`. The core still
decides everything a session decides (who holds the cell, when a take is allowed, when a restarted holder
retakes); this layer adds only what §S12 leaves to the application: the anchor and its translation, when to
publish, what the holder does with an ask, and one clear pause event each time the device stops being the
player.

## 1. Setting it up

```swift
import ColophonHosts
import ColophonListeningKit

let stream = try await HomeStreamHost(account: try ColophonHostAccount(session: session), home: home.id, transport: transport)
stream.start()
let player = await NowPlayingSession.open(
    session: session, stream: stream,
    claimsDatabase: containerURL.appendingPathComponent("colophon-claims.sqlite"),
    options: NowPlayingOptions(label: "Kitchen iPad", restoredAnchor: savedAnchor))
player.onEvent = { event in /* §5 */ }
```

- **The claim store is durable.** `open` takes the path of a SQLite database and keeps the cell's claim there in a
  `SQLiteClaimStore` named `listening.podcasts/now-playing` ([hosts-06.md](hosts-06.md) §6a): one file may hold
  several cells' claims and nothing else, and on iOS it gets the protection class a device playing with its screen
  locked needs. There is no in-memory option in the public API; a claim that does not survive a restart would let
  a restarted device act as holder of a claim it no longer knows.
- **`open` never throws.** If the store cannot be opened, the delegation cannot be signed or the join is refused,
  `state.availability` says why and local playback goes on; `retry()` tries again.
- **Events set late are not lost.** Events that happen before `onEvent` is set (a restarted holder that yields at
  once, for example) are kept and delivered, in order, when it is set.
- **Keep the last anchor.** §S12 says a device SHOULD keep its last anchor. Save `state.localAnchor` (for example
  its `encoded` bytes) when it changes and pass it back as `restoredAnchor`, as it is now: paused unless audio is
  in fact playing. A device that restarts holding the cell retakes it with that anchor.

## 2. The anchor and presence

The anchor is the cell's snapshot and the payload of each ordered message. Its bytes are the canonical JSON
([0.5 §2.1](../spec/colophon-0.5.md#21-canonical-json)) of exactly six fields:

```json
{"at":98765432,"episode":"ep-1","playing":true,"positionMs":1234567,"ratePermille":1250,"show":"show-1"}
```

| Field | Value |
| --- | --- |
| `at` | The publisher's monotonic clock (§S7), in ms, when `positionMs` was true. |
| `episode`, `show` | Listening IDs: 1–1,024 UTF-8 bytes, not only white space, no control character. |
| `playing` | Whether audio was playing at `at`. |
| `positionMs` | The position, in ms, at `at`. |
| `ratePermille` | The rate in thousandths: 1,000 is normal speed, 1,250 is 1.25×, 0 does not move. |

All fields are required; integers are integer tokens (no fraction, no exponent) from 0 to 2^53 − 1. White space
is the Unicode `White_Space` set and a control character is `Cc` (U+0000–U+001F, U+007F–U+009F), spelled out in
the code so every language applies the same sets. An anchor is at most 8,192 bytes (`maxPayload`).

Presence is `{"label":…,"playing":…}`, canonical, with `label` under the same text rule. Each device sends it on
join, when its playing state changes, when it first hears a member, and every third of `presenceTimeoutMs`, so it
does not expire.

**Reading is strict.** `NowPlayingAnchor(decoding:)` and `NowPlayingPresence(decoding:)` accept only the canonical
bytes. Anything else is one `NowPlayingCodingError`, the first of these checks that fails: `tooLarge` (refused
before parsing), `syntax` (not one JSON value in valid UTF-8, a lone surrogate escape, nesting beyond 64, anything
after the value), `duplicateField` (at any depth), `notObject`, `unknownField`, `missingField`, `wrongType`,
`outOfRange`, `badText`, `notCanonical`. Within a check, fields go in canonical order.

## 3. Translation

The holder publishes on its own clock; every other device translates. `anchor.projected(nowMs:clock:maximumProjectionMs:)`
computes §S12's projection in integers, so that every language gets the same millisecond:

- `ageMs = now + offset − at`, exact, clamped to ±(2^53 − 1) (the offset is first clamped to the same range);
- a paused anchor gives `positionMs`, with `elapsedMs` 0 and `errorBoundMs` 0;
- a playing anchor gives `positionMs + floor(ratePermille × elapsedMs / 1000)`, saturating at 2^53 − 1, where
  `elapsedMs = clamp(ageMs, 0, maximumProjectionMs)` and `capped = ageMs > maximumProjectionMs`.

The rate is the integer `ratePermille`; the product is formed exactly (it can exceed 2^53, so JavaScript needs
`BigInt` and Kotlin `Math.multiplyHigh` or `BigInteger`) and rounded down. Two departures from the bare formula are
deliberate: an elapsed time below zero (the offset's error exceeding the anchor's true age, or a clock reset by a
reboot) counts as zero, since playback is never behind its anchor; and a playing anchor is projected at most
`maximumProjectionMs`, by default the 60 s a playing holder may go between anchors plus `holderTimeoutMs`
(75,000 ms with the default policy). A playing anchor older than that cannot belong to a holder that is still
playing and reachable; `capped` tells the app, which may prefer the anchor's own position.

**The error bound.** §S7 bounds the offset by `ceil(rtt / 2)` of the sample it came from. The kit reports
`errorBoundMs = ceil(ratePermille × (offsetError + ceil(2 × sampleAge / 1999)) / 1000)`: that bound, plus the
drift since the sample of two clocks each within 500 ppm of real time (§S0), measured on one of them (at most
2/1999 of the elapsed time, about 1,000.5 ppm), scaled by the rate. When the projection is capped the bound covers
the offset only. It is how far
the result can be from the publisher's own projection at the same instant. The inputs are exposed: a
`NowPlayingStart` carries the anchor as received, its publisher and the whole `NowPlayingProjection` (`ageMs`,
`elapsedMs`, `capped`, `errorBoundMs`). When no offset to the publisher was ever measured, `projection` is nil and
`positionMs` is the anchor's own: the kit never guesses a clock. It measures the offset (`ping`) when another
member starts holding, when it first hears that holder's anchor, and every `pingMs` (30 s) while it follows.

A pass needs none of this: the passed anchor is paused, so the new holder starts from its position exactly.

### 3.1 The vector file

`conformance/0.6-sessions/now-playing-anchor.json` holds §2 and §3 as cases for every kit to replay. It is written
by `scripts/generate-now-playing-vectors.py`, an implementation independent of the Swift kit, in Python with exact
integers (`--check` verifies the file is current).

- `encode`: an anchor's fields and its canonical text; `presence`: the same for `{"label","playing"}`.
- `decode`: an input (`text`, or `base64` for bytes that are not UTF-8), its `kind` (`anchor` or `presence`) and its
  verdict: `valid` with the value, or the `error`, the first failing check in `rules.errorOrder`.
- `translate`: an anchor, `nowMs`, `offsetMs`, `offsetErrorMs`, `sampleAgeMs` and `maximumProjectionMs`, and the exact
  `ageMs`, `elapsedMs`, `capped`, `positionMs` and `errorBoundMs`. Every number in the file is within ±(2^53 − 1),
  but some intermediate products are not: compute them exactly.

## 4. The API

| Call | What it does |
| --- | --- |
| `NowPlayingSession.open(session:stream:claimsDatabase:options:)` | Joins the cell (also `open(account:…)`). |
| `state` (`NowPlayingState`, observable) | `availability`; `holder` (member ID, its presence label, whether it is this device); `isHolder`; `gated`; `holderLapsed`; `lastAnchor` (the holder's); `localAnchor` (this device's); `requesting`; `asks` (prompt); `writesPassiveProgress`. |
| `update(episode:show:positionMs:ratePermille:playing:)` | Reports this device's playback on play, pause, seek, rate change and episode change, and after a stall. Stamped with this device's clock. The holder publishes it at once, and re-publishes while playing every `republishMs` (30 s; §S12 requires at most 60 s). Any other device only keeps it. Never blocked. |
| `requestPlayback() async -> NowPlayingRequestOutcome` | The user pressed Play here. `play(start)`, `playLocally(reason, start)`, `declined(by:)` or `cancelled`. Cancelling the calling task answers `cancelled` for that caller; after `requestTimeoutMs` it answers `playLocally(.noAnswer, …)`. |
| `cancelRequest()` | Stops waiting for the holder: every waiting caller gets `cancelled` (§4.1). |
| `pass(to:)`, `decline(_:)` | The `prompt` policy's answers. |
| `onEvent` | `pause(reason)`, `askReceived(member)`, `passFailed(to:reason:)`, `otherState(anchor, from:)`, `availabilityChanged`. |
| `handoffPolicy` | `automatic` (default), `prompt` or `never`; it may be changed at any time. |
| `leave()`, `close()`, `retry()` | Release the role and leave; stop as a process that ends would; open again after a failure. Both `leave()` and `close()` first, synchronously and once, tell a holder to pause (`pause(.ended)`), abandon a pass under way, clear the role and answer every waiting request (`playLocally(.closed, …)`). |

### 4.1 What `requestPlayback()` does

- **Handoff unavailable** (the stream is not live, the cell failed or could not be joined, the member is not
  entitled or may only read): `playLocally` at once, with the best start this device knows. The cell is not
  touched.
- **This device holds the role** (gated after a restart included: it acts locally, §S0 rule 1): `play` from its
  own anchor.
- **Nobody holds the cell:** `take`, with the last anchor known re-stamped on this device's clock.
- **Another device holds it:** `ask`, then `take` with the re-stamped anchor, which only gives the pending want
  its state: the core takes only when §S5 allows (the holder had lapsed to this device, or it asked and heard no
  holder frame for `askTimeoutMs`). A holder that is live and answering is never displaced: between two live
  devices handoff is ask and pass. A pass that arrives wins; a decline answers `declined`.

**Bounded.** A request never waits forever. Each caller can cancel its own task (it gets `cancelled`; other callers
keep waiting). After `requestTimeoutMs` every waiting caller gets `playLocally(.noAnswer, …)`. The default is the
cell policy's `holderTimeoutMs` + 2 × `askTimeoutMs` (18 s with the default policy): by then the core has done
everything it does on its own (taken after the ask timed out with no holder frame, or after the holder lapsed, which
takes at most `holderTimeoutMs`, with a resent ask in between), so what remains is a holder that is live and not
answering, typically a person who has not decided under `prompt`. A cell that fails while a request waits answers
`playLocally(.cellFailed(…), …)`.

When this device becomes holder this way, the kit publishes `playing: true` at the start position before it returns
`play(start)`; the app starts its engine there and calls `update` if the engine ends up elsewhere. If the stream
goes down while waiting, the request answers `playLocally(.streamDown, …)` at once.

An ask cannot be withdrawn: after `cancelRequest()` (or `playLocally` while waiting), a pass that still arrives
makes this device holder without a request. Only the app starts playback, so the kit publishes the state it
received, paused at its position (the passed stopped anchor, exactly), whatever this device was playing locally
meanwhile; the app may then call `requestPlayback()` to play it. The one exception is a restarted holder that
retakes with its own kept anchor, which it publishes as it is.

### 4.2 The holder's side

When another device asks:

- `automatic`: at once, on the main actor, the kit takes the stopped position (its last `update` projected to now),
  sets its local anchor to it with `playing: false`, delivers `pause(.passed(to:))`, and only then admits `publish`
  of that final anchor and `pass` with it as the snapshot. The commands leave in that order, so the app has paused
  before any frame that hands over the role leaves the device (§S12: a device that passes MUST pause before sending
  `pass`). The stopped position is exact only as far as the last `update` is: report stalls and seeks.
- `prompt`: `askReceived(member)` once per waiting asker; `pass(to:)` runs the same sequence, `decline(_:)` declines.
  An asker that hears no holder frame for `askTimeoutMs` takes (§S5), and a holder sends one only every `beatMs`,
  which is longer; so while an ask waits for the person, the holder re-publishes its anchor (re-stamped, the same
  trajectory) every half `askTimeoutMs`, and the asker keeps asking. The asker's request deadline (§4.1) bounds the
  wait.
- `never`: every ask is declined.

If the core refuses a pass that began (`passFailed`), this device still holds the role, paused at the position it
was going to pass.

## 5. What the audio engine does on each event

| Event or outcome | The app |
| --- | --- |
| `requestPlayback()` → `play(start)` | Start (or resume) at `start.positionMs` (nil: play what the user chose). Call `update` when the engine is playing. |
| `requestPlayback()` → `playLocally(reason, start)` | Play here anyway, from `start` if given; show that handoff is unavailable (`reason`). |
| `requestPlayback()` → `declined(by:)` | Do not play; say that `by.label` kept playing. |
| `pause(.passed(to:))` | Pause now, synchronously, inside the handler. Another device continues from the exact stopped position. |
| `pause(.displaced(by:))` | Pause now. Another device took over (after this one lapsed to it, or a greater claim won). |
| `pause(.superseded)`, `pause(.failed)` | Pause now. Another instance of the app holds the cell's store, or the cell failed; `state.availability` says which, and `retry()` reopens a failed cell. Local playback is not blocked: the user may press Play again (`playLocally`). |
| `askReceived(member)` | (`prompt`) Ask the user; then `pass(to:)` or `decline(_:)`. |
| `otherState(anchor, from:)` | Optional: offer "resume where `from.label` stopped" (a displaced holder's last anchor, or a pass that came after this device took; §S5, G11). |
| `availabilityChanged` | Update the UI. Never stop audio because of it. |

`pause` is delivered exactly once each time this device stops holding the role, whatever the cause, and the kit
never reports this device as the holder after it. While the stream is down a holder keeps the role and keeps
playing locally (§S0 rule 1); it is told to pause only if, once the stream returns, another device holds a greater
claim. Write passive `episode.position` progress only while `state.writesPassiveProgress` (the holder, or a device
that cannot reach the others).

## 6. Background and life cycle

What [hosts-06.md](hosts-06.md) §6b established applies unchanged:

- A device that is playing has the `audio` background mode and an active audio session, so it is not suspended:
  its socket, ticks and beats go on, and it receives an ask and passes from the background. Pass or release the
  role before stopping the audio session.
- When playback stops the app may be suspended. Its role lapses to the others after `holderTimeoutMs`; on resume
  the host reconnects through its own steps, and a holder that was out of contact is gated, then retakes or yields
  (and is told to pause).
- Call `HomeStreamHost.retryNow()` on entering the foreground and on a network change, so the stream reconnects at
  once.
- Anchors use `CLOCK_MONOTONIC`, which keeps counting while the device sleeps; after a reboot a stored anchor's `at`
  can be ahead of the clock, which the translation treats as age zero.

## 7. Where the rules come from

Sessions §S12 (revision 18) is normative for everything in §2 and §3 and for the publishing rules this kit follows:
the closed, required fields and their ranges, the text rule, canonical bytes (and refusing any others, in the order
of §2), no negative rate, the clamps, the cap and saturation, the drift bound, no projection without a measured
offset, whose clock an anchor is on after a pass or a take, re-stamping, the final stopped publish before a pass,
what a holder that did not ask does, and the presence and republish cadence. Revision 17's example was not
canonical; revision 18 corrects it. What remains this kit's own choice: the default `limit` may be changed
(`maximumProjectionMs`), the request deadline (§4.1), and `republishMs` (30 s) and `pingMs` (30 s) within the
spec's bounds. The housekeeping timer is armed for the earliest of the presence, republish and ping deadlines, so a
large `presenceTimeoutMs` cannot delay a republish.

## 8. What was run

`scripts/test-swift-hosts.sh` runs these with the hosts' suites (macOS, a macOS slice of this tree's Rust core and
home module):

- `NowPlayingAnchorTests`: every case of `conformance/0.6-sessions/now-playing-anchor.json` (8 encodings,
  2 presence encodings, 65 decode verdicts of which 9 are valid, 36 translations, including drift extremes, negative and signed 64-bit
  extreme inputs, and a capped projection with its bound) and the re-stamp and pause
  helpers. The file is written by `scripts/generate-now-playing-vectors.py`, an independent implementation of
  §2 and §3 in Python with exact integers (`--check` verifies it is current).
- `NowPlayingSessionTests`, over real endpoints of two members, an in-memory carrier and a manual clock (the
  fast policy): ask then automatic pass, the stopped position exact and the pause delivered before the pass left;
  prompt, decline (no take after the ask times out) and a later pass; never; a lapsed holder taken over from its
  last anchor, projected exactly, and an anchor beyond the limit capped; a restarted holder gated then retaking
  with its kept anchor; a restarted holder that was taken over yielding and told to pause once; both devices
  pressing Play at once (one holder, the other paused once); a seek and rate change racing the ask at nine
  interleavings (B always starts from exactly the anchor A stopped at, A publishes nothing after its final anchor,
  one pause); a pass the core refuses (`passFailed`, still holding, paused); the pause once per loss across three
  handoffs; closing and leaving while holding, while an ask waits and while requesting (one `pause(.ended)`, every
  caller answered); a cancelled caller task, before and while waiting; the request deadline, default and
  configured; a cell failing during a request; a pass after a cancelled request (paused at the passed position
  although the app was playing something else); a member without the namespace (`notEntitled`); the stream down
  (handoff unavailable, local playback going on, nobody told to pause); a cell whose store fails (one pause,
  `playLocally`); a second instance superseding the first; a cell that cannot be joined.
- `NowPlayingEndToEndTests`: two members over a real home (`relay/server.js` on Bun with the home module) and
  real `URLSessionWebSocketTask`s, SQLite claim stores and the system clock. A plays at 1.25×; B follows A's
  anchor and measures its offset; B's user presses Play; A is told to pause, B starts from A's exact stopped
  position, and A then follows B. Measured on one Mac: over five runs, B's request to A's pause event 1.2–4.3 ms, to B's start
  6.8–16.3 ms (B's start waits for its SQLite claim write); position error against A's stopped position 0 ms every
  time, so B starts 7–15 ms behind where A would have been had it kept playing at 1.25×; while following, B's
  projection of A's position was 0–1 ms from A's own, within the 2 ms bound it reported.
- `swift/HostsClient` compiles a player's setup from the public API only, and `scripts/check-swift-hosts-api.py`
  checks that no symbol `ColophonListeningKit` declares is SPI or names or relates to the engine, an endpoint, the
  stream client, an account view, the host access or the cell host, and that its now-playing surface is exactly the
  pinned one (`swift/Tests/ColophonHostsTests/ColophonListeningKit-NowPlaying.public-api`).

## 9. Not verified

iOS, iPadOS or visionOS (only macOS was run), a device in the background or with its screen locked, real audio
(the tests report positions; no engine played anything), a real network between devices (both devices ran in one
process on loopback, sharing one clock), clocks that actually drift, three or more devices, and the Kotlin and
JavaScript kits, which have the vector file but no implementation yet.
