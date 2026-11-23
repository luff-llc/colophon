# Colophon 0.6: sessions

**Status:** unfrozen draft, 2026-11-22. Additive to `colophon-0.5.md`; nothing here changes a
0.5 object, verdict or path. A 0.5 host that ignores this document stays conformant with 0.5.

The words MUST, SHOULD and MAY are used as in 0.5 §0. "0.5 §N" refers to `colophon-0.5.md`.

## S0. What a session is

A **session** is real-time traffic between the members of one account about one **cell**.
Members decide everything themselves. A home is not a party to a session: it may carry
frames (§S9) but it holds no session state, applies no session rule and cannot read a
frame. Nothing in a session is history. What should last is written as ordinary records by
a member entitled to write them.

One member of a session is the **holder**. The holder numbers the ordered lane and owns the
cell's state. The role is identified by a **term**, and it moves by being **passed** by the
holder or **taken** when the holder cannot be reached. The existing 0.5 word "live" (the
replaceable state slots of 0.5 §11.8) is unrelated; this document never uses it.

Design rules that every later section follows:

1. A member is never prevented from acting locally because a peer or a home is unreachable.
2. Two members that can exchange frames by any path agree on the holder.
3. Safety never depends on a clock agreeing with another clock.
4. The same frames give the same state whatever link carried them.

## S1. Cells

A cell is named by `(account, namespace, cell)`. `cell` is 1–64 bytes of `a–z 0–9 . -`.
A cell is declared by the domain that owns the namespace (in 0.6, a fixed registry in the
core, as live rules are in 0.5 §20) together with its **policy**:

| Field | Default | Meaning |
| --- | --- | --- |
| `beatMs` | 5,000 | The holder sends some frame at least this often. |
| `holderTimeoutMs` | 15,000 | A holder not heard from for this long is **lapsed** to the listener. |
| `askTimeoutMs` | 1,500 | How long an asker waits for a `pass` before it may take. |
| `presenceTimeoutMs` | 15,000 | A member's presence is dropped after this silence. |
| `retainMs` | 60,000 | Longest time a carrier keeps a retained frame (§S9). |
| `tail` | 256 | Ordered messages the holder keeps for resume. |
| `maxPayload` | 8,192 | Largest application payload, bytes. |
| `take` | `free` | `free`: any eligible member may take. Other values are reserved; a host that meets one MUST NOT take in that cell. |

**Who may join.** A current member whose terms hold a `records` entry for the namespace
(0.5 §10.1). **Who may hold or submit.** A member whose entry has access `write`. A frame
from anyone else is dropped.

## S2. Session keys

Member private keys stay in the host (0.5 §3.4) and may be unavailable while a device is
locked. A member therefore signs once, when it can, a delegation to a key the core holds in
memory:

```json
{"protocol":"colophon/session-key/6","account":"<64 hex>","member":"<memberID>",
 "session":3,"key":"<base64 P-256 signing point>","namespace":"listening.podcasts",
 "notBefore":"2026-11-22T10:00:00Z","expires":"2026-11-23T10:00:00Z"}
```

Signed `raw` by the member key (0.5 §4.2). `session` is the member's session number
(0.5 §9.6). `expires` − `notBefore` MUST be at most 86,400 s. A verifier accepts a session
key when the envelope verifies, the member is a current member with a `records` entry for
`namespace` at the verifier's accepted authority head, `session` equals the member's current
session number, and the verifier's clock is within the window widened by 60 s. A verifier
that later accepts a history in which the member is revoked, suspended, expired, or has a
higher session number MUST drop that member's session keys and every frame signed by them
from then on.

## S3. Frames

```json
{"protocol":"colophon/session/6","account":"<64 hex>","namespace":"listening.podcasts",
 "cell":"now-playing","from":"<memberID>","key":"<keyID of the session key>",
 "to":"<memberID>","n":41,"epoch":3,"retain":true,
 "nonce":"<base64, 12 bytes>","ciphertext":"<base64>"}
```

- `to` is optional: absent means every member in the session.
- `n` is a counter per session key, starting at 1. A receiver drops a frame whose `n` is not
  greater than the highest it has accepted from that key. Gaps are allowed.
- `retain` is optional and only `true` (§S9).
- `ciphertext` is AES-256-GCM under the namespace epoch key `epoch` (0.5 §11.1), with AAD the
  canonical JSON of `{account, cell, epoch, from, key, n, namespace, protocol, retain, to}`
  (absent fields omitted). A receiver that lacks the epoch drops the frame and syncs.
- Signed `raw` by the session key over the canonical body. The encoded frame MUST be at
  most 16,384 bytes.

A receiver MUST, in order: parse with closed field sets (0.5 §2.3); check `account`,
`namespace` and `cell`; find an accepted session key for `(from, key)`, else hold the frame
for at most 5 s awaiting a `hello` and then drop it; verify the signature; check `n`; open
the ciphertext. Any failure drops the frame silently. No failure changes session state.

The plaintext is `{"kind": …, …}`. Kinds and their fields:

| Kind | Sender | Fields | Meaning |
| --- | --- | --- | --- |
| `hello` | any | `sessionKey` (the §S2 envelope), `seen` (`{term, rank, holder, seq}` or `null`), `lapsed` (bool) | Join or rejoin. Sent on every link-up. |
| `state` | holder | `claim`, `seq`, `snapshot` | Full state for one member (`to` set) or all. |
| `beat` | holder | `claim`, `seq` | Liveness when the holder has nothing else to send. |
| `msg` | holder | `claim`, `seq`, `origin`, `id`, `payload` | One ordered message. |
| `submit` | writer | `id`, `payload` | Ask the holder to order a message. |
| `refuse` | holder | `id`, `reason` | The holder declined a `submit`. |
| `presence` | any | `payload` | Latest value for this member. |
| `ask` | writer | `claim` (the claim the asker believes current) | Ask the holder for the role. |
| `pass` | holder | `claim` (current), `next` (`{term, rank:1, holder}`), `seq`, `snapshot` | Hand the role over. |
| `decline` | holder | `claim` | The holder will not pass now. |
| `take` | writer | `claim` (`{term, rank:0, holder}`), `basis` (`{term, seq}`) | Assume the role. |
| `ping` / `pong` | any | `t` (sender ms); `pong` adds `echo`, `hold` | Round-trip and clock offset (§S7). |
| `bye` | any | `claim` if the sender is holder | Leaving. A holder's `bye` releases the role. |

`payload` and `snapshot` are application bytes (base64), opaque to this document, at most
`maxPayload`. `id` is 16 random bytes, base64url. An unknown `kind` is dropped.

## S4. Claims and the holder

A **claim** is `{term, rank, holder}`: `term` a positive integer at most 2^53−1, `rank` 0
(taken) or 1 (passed), `holder` a member ID. Claims are ordered by `term`, then `rank`, then
`holder` compared as lowercase hex strings. Each member keeps the **greatest claim it has
accepted**, persisted across restarts, and treats its `holder` as the holder. The cell with
no accepted claim, or whose holder said `bye`, has **no holder**.

A member accepts a claim it meets in any frame when all of these hold:

1. The frame passed §S3 and its sender is entitled (§S1).
2. For rank 0, the frame is from `claim.holder` itself.
3. For rank 1, the member has seen the matching `pass`: a `pass` frame from the holder of
   the member's previous accepted claim whose `next` equals this claim, or a `state`, `beat`
   or `msg` from `next.holder` carrying it after such a `pass` was seen. A member that has
   not seen the `pass` treats a rank-1 claim as rank 0 for ordering until it does.
4. It is greater than the member's accepted claim.

**Yielding.** A member that is holder and accepts a greater claim of another member stops
acting as holder at once: it sends no further `state`, `beat`, `msg`, `refuse`, `pass` or
`decline` under its old claim, and reports the change to the application.

**Stale holders.** A holder that receives a frame carrying a lesser claim from another
member answers with `state` to that member.

## S5. Passing and taking

**Ask and pass.** A writer that wants the role sends `ask` to the holder. The holder's
application decides. To pass, the application first stops whatever the role controls, then
the holder sends `pass` with `next = {term: current+1, rank: 1, holder: asker}`, the final
`seq` and the final `snapshot`, to all members, and from that moment is not holder. It
resends the same `pass` when it next hears the asker speak under an older claim. The asker
becomes holder on receiving the `pass`; its state is exactly `snapshot`; its `seq` restarts
at 0 for the new term.

**Take.** A writer may send `take` with `{term: T+1, rank: 0, holder: self}` where `T` is
the term of its accepted claim (0 if none) when one of these holds:

- there is no holder;
- the holder is lapsed to it (§S6);
- it sent `ask` and has heard nothing from the holder for `askTimeoutMs` since.

It becomes holder at once, with the state it last held for the cell (application-defined
projection included, §S7), `seq` 0, and sends `state` to all.

**Renewing.** A holder that learns, from any `hello.seen`, of a term not less than its own
whose holder is not itself and is not present, raises its own claim to that term + 1,
rank 0, and sends `state`. Terms therefore never go backwards for any pair of members that
have exchanged frames.

**Declining.** A holder MAY answer `ask` with `decline`. An asker that receives `decline`
MUST NOT take on the timeout rule for that ask.

## S6. Liveness and lapsing

- The holder sends a frame to all at least every `beatMs`.
- To a listener, the holder is **lapsed** when the listener has a working link and has
  accepted nothing from the holder for `holderTimeoutMs`.
- A holder is **out of contact** when it has had no working link for `holderTimeoutMs`. An
  out-of-contact holder keeps acting locally (rule 1 of §S0) but, on its next link-up, MUST
  send `hello` with `lapsed: true` and MUST NOT send holder frames for `askTimeoutMs`. If
  within that time it accepts a claim of another member that is not lapsed to it, it yields
  (§S4). Otherwise it takes at its accepted term + 1.

This is the stated limit of the design: two members with no path between them can both act
as holder until a path exists. From the first frame exchanged, exactly one remains.

## S7. Time

No clock is shared. Where an application needs a moving value (a play position), the holder
publishes it as an anchor on its own clock, and other members translate.

`ping {t}` is answered by `pong {t: responder ms, echo: the ping's t, hold: ms the responder
held it}`, where `pong.t` is the responder's clock when it sent the `pong`. With `now` the
asker's clock on receipt: `rtt = max(0, (now − echo) − hold)` and
`offset = pong.t − now + floor(rtt / 2)`, so that `responderClock ≈ askerClock + offset`.
A member keeps the offset from the sample with the smallest `rtt` among its last 8 and
reports `ceil(rtt / 2)` as the error bound.
Clocks are the host's monotonic milliseconds; they need not be wall time.

## S8. Ordered lane and resume

- Only the holder sends `msg`. `seq` starts at 1 after each claim change and increases by 1.
  The position of a message is `(claim, seq)`.
- A member applies `msg` frames of its accepted claim in `seq` order, holding those that
  arrive early and discarding those of a lesser claim.
- A member that detects a gap, joins, or changes claim without a snapshot sends `hello`. The
  holder answers that member with the missing `msg` frames when `seen` names its current
  claim and it still holds them (`tail`), else with `state`.
- A writer's `submit` is answered by the holder with a `msg` whose `origin` is the
  submitter and whose `id` is the submit's, or with `refuse`. The holder drops a `submit`
  whose `id` it has ordered in the current term.

## S9. Carriers

A **carrier** moves frames between members. Every carrier gives the same contract: frames
may be lost, duplicated, delayed and reordered; a frame that arrives is unmodified or fails
§S3. A session uses every carrier it has and sends each frame on the best one.

**Home carrier.** A home that offers it accepts frames on its stream from a member it would
serve `/changes` to for the namespace, and forwards each to every other connected member of
the same account that is entitled to the namespace and subscribed to the cell (or only to
`to`). It MUST NOT store a frame, except that it keeps the latest `retain: true` frame per
`(cell, from)` in memory for at most the cell's `retainMs` (or 60 s when it does not know
the cell) and gives it to a member when that member subscribes. It checks only the outer
fields, the size limit and its own caps. It learns the account, namespace, cell, sender,
recipient and sizes, and nothing else. A home MAY refuse or drop any frame; members cannot
tell that from loss.

The holder SHOULD mark its `state` and `beat` frames `retain`, so that a member opening the
application learns of the session from the carrier without waiting for the holder.

**Direct carriers** (device to device) are defined by their own documents and MUST carry
frames unchanged.

## S10. What an application gets

The core exposes, per cell: join and leave; the holder and whether it is this member; the
ordered messages and snapshots; presence values; `ask`, `pass` (with a final snapshot),
`decline`, `take`, `release`; `publish` (holder) and `submit` (writer); the offset and error
to the holder; and events for each change. The core never calls the host for a signature
after the session key exists.

## S11. Guarantees

For members that follow this document, under a network that may lose, duplicate, delay and
reorder frames and partition members for any time:

- **G1.** A member's accepted claim never decreases.
- **G2.** A member never sends a holder frame under a claim less than its accepted claim.
- **G3.** After a `pass` is sent, the passing member sends no holder frame under the old
  claim, and the new holder's initial state equals the pass snapshot.
- **G4.** If frames between two members are eventually delivered both ways, they
  eventually hold the same accepted claim and, for that claim, the same ordered state.
- **G5.** A writer with no holder reachable becomes holder within `askTimeoutMs` of asking,
  or `holderTimeoutMs` of the holder's last frame, whichever its trigger was.
- **G6.** Two members both acting as holder have, since each one's claim began, exchanged no
  frame; once a frame from the greater claim's holder reaches the other, the other stops.
- **G7.** No frame is ever a record, and a carrier never holds a readable payload.
- **G8.** A member dropped by an accepted history is ignored by every member that has
  accepted that history.
- **G9.** The state reached depends only on the set and per-receiver order of frames
  delivered, not on which carrier delivered them.

Conformance is by the vectors in `conformance/0.6-sessions/` and the properties above
checked by the reference explorer and simulator.

## S12. Cell: `listening.podcasts/now-playing`

Policy: defaults. The snapshot, and the payload of each `msg`, is the **anchor**:

```json
{"episode":"<id>","show":"<id>","positionMs":1234567,"rate":1.25,"playing":true,"at":98765432}
```

`at` is the holder's clock (§S7) when `positionMs` was true. A member's projected position
is `positionMs + rate × (now + offset − at)` while `playing` (`offset` as in §S7, zero for
the holder itself), else `positionMs`. The holder
publishes an anchor on play, pause, seek, rate change and episode change, and at least every
60 s while playing. Presence payload: `{"label":"Mike's iPhone","playing":false}`.

A device that plays audio for this account SHOULD hold this cell. A device that yields MUST
pause. A device that passes MUST pause before sending `pass` and put its stopped position in
the snapshot with `playing: false`; the new holder starts from that position exactly. A
device that takes starts from its projected position. Only the holder writes passive
`episode.position` progress; deliberate seeks and every other record are unaffected.
