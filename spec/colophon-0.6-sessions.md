# Colophon 0.6: sessions

**Status:** unfrozen draft, revision 3, 2026-11-23. Revision 2 adopted the findings of the
reference machine (`docs/colophon-0.6-sessions-findings.md`, F1–F20); revision 3 adds `via` to passed claims (F12, F21). Additive to `colophon-0.5.md`; nothing here changes a
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
| `fold` | `latest` | How ordered messages become state: `latest` (state is the last payload) or `append` (state is the list of payloads). |
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
- `n` is a counter per session key, starting at 1. A receiver keeps, per key, the highest
  `n` it has accepted and which of the 128 values below it were accepted. It drops a frame
  whose `n` it has accepted, or whose `n` is more than 128 below the highest. Gaps and
  reordering inside that window are allowed.
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
| `hello` | any | `sessionKey` (the §S2 envelope), `seen` (`{term, rank, holder, seq}` or `null`), `lapsed` (bool) | Join, rejoin or ask to be brought up to date. Sent on every link-up. `seen.seq` is `null` when the sender holds no state for that claim. `lapsed` is informational; receivers ignore it. |
| `state` | holder | `claim`, `seq`, `snapshot` | Full state for one member (`to` set) or all. |
| `beat` | holder | `claim`, `seq` | Liveness when the holder has nothing else to send. |
| `msg` | holder | `claim`, `seq`, `origin`, `id`, `payload` | One ordered message. |
| `submit` | writer | `id`, `payload` | Ask the holder to order a message. |
| `refuse` | holder | `id`, `reason` | The holder declined a `submit`. |
| `presence` | any | `payload` | Latest value for this member. |
| `ask` | writer | `claim` (the claim the asker believes current) | Ask the holder for the role. |
| `pass` | holder | `claim` (current), `next` (`{term, rank:1, holder, via}`), `seq`, `snapshot` | Hand the role over. |
| `decline` | holder | `claim` | The holder will not pass now. |
| `take` | writer | `claim` (`{term, rank:0, holder}`) | Assume the role. |
| `ping` / `pong` | any | `t` (sender ms); `pong` adds `echo`, `hold` | Round-trip and clock offset (§S7). |
| `bye` | any | `claim` if the sender is or was the holder of it, `leaving` (bool) | A holder's `bye` releases the role. `leaving: true` also ends the sender's membership of the session. |

`payload` and `snapshot` are application bytes (base64), opaque to this document, at most
`maxPayload`. `id` is 16 random bytes, base64url. An unknown `kind` is dropped.

## S4. Claims and the holder

A **claim** is `{term, rank, holder, via}`: `term` a positive integer at most 2^53−1,
`rank` 0 (taken) or 1 (passed), `holder` a member ID, and `via` the member ID of the passer,
present exactly when `rank` is 1. Claims are ordered by `term`, then `rank`, then `holder`,
then `via`, member IDs compared as lowercase hex strings. Two passes to one member at one
term, from two holders that could not reach each other, are therefore different claims, and
the ordinary rules below settle them. Each member keeps the **greatest claim it has
accepted**, persisted across restarts, and treats its `holder` as the holder. The cell with
no accepted claim, or whose holder said `bye`, has **no holder**.

A member accepts a claim it meets in any frame when all of these hold:

1. The frame passed §S3 and its sender is entitled (§S1).
2. For rank 0, the frame is from `claim.holder` itself.
3. For rank 1, the frame is from `claim.holder`, or is a `pass` from `claim.via` with
   `next` equal to this claim and `pass.claim.holder` equal to `claim.via`.
4. It is greater than the member's accepted claim.

Rule 3 does not defend against a member that breaks this document (it could take at any
term); among members that follow it, a member claims rank 1 only after receiving a pass.

**Yielding.** A member that is holder and accepts a greater claim of another member stops
acting as holder at once: it sends no further `state`, `beat`, `msg`, `refuse`, `pass` or
`decline` under its old claim, and reports the change to the application.

**Correcting lesser claims.** Any member that receives a holder frame or `take` under a
claim less than its accepted claim answers the sender: a holder with `state`; a member that
released that greater claim with its `bye` again; any other member with `hello`. So a claim
whose holder has gone quiet still reaches everyone who can be reached.

## S5. Passing and taking

**Ask and pass.** A writer that wants the role sends `ask` to the holder. The holder's
application decides. To pass, the application first stops whatever the role controls, then
the holder sends `pass` with `next = {term: current+1, rank: 1, holder: asker, via: self}`, the final
`seq` and the final `snapshot`, to all members, and from that moment is not holder: it
accepts `next` itself, with `snapshot` as its state. It resends the same `pass`, unchanged,
when it next hears the asker speak under an older claim. The asker becomes holder on
receiving the `pass`; its state is exactly `snapshot`; its `seq` restarts at 0 for the new
term. A holder that learns of a greater claim naming itself that it has not acted under (a
second pass to it from another holder) renews (below), so that one state prevails; because
any member holding that greater claim corrects the holder's lesser frames (§S4), this does
not depend on any one frame arriving.

An asker that has heard holder frames from the holder but neither `pass` nor `decline`
within `askTimeoutMs` of its `ask` sends `ask` again.

**Take.** A writer may send `take` with `{term: T+1, rank: 0, holder: self}` where `T` is
the term of its accepted claim (0 if none) when one of these holds:

- there is no holder;
- the holder is lapsed to it (§S6);
- it sent `ask` and has accepted no holder frame from the holder for `askTimeoutMs` since.

It becomes holder at once, with the state it last held for the cell (application-defined
projection included, §S7) or a state the application supplies with the take, `seq` 0, and
sends `state` to all.

**Release.** A holder gives the role up without a successor by sending `bye` with its claim
and `leaving: false`. It stays in the session.

**Renewing.** A holder raises its own claim to the greater term + 1, rank 0, and sends
`state`, when it learns of a claim not less than its own that nobody is holding:

- from a `hello.seen` naming another member that has sent no holder frame or `take` for
  `holderTimeoutMs`;
- from a `hello.seen` or a `pass` naming itself under a greater claim (a pass to it that it
  never received, or a second pass from another holder);
- from a `bye` (a released claim has no holder);
- from a `hello` sent by the named holder itself (a `hello` cannot say whether its sender
  still holds; a sender that does hold then yields to the resulting `state`).

A holder judges "has sent nothing for `holderTimeoutMs`" only once its own link has worked
for `holderTimeoutMs`; before that it treats every member as holding. Terms therefore never
go backwards for any pair of members that have exchanged frames, and a member that has just
returned cannot renew over a live holder.

**Declining.** A holder MAY answer `ask` with `decline`. An asker that receives `decline`
MUST NOT take on the timeout rule for that ask.

## S6. Liveness and lapsing

- The holder sends a frame to all at least every `beatMs`.
- To a listener, the holder is **lapsed** when the listener has accepted no holder frame
  under the accepted claim for `holderTimeoutMs`, counted from the later of the last such
  frame and the listener's last link-up. `ping`, `pong`, `presence` and `submit` do not
  count. A listener whose holder lapses sends `hello` to all.
- A holder is **out of contact** when it has had no working link for `holderTimeoutMs`. An
  out-of-contact holder keeps acting locally (rule 1 of §S0) but, on its next link-up, MUST
  send `hello` with `lapsed: true` and MUST NOT send holder frames for `askTimeoutMs`. If
  within that time it accepts a claim of another member that is not lapsed to it, it yields
  (§S4). Otherwise it takes at its accepted term + 1.
- A member that restarts as the holder of its persisted claim follows the same rule. The
  core persists only the claim, so the application supplies the cell's state when it joins
  or takes; without one the cell restarts empty.

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
- A member that detects a gap, joins, or changes claim without a snapshot sends `hello`, at
  most once per second for gaps. The holder answers that member with the missing `msg`
  frames when `seen` names its current claim with a non-null `seq` and it still holds them
  (`tail`), else with `state`.
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
- **G2.** A member never sends a holder frame under a claim less than its accepted claim,
  other than a resend of a `pass` it already sent.
- **G3.** After a `pass` is sent, the passing member sends no other holder frame under the
  old claim, and a member that becomes holder by that `pass` starts with exactly its
  snapshot.
- **G4.** While a holder is live, if frames between two members are eventually delivered
  both ways, they eventually hold the same accepted claim and, for that claim, the same
  ordered state. With no live holder, members may hold different dead claims until the next
  take or renewal.
- **G5.** A writer with no holder reachable becomes holder within `askTimeoutMs` of asking,
  or `holderTimeoutMs` of the holder's last frame, whichever its trigger was.
- **G6.** Once a frame carrying a claim, sent by that claim's holder, reaches a member, that
  member does not act as holder under any lesser claim.
- **G7.** No frame is ever a record, and a carrier never holds a readable payload.
- **G8.** A member dropped by an accepted history is ignored by every member that has
  accepted that history.
- **G9.** The state reached depends only on the set and per-receiver order of frames
  delivered, not on which carrier delivered them.

Conformance is by the vectors in `conformance/0.6-sessions/` and the properties above
checked by the reference explorer and simulator.

## S12. Cell: `listening.podcasts/now-playing`

Policy: defaults (`fold` `latest`). The snapshot, and the payload of each `msg`, is the **anchor**:

```json
{"episode":"<id>","show":"<id>","positionMs":1234567,"ratePermille":1250,"playing":true,"at":98765432}
```

`at` is the holder's clock (§S7) when `positionMs` was true. A member's projected position
is `positionMs + floor(ratePermille × (now + offset − at) / 1000)` while `playing` (`offset` as in §S7, zero for
the holder itself), else `positionMs`. The holder
publishes an anchor on play, pause, seek, rate change and episode change, and at least every
60 s while playing. Presence payload: `{"label":"Mike's iPhone","playing":false}`.

A device that plays audio for this account SHOULD hold this cell, and SHOULD keep its last
anchor so that it can supply it when it joins or takes after a restart. A device that yields MUST
pause. A device that passes MUST pause before sending `pass` and put its stopped position in
the snapshot with `playing: false`; the new holder starts from that position exactly. A
device that takes starts from its projected position. Only the holder writes passive
`episode.position` progress; deliberate seeks and every other record are unaffected.
