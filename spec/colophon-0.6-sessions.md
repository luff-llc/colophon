# Colophon 0.6: sessions

**Status:** unfrozen draft, revision 15, 2026-11-23. Revision 2 adopted the findings of the
reference machine (`docs/colophon-0.6-sessions-findings.md`, F1–F20); revision 3 added `via` to passed claims (F12, F21); revision 4 answers the first
independent design review (R1–R9 in the findings document): evidence instead of hearsay,
no silent loss of state, key bootstrap and freshness, bounded state; revision 5 adopts what
the rebuilt harness found wrong in revision 4 (R1c–R4a); revision 6 adopted R1f–R1h. Revision 7 answers the second design review by separating
two layers: carriers make every connected group of members fully reachable (§S9
bridging), and the session rules above them assume that and are simpler for it. Revision 8 states
what a bridge checks and how loss beyond the first hop is repaired (B1–B4); revision 9
made the freshness exchange retry (B5). Revision 10 answers the third design review: it
states the timing assumption that convergence needs, makes every frame a broadcast, and
limits 0.6 conformance to the home carrier. Additive to `colophon-0.5.md`; nothing here changes a
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

**The network model.** Members that can exchange frames, directly or through other members
that bridge carriers (§S9), form a **group**. Inside a group every frame sent to all is
eventually delivered to every member, possibly late, duplicated and out of order; between
groups nothing is delivered. Groups split and merge at any time. The session rules are
written for this model: they never need to reason about who can reach whom inside a group,
because bridging makes reachability inside it complete.

**Timing.** A network that may delay frames without limit can keep any protocol of this
kind from settling: an adversary that always delivers a holder's frames just too late
makes members renew over each other for ever. So this document separates two kinds of
guarantee. **Safety** (G1–G3, G6–G9, G11, G12) holds whatever the network does.
**Convergence** (G4, G5, G10) holds from the moment the group is **timely**. A group is
timely from a time T when, from T on:

1. its membership does not change;
2. in every closed interval of length `holderTimeoutMs` − `beatMs` (10 s by default),
   every other member accepts at least one holder frame from each member that is acting as
   holder throughout that interval; and
3. every `hello`, `state`, `take`, `pass`, `yielded`, `ack` and `bye` is accepted by each
   member it concerns within that same length of time after it is first sent, counting the
   resends this document requires.

Loss is allowed as long as these hold: with the default policy one beat lost in a row is
within the condition, and two in a row are not. A home that delivers every frame within `beatMs` and loses none satisfies it
with room to spare. Before that moment claims may change;
they never go backwards and nothing is dropped silently.

**What is and is not promised.** Under this model no protocol can both let a member take
over in bounded time and guarantee that a holder whose frames are merely late keeps the
role. This document chooses the first (rule 1) and makes the cost visible: a displaced
holder's state is never dropped silently (§S5 "Yielding state"). Timeouts are measured on
each member's own clock, which is assumed to run within 500 parts per million of real time
while the process runs; a clock that stalls only delays that member's own timeouts.

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
| `fold` | `latest` | How ordered messages become state: `latest` (state is the last payload) or `append` (state is the most recent payloads, at most `tail` of them and at most `maxPayload` bytes once encoded as a snapshot; oldest dropped first). A snapshot therefore always fits in a frame. With `append`, a payload is at most `maxPayload` − 4 bytes. |
| `take` | `free` | `free`: any eligible member may take. Other values are reserved; a host that meets one MUST NOT take in that cell. |

**Entitlement comes from the host.** The session core is told, by the host, which members
are entitled at the accepted authority head, and is told again whenever that head changes.
When a newly accepted history removes a member, the host MUST tell the core before it
delivers any frame received after that history was accepted; G8 depends on this order.
Until it has been told, it treats nobody as entitled: it accepts no frame as coming from a
writer and passes to no one.

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

A session key is made fresh each time the application process starts a session and is
never written to storage, so a restart always means a new key and a new `n` sequence.

Signed `raw` by the member key (0.5 §4.2). `session` is the member's session number
(0.5 §9.6). `expires` − `notBefore` MUST be at most 86,400 s. A verifier accepts a session
key when the envelope verifies, the member is a current member with a `records` entry for
`namespace` at the verifier's accepted authority head, `session` equals the member's current
session number, and the verifier's clock is within the window widened by 60 s; the window
is checked again for every frame. A verifier
that later accepts a history in which the member is no longer a current member (0.5
§8.5), no longer has the `records` entry, or has a higher session number MUST drop that
member's session keys and every frame signed by them from then on. A member MAY sign a new
delegation for the same session key before the old one expires; receivers keep that key's
window.

## S3. Frames

```json
{"protocol":"colophon/session/6","account":"<64 hex>","namespace":"listening.podcasts",
 "cell":"now-playing","from":"<memberID>","key":"<keyID of the session key>",
 "to":"<memberID>","n":41,"epoch":3,"retain":true,
 "delegation":{…},"ciphertext":"<base64>"}
```

- `to` is optional and is advice to receivers, not a route: every frame is carried to
  every member of the group, and a member that `to` does not name ignores the frame.
- `n` is a counter per session key, starting at 1. A receiver keeps, per key, the highest
  `n` it has accepted and which of the 128 values below it were accepted. It drops a frame
  whose `n` it has accepted, or whose `n` is more than 128 below the highest. Gaps and
  reordering inside that window are allowed.
- `retain` is optional and only `true` (§S9).
- `delegation` is optional: the §S2 envelope for `key`, in the clear. A member includes it
  in every `hello` and MAY include it in any frame. It is not covered by the frame
  signature (it carries its own).
- `ciphertext` is AES-256-GCM with a key used by this session key only:
  HKDF-SHA-256 of the namespace epoch key `epoch` (0.5 §11.1), no salt, `info`
  `colophon/session-frame/6\n<account>\n<namespace>\n<cell>\n<key>`, 32 bytes. The nonce is
  `n` as 12 big-endian bytes; because `n` never repeats for a session key, no nonce does.
  AAD is the canonical JSON of `{account, cell, epoch, from, key, n, namespace, protocol,
  retain, to}` (absent fields omitted). A receiver that lacks the epoch drops the frame and
  syncs.
- Signed `raw` by the session key over the canonical body. The encoded frame MUST be at
  most 16,384 bytes.

A frame is one canonical JSON object. Its `signature` field is a 0.5 §4 `raw` signature
by the session key over the canonical JSON of every other field except `delegation`. The
`delegation` field, when present, is the §S2 envelope as a JSON object.

A receiver MUST, in order:

1. parse with closed field sets (0.5 §2.3), refusing an encoded frame over 16,384 bytes
   before parsing it;
2. check `account`, `namespace` and `cell`;
3. if `delegation` is present, require that it names exactly this frame's `(from, key)`
   and verify it under §S2; a delegation that names another member or key drops the frame;
4. find an accepted session key for `(from, key)`, or the one just verified; if there is
   none, drop the frame, and if `from` is a member entitled to the namespace at the
   receiver's accepted head, send `hello` to it, at most once per `askTimeoutMs` per member
   and four times a second in all;
5. verify the frame signature;
6. check `n` against the window;
7. open the ciphertext and parse the plaintext with closed field sets;
8. apply the freshness rule below, which needs the plaintext `kind`.

Any failure drops the frame silently and changes no state: in particular a key is
remembered, and `n` recorded, only when steps 1–7 have all passed.

**Freshness.** A carrier may replay old frames to a member that has restarted and lost its
windows. Every `hello` carries `fresh`, 16 random bytes new for that `hello`, and `echo`,
the `fresh` values of the hellos the sender is answering (at most 8). A member answers a
`hello` from a key it has no open window for, or whose `fresh` it has not answered, with a
`hello` to that member; it does not answer a `hello` that itself echoes one of its own
`fresh` values, unless that `hello` has just opened the window. The exchange therefore ends
after at most four hellos. Until a member has accepted, from a given key, a
`hello` whose `echo` contains the `fresh` of one of the member's own hellos sent since it
started, it accepts only `hello` frames from that key and takes from them only the
delegation, `fresh` and `echo`. A member honours an echo
only of a `fresh` value it sent within the last 60 s (it need remember no more than its 32
most recent), so the exchange needs a round trip within 60 s. That echoing frame's `n`
opens the window: frames with a
lower `n` from that key are dropped. A member that drops a frame because the window for
its key is not open sends that key's member a `hello`, at most once per `askTimeoutMs`, so
a lost `hello` or a lost answer does not leave the two unable to hear each other.

A member keeps open windows for at most 4 session keys per member, closing the one it
accepted first. A closed window is not forgotten: for every key it has accepted the member
keeps the highest `n` it accepted until that key's delegation expires, and a frame from
that key with a lower or equal `n` is dropped even if the key is presented again. It keeps
such floors for at most 64 keys per member, and while it holds 64 it accepts no new key
from that member. It drops everything it holds for a member it no longer accepts (§S2).

The plaintext is `{"kind": …, …}`. Kinds and their fields:

| Kind | Sender | Fields | Meaning |
| --- | --- | --- | --- |
| `hello` | any | `fresh`, `echo`, `seen` (`{term, rank, holder, via, seq}` or `null`), `lapsed` (bool) | Join, rejoin or ask to be brought up to date. Sent on every link-up. `seen.seq` is `null` when the sender holds no state for that claim. `lapsed` is informational; receivers ignore it. |
| `state` | holder | `claim`, `seq`, `snapshot` | Full state for one member (`to` set) or all. |
| `beat` | holder | `claim`, `seq` | Liveness when the holder has nothing else to send. |
| `msg` | holder | `claim`, `seq`, `origin`, `id`, `payload` | One ordered message. |
| `submit` | writer | `id`, `payload` | Ask the holder to order a message. |
| `refuse` | holder | `id`, `reason` (at most 64 bytes of `a–z 0–9 -`) | The holder declined a `submit`. |
| `presence` | any | `payload` | Latest value for this member. |
| `ask` | writer | `claim` (the claim the asker believes current) | Ask the holder for the role. |
| `pass` | holder | `claim` (current), `next` (`{term, rank:1, holder, via}`), `seq`, `snapshot` | Hand the role over. |
| `decline` | holder | `claim` | The holder will not pass now. |
| `take` | writer | `claim` (`{term, rank:0, holder}`) | Assume the role. |
| `ping` / `pong` | any | `t` (sender ms); `pong` adds `echo`, `hold` | Round-trip and clock offset (§S7). |
| `yielded` | former holder | `claim` (the claim it held), `seq`, `snapshot` | Sent to the new holder by a member that yields to a take (§S5). |
| `ack` | writer | `yielded` or `passed` (the claim named by the `yielded` or the `next` of the `pass` it answers) | The sender's application has been given that state. |
| `bye` | any | `claim` if the sender is or was the holder of it, `leaving` (bool) | A holder's `bye` releases the role. `leaving: true` also ends the sender's membership of the session. |

`payload` and `snapshot` are application bytes (base64), opaque to this document, at most
`maxPayload`; a frame that exceeds it is dropped. `id` and `fresh` are 16 random bytes,
unpadded base64url (22 characters). Every integer in a frame is at most 2^53−1. An unknown
`kind` is dropped.

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

1. The frame passed §S3 and its sender is a **writer** at the member's accepted authority
   head (§S1). A claim met in a frame from a member that may only read, in any field
   (`claim`, `next`, `hello.seen`, `bye`, `yielded`), is ignored, and so is a claim that
   names as holder a member that is not a writer. Readers take part in freshness, presence
   and the ordered lane as listeners only.
2. For rank 0, the frame is from `claim.holder` itself.
3. For rank 1, the frame is from `claim.holder`, or is a `pass` from `claim.via` with
   `next` equal to this claim and `pass.claim.holder` equal to `claim.via`.
4. It is greater than the member's accepted claim.

A claim whose term is more than 1,048,576 above the member's accepted term is ignored, so
one faulty writer cannot exhaust the term space in a step.

Rule 3 does not defend against a member that breaks this document (it could take at any
term); among members that follow it, a member claims rank 1 only after receiving a pass.

**Yielding.** A member that is holder and accepts a greater claim of another member stops
acting as holder at once: it sends no further `state`, `beat`, `msg`, `refuse`, `pass` or
`decline` under its old claim, and reports the change to the application.

**Correcting lesser claims.** Any member that receives a holder frame or `take` under a
claim less than its accepted claim answers the sender: a holder with `state`; a member
that released that greater claim with its `bye` again; any other member with `hello`. The
same answer is given to a `hello` whose `seen` is `null` or names a lesser claim. A claim
whose holder has gone quiet therefore still reaches everyone in the group, who then apply
"Renewing" (§S5).

## S5. Passing and taking

**Ask and pass.** A writer that wants the role sends `ask` to the holder. The holder's
application decides. A holder passes only to a member whose `ask` it accepted under its
current claim and has not answered, and that is still entitled at the holder's accepted authority head and has not said
`bye`. To
pass, the application first stops whatever the role controls; the holder persists `next` as
its accepted claim; then
the holder sends `pass` with `next = {term: current+1, rank: 1, holder: asker, via: self}`, the final
`seq` and the final `snapshot`, to all members, and from that moment is not holder: it
accepts `next` itself, with `snapshot` as its state. Until it receives an `ack`
whose `passed` names `next`, it resends the same `pass`, unchanged, whenever it hears a
frame from the asker, at most once per `askTimeoutMs`. A member that receives a `pass`
naming it gives the snapshot to its application (as its starting state, or as a late pass
if it has already moved to a greater claim) and answers `ack`, every time, so a passed
state always reaches the application it was passed to. The asker becomes holder on
receiving the `pass`; its state is exactly `snapshot`; its `seq` restarts at 0 for the new
term. A holder that learns of a greater claim naming itself that it has not acted under (a
pass that arrived after it took, or a second pass from another holder) reports that pass's
snapshot to the application and renews (below) with its current state; the application may
then publish a correction. Because any member holding that greater claim corrects the
holder's lesser frames (§S4), this does not depend on any one frame arriving.

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
and `leaving: false`. It stays in the session. It persists that it released the claim, so
that after a restart it does not act as that claim's holder.

**Yielding state.** A member that yields to a `take` (not to a `pass` it sent) sends
`yielded`, with the claim it held, its last `seq` and its state, to the holder it now
accepts. A `yielded` is accepted only from the member named as holder in the claim it
carries, and an `ack` only from the member the receiver accepts as holder. That holder
reports the `yielded` to the application and answers `ack`. Until it receives an
`ack` naming that claim, the displaced member resends `yielded` to whichever member it
currently accepts as holder, when it hears a frame from that holder, at most once per
`askTimeoutMs`. It changes no claim and no ordered state: it exists so that what the
displaced holder knew is never lost without an application being told. A displaced member
that restarts has only what its application kept, so applications that care SHOULD keep
their state (§S12).

A pass whose `next` names a member that has since moved to a greater claim (it renewed
before the pass arrived) is still reported to that member's application, once.

**Renewing.** A holder raises its own claim to the greater term + 1, rank 0, and sends
`state`, when it learns of a claim not less than its own that nobody is holding:

- from a `hello.seen` naming another member from which it has accepted no holder frame or
  `take` for `holderTimeoutMs`, counted only once its own link has worked that long (inside
  a group a live holder would have been heard; a member that has just joined a group has
  not listened long enough to judge, and treats every member as holding until it has);
- from a `hello.seen` or a `pass` naming itself under a greater claim;
- from a `bye` (a released claim has no holder);
- from a `hello` sent by the named holder itself (a `hello` cannot say whether its sender
  still holds; a sender that does hold then yields to the resulting `state`).

A writer that becomes holder orders its own unanswered submits. Terms never go backwards
for any pair of members that have exchanged frames. A member whose term has reached 2^53−1
does not take or renew.

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
  whose `id` is among the last `tail` it ordered in the current term.
- Delivery of a `submit` is **at least once**. A writer resends an unanswered `submit` when
  the holder changes and every `askTimeoutMs`, at most 8 times, and then reports it failed.
  Across a change of holder the same `id` may be ordered twice; applications that cannot
  tolerate that MUST ignore a repeated `id`.
- A member keeps at most `tail` ordered messages and at most `tail` early messages; older
  ones are dropped and a gap is repaired by `state`.

## S9. Carriers

A **carrier** moves frames between members. Every carrier gives the same contract: frames
may be lost, duplicated, delayed and reordered; a frame that arrives is unmodified or fails
§S3. A session uses every carrier it has and sends each frame on the best one.

**Home carrier.** A home that offers it accepts frames on its stream from a member it would
serve `/changes` to for the namespace, and forwards each to every other connected member of
the same account that is entitled to the namespace and subscribed to the cell, whether or not the frame carries `to`. It MUST NOT store a frame, except that it keeps the latest `retain: true` frame per
`(cell, from)` in memory for at most the cell's `retainMs` (or 60 s when it does not know
the cell) and gives it to a member when that member subscribes. It checks only the outer
fields, the size limit and its own caps. It learns the account, namespace, cell, sender,
recipient, session key ID, counter `n`, epoch number, the `retain` flag, each delegation
(member, session number, validity window, session public key), frame sizes and timing; the
kind of a frame can often be guessed from its size. It learns no payload, claim or state. A home MAY refuse or drop a frame under its caps; to
members that is loss, and a home that drops without limit keeps its group from being
timely (§S0).

The holder SHOULD mark its `state` and `beat` frames `retain`, so that a member opening the
application learns of the session from the carrier without waiting for the holder.

**Direct carriers** (device to device) are defined by their own documents and MUST carry
frames unchanged.

**0.6 conformance covers one carrier, the home.** Members connected to the same home are
one group, and nothing below is needed. Bridging is specified here so that the session
rules do not change when direct carriers arrive, and is not part of 0.6 conformance.

**Bridging.** Every member bridges. A member with more than one carrier, or a carrier that
reaches only some members, forwards every frame it sees for the first time, unchanged, on
each of its other carriers and to each of its other direct peers; it never forwards a frame
back to where it came from, and never forwards the same `(key, n)` twice. To be forwarded a
frame need only pass the outer checks of §S3 up to and including the frame signature under
an accepted session key; a bridge does not wait for its own freshness exchange with the
origin, which governs only what the bridge itself acts on. It remembers forwarded `(key,
n)` values in the same 128-wide window shape as §S3, kept separately from its acceptance
window, and does not forward a frame older than that window. A frame lost beyond the first
hop is not sent again under the same `n`: the session rules repair loss with new frames
(`hello`, `state`, resends), which are bridged like any other. A bridge keeps forwarding
windows for at most 4 session keys per member, and SHOULD limit what it forwards per
origin member (by default 50 frames and 262,144 bytes per second), dropping the excess: a
member that floods is thereby limited to its own neighbourhood. A frame addressed with `to` is forwarded the same way and ignored by
members it does not name. Frames are signed by their origin, so a bridged frame is verified
exactly as a direct one, and the freshness exchange of §S3 works across bridges because
hellos are bridged too. Bridging is what makes a group fully reachable; with only the home
carrier it has nothing to do.

## S10. What an application gets

The core exposes, per cell: join and leave; the holder and whether it is this member; the
ordered messages and snapshots; presence values; `ask`, `pass` (with a final snapshot),
`decline`, `take`, `release`; `publish` (holder) and `submit` (writer); the offset and error
to the holder; and events for each change. The core never calls the host for a signature
after the session key exists.

## S11. Guarantees

For members that follow this document, under a network that may lose, duplicate, delay and
reorder frames and partition members for any time. G4, G5 and G10 are convergence
guarantees and hold from the moment the group is timely (§S0); the rest hold always.

- **G1.** A member's accepted claim never decreases.
- **G2.** A member never sends a holder frame under a claim less than its accepted claim,
  other than a resend of a `pass` it already sent.
- **G3.** After a `pass` is sent, the passing member sends no other holder frame under the
  old claim, and a member that becomes holder by that `pass` starts with exactly its
  snapshot.
- **G4.** While a holder is live, members of one group eventually hold the same accepted
  claim, and every ordered message the holder sends under that claim is eventually applied
  by every member, in order (so their states are equal whenever the holder stops sending).
  With no live holder, members may hold different dead claims until the next take or
  renewal.
- **G5.** A writer with no holder reachable becomes holder within `askTimeoutMs` of asking,
  or `holderTimeoutMs` of the holder's last frame, whichever its trigger was, measured on
  its own clock, plus the delay with which its host delivers timer expiries. A host MUST
  deliver a timer expiry within 250 ms of its due time.
- **G6.** Once a member accepts a frame carrying a claim, sent by that claim's holder (the
  frame names that member or no one, and passes §S3, freshness included), that member does
  not act as holder under any lesser claim.
- **G7.** No frame is ever a record, and a carrier never holds a readable payload.
- **G8.** A member dropped by an accepted history is ignored by every member that has
  accepted that history.
- **G9.** A member's state depends only on the order of its own inputs (frames delivered,
  timer expiries and application commands), not on which carrier delivered a frame.
- **G10.** With no application command and no change in which members can reach which, the
  set of claims in use stops changing: there is no endless renewing or taking.
- **G11.** The state of a holder displaced by a take, and a pass that arrives after its
  asker took, are each reported to the application of a member that holds afterwards,
  provided the displaced member keeps running and frames between it and some later holder
  are eventually delivered.
- **G12.** A member that stops at any point between two outputs and restarts from what it
  persisted breaks none of G1–G3.

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
60 s while playing. Presence payload: `{"label":"Kitchen iPad","playing":false}`.

A device that plays audio for this account SHOULD hold this cell, and SHOULD keep its last
anchor so that it can supply it when it joins or takes after a restart. A device that yields MUST
pause. A device that passes MUST pause before sending `pass` and put its stopped position in
the snapshot with `playing: false`; the new holder starts from that position exactly. A
device that takes starts from its projected position. Only the holder writes passive
`episode.position` progress; deliberate seeks and every other record are unaffected.
