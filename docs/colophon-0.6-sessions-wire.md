# Colophon 0.6 sessions: the wire

How a session frame is signed, sealed, carried and opened, at the byte level, for
implementers of the Swift, Kotlin and JS runtimes. The normative text is
`spec/colophon-0.6-sessions.md` (revision 15) §S2 and §S3; this document states exactly what
the reference core (`colophon_core::v06::session::{keys, wire, codec, endpoint}`)
implements. Byte-for-byte vectors are in `conformance/0.6-sessions/wire/`.

Notation: "canonical JSON" is 0.5 §2.1; "base64" is standard padded base64 with canonical
padding bits (0.5 §2.2); "base64url" is unpadded. Member IDs and key IDs are the first 32
lowercase hex characters of SHA-256 of a signing point (0.5 §3.1).

## 1. Layers

| Layer | Owns |
| --- | --- |
| Host | Member private keys and their signatures (0.5 §3.4), epoch keys, the accepted authority head, clocks, randomness, storage of `Persist` effects, carriers. |
| Codec (`keys`, `wire`, `codec`) | This member's session key, delegations, the frame envelope, sealing and opening, frame signatures, and the lifecycle of other members' session keys: accepted, open (at most 4 per member), closed with a replay floor, retired, expired (at most 64 per member), with a 128-wide replay window per open key. |
| State machine (`session::Session`) | Claims and ordering, writer-only claims (§S4 rule 1), and the §S3 freshness exchange: `fresh`, `echo`, the window floor opened by an echoing `hello`, the 60 s / 32-value memory of its own `fresh` values, and the rate-limited `hello`s. |
| Façade (`endpoint::Endpoint`) | Wiring: application commands, ticks, account views and received bytes in; sealed frames, `Persist` and events out. It applies this member's own access. |

The codec hands the machine each opened frame with the sender's `writer` flag, the session
key ID and `n`, and tells it when it closes a key (`close_window`), retires or expires one,
or forgets a member (`forget_member`). The codec is the one owner of which keys are known,
open or closed; the machine's freshness windows exist only for keys the codec has open, so
the two cannot disagree. The machine never sees bytes; the codec never interprets claims.

## 2. Session keys (§S2)

A session key is a P-256 key made from 32 fresh random bytes from the host when the process
starts a session. It is held only in memory, never serialized, never copied, and wiped when
dropped. Its key ID is the frame's `key`.

The member signs a delegation body. The core builds the exact bytes; the host signs them
`raw` (ES256 over the exact bytes, `r ‖ s`, 64 bytes) with the member key; the core verifies
the result before it uses it. The body is canonical JSON with exactly these fields:

```json
{"account":"<64 hex>","expires":"2026-11-23T10:00:00Z",
 "key":"<base64 of the 65-byte uncompressed session signing point>",
 "member":"<member ID>","namespace":"listening.podcasts",
 "notBefore":"2026-11-22T10:00:00Z","protocol":"colophon/session-key/6","session":0}
```

Dates are 0.5 §2.2 dates; `notBefore ≤ expires` and `expires − notBefore ≤ 86,400 s`. The
envelope is the 0.5 §4.1 `raw` envelope, `{"body":"<base64 of the body bytes>",
"signature":"<base64>"}`, canonical, body at most 1,024 bytes.

A verifier accepts a delegation for a frame when, at its accepted authority head:

1. the envelope verifies under the member's signing point;
2. `account` is its account and `namespace` is the frame's namespace;
3. the member is a current member by the 0.5 member rule (§8.5: not revoked, not
   provisional, not expired at the verifier's wall clock) and holds a `records` entry for
   the namespace;
4. `session` equals the member's current session number (its count of `endSessions`);
5. the verifier's wall clock is in `[notBefore − 60 s, expires + 60 s]`.

Rules 3–5 are re-checked for every frame.

**Renewal.** A member may sign a new delegation for the same key before the old one
expires. Receivers replace the stored delegation and keep the key's replay window, so an
old frame re-wrapped with the renewed delegation is still a replay. A key is never delegated
under another session number: a sender whose session number changes retires its key, and a
new session needs a new key.

**A new authority head.** The host gives the core a new account view before any frame
received after it accepted that head. For other members: a member that is no longer current
or lost the `records` entry is forgotten (every key, window and floor dropped; the machine
forgets it); a member with another session number keeps its keys only as retired tombstones
until they expire, so no delegation signed again for an old key revives its frames. For this
member: promoted to write, it may ask, take and submit; reduced to read, it releases at once
(`bye` with its claim, release persisted) and seals only what a reader may send; without the
namespace, it leaves and seals nothing.

## 3. Frames (§S3)

### 3.1 Fields

A frame is one canonical JSON object, at most 16,384 bytes, with exactly these fields:

| Field | Value |
| --- | --- |
| `protocol` | `"colophon/session/6"` |
| `account` | 64 lowercase hex |
| `namespace` | 0.5 namespace grammar |
| `cell` | 1–64 bytes of `a–z 0–9 . -` |
| `from` | the sender's member ID |
| `key` | the key ID of the sender's session key |
| `to` | optional; a member ID |
| `n` | integer, 1 to 2^53−1 |
| `epoch` | integer, 1 to 2^53−1 |
| `retain` | optional; only `true` |
| `ciphertext` | base64 of the AES-256-GCM ciphertext and its 16-byte tag |
| `signature` | base64 of the 64-byte raw ES256 signature |
| `delegation` | optional; the §2 envelope as a JSON object |

A reader refuses duplicate names, lone surrogates, nesting over 64, unknown fields, absent
required fields, `retain: false`, non-integer or out-of-range numbers and non-canonical
bytes.

### 3.2 Recipe

With `E` the 32-byte key of namespace epoch `epoch` (0.5 §11.1):

```
info  = "colophon/session-frame/6\n" ‖ account ‖ "\n" ‖ namespace ‖ "\n" ‖ cell ‖ "\n" ‖ key
K     = HKDF-SHA-256(IKM = E, salt = none, info, L = 32)
nonce = 0x00000000 ‖ n as 8 big-endian bytes            (12 bytes)
AAD   = canonical JSON of {account, cell, epoch, from, key, n, namespace, protocol, retain?, to?}
C     = AES-256-GCM-Encrypt(K, nonce, plaintext, AAD)   (ciphertext ‖ tag)
S     = canonical JSON of the AAD object plus "ciphertext": base64(C)
sig   = ES256(session key, S), raw r ‖ s
frame = canonical JSON of S's object plus "signature": base64(sig) and, optionally,
        "delegation": <envelope object>
```

The signature therefore covers every field except `delegation`. `n` is the session key's
counter: 1 for its first frame, then 1 more for every frame it numbers, including frames
that turn out too large to send. Because `K` is used by one session key only and `n` never
repeats for that key, no `(K, nonce)` pair repeats; a restart makes a new key, so a new `K`.

The delegation is not signed by the frame. A `hello` always carries it; the reference sender
attaches it to every other frame while the frame stays within 16,384 bytes.

### 3.3 Plaintext

The plaintext is canonical JSON of `{"kind": …, …}` with exactly the fields of the §S3 table:

| Kind | Fields |
| --- | --- |
| `hello` | `echo`, `fresh`, `lapsed`, `seen` (`{term, rank, holder, via?, seq}` or `null`; `seq` may be `null`) |
| `state` | `claim`, `seq`, `snapshot` |
| `beat` | `claim`, `seq` |
| `msg` | `claim`, `id`, `origin`, `payload`, `seq` |
| `submit` | `id`, `payload` |
| `refuse` | `id`, `reason` (at most 64 bytes of `a–z 0–9 -`) |
| `presence` | `payload` |
| `ask`, `decline`, `take` | `claim` |
| `pass` | `claim`, `next`, `seq`, `snapshot` |
| `ping` | `t` |
| `pong` | `echo`, `hold`, `t` |
| `yielded` | `claim`, `seq`, `snapshot` |
| `ack` | exactly one of `yielded` and `passed` |
| `bye` | `leaving`, and `claim` only when the sender is or was the holder (never `null`) |

Claims are `{term, rank, holder, via?}` with `via` present exactly when `rank` is 1; member
IDs (`holder`, `via`, `origin`) are key IDs. `id` and `fresh` are 16 bytes as 22 characters of
base64url. `payload` and `snapshot` are base64, at most the cell's `maxPayload` bytes. Every
integer is at most 2^53−1. `echo` has at most 8 values. A reader decodes, checks all of this,
and requires the bytes to equal the canonical encoding of what it decoded.

Only a writer sends `state`, `beat`, `msg`, `refuse`, `pass`, `decline`, `submit`, `ask`,
`take`, `yielded` and `ack`; the machine drops them from anyone else. From a member that may
only read, every claim is ignored, `hello.seen` included (it survives only when it names the
receiver's own accepted claim, as a resume position) and `bye.claim` included; readers take
part in freshness, presence, pings and the ordered lane as listeners. A claim more than
1,048,576 terms above the receiver's accepted term is ignored from anyone.

### 3.4 Policy bounds

`maxPayload` is at most 8,192. At construction the façade checks that the largest frame of
every kind (every integer at 2^53−1, the payload or snapshot at `maxPayload`, `to`, `retain`
and the largest possible delegation attached) fits in 16,384 bytes; with the default policy
the largest is 16,114 bytes. It also checks that every timeout is positive,
`holderTimeoutMs` exceeds `beatMs`, `tail` is at least 1, and `maxPayload` is at least 5 under
`append`.

## 4. Receiving

A receiver runs these checks in order. Any failure drops the frame silently and changes no
state: a key is remembered, and `n` recorded, only when steps 1–7 have all passed.

1. Size ≤ 16,384 bytes, checked before parsing; parse with closed field sets (§3.1).
2. `account`, `namespace`, `cell` are this cell's; `from` is not this member.
3. If `delegation` is present: it must name exactly `(from, key)` (its `member` is `from` and
   its point's key ID is `key`), else the frame is dropped; it must verify under §2. A
   delegation byte-identical to the one already accepted for `(from, key)` is not verified
   again.
4. Find an accepted session key for `(from, key)`: the one just verified, or a stored one
   that is not retired, with §2 rules 3–5 re-checked. If there is none, drop the frame, and
   if `from` is a member entitled to the namespace at the accepted head (any `records`
   entry), have the machine send it `hello`: at most once per `askTimeoutMs` per member and
   four times a second in all. A new key from a member that already has 64 is refused.
5. Verify `signature` over the signed body under the session key.
6. Check `n`: a key that was ever closed drops every `n` at or below its floor; then the
   key's window: the highest accepted `n` and which of the 128 values below it were
   accepted. Drop an accepted `n`, or one more than 128 below the highest.
7. Look up epoch `epoch` (if absent, drop; the host should sync epochs); derive `K`, decrypt
   with the nonce and AAD, decode the plaintext (§3.3).
8. Commit: remember or renew the key and record `n`. A new key, or a closed key presented
   again above its floor, opens a window; beyond four open windows the member's
   first-opened key is closed (its floor is its highest accepted `n`) and the machine closes
   its freshness window. Hand the machine the frame, `writer` (the sender's entry has access
   `write`), `key` and `n`; the machine applies freshness: until the window for
   `(from, key)` is open it uses only a `hello`'s `fresh` and `echo`, and drops frames below
   the `n` of the `hello` that opened it.

Floors are kept until the key's delegation has expired and its 60 s slack has passed; the
façade frees them on `tick`.

**Why recording `n` before freshness is safe.** A frame that the machine then drops for want
of a window has passed steps 1–7: it is an authentic frame of that key, so recording its `n`
cannot burn a value an honest sender has yet to use. A carrier that replays such frames to
fill the window can only replay values the sender already used; it cannot move the window
past values the sender has not sent, because every `n` it can present carries the sender's
signature. A frame withheld long enough to fall more than 128 below the highest is lost, as
loss is in any case.

## 5. Host interface

The façade takes everything from the host, so it is deterministic given its inputs:

| Input | When |
| --- | --- |
| 32 random bytes | At construction: the session key. Must be fresh per process start; the bytes are wiped. |
| 16 random bytes | At construction: the seed of the machine's `fresh` values. Must be fresh per process start. |
| Member signature | `begin_delegation` returns the body; the host signs it `raw` with the member key; `finish_delegation` verifies and installs it. Before that, nothing can be sent. Called again to renew. |
| Account view | At construction and after every newly accepted authority head (`set_account`), before any frame received after it. `SessionAccount::from_history_state` builds it from a verified 0.5 history. |
| Epoch keys | `current_epoch(namespace)` (frames are sealed under it) and `epoch_key(namespace, epoch)`, per call. Returned key bytes are wiped after use. |
| Clocks | With every call: monotonic ms (all session timers) and wall-clock ms (delegation windows, member expiry, floor expiry). |
| Ticks | At `next_deadline`, within 250 ms (§S11 G5). |

Each call returns the effects in order (`Send`, `Persist`, `Event`, `Unsent`); `Persist` must
be stored before any later effect is carried out. `Unsent` means a frame could not be sealed
(no delegation yet, delegation window passed, key retired, no epoch, oversize, this member
not entitled, or a writer frame while this member may only read): to the protocol it is loss.

## 6. What is wiped, and what is not

Wiped by the core:

- the session key's private scalar (on drop) and the random bytes it was made from;
- epoch keys handed to the core, every derived frame key `K` and the HKDF PRK copy the core
  holds;
- decrypted plaintext buffers and the encoded plaintext before sealing.

Not wiped: the HMAC state inside the HKDF implementation (not reachable for wiping; it is
dropped at once), and everything the protocol hands to the application. Application
plaintext lives on in the decoded `Body` (payloads, snapshots, claims), in the machine's
state (the ordered state, its tail and early messages, presence values, pending submits),
and in `Event`s; the `Debug` output of all of these types contains it. A host that must keep
application data out of logs does not log these values. The core never returns epoch keys,
frame keys or the session key's scalar.

## 7. What a carrier sees

A carrier, including a home, sees every outer field in the clear: `account`, `namespace`,
`cell`, `from`, `to`, `key`, `n`, `epoch`, `retain`, frame sizes and timing, and the
delegation when attached: the member ID, its session number, the session key's point, the
namespace and the delegation window. From these it can count frames per session key, see
restarts (a new `key`), see when a member's session number changes, and often guess kinds
from size, `to` and `retain` (a `hello` carries a delegation; `beat` frames have a fixed
size). It cannot read any payload, snapshot, claim, `seq` or presence value, and it cannot
forge, alter or reorder a frame into acceptance: every field but `delegation` is signed, the
delegation carries its own member signature, and a replayed `(key, n)` is dropped, also for
keys a receiver has closed. This is the list §S9 gives since revision 15.

## 8. Decisions

What the first implementation found open in revision 14, and what revision 15 decided.

| # | Question | Decision (revision 15) |
| --- | --- | --- |
| 1 | Freshness needs the plaintext kind, but was listed before opening. | Eight ordered steps: the replay window before opening, freshness after (§4). |
| 2 | The frame signature's field and body were not defined. | One canonical object; `signature` covers every field except `delegation`. |
| 3 | The delegation's form. | The envelope as a JSON object. |
| 4 | A delegation naming another `(from, key)`. | The frame is dropped. |
| 5 | Remembering a key before the frame passes. | Nothing is remembered, and `n` not recorded, unless steps 1–7 pass. |
| 6 | Which `n` is "accepted". | Every frame that passed steps 1–7, including one the freshness gate then drops (safe, §4). |
| 7 | The unknown-key `hello` was unbounded. | Only to a member entitled to the namespace; once per `askTimeoutMs` per member and four a second in all. |
| 8 | Size headroom and `refuse.reason`. | `maxPayload` at most 8,192, checked with the largest frame at construction; `reason` at most 64 bytes of `a–z 0–9 -`. |
| 9 | Sessions longer than a day. | A member may sign a new delegation for the same key; receivers keep its window. |
| 10 | "Oldest" key, and eviction re-enabling replay. | At most 4 open windows per member, closing the first opened; a closed key keeps a replay floor until its delegation expires; at most 64 floors per member, and no new key while 64 are held. |
| 11 | What a carrier learns. | §S9 lists it (§7). |
| 12 | A pass could be lost for good. | The passer resends the same `pass` on any frame from the asker, at most once per `askTimeoutMs`, until `ack {passed}`; the member a pass names gives its snapshot to the application and answers `ack` every time. |
| 13 | "Suspended" members. | §S2 uses the 0.5 current-member rule. |

Beyond the text, the reference core also: retires a member's keys (rather than forgetting
them) when its session number changes, so that a delegation signed again for an old key
cannot revive replayed frames; keeps up to four unacknowledged passes per member and also
resends them on a timer, at most once per `askTimeoutMs` (an asker that has moved on and
listens quietly may never send a frame the passer hears); drops a pass once its asker is no
longer a writer; and keeps a
writer's `hello.seen` that names a member no longer a writer (it is never adopted, but a
holder renews over it, so a claim accepted before a revocation was known still converges).
