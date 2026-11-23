# Colophon 0.6 sessions: the wire

How a session frame is signed, sealed, carried and opened, at the byte level, for
implementers of the Swift, Kotlin and JS runtimes. The normative text is
`spec/colophon-0.6-sessions.md` (revision 14) §S2 and §S3; this document states the reading
the reference core (`colophon_core::v06::session::{keys, wire, codec, endpoint}`) implements,
including where the draft leaves a choice open. Byte-for-byte vectors are in
`conformance/0.6-sessions/wire/`.

Notation: "canonical JSON" is 0.5 §2.1; "base64" is standard padded base64 with canonical
padding bits (0.5 §2.2); "base64url" is unpadded. Member IDs and key IDs are the first 32
lowercase hex characters of SHA-256 of a signing point (0.5 §3.1).

## 1. Layers

| Layer | Owns |
| --- | --- |
| Host | Member private keys and their signatures (0.5 §3.4), epoch keys, the accepted authority head, clocks, randomness, storage of `Persist` effects, carriers. |
| Codec (`keys`, `wire`, `codec`) | The session key, delegations, the frame envelope, sealing and opening, frame signatures, the 128-wide replay window per `(member, key)` (at most 4 keys per member), entitlement flags. |
| State machine (`session::Session`) | Everything about claims and ordering, and the §S3 freshness exchange: `fresh`, `echo`, the window floor opened by an echoing `hello`, the 60 s / 32-value memory of its own `fresh` values, the once-per-`askTimeoutMs` retry hello, and the 4-key cap on freshness windows. |
| Façade (`endpoint::Endpoint`) | Wiring: application commands, ticks and received bytes in; sealed frames, `Persist` and events out. |

The codec hands the machine each opened frame with the sender's `writer` flag, the session
key ID and `n`. The machine never sees bytes; the codec never interprets claims.

## 2. Session keys (§S2)

A session key is a P-256 key made from 32 fresh random bytes from the host when the process
starts a session. It is held only in memory, never serialized, never copied, and wiped when
dropped. Its key ID is the frame's `key`.

The member signs, once, a delegation body. The core builds the exact bytes; the host signs
them `raw` (ES256 over the exact bytes, `r ‖ s`, 64 bytes) with the member key; the core
verifies the result before it uses it. The body is canonical JSON with exactly these
fields:

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
3. the member is current (not revoked, provisional or expired at the verifier's wall clock;
   0.5 `State::current_principal` with the member rule) and holds a `records` entry for the
   namespace;
4. `session` equals the member's current session number (its count of `endSessions`);
5. the verifier's wall clock is in `[notBefore − 60 s, expires + 60 s]`.

Rules 3–5 are re-checked for every frame. When the host accepts a new authority head it
gives the core a new account view before any frame received after it; keys whose member is
no longer current, lost the namespace or has another session number are dropped with their
windows, and the machine is told to forget that member's freshness windows.

A delegation may be renewed for the same key (same body shape, new window). Receivers
replace the stored delegation and keep the key's replay window.

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

`n` is the session key's counter: 1 for its first frame, then 1 more for every frame it
numbers, including frames that turn out too large to send. Because `K` is used by one session
key only and `n` never repeats for that key, no `(K, nonce)` pair repeats; a restart makes a
new key, so a new `K`.

The delegation is not signed by the frame. A `hello` always carries it; the reference sender
attaches it to every other frame while the frame stays within 16,384 bytes. The largest
default-policy frame (a `pass` with an 8,192-byte snapshot, both claims at the maximum term,
`to` and `retain`) is 16,000 bytes with the delegation.

### 3.3 Plaintext

The plaintext is canonical JSON of `{"kind": …, …}` with exactly the fields of the §S3 table:

| Kind | Fields |
| --- | --- |
| `hello` | `echo`, `fresh`, `lapsed`, `seen` (`{term, rank, holder, via?, seq}` or `null`; `seq` may be `null`) |
| `state` | `claim`, `seq`, `snapshot` |
| `beat` | `claim`, `seq` |
| `msg` | `claim`, `id`, `origin`, `payload`, `seq` |
| `submit` | `id`, `payload` |
| `refuse` | `id`, `reason` |
| `presence` | `payload` |
| `ask`, `decline`, `take` | `claim` |
| `pass` | `claim`, `next`, `seq`, `snapshot` |
| `ping` | `t` |
| `pong` | `echo`, `hold`, `t` |
| `yielded` | `claim`, `seq`, `snapshot` |
| `ack` | `yielded` |
| `bye` | `leaving`, and `claim` only when the sender is or was the holder (never `null`) |

Claims are `{term, rank, holder, via?}` with `via` present exactly when `rank` is 1; member
IDs (`holder`, `via`, `origin`) are key IDs. `id` and `fresh` are 16 bytes as 22 characters of
base64url. `payload` and `snapshot` are base64, at most the cell's `maxPayload` bytes. Every
integer is at most 2^53−1. `echo` has at most 8 values. A reader decodes, checks all of this,
and requires the bytes to equal the canonical encoding of what it decoded.

## 4. Receiving

A receiver runs these checks in order. Any failure drops the frame silently and changes no
state; nothing is remembered until every check has passed.

1. Size ≤ 16,384 bytes; parse with closed field sets (§3.1).
2. `account`, `namespace`, `cell` are this cell's; `from` is not this member.
3. If `delegation` is present: it must name `(from, key)` (its `member` is `from` and its
   point's key ID is `key`) and verify under §2. A delegation byte-identical to the one
   already accepted for `(from, key)` is not verified again.
4. Find an accepted session key for `(from, key)`: the one just verified, or a stored one.
   If there is none, drop and have the machine send `hello` to `from` (at most once per
   `askTimeoutMs` per member, shared with the machine's freshness probe). Re-check §2 rules
   3–5 at the wall clock.
5. Verify `signature` over the signed body under the session key.
6. Check `n` against the key's window: the highest accepted `n` and which of the 128 values
   below it were accepted. Drop an accepted `n`, or one more than 128 below the highest.
7. Look up epoch `epoch`; if absent, drop (the host should sync epochs).
8. Derive `K`, decrypt with the nonce and AAD, decode the plaintext (§3.3).
9. Commit: remember the key (at most 4 per member, the oldest by acceptance dropped) and
   record `n`. Hand the machine the frame, `writer` (the sender's entry has access `write`),
   `key` and `n`. The machine then applies freshness: until the window for `(from, key)` is
   open it uses only a `hello`'s `fresh` and `echo`, and drops frames below the `n` of the
   `hello` that opened it.

A frame the machine drops for freshness has still had its `n` recorded at step 9.

## 5. Host interface

The façade takes everything from the host, so it is deterministic given its inputs:

| Input | When |
| --- | --- |
| 32 random bytes | At construction: the session key. Must be fresh per process start; the bytes are wiped. |
| 16 random bytes | At construction: the seed of the machine's `fresh` values. Must be fresh per process start. |
| Member signature | `begin_delegation` returns the body; the host signs it `raw` with the member key; `finish_delegation` verifies and installs it. Before that, nothing can be sent. |
| Account view | At construction and after every newly accepted authority head (`set_account`), before any frame received after it. |
| Epoch keys | `current_epoch(namespace)` (frames are sealed under it) and `epoch_key(namespace, epoch)`, per call. Returned key bytes are wiped after use. |
| Clocks | With every call: monotonic ms (all session timers) and wall-clock ms (delegation windows, member expiry). |
| Ticks | At `next_deadline`, within 250 ms (§S11 G5). |

Each call returns the effects in order (`Send`, `Persist`, `Event`, `Unsent`); `Persist` must
be stored before any later effect is carried out. `Unsent` means a frame could not be sealed
(no delegation yet, delegation window passed, no epoch, oversize): to the protocol it is loss.

## 6. What must be wiped

- The session key's private scalar (on drop) and the random bytes it was made from.
- Epoch keys handed to the core, and every derived frame key `K`.
- Decrypted plaintext buffers.

The core never returns epoch keys, frame keys or the session key's scalar.

## 7. What a carrier sees

A carrier, including a home, sees every outer field in the clear: `account`, `namespace`,
`cell`, `from`, `to`, `key`, `n`, `epoch`, `retain`, the size of the ciphertext, and the
delegation when attached: the member ID, its session number, the session key's point, the
namespace and the delegation window. From these it can count frames per session key, see
restarts (a new `key`), see when a member's session number changes, and guess kinds from
size, `to` and `retain` (a `hello` carries a delegation; `beat` frames have a fixed size).
It cannot read any payload, snapshot, claim, `seq` or presence value, and it cannot forge,
alter or reorder a frame into acceptance: every field but `delegation` is signed, the
delegation carries its own member signature, and a replayed `(key, n)` is dropped.

§S9 says a home learns "the account, namespace, cell, sender, recipient and sizes, and
nothing else"; the list above is what it actually learns.

## 8. Open points in revision 14

These are the places where the draft text leaves a choice; the reference core implements the
reading given.

1. **Freshness before opening.** §S3 lists "check `n` and freshness" before "open the
   ciphertext", but whether a frame may pass a closed freshness window depends on whether it
   is a `hello`, which is inside the ciphertext. Reading: the replay window is checked before
   opening; freshness is applied after opening, by the machine.
2. **The frame signature's encoding.** The draft says the frame is "signed `raw` by the
   session key over the canonical body" but does not name the signature field or define the
   body. Reading: a flat canonical object with a `signature` field; the signed body is the
   frame without `delegation` and `signature`; the whole frame must be canonical.
3. **The delegation's form.** The example shows `"delegation":{…}`, while 0.5 embeds
   envelopes as base64 of canonical JSON. Reading: the envelope object itself.
4. **A delegation that names another `(from, key)`.** The draft says to verify a delegation
   "if present and names `(from, key)`", without saying what to do otherwise. Reading: the
   frame is dropped.
5. **Remembering a key before the frame passes.** "Verify it and remember the key" precedes
   the signature check, while "no failure changes session state". Reading: the key is
   remembered only once the whole frame passes.
6. **Which `n` is "accepted".** A frame that passes every codec check but is discarded by the
   machine's freshness gate still has its `n` recorded.
7. **The no-key `hello` is not rate-limited.** Unlimited, a stream of frames under unknown
   keys draws one `hello` each. Reading: it shares the freshness probe's limit, once per
   `askTimeoutMs` per member.
8. **Size headroom.** With `maxPayload` 8,192 the largest frame is 16,000 bytes, 384 below
   the limit; `refuse.reason` has no bound of its own. A cell with a larger `maxPayload`
   cannot carry a full snapshot. The draft should bound `maxPayload` (or the frame limit)
   and `reason` explicitly.
9. **Sessions longer than a day.** §S10 says the core never asks the host for a signature
   after the session key exists, but a delegation lasts at most 86,400 s. Reading: the host
   may renew the delegation for the same key; receivers keep the key's window.
10. **"Oldest" key.** Which of a member's keys is the oldest is not defined. Reading: by
    acceptance in the codec; the machine's freshness windows are ordered by when they opened.
    A mismatch only means a frame is dropped for want of a key or a window.
11. **What a carrier learns** (§7) is more than §S9 lists.
12. **A pass can be lost for good.** If a `pass` and its resend are both lost, the asker takes
    on the ask timeout, then learns of the passed claim from the passer's `hello.seen` and
    renews over it. The passer resends a pass only while the asker speaks under an older
    claim, so the passed snapshot is never reported to the asker's application (§S5, G11).
    The reference handoff test meets this in about one run in forty at 15 % loss.
13. **Suspended members.** §S2 drops keys of a member that is "revoked, suspended, expired, or
    has a higher session number", but 0.5 suspends keys only while a transition removing
    them is pending (§8.7), which concerns controllers and homes, not ordinary members.
    Reading: a member is current exactly when the 0.5 member rule says so.
