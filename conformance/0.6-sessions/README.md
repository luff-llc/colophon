# 0.6 session vectors

Transcripts of the reference session machine (`colophon_core::v06::session`, spec
`spec/colophon-0.6-sessions.md` revision 15, §S3–§S9), for replay by the Swift, Kotlin and JS bindings.
They are generated and checked by `crates/colophon-core/tests/v06_session_vectors.rs`
(`COLOPHON_REGEN_VECTORS=1` rewrites them). The draft is unfrozen: these files change with it.

0.6 conformance is the home carrier: every frame a member sends is carried to every other
member of the cell, and `to` is advice. The scenario files are written that way: each sent
frame is delivered to every other member, and a member that `to` does not name ignores it
(its step has no outputs). Bridging (`bridge.json`) is specified but is not part of 0.6
conformance.

The machine runs with `Fixes::default()` (every fix in
`docs/colophon-0.6-sessions-findings.md`); each file records the `fixes` it used.

## Scenario files (`<name>.json`)

```json
{
  "format": "colophon/session-vectors/6",
  "name": "ask-pass",
  "description": "…",
  "policy": {"beatMs": 5000, "holderTimeoutMs": 15000, "askTimeoutMs": 1500,
             "presenceTimeoutMs": 15000, "retainMs": 60000, "tail": 256, "maxPayload": 8192,
             "fold": "latest", "take": "free"},
  "fixes": {"rank1FromHolder": true, "…": true},
  "members": [{"id": "a", "canWrite": true, "persisted": null, "freshSeed": null}],
  "steps": [{"member": "a", "at": 0, "input": {…}, "outputs": [{…}]}, {"member": "a", "restart": true}],
  "final": [{"member": "a", "view": {…}, "digest": "<sha256 hex>"}]
}
```

To replay: create one machine per member (`Session::with_fixes(id, canWrite, policy,
persisted, fixes)`, then `.with_fresh_seed(seed)` when `freshSeed` is given; the seed is 16
bytes in hex, and `fresh` values are the first 16 bytes of SHA-256(seed ‖ counter as 8
big-endian bytes), counting from 1). For each step in order, call `handle(input, at)` on that member and
compare the returned outputs, in order, with `outputs`. A `restart` step replaces the member's
machine with a new one built from what the member persisted (the last `persist` output:
`{claim, released}`). At the end compare each member's `view` and `digest`.

- `at` is that member's own monotonic clock in ms; members' clocks are unrelated. A `tick`
  is a timer expiry; a host schedules it from `next_deadline()` (not recorded here).
- `input` is tagged by `input`: `frame` (`frame`, `writer`, and, in keyed scenarios, the
  sender's `key` and the frame's `n` for the §S3 freshness gate), `entitled {writers}` (the
  writers entitled at the accepted authority head, from the host; until a machine has had
  one, nobody is entitled: a `join` waits for it, no frame is accepted as a writer's and no
  `pass` is made; a `pass` to a member outside it is rejected with `not-entitled`; every
  machine, including one rebuilt by a `restart` step, is given one before its `join` takes
  effect), `tick`, `linkUp`, `linkDown`,
  `app` (`command`, tagged by `command`: `join {state|null}`, `leave`, `ask`, `pass {to, snapshot}`,
  `decline {to}`, `take {state|null}`, `release`, `publish {id, payload}`,
  `submit {id, payload}`, `presence {payload}`, `ping {to}`). A `legacyEvidence` input exists
  only for the revision 6 regression presets and never appears here.
- A frame is `{from, to?, retain?, body}`; `body` is the §S3 plaintext tagged by `kind` with
  the spec's field names. Claims are `{term, rank, holder, via}` (`via` only at rank 1).
  `hello` is `{fresh, echo, seen, heard, lapsed}`: `seen` is `{term, rank, holder, via,
  seq}` where `seq` may be `null`, `heard` is `live`, `lapsed` or `unknown`. `yielded` is
  `{claim, seq, snapshot}` and `ack` is `{yielded}` or `{passed}` (exactly one). `bye` carries `leaving`. `hello.heard`
  appears only in revisions 4–6 and not in these files, nor does the revision 6 `forward`
  output.
- Outputs are tagged by `output`: `send {frame}`, `persist {claim, released?}`, `event {event}`; events are
  tagged by `event` (`becameHolder`, `yielded`, `holderChanged`, `askReceived`, `declined`,
  `message`, `snapshot`, `refused`, `presenceChanged`, `holderLapsed`, `offsetChanged`,
  `latePass`, `displaced`, `submitFailed`, `rejected`).
- `id` and `fresh` are 16 bytes, unpadded base64url; other bytes (`payload`, `snapshot`,
  `state`) are standard base64. Every integer is at most 2^53 − 1. Under `fold: append` a
  state is a list of payloads, each a 4-byte big-endian length and the bytes, the last `tail`
  kept.
- Frames may come from a member in no entitled set (`r` in `reader-claims-ignored`); its
  `writer` flag may be either value, and every claim it carries is ignored (§S4 rule 1,
  revision 15).
- `view` is `{accepted, holder, holding, gated, synced, seq, state}`; `digest` is the SHA-256 of
  its JSON as written by the reference (fields in that order, no spaces).

## `offset.json`

The §S7 integer formula: `rtt = max(0, (now − echo) − hold)`,
`offset = t − now + floor(rtt / 2)`, `error = ceil(rtt / 2)`, computed without overflow
(`offset` saturates to the signed 64-bit range). `cases` are single samples; `bestOfLast8` is a
sequence where each entry gives the best sample after adding it (the smallest `rtt` among the
last 8, the most recent among equals).

## `bridge.json`

§S9 bridging on the chain m0–m1–m2–m3, for the carrier layer (`colophon_core::v06::bridge`).
`links` names each directed link; a member refers to a link by the direction leaving it.
Each step is either a `send` by a member (its own frame, with the links it is transmitted on)
or a `receive` on a link (the link back to the sender), with whether the frame is delivered
to the session layer and the links it is forwarded on. A wire is `{key, n, frame}`; the
window per key is 128 wide, so a frame already seen, or more than 128 below the highest `n`,
is neither delivered nor forwarded. A bridge keeps forwarding windows for at most 4 keys per
origin member (the oldest dropped) and rate-limits forwarding per origin (default 50 frames/s
and 262,144 bytes/s); the file has no clock, so the rate limit is not exercised there
(`crates/colophon-core/tests/v06_bridge.rs` checks it).
