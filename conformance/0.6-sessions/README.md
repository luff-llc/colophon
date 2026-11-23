# 0.6 session vectors

Transcripts of the reference session machine (`colophon_core::v06::session`, spec
`spec/colophon-0.6-sessions.md` revision 5, §S3–§S8), for replay by the Swift, Kotlin and JS bindings.
They are generated and checked by `crates/colophon-core/tests/v06_session_vectors.rs`
(`COLOPHON_REGEN_VECTORS=1` rewrites them). The draft is unfrozen: these files change with it.

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

- `at` is that member's own monotonic clock in ms; members' clocks are unrelated.
- `input` is tagged by `input`: `frame` (`frame`, `writer`, and, in keyed scenarios, the
  sender's `key` and the frame's `n` for the §S3 freshness gate, and `forwarded {via,
  windowed}` when another member forwarded it as evidence; `windowed: false` means the
  receiver has no window for the origin's key and uses only the claim), `tick`, `linkUp`, `linkDown`,
  `app` (`command`, tagged by `command`: `join {state|null}`, `leave`, `ask`, `pass {to, snapshot}`,
  `decline {to}`, `take {state|null}`, `release`, `publish {id, payload}`,
  `submit {id, payload}`, `presence {payload}`, `ping {to}`).
- A frame is `{from, to?, retain?, body}`; `body` is the §S3 plaintext tagged by `kind` with
  the spec's field names. Claims are `{term, rank, holder, via}` (`via` only at rank 1).
  `hello` is `{fresh, echo, seen, heard, lapsed}`: `seen` is `{term, rank, holder, via,
  seq}` where `seq` may be `null`, `heard` is `live`, `lapsed` or `unknown`. `yielded` is
  `{claim, seq, snapshot}` and `ack` is `{yielded}`. `bye` carries `leaving`.
- Outputs are tagged by `output`: `send {frame}`, `forward {to, frame}` (another member's
  frame, unchanged, as evidence), `persist {claim, released?}`, `event {event}`; events are
  tagged by `event` (`becameHolder`, `yielded`, `holderChanged`, `askReceived`, `declined`,
  `message`, `snapshot`, `refused`, `presenceChanged`, `holderLapsed`, `offsetChanged`,
  `latePass`, `displaced`, `submitFailed`, `rejected`).
- `id` and `fresh` are 16 bytes, unpadded base64url; other bytes (`payload`, `snapshot`,
  `state`) are standard base64. Every integer is at most 2^53 − 1. Under `fold: append` a
  state is a list of payloads, each a 4-byte big-endian length and the bytes, the last `tail`
  kept.
- `view` is `{accepted, holder, holding, gated, synced, seq, state}`; `digest` is the SHA-256 of
  its JSON as written by the reference (fields in that order, no spaces).

## `offset.json`

The §S7 integer formula: `rtt = max(0, (now − echo) − hold)`,
`offset = t − now + floor(rtt / 2)`, `error = ceil(rtt / 2)`, computed without overflow
(`offset` saturates to the signed 64-bit range). `cases` are single samples; `bestOfLast8` is a
sequence where each entry gives the best sample after adding it (the smallest `rtt` among the
last 8, the most recent among equals).
