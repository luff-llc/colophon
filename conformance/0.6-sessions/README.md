# 0.6 session vectors

Transcripts of the reference session machine (`colophon_core::v06::session`, spec
`spec/colophon-0.6-sessions.md` §S4–§S8), for replay by the Swift, Kotlin and JS bindings.
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
             "take": "free", "reducer": "latest"},
  "fixes": {"rank1FromHolder": true, "…": true},
  "members": [{"id": "a", "canWrite": true, "persisted": null}],
  "steps": [{"member": "a", "at": 0, "input": {…}, "outputs": [{…}]}, {"member": "a", "restart": true}],
  "final": [{"member": "a", "view": {…}, "digest": "<sha256 hex>"}]
}
```

To replay: create one machine per member (`Session::with_fixes(id, canWrite, policy,
persisted, fixes)`). For each step in order, call `handle(input, at)` on that member and
compare the returned outputs, in order, with `outputs`. A `restart` step replaces the member's
machine with a new one whose persisted claim is the member's current accepted claim (the last
`persist` output). At the end compare each member's `view` and `digest`.

- `at` is that member's own monotonic clock in ms; members' clocks are unrelated.
- `input` is tagged by `input`: `frame` (`frame`, `writer`), `tick`, `linkUp`, `linkDown`,
  `app` (`command`, tagged by `command`: `join`, `leave`, `ask`, `pass {to, snapshot}`,
  `decline {to}`, `take {snapshot|null}`, `release`, `publish {id, payload}`,
  `submit {id, payload}`, `presence {payload}`, `ping {to}`).
- A frame is `{from, to?, retain?, body}`; `body` is the §S3 plaintext tagged by `kind` with
  the spec's field names. `hello.seen` is `{term, rank, holder, seq}` where `seq` may be
  `null` (finding F2); `hello.sessionKey` is an empty placeholder in this layer.
- Outputs are tagged by `output`: `send {frame}`, `persist {claim}`, `event {event}`; events are
  tagged by `event` (`becameHolder`, `yielded`, `holderChanged`, `askReceived`, `declined`,
  `message`, `snapshot`, `refused`, `presenceChanged`, `holderLapsed`, `offsetChanged`,
  `rejected`).
- Bytes (`payload`, `snapshot`, `id`, `state`, `sessionKey`) are standard base64.
- `view` is `{accepted, holder, holding, gated, synced, seq, state}`; `digest` is the SHA-256 of
  its JSON as written by the reference (fields in that order, no spaces).

## `offset.json`

The §S7 integer formula: `rtt = max(0, (now − echo) − hold)`,
`offset = t − now + floor(rtt / 2)`, `error = ceil(rtt / 2)`, computed without overflow
(`offset` saturates to the signed 64-bit range). `cases` are single samples; `bestOfLast8` is a
sequence where each entry gives the best sample after adding it (the smallest `rtt` among the
last 8, the most recent among equals).
