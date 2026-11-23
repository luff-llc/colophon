# 0.6 session wire vectors

Byte-level vectors for session keys and frames (`spec/colophon-0.6-sessions.md` revision 15,
§S2 and §S3), for the Swift, Kotlin and JS runtimes. The recipe they exercise is written out
in `docs/colophon-0.6-sessions-wire.md`. They are generated and checked by
`crates/colophon-core/tests/v06_wire_vectors.rs` (`COLOPHON_REGEN_VECTORS=1` rewrites
them). The draft is unfrozen: these files change with it.

Every key in this file is a fixed test key. None is used anywhere else.

## `vectors.json`

| Field | Meaning |
| --- | --- |
| `account`, `namespace`, `cell` | The cell every frame is sealed for. |
| `maxPayload` | The receiver's cell policy value. |
| `clockMs` | The receiver's wall clock, ms since the Unix epoch (2026-11-22T10:00:00Z). |
| `epochs` | Namespace epoch keys the receiver holds (hex). |
| `members` | Member signing keys (private scalar hex, uncompressed point base64, key ID), session numbers and `records` access for the namespace. Together they are the receiver's account view. |
| `receiver` | The member ID that opens the frames. |
| `sessionKey` | The sender's session key (scalar, point, key ID), the HKDF `info` string and the derived 32-byte frame key for epoch 1. |
| `delegation` | The `colophon/session-key/6` body bytes, the member's raw signature over them and the envelope as carried in a frame. |
| `frames` | Positive vectors, sealed in order with `n` from 1: one or more per plaintext kind. |
| `negative` | Frames that must be dropped, each with the reason. |
| `views` | Named account views (members with signing points, session numbers and access) that scenarios switch between; `default` is the view of `members`. |
| `scenarios` | Multi-step receiver runs (revision 15): eviction replay, probes only to entitled members, a read-only member's claims, entitlement changes, floor exhaustion, delegation renewal, pass acknowledgement. |

Each positive frame gives `plaintext` (the exact canonical bytes), `to`, `retain`, `n`, the
12-byte `nonce` (hex), the `aad` and `signedBody` (exact bytes as strings), the `ciphertext`
and `signature` (base64), the complete `frame` bytes, and `writer`: whether the receiver
hands the frame to the state machine as coming from a writer. The last positive frame is a
`take` from a read-only member: it opens, with `writer: false`.

Each negative vector gives `accept` (frames a fresh receiver opens first, at `clockMs`), the
`frame` to try and the expected `drop` code. A vector may override `clockMs` or
`maxPayload` for the attempt. `drop: null` means the frame must be accepted (the edge of the
128-wide window). After a drop the receiver's state must be unchanged.

Each scenario runs against one fresh receiver (`receiver` if the scenario names one, else
the file's), starting with the `default` view, through its `steps` in order:

- `{"open": frame, "clockMs"?, "expect": {...}}`: open the frame at `clockMs` (default the
  file's). `expect.drop` is a drop code or `null` (accepted); for a drop the receiver's state
  must be unchanged and, when given, `helloTo` is the member §S3 step 4 sends `hello` to
  (`null`: none). For an accepted frame, `writer` is the flag handed to the machine and
  `closed` the key ID whose window the acceptance closed (`null`: none).
- `{"setView": name, "expect": {"forgottenMembers": [...], "closedKeys": [[member, key], ...]}}`:
  a newly accepted authority head; the members forgotten entirely and the keys retired.
- `{"expire": clockMs, "expect": {"expired": n}}`: forget the floors of keys whose delegation
  expired more than 60 s before `clockMs`; `n` were.

Drop codes: `oversize`, `malformed`, `account`, `namespace`, `cell`, `fromSelf`,
`delegation`, `noKey`, `keyWindow`, `retired`, `keyLimit`, `signature`, `floor`, `replay`,
`tooOld`, `noEpoch`, `open`, `plaintext`, `unknownKind`, `range`. On the wire every drop is silent; the code is what a
conformance harness compares.

## How to check

1. Recompute `sessionKey.signing` and `sessionKey.id` from the scalar, then `frameKey` from
   epoch 1's key and `info`.
2. For each positive frame, in order, with one receiver: parse `frame`, recompute `aad`,
   `signedBody` and `nonce`, verify `signature` under the session key, decrypt, and compare
   the plaintext bytes and `writer`.
3. Re-seal each positive plaintext yourself with the same session key, `n`, `to` and
   `retain`: `aad`, `ciphertext` and `signedBody` must match byte for byte. Signatures are
   ECDSA P-256 with SHA-256 and RFC 6979 deterministic nonces; a runtime whose signer is
   randomized (CryptoKit, WebCrypto) cannot reproduce `signature` or `frame` exactly and
   instead checks that its own signature verifies and that the vector's verifies.
4. For each negative vector, with a fresh receiver, open `accept`, then the `frame`, and
   compare the drop code.
