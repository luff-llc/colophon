# Colophon 0.3 handoff

The interrupted `bb811e2` was audited against `main`, the complete brief, and committed Marginalia
sources (`b93cc923` and committed HEAD `6c29f3ea12ce4768c31dad39a8eeddd975e8dad0`: spec,
November 6 decision, readiness design and verification record).
Its version/path/layout/live-state groundwork was retained. Work remains uncommitted on `v03`.

## Audit and repairs

The WIP changed 153 files and passed 144 Rust tests, but passing tests did not establish the complete
behavior. Live data bypassed signature verification in one overlay path, overlays polluted immutable
reducer state, existing live paths were not refreshed by sessions, scoped missing-record checks were
incomplete, relay replacement was unconditional, provider versions were not integrated, and live writes
could miss their FFI receipt. These paths are repaired and exercised by added tests.

Stale 0.2 records left in the renamed conformance directory were moved out: the directory now contains
exactly the 28 records in `conformance/0.3/library.json`. Misplaced tracked XCFramework contents at
`sdk/apple/` were moved into the ignored validation directory; the rebuilt artifact is correctly at
`sdk/apple/ColophonFFI.xcframework`. Both sets of WIP artifacts remain recoverable under
`target/v03-validation/`.

## Version and layout

- The Rust core, FFI/WASM packages, JS package/lockfiles, SDK artifacts, relay package/protocol,
  README, active docs and generated vectors use 0.3. `spec/colophon-0.2.md` is a short pointer;
  `conformance/0.3` replaces 0.2. Historical handoff prose and actual dependency versions remain
  historical; links to moved fixtures/spec sections are updated.
- Protocol and digest purposes use `/3`. This is not automatic wire compatibility with unpublished
  Rust `/2` records. Legacy **flat paths containing valid /3 records** are still verified.
- The spec distinguishes Marginalia's Swift “Colophon 0.2” layout-2 step from Rust Colophon 0.3.
- New libraries contain a root-signed layout-2 entry. Unsupported authenticated layouts stop before
  content reads/writes. Both SDKs expose `updateRequired`, including when the first source is a relay;
  they preserve identity and storage rather than treating the library as empty.

## Namespace, intent, live state and relay

Operations use `ops/<author>/<namespace>/<12-digit-clock>-<operationID>.json`. Verified headers must
match path author, namespace, clock and ID. Session folder enumeration skips sibling namespace
subtrees before checking hydration; legacy flat paths, authority and requests remain candidates for
verification. Missing immutable records in the selected namespace fail explicitly. Sibling namespace
absence cannot cause that failure. Checkpoints bind the selected namespaces. A partial replica cannot
safely count a grant-wide budget across unseen namespaces, so it explicitly refuses contributions
from capped grants extending outside its scope (`budgetScopeUnavailable`) and refuses local writes
under those partial grants. Unrelated content remains usable; complete-scope replicas retain the
existing global budget rule. This closes a visibility gap introduced by namespace filtering.

Passive podcast `position` writes use the per-author SHA-256 episode slot and a signed library/slot/
generation/operation-ID stamp. Signature, admission, decrypted slot and ID binding precede promotion.
Lower generations cannot replace a verified head; conflicting same-generation bytes fail. Revoked or
expired writers cannot supply current live state. Capped/expiring local writers, imported baselines,
stale regressions and payload extensions use immutable intent. Deliberate seeks, completion, queue
edits and recovery remain immutable.

Each live publication stores its exact signed engagement evidence in `history/` first. Deliberate
writes conservatively retain observed live heads at immutable operation paths; explicit cross-author
references are retained too. Own causal live chains collapse their expectation to the durable
predecessor. Live heads are overlays over immutable reducers, never checkpointed as durable intent.
Successful playback operations form ordering barriers so later deliberate state supersedes older
live heads. Retained/live duplicates fold once. Reducer schema 6 invalidates old projections.

The relay supports namespace-filtered feeds. Live creation requires `If-None-Match: *`; replacement
requires the exact prior digest in `If-Match`. Racing replacement returns 412, unconditional replacement
428. SDK sync authenticates fresh authority first, verifies live candidates using that authority,
synchronizes history/intent before promoting heads, and conditionally replaces both local and remote
slots. Live verification uses the same canonical UTC timestamp formats as the existing SDK operations. The relay remains an
untrusted byte exchange; signature validation stays in the client. Cursor persistence is scoped to the
endpoint, protocol and namespace selection. Same-size live rewrites are reconciled after relay restart.

## Verified cache and session readiness

The Rust verified-prefix cache already authenticated library, recipient, authority, exact envelope
digests, admitted prefixes and reducer state. Added bindings include selected namespaces, layout,
author signing-key digest, epoch and provider content version. A changed provider token re-verifies
signature/decryption/admission even when bytes match. Changed bytes at immutable paths are equivocation;
trusted digest evidence survives projection invalidation. Epoch keys are not persisted: the bound
authority/key shares and required host unlock tie the epoch to its actual key material.

The new `checkpoint` module closes the private-key protection gap: a random cache key is HPKE-sealed
to the member and its ticket is signed by that member; AES-256-GCM protects checkpoint plaintext with
the signed ticket as additional data. Opening verifies purpose/library/member/signature before ECDH.
Wrong recipient, wrong library, forged ticket, wrong ECDH and modified ciphertext fail. Host-owned keys
and persistence remain outside Rust. Providers without content versions require explicit digest audits.

Both SDK sessions distinguish opening, waiting for download, ready, refreshing, retry and update-required.
Usable content from the same connection survives transient refresh/publication failures. Writes refresh
and authorize before signing; query completions and snapshots are fenced by revision and connection.
Switching identity invalidates previous results. The Swift gate keeps usable content visible during
refresh/retry and provides an update-required gate.

Swift now matches Android's incremental record I/O: scoped path listing, provider versions, reads only
changed/new bodies, narrow `recordsAt` publication, conditional live replacement and journaled retry.
An unchanged built-in memory-store refresh reads **zero record bodies** in both SDK tests. Folder
providers use inode/file-key, size and modification versions. Custom providers without version tokens
reread conservatively, and must implement conditional live replacement to publish live samples.
Directory listing and full projection/evidence comparison still scale with indexes/projection size;
this change does not claim that all session CPU work is O(delta).

## Sole-copy blob protection

Zero-reference and stale orphan chunks are retained unless a relay receipt confirms custody elsewhere,
or the owner explicitly calls `discardSoleCopy: true` / `discardSoleCopy = true`. References and required
content retain existing pinning. Another member merely referencing a blob is not treated as evidence
that it actually holds the chunk; this deliberately favors retention. No relay-side deletion was added.

## Benchmarks and validation

The final storage-engine 100k rebuild is **1,335.215 ms**, unchanged checkpoint open **92.261 ms**,
local immutable write **0.899 ms**, and fresh-process checkpoint plus 1,000 operations **116.858 ms**.
The latter misses the earlier 100 ms target; the full-rebuild/local-write targets remain met.
The separate native-compatible `Library` benchmark takes 1,600.736 ms for a full rebuild and
95.622 ms for a passive podcast write; incremental session I/O does not remove its projection CPU cost.
Taupe-shaped 10,000-sample cold opening is **143.115 → 1.971 ms**, with **10,002 → 3** opening paths
and **10,002 → 2** immutable operations. All 10,000 engagement evidence records remain; this is not
a storage-compaction claim. Marginalia's separate 50k Swift measurements are included for context.

See [performance.md](performance.md) for the complete results, reproduction commands and
Marginalia's committed Swift measurements. Local raw logs are in `target/v03-validation/`.

| Check | Result |
| --- | --- |
| `cargo test --offline` | 152 passed, 0 failed, 1 ignored opt-in benchmark; 19 focused 0.3 tests |
| `cargo clippy --offline --workspace --all-targets -- -D warnings` | Passed, no warnings |
| `cargo fmt --all --check` | Passed |
| `COLOPHON_SOFTWARE_KEYS=1 bash scripts/test-swift.sh` | All five runs passed: 28 + 35 + 1 + 9 + 12 = 85 reported tests; 2 opt-in cases skipped |
| `node --test relay/` | 12 passed, 0 failed |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed; key-security regressions, Node smoke, Rust/WASM fixture parity and books queries/tools |
| `bash scripts/test-android.sh` | 58 passed, 0 failed, 1 cross-journey case skipped by default |
| `bash scripts/test-relay-cross.sh` | All 6 stages passed: Apple create/approve/verify; Android join/write/verify; records, live replacement, deliberate rewind and blobs |
| `SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Passed; regenerated Swift/Kotlin bindings and 165 MiB XCFramework with macOS arm64, iOS arm64 and iOS-simulator arm64 slices |

The literal nested-sandbox `swift test` invocation was rejected by macOS `sandbox-exec`; the existing
wrapper sets workspace module caches and runs `swift test --disable-sandbox` with software keys.
The cross-journey script now uses that same wrapper. No simulator execution was attempted. Xcode
reported the unavailable CoreSimulator service while packaging, but `-create-xcframework` succeeded.
JVM checks retain the environment's SDK-XML/FSEvents/Gradle deprecation warnings; no test failed.

The FFI additions are `beginLayout`, `liveGeneration` and `setReadScope`. The generated sources are
checked-in source changes; the rebuilt XCFramework is an ignored local deliverable. The protected
checkpoint API is pure Rust and does not introduce a native session persistence format.

## Deliberate boundaries

- The Swift authority/keyring/controller/WebAuthn architecture was not imported. Rust keeps its
  existing P-256/HPKE authority and shared reducers; only the selected layout/readiness/cache concepts
  are adopted. Domain behavior remains Rust-owned, with regenerated Swift/Kotlin bindings.
- Native sessions still use the compatible `Library` adapter and verify records on cold open; they
  do not yet persist the storage-engine checkpoint. Adding that adapter is separate from fixing
  refresh/publication I/O. The protected checkpoint API is available to storage-engine hosts now.
- No persistent per-slot live high-water witness or global freshness proof is claimed. A fresh client
  cannot detect replay of an older valid live head without private witness data. In-process monotonic
  checks, exact CAS, immutable referenced predecessors and current authority checks are implemented.
- Engagement evidence remains append-only; live state reduces opening/replay work, not the number of
  signed evidence files or total retained storage. No engagement compaction or live-witness retention
  policy was invented.
- Custom providers need coherent listing/version/CAS contracts; default implementations cannot turn
  an incoherent or permanently offline provider into a trustworthy source.
- No simulator/device testing or visionOS runtime claim is made. The requested macOS Swift tests,
  Android JVM tests and Apple–Android relay journey are the available executable platform checks.
