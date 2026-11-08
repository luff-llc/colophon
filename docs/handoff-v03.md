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
exactly the 27 records in `conformance/0.3/library.json`. Misplaced tracked XCFramework contents at
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
live heads. Retained/live duplicates fold once. The review fixes below raise reducer schema 6 to 7.

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
- The reviewed storage engine now persists per-slot high-water witnesses in its authenticated cache.
  A fresh client without a witness still cannot detect replay of an older valid live head. No global
  freshness proof or protection against rollback of the entire private cache is claimed.
- Engagement evidence remains append-only; live state reduces opening/replay work, not the number of
  signed evidence files or total retained storage. No engagement compaction or live-witness retention
  policy was invented.
- Custom providers need coherent listing/version/CAS contracts; default implementations cannot turn
  an incoherent or permanently offline provider into a trustworthy source.
- No simulator/device testing or visionOS runtime claim is made. The requested macOS Swift tests,
  Android JVM tests and Apple–Android relay journey are the available executable platform checks.

## Review fixes

Addressed all eleven findings in [review-v03-agy.md](review-v03-agy.md). This section and the
rerun [performance report](performance.md) supersede the earlier validation/timing summary above.
Changes remain uncommitted. No FFI API or `crates/colophon-ffi` source changed; session edits are
limited to the expiry/readiness checks and the cold-open authority barrier.

| Finding | Fix | Regression and result |
| --- | --- | --- |
| 1. Forward-generation exhaustion / lost durable actions | Live heads obey the 1,024 forward-clock bound and never advance the durable admission clock. Before exceeding the bound, passive publication retains its head and writes an immutable anchor. Local clocks consider only relevant live dependencies. Batched incoming anchors are authenticated before live replacement. A signed, inadmissible initial maximum-generation record cannot pin a slot either. | `review_long_playback_then_deliberate_write_survives_reopen` exercises 1,030 ticks, a lagging reader, a seek and cold reopen. `review_forward_exhaustion_is_refused` rejects a signed maximum generation, permits an immutable write and recovers that same live slot. Passed. |
| 2. Engine loses referenced live envelopes | The shared write preparer obtains predecessor bytes through a callback. Engine reads the exact source envelope, checks its indexed digest and supplies it to `PendingBatch.copies`; missing/changed bytes fail instead of silently omitting the copy. | `review_engine_retains_predecessor_without_replay` requires one exact copy and verifies the conditional seek. Both updated benchmark harnesses exercise this boundary. Passed. |
| 3. Unverified replacements evict valid state | Every replacement must pass signature, stamp/path/library, referenced grant/epoch and payload binding checks. Incoming dates never invalidate the old head; malformed or unavailable replacements leave old bytes intact. Locked same-generation signed conflicts are explicit. | `review_malformed_and_locked_replacements_preserve_head`, `review_locked_equivocation_is_explicit`, plus the existing forged-signature/stale-generation test. Passed. |
| 4. Expiring/backdated live writers become durable | Admission refuses any live-stamped operation from an expiring or budget-capped grant, including a retained `ops/` copy. Such records never enter the live map, admitted views, member/ledger admission or retention batches. | Strengthened `live_expiry_and_plaintext_slot_binding_are_checked_at_read_time` now checks refusal before expiry, after expiry, after copying to `ops/`, and before an honest writer prepares retention. Passed. |
| 5. Engine equivocation, rollback, index dedup and audits | Authenticated per-slot generation/envelope-digest witnesses survive checkpoints and replay invalidation. Rollback, equal-generation different bytes and invalid replacements fail closed and cannot be checkpointed. Stable sorting keeps the newest index entry. Audits require exact indexed bytes and check library/path/key/epoch bindings. | `review_engine_same_generation_equivocation_and_rollback_fail_closed` includes checkpoint reopen; `review_bulk_live_refresh_keeps_new_digests_and_audits_binding` updates 40 slots and rejects a foreign-library audit. Passed. |
| 6. Retention invalidates the immutable prefix / retains unrelated heads | Only immutable records advance namespace/author replay tails. Retention selects target episode heads (including completion events) and explicit revision references. | `review_received_retained_predecessor_does_not_invalidate_prefix`, `review_unrelated_commands_do_not_retain_all_live_slots`, and the storage benchmark's full-prefix live/seek assertion. Passed. |
| 7. Swift expiry timer | Parse both accepted ISO 8601 forms and schedule at the first whole-second host instant strictly after the inclusive expiry. Existing cancellation ownership is preserved. | `expiryRefreshWaitsForHostClock` tests whole seconds and `.555Z`; both deadlines are the following second. Passed. |
| 8. Checkpoint key/epoch fields unused | Cache entries now also bind the referenced authority sequence. Restore validates author-key digests and authenticated epoch/authority pairs; lazy fetches and audits compare the exact header bindings. Container `COLOENG4` / metadata version 4 invalidates old containers. Reducer schema 7 invalidates older projections. | `review_checkpoint_checks_author_and_epoch_bindings` changes each field and recomputes a valid local tag; both caches invalidate and replay correctly. Passed. |
| 9. Kotlin double merge / misplaced layout catch | Both workers open/authenticate authority once, merge content and journal before setting `opened`, track authority separately and remove the unreachable second-open branch. Kotlin translates unsupported layout at the actual authority barrier. | `coldOpenDoesNotMergeAuthorityTwiceAndTranslatesLayoutError` uses a counting core and calls the worker directly for unsupported layout. Existing incremental-I/O and future-layout tests also pass. |
| 10. Readiness inconsistency | Swift queries and the UI protocol default accept retained-content refresh/download/retry phases. Query results still require the same connection/revision, and core access checks remain in force. | `namespaceCachesAndStaleActions` performs a real query while storage is unavailable; `retainedPhasesAreUsable` checks the protocol default. Passed. |
| 11. Benchmark/docs overstatement | Taupe now performs a deliberate Engine seek after 10,000 passive ticks, checks retention/incremental application and cold-open position. The storage benchmark also tests live-to-durable retention over its full 100k prefix. Current schema/cache docs and measured path counts/timings are corrected. | All benchmark assertions pass; measurements and limits are in `performance.md`. The conformance vector was regenerated for narrower queue retention and now contains exactly 27 records. |

The original implementation was replayed against nine new core regressions and the strengthened
expiry case: all failed, then passed with the fixes. The Kotlin cold-open regression likewise failed
against the original worker. Swift readiness tests failed against the original session/protocol;
the timer test seam was temporarily given the original parsing/deadline policy, and both timestamp
cases failed. These experiments restored the working files afterwards. Logs are
`target/v03-validation/review-before-*.log`; no Git writes were used.

Final validation (software keys, JDK 17; logs under `target/v03-validation/review-*`):

| Check | Result |
| --- | --- |
| `cargo test --offline` | 162 passed, 0 failed, 1 opt-in benchmark ignored; 24 focused 0.3 tests and 19 storage tests |
| `cargo clippy --offline --workspace --all-targets -- -D warnings` | Passed |
| `cargo fmt --all --check` and `git diff --check` | Passed |
| `COLOPHON_SOFTWARE_KEYS=1 bash scripts/test-swift.sh` | All five products passed: 29 + 36 + 1 + 9 + 12 = 87 reported tests; 2 opt-in cases skipped |
| `node --test relay/` | 12 passed |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed, including regenerated-fixture Rust/WASM parity |
| `bash scripts/test-android.sh` | 59 passed; default cross-journey case skipped and exercised separately below |
| `bash scripts/test-relay-cross.sh` | All six Apple/Android stages passed, including live replacement, deliberate rewind and blobs |
| `SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Passed; generated binding sources unchanged, rebuilt 167 MiB macOS/iOS/iOS-simulator XCFramework |
| Release `bench`, `storage_bench`, fresh-process `--cold-suffix`, `taupe_bench 10000` | Passed; corrected measurements in `performance.md` |

The Swift wrapper runs the requested `swift test` with workspace module caches and
`--disable-sandbox`, as required by this nested macOS sandbox. Xcode's unavailable CoreSimulator
service and the existing Gradle/SDK/FSEvents warnings did not fail the checks. No visionOS runtime
or simulator execution is claimed. Per-slot witnesses protect an existing Engine/cache; a fresh
replica without witnesses still cannot prove global freshness or detect rollback of an entire
otherwise valid private cache.

## Second review fixes

Addressed the remaining findings 1, 3 and 6 and the four new problems in
[review-v03-agy-2.md](review-v03-agy-2.md) on `engine-sessions`. These changes cover the
storage engine used by native sessions and the compatibility `Library`. This section supersedes
the first review's live-verification, anchoring and predecessor-cache claims. Changes remain
uncommitted; no Git write commands were used.

| Problem | Final behavior | Regression coverage |
| --- | --- | --- |
| Authority-only relay verification rejects generations above 1,024 | `live_generation` authenticates signature, authority, epoch, stamp, payload and the absolute interoperable clock limit without assuming a local durable prefix. Compatibility merge and both ingestion paths retain the relative 1,024 bound. Incoming immutable anchors and changed authority are evaluated before replacing a head. | `second_review_authority_only_relay_verifier` authenticates generation 2,049 using only authority and keys, then checks normal admission with anchors. Existing forward-exhaustion and forged/stale-head tests remain green. |
| Locked/new-epoch replacements are silently lost | Compatibility merge quarantines signed, admissible candidates separately from the old envelope and retries them after unlock. Malformed candidates cannot evict the old head or another queued valid candidate. Engine refresh defers unavailable payloads until host ECDH, preserves authenticated fallbacks and witnesses, and refuses a checkpoint over unresolved candidates. Carried fallbacks are readmitted against current authority and the rebuilt durable clock. | `second_review_locked_and_rekeyed_replacements_are_retried`, `second_review_deferred_invalid_payload_never_evicts_valid_candidate`, `second_review_engine_rekeyed_live_replacement_waits_for_unlock`, and `second_review_carried_head_loses_revoked_clock_anchor`. |
| Passive boundary transitions can strand subsequent durable actions | Shared preparation publishes an immutable anchor when the next passive clock reaches the durable clock plus 1,024. It retains target/cited predecessors, including other authors' heads and older peers' live samples already at the limit. Admission and local write clocks never decrease when older predecessors become durable. Seeks, completion and queue edits stay immutable. | `second_review_passive_anchor_boundary_and_durable_actions` and `second_review_engine_boundary_and_durable_actions_survive_cold_open` each exercise more than 1,024 further ticks, a seek, a queue edit, completion and cold reopen. `second_review_cross_author_and_other_episode_boundary` checks device/episode changes and older boundary samples. |
| Retaining a live head behind unrelated durable work invalidates the prefix | Only exact authenticated envelope/order matches can bypass earlier-arrival replay. The engine preserves the verified prefix; compatibility inserts the predecessor in canonical durable order and rebuilds its prefix hashes. Neither path reapplies unrelated durable operations. Intervening episode changes, admission rejections and reducer conflicts/invalid outcomes retain conservative ordered replay. | `second_review_retained_head_behind_immutable_tail_keeps_cache` checks two reducer applications on both paths after twenty unrelated writes, engine `VerifiedPrefix`, matching cold state and zero-application checkpoint restoration. `second_review_retention_replays_past_conditional_failures` ensures insertion still reevaluates a conditional operation whose historical outcome changes. |

Seven new regressions failed against the pre-task implementation and passed after the fixes.
The exact older-peer cross-author boundary case already passed in this merged worktree: its
shared preparer already retained passive-anchor dependencies. The new boundary-policy tests fail
before the earlier anchoring change. The initial engine-only cache experiment also independently
failed with `Earlier arrival or duplicate changes admission order`; the combined regression exposes
compatibility's twenty unnecessary prefix applications first. Logs are in
`target/second-review/{before.log,before-all.log}`. A further failing experiment caught a carried
head surviving revocation of its supporting anchor; `carried-before.log` / `carried-after.log`
record that correction. The ten new tests are in `tests/v03.rs` and `tests/storage.rs`.

Updated specification §5.1 covers standalone authentication versus admission, deferred replacement,
current-authority fallback checks, boundary anchors, exact predecessor insertion and monotonic
clocks. No public FFI API, generated binding source, reducer schema or checkpoint format changed.
Bindings were regenerated and the XCFramework rebuilt so native tests exercise the new Rust core.
Compatibility insertion still rebuilds prefix hashes; this is not a claim that all compatibility
CPU work is O(delta). Existing private-cache/global-freshness and mobile-performance limitations
remain as documented in [handoff-engine-sessions.md](handoff-engine-sessions.md).

Final validation logs and preserved Android XML results are under `target/second-review/`:

| Check | Result |
| --- | --- |
| `cargo test` | 175 passed, 0 failed; one existing opt-in benchmark ignored |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo fmt --all --check`, `git diff --check` | Passed |
| `COLOPHON_SOFTWARE_KEYS=1 bash scripts/test-swift.sh` | All five runs passed: 29 + 39 + 1 + 9 + 12 reported tests; three existing opt-in cases skipped |
| `node --test relay/` | 12 passed |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed; final WASM rebuild, key-security checks, Node smoke and Rust/WASM fixture/query parity passed |
| `bash scripts/test-android.sh` | 60 passed, 0 failed; two existing opt-in cases skipped |
| `bash scripts/test-relay-cross.sh` | All six Apple/Android stages passed on the final build, including live replacement, deliberate rewind and blobs |
| `SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Passed; generated sources unchanged, 182 MiB macOS/iOS-device/iOS-simulator XCFramework rebuilt |

Swift uses the existing workspace-cache wrapper for `swift test --disable-sandbox` with software
keys because nested SwiftPM sandboxing is unavailable here. Android used JDK 17, the supplied
SDK/NDK paths and the writable shared Gradle home. Existing SDK XML/FSEvents/Gradle, SwiftPM cache
and unavailable CoreSimulator warnings did not fail checks. No visionOS or device/simulator
execution is claimed.
