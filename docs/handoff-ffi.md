# Native bindings handoff — November 6, 2026

Implemented in the `ffi` worktree, left uncommitted as requested. Nothing was pushed or
published. No files in `crates/colophon-core` or `docs/domains/` were changed; no additive core
conveniences were needed. The existing 0.1 Swift sources and tests are unchanged.

## Delivered

- `crates/colophon-ffi`: UniFFI 0.32.2, exact-pinned, proc-macro mode, defaults off. Only the
  optional `bindgen` feature enables its CLI. UniFFI is the only newly introduced direct Rust
  dependency; serde and serde_json reuse workspace pins. The dependency reason and feature
  boundary are recorded in `architecture.md`.
- A mutex-protected `NativeLibrary`, host-owned key callbacks, explicit prepare/sign/commit
  and prepare/agree/finish steps, typed members/grants/outcomes/ledger/views/change summaries,
  and JSON bytes for domain inputs/state/tool results. The wrapper does no I/O, clock reads,
  or entropy generation. Callbacks run outside the mutex. Prepared mutations reject a changed
  revision or a different session, rather than silently committing against newer authority.
- `ColophonKit` in the root Swift package: generated immutable Sendable transport types,
  an async actor facade, an independently suspending `AsyncKeyProvider` protocol, typed
  access errors, CryptoKit software keys and restorable Secure Enclave references. Software
  fallback is explicit and only applies when hardware is unavailable. Key-operation failures
  map to the declared UniFFI error type. Cancellation is checked before committing.
- The JavaScript API journey is mirrored: create/open/requestAccess, approval with optional
  narrowed grant fields, revoke, records/merge/ready, write/view, tools/call, handover/recover,
  members, and ledger. Native callers additionally supply timestamps and fresh action seeds.
- `sdk/kotlin`: generated Kotlin, a synchronous local-provider facade, JCA P-256 providers,
  a checksum-pinned Gradle 8.14.3 wrapper, Kotlin 2.2.21, and JNA 5.18.1. Private JCA key
  handles can come from Android Keystore; no private-key export is requested by the facade.
- Five-slice Apple XCFramework, Android two-ABI AAR build script, Swift and JVM journeys,
  actual Swift/JNA ABI measurements against native Rust, and reproducible build/test scripts.

`docs/native-bindings.md` is the integration/build guide. The bindings status is also recorded
in the owned step of `docs/app-migration.md`.

## Build and test

From this worktree on an Apple Silicon Mac with Xcode and Swift 6.2+:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
bash scripts/build-apple.sh
bash scripts/check-apple-swift.sh
COLOPHON_SOFTWARE_KEYS=1 swift test

export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export GRADLE_USER_HOME="$PWD/.gradle-home"
bash scripts/test-kotlin.sh

cargo test
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
npm ci --prefix js
npm --prefix js run build
npm --prefix js test
```

`scripts/generate-bindings.sh` builds the host dylib without generator features and the
in-repo `uniffi-bindgen` binary separately. Regenerate Swift/Kotlin and rebuild all native
binaries together after changing the FFI API. UniFFI configuration uses its 0.32.2 global
configuration format. Generated files are checked in; binaries and caches are ignored.

visionOS built successfully with the installed nightly 1.101.0 (2026-11-05), rust-src, and
`-Zbuild-std=std,panic_abort`. Stable targets used Rust 1.91.1. The script installs nightly
with rust-src if missing; `VISIONOS_TOOLCHAIN` can select a dated nightly. `SKIP_VISIONOS=1`
is the documented explicit fallback for a builder unable to install those prerequisites.
It was not needed here. Xcode was 27.2; Swift was 6.4.2.

For the enclosing sandbox, use `bash scripts/test-swift.sh` instead of bare `swift test`.
It places module caches inside the worktree and disables SwiftPM's nested sandbox, which
otherwise fails with `sandbox_apply: Operation not permitted`. It does not grant access to
macOS services blocked by the enclosing sandbox.

### What passed

- All five Rust Apple builds and XCFramework packaging: macOS arm64, iOS device arm64,
  iOS simulator arm64, visionOS device arm64, visionOS simulator arm64.
- Generated Swift, async facade, and CryptoKit providers typechecked against both iOS SDKs
  and both visionOS SDKs. The macOS code was built and executed by Swift Testing.
- `cargo test`: all 19 existing Rust tests passed, plus workspace/doc-test targets.
- Clippy across the workspace, all targets and all features with `-D warnings`; formatting;
  shell script syntax; `git diff --check`.
- JavaScript build and `npm --prefix js test`: key-validation regressions and Node smoke,
  including Rust/WASM conformance parity.
- All ColophonKit functional tests: consent journey, narrowed grants, AI attribution despite
  a spoofed payload field, kept notes, revocation, reopen, tools, software-key restoration,
  callback signatures/ECDH, explicit fallback policy, all six refusal reasons, provider errors,
  invalid signatures, stale actions, suspended signing with a concurrent merge, and cancellation.
  Swift reports 9 test declarations in the new target, including the opt-in benchmark normally
  skipped; the restricted-grant test has two argument cases. The benchmark passed when enabled.
- JVM consent journey and provider tests passed using the host `libcolophon_ffi.dylib`.
  The opt-in JVM benchmark also passed. Kotlin compilation uses the in-process strategy to
  avoid a restricted-host compiler-daemon failure; FSEvents warnings do not affect the tests.

### Full Swift suite is not green in this sandbox

The unchanged 0.1 target runs 368 tests and reports 13 failures in file-coordination or
backup-metadata tests. The original `HEAD:Package.swift`, temporarily restored for a baseline
run and then replaced with the new manifest, produces exactly the same 13 failing test names.
The new target passes. No legacy tests were disabled and no production storage behavior was
changed to hide this restriction.

The baseline failures are `pendingAuthorityFileIsNotTheHead`,
`signedBatchSurvivesFolderReconstructionSyncAndReplay`,
`placeholderArrivingAfterPreflightStillReportsPending`,
`placeholderReadThrowsPendingWithoutCoordinating`, `vectorsStillHold`,
`keyringVectorsStillHold`, `folderStoreCarriesALibrary`,
`newIdentityIsLeftOutOfBackups`, `existingIdentityIsMovedOutOfBackupsWithoutChanging`,
`readThrowsUnavailableWithinTheDeadlineWhileAWriteClaimIsHeld`,
`ubiquitousClaimTimeoutThrowsPending`, `timedOutWaitingWriteDoesNotLandLater`, and
`writeAlreadyInsidePerformWaitsForItsResult`.

Repeat the full software-key suite on an unrestricted macOS runner before treating the
all-green Swift gate as satisfied. Local build/test/baseline logs are in the ignored
`target/ffi-validation/` directory.

## Built artifact sizes and release path

Actual archive sizes from this build; static archive size is not final app download size:

| Artifact | Bytes |
| --- | ---: |
| macOS arm64 static library | 31,411,776 |
| iOS arm64 static library | 31,197,040 |
| iOS simulator arm64 static library | 31,192,128 |
| visionOS arm64 static library | 34,895,944 |
| visionOS simulator arm64 static library | 34,920,104 |
| Entire XCFramework, including headers and metadata | 163,818,080 |
| Zipped XCFramework | 47,975,868 |
| Host `libcolophon_ffi.dylib` | 2,049,456 |
| Kotlin JVM jar | 350,308 |

Artifacts remain at `sdk/apple/ColophonFFI.xcframework`,
`sdk/apple/ColophonFFI-0.2.0.xcframework.zip`, and `target/release/libcolophon_ffi.dylib`.
Cargo's rebuildable caches were cleaned and the required host artifacts rebuilt; about 22 GiB
was free at the final check. Cross-target intermediates are gone, but the packaged slices remain.

The root package currently uses the local XCFramework path. Proposed release target below:
the URL is **not published**. This checksum was computed from the retained zip with
`swift package compute-checksum` and independently checked with SHA-256.

```swift
.binaryTarget(
    name: "ColophonFFI",
    url: "https://github.com/luff-llc/colophon/releases/download/v0.2.0/ColophonFFI-0.2.0.xcframework.zip",
    checksum: "41eb919ec7689f249e4296656165e423265dbd21eec984a32b5281fa72a4c6a8"
)
```

Upload only that exact reviewed archive at release time. Any rebuild/repack requires computing
the checksum again and shipping matching generated Swift. Intel Apple slices are not included.

## Android and other known gaps

- `scripts/build-android.sh` was syntax-checked, not executed: this machine has no Android SDK
  or NDK. Prerequisites are JDK 17, Android command-line SDK, NDK r28+, cargo-ndk, and
  `ANDROID_HOME`/`ANDROID_NDK_HOME`. It builds arm64-v8a and x86_64 and creates an AAR with
  manifest, classes.jar, JNI libraries, and consumer rules. API 31 is the default for Keystore
  ECDH. Consumers must also include Kotlin stdlib and JNA's Android AAR; a local AAR has no POM.
- Physical-device Secure Enclave, Android Keystore/StrongBox, authentication prompts, and
  Android 16 KB page-size behavior still require device validation. Here, software P-256,
  unavailable-hardware fallback policy, Swift SDK compilation, and JVM JCA were exercised.
- Kotlin's convenience facade is synchronous for local providers. Suspending stores drive
  the exported prepare/finish steps on their own dispatcher. Swift provides a suspending
  provider facade directly. Neither path blocks on a Rust async executor.
- Change summaries conservatively invalidate all declared namespaces after record changes;
  they do not invent incremental engine deltas. Unlocks report the affected namespace.
  Storage, sync, sessions, checkpoint persistence and typed app-domain stores remain outside
  this binding layer. `records` is a snapshot. A commit followed by an unlock error still
  leaves committed records for the host to persist.
- The concurrent engine worker's changes are not merged into this worktree. Rebuild the
  bindings and rerun journeys/benchmarks after that merge; the wrapper only uses the public
  core API. Keep the FFI section when merging the separately edited performance document.

## Performance evidence

`docs/performance.md#ffi` records three repeated runs and the exact methodology. Per-run
medians are retained in `crates/colophon-ffi/benchmarks/2026-11-06.json`.

Against a fixed 21-operation history, median native query/write times were 5.067/10.860 ms;
Swift ABI times were 5.473/11.606 ms and Kotlin/JNA times were 5.525/11.755 ms. The complete
foreign paths add approximately 0.4–0.5 ms per query and 0.7–0.9 ms per write. Host signing,
unlocking, persistence and actor/dispatcher scheduling are excluded; core sealing, signature
verification, commit and result retrieval are included. This is pre-incremental-core transport
evidence, not a mobile-device or 100k-operation performance claim.

Reproduce with `bash scripts/build-apple.sh` followed by `bash scripts/bench-ffi.sh`.

## Intended commits

1. `Add UniFFI native transport with host key steps and typed outcomes`
   — workspace/crate/lockfile, proc-macro generator configuration, dependency rationale.
2. `Add ColophonKit and five-platform Apple XCFramework builds`
   — package product, generated Swift, async facade, CryptoKit providers, Swift journeys,
   Apple build/typecheck and Swift test scripts. Keep generated binaries out of Git.
3. `Add Kotlin JVM bindings and script Android AAR packaging`
   — generated Kotlin, local JCA facade/providers, Gradle wrapper/project, JVM journeys,
   Android build and Kotlin test scripts.
4. `Measure native binding overhead and document platform handoff`
   — benchmark harnesses/results, performance FFI section, integration guide, migration status,
   handoff, and artifact/cache ignore rules.

No commits were attempted because this sandbox cannot write `.git`. All changes are available
for review in this worktree. Work stops with this handoff.
