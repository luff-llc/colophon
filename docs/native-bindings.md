# Native bindings (0.2)

`colophon-ffi` wraps the public Rust `Library` API; it does not implement protocol rules or
storage. `ColophonKit` is the Swift product. `sdk/kotlin` contains the JVM bindings and a local
key-provider facade. All records cross as maps of path to exact bytes; domain inputs, state,
and tool results cross as UTF-8 JSON bytes. Members, grants, attribution, ledger events,
namespace evidence, changes, and expected refusals have generated types.

## Build on an Apple Silicon Mac

Install Xcode with the iOS and visionOS SDKs, select it with `xcode-select`, and use Swift 6.2+
(the new async facade uses `@concurrent`). The existing 0.1 products remain in `Package.swift`.
The local binary artifact is ignored by Git and must be built before SwiftPM resolves the package.

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
rustup toolchain install nightly --component rust-src
bash scripts/build-apple.sh
COLOPHON_SOFTWARE_KEYS=1 swift test
```

The build creates `sdk/apple/ColophonFFI.xcframework`: macOS arm64, iOS device arm64, iOS
simulator arm64, visionOS device arm64, and visionOS simulator arm64. visionOS uses nightly
`-Zbuild-std=std,panic_abort`; the others use stable. `VISIONOS_TOOLCHAIN` can select a dated
nightly for a release. `SKIP_VISIONOS=1` explicitly builds only the three stable targets when a
builder cannot install nightly/rust-src or lacks the visionOS SDK. Never publish that reduced
artifact as a five-platform release. Neither Intel macOS nor Intel simulators are included.

`generate-bindings.sh` builds the host dylib without generator features, builds the in-repo
`uniffi-bindgen` target with the separate `bindgen` feature, and emits Swift and Kotlin from
that library. The generator uses UniFFI 0.32.2's global configuration format. Generated source,
headers, and module maps are checked in; regenerate them together with binaries after API edits.
Do not edit generated code by hand or mix binaries from different versions.

Restricted builders may need `bash scripts/test-swift.sh`, which keeps module caches local
and disables SwiftPM's nested `sandbox-exec`. This does not bypass the enclosing sandbox or
make macOS file coordination/backup services available. See the handoff for the observed
baseline failures; the tests are not skipped or weakened by that script.

## Swift

```swift
import ColophonKit

let owner = SoftwareKeys() // Persist through host-protected storage before creating a library.
let library = try await Library.create(
    owner: owner, label: "My library", ownerLabel: "My Mac", namespaces: ["notes"])
let records = try await library.records // Persist and sync these exact immutable records.
let recovery = library.recoveryKeys     // Persist separately; never put private keys in records.

let result = try await library.write(
    namespace: "notes", kind: "createNotebook",
    payload: Data(#"{"id":"ideas","title":"Ideas"}"#.utf8))
switch result {
case .success(let operation): print(operation.id)
case .failure(let denial): print(denial.reason, denial.detail)
}
```

`Library.create/open/requestAccess`, `approve`, `revoke`, `write`, `view`, `tools`, `call`,
`handover`, and `recover` mirror the JavaScript facade. `GrantOptions.narrowing` fills omitted
scope fields from the request; supplied arrays must narrow it. `Outcome.get()` throws an
`AccessError` containing the typed denial when a caller prefers Swift error handling. Malformed
records and host failures throw `BindingError`/provider errors rather than access outcomes.

`merge(records:)` applies authority synchronously on the actor. Await `ready()` before reading
newly shared keys. Mutation methods do this themselves. Records are snapshots, not a live map;
obtain a new snapshot after mutation and persist the delta. A successful commit can be followed
by an unlock-provider failure: inspect/persist `records` even when that later step throws.
There is no storage rollback or implicit network sync.

`NativeLibrary` is internally mutex-protected and UniFFI marks its Swift handle `Sendable`.
Generated records/enums are immutable `Sendable` values. Change summaries expose a local
revision and conservatively mark every declared namespace after a record change. Duplicate
merges do not increment the revision. Unlocking a new key increments it for that namespace.
These revisions are invalidation hints, not persistent checkpoint or protocol ordering IDs.

### Keys and async behavior

- `SoftwareKeys` uses CryptoKit and can restore from its two private scalar representations.
  Hosts must protect and persist these independently of the record map.
- `SecureEnclaveKeys()` requires available hardware and propagates keychain/authentication
  errors. `SecureEnclaveKeys(fallback: .software)` permits software only when hardware is
  unavailable. The environment variable used by the 0.1 tests does not change this policy.
  Persist `signingReference` and `agreementReference` for hardware-backed keys. If explicit
  fallback occurred, `softwareFallbackKeys` exposes the software provider for persistence.
- Secure Enclave references are device-bound; moving records to another device does not move
  the private keys. Recovery is a separate provider and should be stored independently.
- The generated synchronous `KeyProvider` callback is useful for CryptoKit/JCA local calls.
  It exposes `signingPublicKey`, `agreementPublicKey`, `sign(body:)`, and `agree(peer:)`.
  No callback runs while the library mutex is held.
- `AsyncKeyProvider` is the Swift suspension boundary. Implement it for authentication or a
  remote store; `publicKeys`, `sign`, and `agree` can await normally. There are no semaphores,
  blocked Rust futures, or Rust executor dependencies. A callback needing asynchronous work
  should use these two-phase APIs rather than blocking its synchronous callback thread.

Public keys are uncompressed X9.63 P-256 points (65 bytes). Signatures are ECDSA/SHA-256 raw
`r || s` (64 bytes), not DER. ECDH returns the raw shared secret (32 bytes). Swift and Kotlin
providers convert platform representations appropriately; private scalars never cross FFI.
The native layer takes a fresh 32-byte seed and UTC timestamp for each action; the facades
supply them from platform cryptographic randomness and clocks.

Actor reentrancy is deliberate. If records change while a key provider is suspended,
`commit` throws `BindingError.StaleAction`; prepare again with fresh entropy after reviewing
the new state. There is no hidden retry. Cancellation is checked before committing a signed
Swift mutation; after commit the records remain committed. Cancellation cannot force a host
provider to dismiss its own authentication prompt.

## Kotlin JVM

Use JDK 17 (the machine's default JDK 27 is too new for this Gradle pin):

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export GRADLE_USER_HOME="$PWD/.gradle-home"
bash scripts/generate-bindings.sh
bash scripts/test-kotlin.sh
```

The Gradle wrapper is checksum-pinned at 8.14.3; Kotlin is 2.2.21 and JNA is 5.18.1.
Tests load `target/release/libcolophon_ffi.dylib` using `jna.library.path`. Runtime dependencies
are Kotlin stdlib and JNA; no Android SDK or NDK is required for this path.

```kotlin
val owner = PlatformKeys.software()
ColophonLibrary.create(owner, "My library", "My Mac", listOf("notes")).use { library ->
    val result = library.write("notes", "createNotebook",
        """{"id":"ideas","title":"Ideas"}""".toByteArray())
    val operation = result.get() // AccessException carries a typed Denial on refusal.
}
```

`ColophonLibrary` is synchronous for local key stores; use a worker dispatcher in an app.
Its `native` property exposes the complete two-phase interface for suspending Kotlin stores:
prepare, read `signingSteps()`, suspend to sign, then `commit`; similarly `beginUnlock`, suspend
for ECDH, then `finishUnlock`. The same stale-action rules apply. Close `HostAction` and
`NativeLibrary` handles with `use`/`close` to release them deterministically. Generated records
use `val`, but JVM byte arrays remain mutable; do not mutate shared input arrays concurrently.

## Android AAR (scripted, not run on this machine)

Install Android command-line tools, an SDK platform, NDK r28 or newer, JDK 17, and `cargo-ndk`:

```sh
cargo install cargo-ndk --locked
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/<installed-version>"
bash scripts/build-android.sh
```

The script installs the two Rust targets and builds `arm64-v8a` and `x86_64` shared libraries
with cargo-ndk. It packs `sdk/android/build/colophon-0.2.0.aar` with `AndroidManifest.xml`,
`classes.jar`, `jni/<abi>/libcolophon_ffi.so`, and consumer ProGuard rules. No Gradle Android
plugin or SDK installation is added to this worktree. In the consuming app also declare
`org.jetbrains.kotlin:kotlin-stdlib:2.2.21` and `net.java.dev.jna:jna:5.18.1@aar` so JNA's
Android `libjnidispatch` is packaged; a local AAR alone does not carry dependency metadata.
Validate both the Rust and JNA libraries on a device, including 16 KB page-size compatibility.
NDK r28+ enables 16 KB alignment by default; application packaging must support it too.
[Android guidance](https://developer.android.com/guide/practices/page-sizes).

The default minimum API is 31 because Android Keystore adds `PURPOSE_AGREE_KEY` there.
Create separate P-256 signing and agreement aliases in `AndroidKeyStore`, with signing/SHA-256
and agreement purposes respectively, then pass their `KeyPair` handles to `PlatformKeys`.
Private-key export is never requested. Configure user authentication and StrongBox according
to the host's policy; do not silently replace an unavailable hardware key with software.
Hardware-backed Keystore and StrongBox are not exercised by the JVM tests.
[Android key purposes](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_AGREE_KEY),
[cargo-ndk](https://github.com/bbqsrc/cargo-ndk).

## Release artifact

Development uses `.binaryTarget(name: "ColophonFFI", path: "sdk/apple/ColophonFFI.xcframework")`.
After building and testing all slices, create the archive and checksum:

```sh
(cd sdk/apple && zip -qry ColophonFFI-0.2.0.xcframework.zip ColophonFFI.xcframework)
swift package compute-checksum sdk/apple/ColophonFFI-0.2.0.xcframework.zip
```

Publish that exact archive as a release asset only after review, then replace the path target
with the URL/checksum target recorded in `handoff-ffi.md`. The documented release URL is a
proposed asset location, not a claim that an asset has been published. Regenerating/repacking
an archive requires a new checksum. Keep the generated Swift source and binary in the same
release. The static library's archived size includes Rust's standard library; dead stripping
in the final app means this is not an estimate of app download size.

## Validation and measurements

`bash scripts/bench-ffi.sh` creates a fixed 21-operation fixture, runs native Rust and the Rust
binding facade, then optimized Swift and a warmed JVM through their actual ABI. Setup and
host signature generation are outside timing; signature verification stays inside it. See the
FFI section of `performance.md` for results and limitations. This is transport evidence for
the current core, not an incremental-engine or 100k-operation performance claim.

UniFFI references: [two-phase host scheduling needs no Rust executor](https://mozilla.github.io/uniffi-rs/latest/futures.html),
[callback interfaces](https://mozilla.github.io/uniffi-rs/next/types/callback_interfaces.html).

`bash scripts/check-apple-swift.sh` also typechecks the generated Swift and CryptoKit providers
against the iOS device/simulator and visionOS device/simulator SDKs. This is a compile check,
not simulator or physical-device execution.

## Apple app layer

Apps can now depend on `ColophonSession`, with `ColophonKitStorage` underneath, instead of
assembling persistence and lifecycle around `Library` directly. See [new app](new-app.md)
and [session contracts](session.md). The current adapter still uses this snapshot binding;
the core storage-backed engine is available, but its `RecordSource` and verified-prefix
checkpoint interfaces still need a native bridge before this adapter can consume them.

### Read-only named queries

`NativeLibrary.query(namespace:name:arguments:now:) -> JsonOutcome` is an additive read path.
`Library.query(namespace:name:arguments:)` wraps it asynchronously. It calls core `Library::query`
directly, requires read access, and cannot prepare or commit writes. This preserves the bounded
0.2 query envelopes even when names such as podcast `episode`/`queue` also name operations.
The four typed domain products use this through `ColophonSession`; apps normally use their stores.

## Pure 0.1 migration bridge

`importLegacyBatch(namespace:operations:stateJson:)` / `import_legacy_batch` exposes all four
core domain importers. `LegacyImportOperation` carries source library, author ID/label, old
operation ID, exact signed-body SHA-256, kind/version, original payload JSON, admitted order,
original claimed-date JSON, admission and **evaluated old fold outcome**. The binding does not
verify old signatures or infer effectiveness from admission. Batches are limited to 1,024
records and must have increasing admitted order within a source library.

`contextJson` is the corresponding domain's serialized import context. Listening and saved
use their camel-case serde field names; notes uses its existing snake-case context field names.
Missing context fields receive the core type's defaults. Missing semantic facts fail closed to
evidence. Books instead carries its own old-fold/identity context in opaque `stateJson`.
Commands have a stable output key and source index. `expectFromChild` identifies a prior
saved-reading child whose actual signed ID must be substituted before writing. Bind planned
book heads through `bindLegacyImportState` after signing each batch. These are planned keys,
never new authenticated operation IDs. Evidence and blob JSON preserve the complete core
results, including baseline flags and publication-barrier requirements. The host must durably
bind actual output IDs, archive exact source envelopes and handle blob publication.

The generated Swift/Kotlin APIs and three-slice XCFramework were rebuilt for this bridge with
`SKIP_VISIONOS=1`; this artifact is not a five-platform release. The migration handoff records
acceptance and remaining engine requirements.

## Engine3 import publication and blobs

Generated Swift/Kotlin now expose `NativeLibrary.beginImport`, `beginBlob`, `readBlobChunk`,
`NativeBlobWriter.push/finish`, `BlobSource`, `BlobReadOutcome`, `importOutputId`,
`importOccurrenceId`, `importIdentityCategory` and `reconcileImportPrefix`. JSON arguments use
the [engine3 wire/API shapes](engine.md#engine3-authenticated-import-storage-and-blobs).
`LegacyImportCommand.baseline` carries the trusted transform receipt separately from payload
extensions. `beginImport` produces one signed parent with deterministic virtual child revisions;
use `importReceipt` to verify its accepted bindings after persistence and refreshed admission.

Blob callbacks supply only immutable ciphertext. The library checks grants before fetching and
again after callback reentry; available results contain authenticated plaintext. Missing,
inaccessible and invalid content are separate outcomes. Hosts stream at most 64 KiB per call and
verify the complete plaintext descriptor before certifying the full original. The Kotlin ABI
regression exercises publication, evidence, deterministic bindings, blob read/missing/corruption,
and a reentrant callback. The Swift migration regression queries evidence through synchronized
records and verifies source-unit crash/retry behavior.
