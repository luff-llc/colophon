# Native bindings (0.3)

`colophon-ffi` exposes the storage-backed `NativeEngine` used by native sessions and the
compatible `NativeLibrary` API. It does not implement protocol rules or filesystem storage. `ColophonKit` is the Swift product. `sdk/kotlin` contains the JVM bindings and a local
key-provider facade. Engine records are fetched on demand through host callbacks; deltas cross as maps of exact bytes; domain inputs, state,
and tool results cross as UTF-8 JSON bytes. Members, grants, attribution, ledger events,
namespace evidence, changes, and expected refusals have generated types.

## Storage engine transport

`NativeEngine.openInventory` accepts one binary inventory (little-endian u32 UTF-8 path
length, path, u32 UTF-8 provider-version length, version; empty version means unavailable).
`open` also accepts generated lists/maps. `EngineRecordSource.read` returns coherent exact
bytes synchronously on the session worker. Callbacks must be thread-safe and must not reenter
the engine; the engine uses a nonblocking mutex so reentry fails instead of deadlocking.
Signing and agreement happen outside that mutex through the existing host key-provider API.

`NativeCheckpointPreparation` returns a member signing request. `NativeCheckpointOpening`
verifies the protected ticket before returning an agreement peer. Their finished opaque key
handles feed `NativeEngine`; raw cache keys never cross FFI. `checkpoint` returns an encrypted,
member-bound envelope for `CheckpointCache`, never a synchronized library record. The new
binary private envelope avoids base64 copies of large caches; the existing JSON envelope remains
readable. The engine's authenticated-prefix format and trust rules are unchanged.

The engine exports named `query`, namespace `revisions`, delta `ChangeSummary`, readiness/access,
member metadata, bounded operation receipts, live generation checks, blob writers/readers, and
independent `verifyBatch` audits. `commit` rejects actions from another engine or an obsolete
revision. `mergeObserved` binds provider tokens and re-verifies changed tokens. After durable
publication and exact readback, hosts replace the source and acknowledge provider versions.
Authority/layout validation precedes content reads; current authority still governs every write.

Full `ledger` and administrative approval/revocation are explicit compatibility materializations.
They can read/decrypt history and are not part of launch, named queries or passive writes.
See [the session handoff](handoff-engine-sessions.md) for lifecycle and performance limits.

## Build on an Apple Silicon Mac

Install Xcode with the iOS and visionOS SDKs, select it with `xcode-select`, and use Swift 6.2+
(the async facade uses `@concurrent`). The root `Package.swift` is named **ColophonSDK**
and exports only 0.3 products. The 0.1 reference package and CLI live in `reference/swift/`.
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

## Package identity and coexistence with 0.1

SwiftPM derives dependency identity from the last component of the dependency path or URL
(lowercased, with `.git` removed). `Package(name: "ColophonSDK")` is the display/package name;
changing it or the `.package(name: ...)` label does **not** rename a `colophon` identity.
An app with `packages/Colophon` must point at an SDK path whose last component differs.

From the consuming repository, make a separate checkout (choose this or the submodule below):

```sh
mkdir -p packages
git clone https://github.com/luff-llc/colophon.git packages/ColophonSDK
# Check out the reviewed restructure revision in that checkout when it is available.
(cd packages/ColophonSDK && bash scripts/build-apple.sh)
```

Or add a pinned submodule at that same path:

```sh
git submodule add https://github.com/luff-llc/colophon.git packages/ColophonSDK
git submodule update --init --recursive
(cd packages/ColophonSDK && bash scripts/build-apple.sh)
```

These are consumer setup commands, not a claim that this uncommitted restructure is published.
For an existing SDK checkout named `colophon`, move it to `packages/ColophonSDK` and update the
package reference; do not rename the app's existing `packages/Colophon` package.
In a consumer `Package.swift` at that repository root:

```swift
dependencies: [
    .package(path: "packages/Colophon"),
    .package(path: "packages/ColophonSDK"),
],
targets: [
    .target(name: "Shelf", dependencies: [
        .product(name: "ColophonBooks", package: "colophon"), // app's 0.1 stack, if needed
        .product(name: "ColophonBooksKit", package: "colophonsdk"),
        .product(name: "ColophonMigration", package: "colophonsdk"),
    ]),
]
```

In Xcode, remove the external SDK reference ending in `colophon` (retain the app's local
Colophon reference), choose Add Local Package for `packages/ColophonSDK`, and attach only the
0.3 products each target needs. Update any project generator's local package path too, regenerate
it, then resolve packages and build the entire app graph. Relative paths are relative to the
consumer manifest/project, so adjust them for an `apps/suite` project.

The submodule's remote may still end in `colophon.git`: SwiftPM sees the **local dependency
path** `ColophonSDK`. A direct remote `.package(url: "https://github.com/luff-llc/colophon.git", ...)`
still collides; use a real separately named remote/mirror ending in `ColophonSDK.git` if remote
resolution is required. A manifest label, product name or module alias cannot fix package
identity. No such alternate hosted URL or binary release is supplied here.

Do not add `reference/swift` or `ColophonLegacyAdapter` to a graph that already contains the
app's own 0.1 modules. Implement the small [legacy-source protocol](migration.md) over those
existing modules instead. The root SDK no longer exports any of the colliding 0.1 module names.

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

## Android AAR and session SDK

Install Android command-line tools, SDK platform 35, NDK r28 or newer, JDK 17, and `cargo-ndk`.
`sdk/android` is a Gradle Android library (`org.luff.colophon:colophon-android`, minSdk 33,
compileSdk 35) that compiles the generated Kotlin, the session, Keystore keys, and the
file-backed store, and packs both JNI ABIs.

```sh
cargo install cargo-ndk --locked
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/<installed-version>"
bash scripts/build-android.sh
```

The script installs the two Rust targets, builds `arm64-v8a` and `x86_64` shared libraries
with cargo-ndk (`-p 33`), and assembles `sdk/android/build/colophon-android-0.3.0.aar`.
Consuming apps must also declare `org.jetbrains.kotlin:kotlin-stdlib:2.2.21`,
`net.java.dev.jna:jna:5.18.1@aar`, and `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2`
so JNA's Android `libjnidispatch` is packaged; a local AAR alone does not carry POM metadata.
Validate both the Rust and JNA libraries on a device, including 16 KB page-size compatibility.
NDK r28+ enables 16 KB alignment by default; application packaging must support it too.
[Android guidance](https://developer.android.com/guide/practices/page-sizes).

`KeystoreKeys` creates separate non-exportable P-256 signing (SHA-256) and agreement
(`PURPOSE_AGREE_KEY`) aliases in `AndroidKeyStore`, using StrongBox when available and the
TEE Keystore otherwise. It never mints software keys on a hardware failure. `SoftwareKeys`
is the explicit test provider. See [Android session](android.md).
[Android key purposes](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_AGREE_KEY),
[cargo-ndk](https://github.com/bbqsrc/cargo-ndk).

## Release artifact

Development uses `.binaryTarget(name: "ColophonFFI", path: "sdk/apple/ColophonFFI.xcframework")`.
After building and testing all slices, create the archive and checksum:

```sh
(cd sdk/apple && zip -qry ColophonFFI-0.3.0.xcframework.zip ColophonFFI.xcframework)
swift package compute-checksum sdk/apple/ColophonFFI-0.3.0.xcframework.zip
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
and [session contracts](session.md). Sessions use the `NativeEngine` callback/checkpoint bridge
described above; direct `Library` callers retain the compatibility snapshot API.

### Read-only named queries

`NativeLibrary.query(namespace:name:arguments:now:) -> JsonOutcome` is an additive read path.
`Library.query(namespace:name:arguments:)` wraps it asynchronously. It calls core `Library::query`
directly, requires read access, and cannot prepare or commit writes. This preserves the bounded
0.3 query envelopes even when names such as podcast `episode`/`queue` also name operations.
The four typed domain products use the equivalent `NativeEngine.query` path through
`ColophonSession`; apps normally use their stores.

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

## 0.3 scoped replicas

Session adapters call `NativeLibrary.setReadScope(namespaces)` after authority-only opening and before
merging content. Low-level hosts that filter storage must do the same (or use Rust storage-engine
`EngineOptions.namespaces`). The empty list means a complete library listing. Queries outside the
selected scope are unavailable, and capped grants extending beyond that scope yield explicit
`budgetScopeUnavailable` rejections: their grant-wide budget cannot safely be counted from a subset.
This does not block unrelated writers or require reading sibling namespaces.
