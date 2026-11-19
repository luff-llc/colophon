# Android and Kotlin on Colophon 0.5

`com.luff.colophon.session` is the Kotlin session over the 0.5 UniFFI exports: the same session the Swift SDK gives an
Apple app ([session.md](session.md)), with the same names where Kotlin allows. It is plain Kotlin/JVM in `sdk/kotlin`
(so its tests run on a Mac), and `sdk/android` packages it with the native library and the Android pieces in
`org.luff.colophon.session`. The contract underneath is [bindings-05.md](bindings-05.md). Taupe for Android and Taupe
for iPhone share one library through it.

| Piece | Kotlin | What it is |
| --- | --- | --- |
| Session | `ColophonSession` | The one object an app holds. State is `state: StateFlow<SessionState>` (phase, revision, members, requests, notices, homes, duties, sync state, home faults and issues). Every call is `suspend` and safe to call from the main thread: the session's state changes on one serial lane, and all work runs in the worker. |
| Worker | `SessionWorker` (internal) | A port of the Swift worker: a gate (mutex) around complete operations, reconcile, owner operations, creation with the creation's own engine, the exchange with every home, the journal and the sealed saved state. |
| Engine | `ColophonEngine` | One `AccountEngine` on its own serial dispatcher; `execute(custody)` runs prepare, PRF, sign, finish. |
| Keys | `AsyncKeyProvider`, `KeyCustody`, `SoftwareKeys`, `SecretBytes` | Custody answers the engine's signing steps, PRF requests, unlock inputs and epoch agreements; the core never calls a key provider. |
| Storage | `RecordMedium`, `FolderMedium`, `MemoryMedium` | The record store the engine reads. `FolderMedium` writes each batch all or none across a kill (staged, a commit record, moved into place) and never follows a symbolic link. |
| Homes | `HomeConfiguration`, `HomeTransport`, `HttpHomeTransport` | `HttpURLConnection`: no cookies, no cache, no redirects, `https` only (loopback `http` with the testing option), each response bounded. One home is the supported configuration in 0.5; more than one is experimental (spec §13.1). |
| Android | `AndroidSession.medium`, `.privateDirectory`, `.memberKeys`, `.deviceSecrets`; `KeystoreDeviceSecrets`; `PasskeyController` | App-private storage in `noBackupFilesDir`; the member key in Android Keystore (the 0.4 `KeystoreKeys`, StrongBox first); the device key sealed by a Keystore AES key; the person's passkey through Credential Manager with PRF. |

**A stopped account, a home's refusals, waiting for approval.** The Kotlin session has the same names and behaviour as the
Apple session (`docs/session.md`, "A stopped account, a home's refusals, waiting for approval"): `SessionPhase.Stopped(seq,
layout)` from the verified status only, readable and with no exchange; `HomeProblem.RemoteCallRefused(code,
retryAfterSeconds)` for any `refused:` name a home gives, validated by `HomeRefusal`; `HomeProblem.HomeUnavailable` for a
home's `503 {"result":"unavailable"}`; `HomeProblem.WaitingForApproval` for a joining device's `refused:revoked`. Tests:
`StoppedAndRefusalTest` (`sdk/kotlin`, JVM, against the real relay).

**A namespace this member was never granted.** A session is `denied` only when its own member has lost access it was
granted, never because the library declares namespaces this member was never granted (`libraryNamespaces` wider than
`namespaces`). For each namespace in `libraryNamespaces` the session asks the engine's `access`: no denial, the namespace
is readable; `notReadable` or `unavailable`, the phase is `unavailable(reason)`; `notGranted` for a namespace that the
member's verified grant (`me().member.grant.namespaces`) does not name, while the member is not provisional, is not this
member's namespace and is skipped (neither denied nor published); anything else (`revoked`, `expired`, `budgetSpent`,
`notGranted` while provisional or on a granted namespace) is `denied`. Revisions are published only for the library
namespaces whose `access` has no denial. Tests: `LibraryNamespacesTests` (Swift), `LibraryNamespacesTest` (Kotlin), "a
member of a wider library" (JS).

## Adopting it in an Android app

Build the AAR (`bash scripts/build-android.sh`: the release library for `arm64-v8a` and `x86_64` with cargo-ndk, the
bindings, then `assembleRelease`; the artefact is `sdk/android/build/colophon-android-0.3.0.aar`, the script's old
name) and add it with its runtime:

```kotlin
dependencies {
    implementation(files("libs/colophon-android-0.3.0.aar"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.2.21")
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.credentials:credentials:1.5.0") // passkeys
}
```

One session per process and account, made in `Application`:

```kotlin
val session = ColophonSession(SessionConfiguration(
    memberLabel = "Taupe", namespaces = listOf("reading.saved"),
    medium = AndroidSession.medium(context), privateDirectory = AndroidSession.privateDirectory(context),
    keys = AndroidSession.memberKeys(context, "org.luff.taupe.member"),          // this app's member (Keystore)
    ownerController = PasskeyController(PasskeyProvider.restore(descriptor, CredentialManagerAdapter(activity)),
                                        authorityOrigins = appPasskeyOrigins(context) + "https://id.luff.works"),
    homes = listOf(HomeConfiguration("https://relay.toolsperson.com/v1/libraries/<slot>/",
                                     request = { account -> homeService.memberRequest(account) })),
    deviceSecrets = AndroidSession.deviceSecrets(context)))
lifecycleScope.launch {
    session.restore()
    if (session.phase == SessionPhase.NoLibrary) session.create()        // appoints the home, approves this device
    session.perform(DomainCommand("reading.saved", "capture", payloadJson), session.observedRevision)
}
session.state.collect { render(it.phase, it.notices) }                    // pending changes, no home, locked, ...
```

* **The passkey's origins.** `PasskeyController` puts every platform origin of `authorityOrigins` (the app's
  `android:apk-key-hash:...` from `appPasskeyOrigins`) into the descriptor's `origins` too: the core admits a platform
  authority origin only when `origins` names it (spec §3.1). `AndroidSessionTest.anAndroidAppOriginCreatesAndApproves`
  runs this call with assertions made under such an origin.
* **A second device** restores over a copy of the history (a shared folder) or with nothing and shows
  `SessionPhase.WaitingForApproval` (no code). Approval spends a confirmed pairing for exactly its key (spec §7.3, §9.1):
  the owner device scans the request the new device shows (`exportRequest()` as a QR code, then `scanRequest(bytes)` and
  `approve(scanned.request, scanned.pairing)`), or the two run the six-digit code (`beginJoinPairing()` on the new device;
  `beginApproval(commitment)`, `approvalCode(pairing, e, nb)` and `pairing.confirm()` on the owner device; `rejectPairing`
  on both when the digits differ; `abandonApproval` to cancel). One ceremony at a time and five failures an hour, kept in a
  sealed ledger in the private directory, as `docs/session.md` describes. The new device learns its approval through the
  home (`syncNow()`).
* **Reads**: `query(namespace, name, argumentsJson)` and `view(namespace)`; there is no typed domain kit in Kotlin yet
  (the Swift `ColophonSavedKit` has no Kotlin twin): an app passes the payload JSON its domain defines.
* **Blobs**: `putBlob(bytes | file, ...)`, `blobAvailability`, `blobData`, `prefetchBlob`, `downloadRequiredBlobs`,
  `setBlobReference`. A required blob arrives with the exchange, an optional one when asked.
* **What a person must see**: `notices.pending` (with `vetoable`), `veto(digest)`, `proposeTransition(json)`,
  `notices.unseenActivations` and `acknowledgeActivation(seq)`, `notices.noHome`, `duties` (sole device,
  submissions, dead transitions, the removal follow-up with `removeFollowUp` / `keepFollowUp`). `duties` also exposes
  optional route-registration state for host extensions; routes are not a 0.5 requirement.
* **Lock** on `onStop` (`lock()`), `unlock()` on `onStart`. `shutdown()` locks the engine and stops the loops.
* Background exchange polls every `duties.pollIntervalMs`; `requestSync()` wakes it, `stopSync()` stops it.

## What is proven, and how

| Claim | Test | Where it ran |
| --- | --- | --- |
| Two Kotlin devices sync through the real relay (`bun relay/server.js`, the Rust home module, calls required): create with the home, approve a second device that learns it through the home, both write and read with a required and an optional blob, approve then revoke a third (refused with exactly `refused:revoked`, by the home under `members`, by its own check under `public`), propose a policy change on one device and veto it on the other. Under `members`, `public`, and two homes at `headQuorum` 2. | `RelayJourneyTest` (`sdk/kotlin`) | JVM on macOS |
| A pass cancelled mid-request abandons the pass; the next one starts from the head. | `ExchangeCancelTest` | JVM |
| Creation without a home only by opt-out; `https` only; writes bound to the observed revision; lock and unlock; a folder store reopens cold after the session wrote its sealed saved state; a second device approved over a shared store, then revoked (`Denied`); a failing owner key is a key failure. | `SessionTest` | JVM |
| Keys, secrets wiped after their call, DER to `r||s`, custody refusals; the folder's all-or-none batches and crash recovery; transport bounds and redirects; the JSON reader. | `KeysTest`, `MediumTest`, `TransportTest`, `JsonTest` | JVM |
| A passkey owner (synthetic Credential Manager client: real ES256 assertions, PRF `results.first`) creates the account with its PRF slot, opens it by PRF to approve a device; a passkey without PRF fails creation and stores nothing; the device key wrapping. | `AndroidSessionTest` (`sdk/android`, unit) | JVM |
| On Android: the AAR's native library, member and owner keys in Android Keystore (signing and ECDH by Keystore), the device key sealed by a Keystore AES key, app-private folder storage: create, write, a blob, lock and unlock, a cold reopen after the sealed saved state was written (whether the engine resumed from it rather than replaying is not asserted). | `OnDeviceSessionTest` (`sdk/android`, instrumented) | API 36 arm64 emulator (`google_apis`), not a phone |

`scripts/test-kotlin.sh` builds the release library, checks the committed bindings against the generator, builds the
home module and runs every JVM test in `sdk/kotlin` (the 0.4 wrappers too), then fails if any relay process is left.
`scripts/test-android.sh` runs `sdk/android`'s unit tests; the instrumented test needs a running emulator
(`connectedDebugAndroidTest`).

## Not built or not proven

* **The relay journey on Android.** It runs on the JVM only; on the emulator the session ran without a home.
* **A physical device**, StrongBox, and Keystore keys that require user authentication (`KeystorePresence`).
* **Passkeys against Credential Manager.** `PasskeyController` is written over the 0.4 `PasskeyProvider` and
  `CredentialManagerAdapter`; it has run only with a synthetic client. Registration is the 0.4 `PasskeyProvider.register`
  (it keeps no registration PRF output). The Swift move's one-assertion two-salt ceremony is not implemented.
* **Pairing and seed transfer** (`addController`, `transferSeed`, `acceptSeedTransfer`) are ported from Swift but not
  exercised by a Kotlin test; the core's own journeys cover them through the exports.
* Delivery-route registration is a host callback (the relay offers none). No ingress inbox, no Swift-move session
  steps, no typed domain kits in Kotlin.
* A Kotlin `FolderMedium` assumes one process per folder (Android app-private storage); it takes no file lock.
* **Known gap: the spec §6.4 warnings before creation.** This session does not yet give the §6.4 warnings before the genesis is written: it exposes `soleDevice` after creation. The warnings stay normative for a host (a person must see them before an account is created). Until the session gives them, an app checks the three conditions from the creation parameters (one home, every control key on one device, exactly one recovery unit) and warns before it calls create. Spec §21.1 lists this among what 0.5.0 does not do.

## The 0.4 session (`org.luff.colophon`, still in the AAR)

The 0.4 Android session below stays in the AAR for apps that have not moved yet; it uses the 0.4 exports, which are
unchanged. New work uses the 0.5 session above.

Sessions use the storage engine through `NativeEngine`, with member-protected checkpoints in
`CheckpointCache`. Checkpoints are scheduled after one idle second; `flushCheckpoint()` is an
explicit persistence barrier. A valid cache skips covered history verification/decryption;
named queries and passive writes use engine state and namespace revisions. Public session,
domain-store, write and blob APIs remain source-compatible.

The compatibility `ledger` is now lazy: Swift materializes on property access; Kotlin on List
inspection (size, indexing, iteration or equality). Reading a large ledger can block the calling
thread and is outside the fast launch path. Kotlin publishes lazy snapshot identities without
forcing List equality during StateFlow updates. A retained, not-yet-inspected Kotlin ledger reads
engine history when first inspected; it is not a frozen historical snapshot. Use named queries
for app screens. See [design, checks and limitations](handoff-engine-sessions.md).

Storage providers may supply complete change deltas. Built-in memory stores do; folder providers
continue to enumerate metadata and compare versions. Providers without a synchronous Swift
`engineReader()` implementation use the protocol's conservative snapshot fallback. Custom readers
must be thread-safe, synchronous, coherent, and must not call the engine recursively.

`sdk/android` is the Gradle Android library `org.luff.colophon:colophon-android`
(minSdk 33, compileSdk 35). It packages the UniFFI Kotlin bindings, `libcolophon_ffi.so`
for `arm64-v8a` and `x86_64`, an Android Keystore `KeyProvider`, a file-backed record
store, and `ColophonSession`.

Build the AAR once:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export ANDROID_HOME=/Users/mikelxc/.local/share/luff/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/30.0.16248370"
bash scripts/build-android.sh
```

The artifact is `sdk/android/build/colophon-android-0.3.0.aar`.

### Add the AAR to an app

Copy the AAR into the app module (for example `app/libs/`) and declare the
UniFFI/JNA runtime that a local AAR does not carry:

```kotlin
dependencies {
    implementation(files("libs/colophon-android-0.3.0.aar"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.2.21")
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
```

`jna:5.18.1@aar` is required so JNA's `libjnidispatch` is packaged; the Kotlin
bindings load `libcolophon_ffi` through it. Keep `arm64-v8a` and `x86_64` in the
app's `ndk.abiFilters` if you override ABIs. NDK r28+ aligns the native library
for 16 KB pages; the app's packaging must allow that too.

### Session usage

Own one session at the process entry point. Await `restore()` before dependent
work; render `phase` explicitly and open product UI only on `Ready`.

```kotlin
val session = ColophonSession(
    SessionConfiguration.app(
        filesDir = filesDir,
        memberLabel = "My app",
        namespaces = listOf("reading.saved"),
        keys = KeystoreKeys.openOrCreate(this, "colophon.member"),
    ),
)
session.restore()
if (session.phase.value is SessionPhase.NoLibrary) session.create()
val observed = session.observedRevision
session.perform(DomainCommand.saveLink(url = "https://example.com/", title = "Saved"), observed)
val links = NamespaceStore.savedLinks(session)
links.load(SavedLinksQuery())
```

To share the library with other devices (an iPhone, another Android), add a relay slot
([sync](sync.md)) and keep its token in app-private encrypted storage:

```kotlin
SessionConfiguration.app(filesDir, "My app", listOf("reading.saved"), keys,
    relay = RelayConfiguration("https://relay.example.ts.net/v1/libraries/home", token))
```

Collect `session.syncState` and call `session.syncNow()` from `onResume`. With an empty local
store the session stays `Unavailable` until the relay has been listed; it never reports
`NoLibrary` for an unreachable relay.

`KeystoreKeys` creates non-exportable P-256 signing and agreement keys.
Construction does not touch Keystore; the first provider call runs on the
session thread. StrongBox is requested first. A `ProviderException` or
`InvalidAlgorithmParameterException` on that attempt falls back to the TEE and
deletes aliases that attempt created. On the API 36 `google_apis` arm64
emulator, `usedStrongBox` was false. An incomplete alias pair fails closed and
is left in place. If both aliases are missing for a library that already
recorded an identity, the session enters `Failed` and does not submit a pairing
request. Keystore may still generate a new pair, which the journal refuses.
Hardware failure does not substitute a software key. Use `SoftwareKeys.stored(file)`
in tests; a corrupt file is left in place. Writes carry the revision observed
when the action began. Core FFI, storage, and signing run on one background
thread.

### How this differs from the Apple session

- Observation is `StateFlow<SessionPhase>` rather than an `@Observable @MainActor` type.
- Storage is the app's private files directory. Immutable records try `link(2)`,
  then `renameat2(RENAME_NOREPLACE)`, then `Files.copy` (`O_CREAT|O_EXCL`).
  The API 36 emulator denies `link(2)` in private app storage, so publication
  uses `renameat2`. The journal and checkpoint use a replacing atomic rename.
  There is no App Group, iCloud, or `NSFileCoordinator` location policy.
- Identity is Android Keystore. StrongBox is requested and falls back to the TEE
  when generation throws a provider or parameter error. The instrumented image
  reported a TEE key (`usedStrongBox == false`). Software keys are an explicit
  test provider. The Apple session uses the Secure Enclave and Keychain.
- Pairing, create, approve, revoke, leave and rejoin match the Apple session.
  Device-only App Group starter enrollment and the extension ingress inbox are
  Apple-only in this release.
- `SessionPhase.Migrating` is entered while `SessionConfiguration.migrationMarker`
  points at an active `MigrationMarker`, exactly like Apple: such a session neither
  creates nor writes. Only the session with `migrationWriter = true` writes during the
  upgrade, and only it may publish `colophon.importBatch` source units (≤1 MiB), the
  path that gives imported positions and states baseline semantics. Member-protected checkpoint
  bytes persist in the private container and feed verified-prefix restoration, matching Apple.
- Blobs: `putBlob(bytes|file)`, `readBlob`/`blobBytes`/`blobFile`, `blobAvailability`,
  `setBlobReference`, `prefetchBlob`, `downloadRequiredBlobs`, `collectBlobGarbage` and the
  `blobDownloads` StateFlow match the Apple session ([sync](sync.md#blobs)).
- A write copies only its own signed records out of the core, a refresh reads only paths the
  core has not merged, publication reads back only the pending records, and observed paths
  are appended to `session-known.log` instead of rewriting `session.json`. Views are still
  serialized per refresh (O(projection)); named queries are not exposed on Android yet.
- JVM unit tests exercise the session against the host dylib; Keystore is
  proven on an emulator, not on the JVM.

See [session contracts](session.md) for the shared lifecycle rules and
[native bindings](native-bindings.md) for the FFI surface.
