# Android session SDK (0.2)

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

The artifact is `sdk/android/build/colophon-android-0.2.0.aar`.

## Add the AAR to an app

Copy the AAR into the app module (for example `app/libs/`) and declare the
UniFFI/JNA runtime that a local AAR does not carry:

```kotlin
dependencies {
    implementation(files("libs/colophon-android-0.2.0.aar"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.2.21")
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
```

`jna:5.18.1@aar` is required so JNA's `libjnidispatch` is packaged; the Kotlin
bindings load `libcolophon_ffi` through it. Keep `arm64-v8a` and `x86_64` in the
app's `ndk.abiFilters` if you override ABIs. NDK r28+ aligns the native library
for 16 KB pages; the app's packaging must allow that too.

## Session usage

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

## How this differs from the Apple session

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
- `SessionPhase.Migrating` is reserved for the 0.1→0.2 importer and is not
  entered yet. Checkpoint bytes persist in the private container and are not
  consumed until the verified-prefix engine is wired, matching Apple.
- JVM unit tests exercise the session against the host dylib; Keystore is
  proven on an emulator, not on the JVM.

See [session contracts](session.md) for the shared lifecycle rules and
[native bindings](native-bindings.md) for the FFI surface.
