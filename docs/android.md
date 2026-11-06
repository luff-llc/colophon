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

`KeystoreKeys` creates non-exportable P-256 signing and agreement keys, with
StrongBox when the device provides it, and never replaces an unreadable
identity with software. Use `SoftwareKeys.stored(file)` in tests. Writes carry
the revision observed when the action began; a stale observation fails closed.
Core FFI, storage and signing run on one background thread.

## How this differs from the Apple session

- Observation is `StateFlow<SessionPhase>` rather than an `@Observable @MainActor` type.
- Storage is the app's private files directory with atomic rename; there is no
  App Group, iCloud, or `NSFileCoordinator` location policy.
- Identity is Android Keystore (TEE, StrongBox when available) rather than
  Secure Enclave / Keychain. Software keys are an explicit test provider.
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
