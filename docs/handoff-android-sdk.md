# Android SDK handoff — November 6, 2026

Implemented in the `android` worktree of `luff-llc/colophon`. Left uncommitted for review.
Nothing was committed, pushed, or published.

## Delivered

- `sdk/android` is the Gradle library `org.luff.colophon:colophon-android` (minSdk 33,
  compileSdk 35). It compiles the checked-in UniFFI Kotlin (`com.luff.colophon`) and packs
  `libcolophon_ffi.so` for `arm64-v8a` and `x86_64`.
- `ColophonSession` takes a configuration and exposes `StateFlow<SessionPhase>`:
  `Opening`, `NoLibrary`, `Creating`, `WaitingForApproval`, `Denied`, `Unavailable`,
  `Migrating`, `Ready`, `Failed`. Restore is a barrier before dependent work. Create, join,
  approve, revoke, leave, and rejoin match the Apple session. Writes go through domain
  commands carrying the observed revision. Namespace revision flows and cached query results
  live on `NamespaceStore`. Core calls run on one background thread. An inaccessible library
  stays `Unavailable`; key failures surface as `Failed`.
- `KeystoreKeys` creates two non-exportable P-256 aliases (sign and agree). StrongBox is
  requested first and the TEE is the fallback. An incomplete alias pair is deleted. Hardware
  failure does not mint a software key. `SoftwareKeys` is the explicit test provider.
- `FileRecordStore` keeps records in the app's private files directory. Writes are staged
  and fsynced. Immutable records are hard-linked where `link(2)` works, and otherwise
  published with `renameat2(RENAME_NOREPLACE)` through the existing JNA. The journal and
  checkpoint cache use an atomic replacing rename. `CheckpointCache` is device-local and
  opaque. `SessionPhase.Migrating` exists and is not entered.
- `docs/android.md` covers adding the AAR, a short session example, and the Apple
  differences. `scripts/build-android.sh` and `scripts/test-android.sh` build and test it.
  Homebrew's `JAVA_HOME` prefix is rewritten to the JDK home that contains `release`.

## Commands and results

Host: Apple Silicon. `JAVA_HOME` for Gradle was
`/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home`. `GRADLE_USER_HOME` was
this worktree's `.gradle-home`. `ANDROID_HOME` was
`/Users/mikelxc/.local/share/luff/android-sdk`, NDK `30.0.16248370`.

JVM unit tests, final run:

```text
bash scripts/test-android.sh
```

Exit 0. `cargo build --locked -p colophon-ffi --release` finished in 0.12s.
`testDebugUnitTest` `BUILD SUCCESSFUL in 9s`. All 10 tests passed:
`SessionTest.missingKnownRecordsAreNotEmpty`, `namespaceCachesAndStaleActions`,
`fileBackedColdReopen`, `pairingRevocationAndFreshRejoin`,
`restoreCreateWriteQueryLeaveAndRejoin`; `StorageTest.atomicWriteIsDurableAndImmutable`,
`checkpointCacheRoundTrip`, `fileStoreRejectsConflictsAndInvalidPaths`,
`missingObservedRecordsAreUnavailable`, `journalRoundTripAndCorruptDecode`.

Release AAR, final run after the Keystore and storage fixes:

```text
bash scripts/build-android.sh
```

Exit 0. Both Rust targets were already installed. Host and both `cargo ndk` release
builds were up to date (0.06–0.11s). `assembleRelease` `BUILD SUCCESSFUL in 10s`.
Printed `Built sdk/android/build/colophon-android-0.2.0.aar` (also copied to
`sdk/android/build/colophon-0.2.0.aar`). `unzip -l` listing:

| Path | Bytes |
| --- | --- |
| `classes.jar` | 537012 |
| `jni/arm64-v8a/libcolophon_ffi.so` | 5169016 |
| `jni/x86_64/libcolophon_ffi.so` | 5139312 |
| total | 10845855 |

App dependencies printed by the script:
`org.jetbrains.kotlin:kotlin-stdlib:2.2.21`,
`net.java.dev.jna:jna:5.18.1@aar`,
`org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2`.

`llvm-readelf -l` on both JNI libraries: every `LOAD` is `Align 0x4000`, and
`p_offset % p_align == p_vaddr % p_align`. AGP warned that it could not strip
`libcolophon_ffi.so` and packaged it as built. That warning is non-fatal.

Instrumented test. The only installed system image is
`system-images/android-36/google_apis/arm64-v8a`. No x86_64 image is installed, and this
Mac is arm64, so the AVD `colophon-android-test` (Pixel 6, Google APIs, Android 16, 512 MB
sdcard) uses that image. The emulator was already running headless:

```text
"$ANDROID_HOME/emulator/emulator" -avd colophon-android-test -no-window -no-audio -no-snapshot -no-boot-anim -gpu swiftshader_indirect
```

`adb devices` showed `emulator-5554 device`. The test command was:

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home GRADLE_USER_HOME=/Users/mikelxc/projects/colophon-wt/android/.gradle-home sdk/android/gradlew -p sdk/android --no-daemon connectedDebugAndroidTest
```

First device run, before the signing fix: exit 1.
`SessionInstrumentedTest.keystoreCreateWriteQueryRevokeAndColdReopen` failed with
`BindingException.KeyProvider: detail=no such algorithm: SHA256withECDSA for provider AndroidKeyStore`
at `PlatformKeys.sign`. Key generation had already succeeded.

After `Signature.getInstance("SHA256withECDSA")` with no provider: exit 1.
`expected:<Ready> but was:<Unavailable(reason=.../authority/00000001.json -> .../.stage-...)>`.
`Files.createLink` is denied for app private files. Exclusive `renameat2` replaced that path.

Final device run, on the code now in the tree: exit 0. `BUILD SUCCESSFUL in 23s`.
Started and finished 1 test on `colophon-android-test(AVD) - 16`. The test creates a
Keystore owner, signs, creates a library, saves a link, queries it, joins a second
Keystore member, approves, revokes, and cold-reopens the owner from disk. The reopened
private key's `encoded` form is null. The test does not read `KeyInfo.securityLevel`.

Shutdown:

```text
"$ANDROID_HOME/platform-tools/adb" emu kill
```

Exit 0 (`OK: killing emulator, bye bye`). A later `adb devices` listed no devices, and
`pgrep -lf colophon-android-test` found no process.

Deleting the AVD was blocked by the session permission check, so it is still installed:

```text
"$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" list avd
```

shows `colophon-android-test` at `/Users/mikelxc/.android/avd/colophon-android-test.avd`,
target `google_apis/arm64-v8a` Android 16. Remove it with:

```text
"$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" delete avd -n colophon-android-test
```

## Dependencies

No new coordinate was added. Pins already recorded in `docs/architecture.md`:

| Dependency | Version | Why |
| --- | --- | --- |
| `net.java.dev.jna:jna` AAR | 5.18.1 | UniFFI loads `libjnidispatch`. The same JNA calls libc `renameat2(RENAME_NOREPLACE)` because Android denies `link(2)` in private app storage. JVM tests keep the JAR. |
| `kotlinx-coroutines-core` / `android` | 1.10.2 | `StateFlow` and the single-thread session dispatcher. |
| Android Gradle Plugin | 8.7.3 | AAR at compileSdk 35 / minSdk 33. |
| Kotlin | 2.2.21 | Same pin as the JVM bindings. |
| Gradle wrapper | 8.14.3 | Checksum-pinned. |
| JUnit / AndroidX Test | 4.13.2 / 1.6.x | JVM tests and the instrumented journey. |

An earlier Gradle configure installed Android SDK Build-Tools 34.0.0 into the shared SDK.
It was left in place.

## Gaps

- The x86_64 `.so` is in the AAR and is 16 KB aligned. It was not executed. The only
  installed system image is API 36 `google_apis/arm64-v8a`, so the instrumented journey
  ran there. No x86_64 image was downloaded.
- `SessionPhase.Migrating` is not entered. The 0.1 importer is not wired.
- `CheckpointCache` is persisted and not consumed. There is no verified-prefix engine on
  this host yet, matching Apple.
- StrongBox was not measured. The Pixel 6 Google APIs image does not provide it, and the
  provider falls back to the TEE when StrongBox generation throws. The test proved only
  that the Keystore private key is non-exportable (`encoded == null`).
- API 33 itself was not booted. compileSdk is 35; the device run was API 36.
- Android Keystore does not advertise `SHA256withECDSA`. Signing uses
  `Signature.getInstance("SHA256withECDSA")` with no provider so the platform workaround
  selects the Keystore key. ECDH tries provider `AndroidKeyStore`, then the default
  provider. The device journey exercises both.
- `link(2)` in app private storage fails (the message is `dest -> stage` with no errno
  text). Publication falls back to `renameat2(RENAME_NOREPLACE)`. A plain `rename(2)`
  would replace an existing record. If `renameat2` is missing, the last fallback is an
  exists-check plus `Files.move`, which is not cross-process exclusive.
- AGP reports SDK XML version 4 while its command-line tools understand up to 3.
- `kotlinOptions.jvmTarget` is deprecated on this Kotlin pin. `MemoryRecordStore.append`
  warns that its parameter name differs from `RecordStore.records`.
- `target/aarch64-linux-android` and `target/x86_64-linux-android` were left on disk.
  The host `target/release` dylib is what the JVM tests load.
- AVD `colophon-android-test` is shut down and not deleted. See the command above.
