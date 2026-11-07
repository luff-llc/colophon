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
- `KeystoreKeys` creates two non-exportable P-256 aliases (sign and agree) on first use,
  on the session thread. StrongBox is requested first. A `ProviderException` or
  `InvalidAlgorithmParameterException` falls back to the TEE and deletes aliases that
  attempt created. An incomplete alias pair already present fails closed and is left in
  place. A missing pair for an existing journal identity fails closed and does not enter
  `WaitingForApproval`. Keystore may still generate a new pair, which the journal refuses.
  Hardware failure does not mint a software key. `SoftwareKeys` is the explicit test
  provider; a corrupt stored file is left in place.
- `FileRecordStore` keeps records in the app's private files directory. Writes are staged
  and fsynced. Immutable records try `link(2)`, then cached JNA
  `renameat2(RENAME_NOREPLACE)` with `Function.THROW_LAST_ERROR`, then `Files.copy`
  (`O_CREAT|O_EXCL`). A shorter conflicting write is `StorageException.Conflict`. The
  journal and checkpoint cache use a replacing atomic rename. `CheckpointCache` is
  device-local and opaque. `SessionPhase.Migrating` exists and is not entered.
- `docs/android.md` covers adding the AAR, a short session example, and the Apple
  differences. `scripts/build-android.sh` and `scripts/test-android.sh` build and test it.
  Homebrew's `JAVA_HOME` prefix is rewritten to the JDK home that contains `release`.

## Commands and results

The measurements in this section are the first device pass. The review-fix pass, including
the rebuilt AAR and the four instrumented tests, is under [Review fixes](#review-fixes).

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

Final device run of that pass: exit 0. `BUILD SUCCESSFUL in 23s`.
Started and finished 1 test on `colophon-android-test(AVD) - 16`. The test creates a
Keystore owner, signs, creates a library, saves a link, queries it, joins a second
Keystore member, approves, revokes, and cold-reopens the owner from disk. The reopened
private key's `encoded` form is null. That test does not read `KeyInfo.securityLevel`.

Shutdown:

```text
"$ANDROID_HOME/platform-tools/adb" emu kill
```

Exit 0 (`OK: killing emulator, bye bye`). A later `adb devices` listed no devices, and
`pgrep -lf colophon-android-test` found no process.

Deleting the AVD was blocked by the session permission check, so `colophon-android-test`
was still installed at the end of that pass:

```text
"$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" list avd
```

showed `colophon-android-test` at `/Users/mikelxc/.android/avd/colophon-android-test.avd`,
target `google_apis/arm64-v8a` Android 16. The review-fix pass later found no AVDs.

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
- StrongBox on this image was measured in the review-fix pass: `usedStrongBox` was false.
  The JVM fallback tests cover a StrongBox `ProviderException` and
  `InvalidAlgorithmParameterException`. No device with a working StrongBox was booted.
- API 33 itself was not booted. compileSdk is 35; the device run was API 36.
- Android Keystore does not advertise `SHA256withECDSA`. Signing uses
  `Signature.getInstance("SHA256withECDSA")` with no provider so the platform workaround
  selects the Keystore key. ECDH tries provider `AndroidKeyStore`, then the default
  provider. On API 31+ the AndroidKeyStore call succeeds, so the device journey does not
  exercise the default-provider branch.
- `link(2)` in app private storage fails. The instrumented test requires
  `Files.createLink` to throw, and `renameat2` then returns `0` or errno `17` (`EEXIST`).
  If `renameat2` is missing, the last fallback is `Files.copy` (`O_CREAT|O_EXCL`), which
  does not replace an existing record.
- AGP reports SDK XML version 4 while its command-line tools understand up to 3.
- `kotlinOptions.jvmTarget` is deprecated on this Kotlin pin. `MemoryRecordStore.append`
  warns that its parameter name differs from `RecordStore.records`.
- `target/aarch64-linux-android` and `target/x86_64-linux-android` were left on disk.
  The host `target/release` dylib is what the JVM tests load.
- No AVD remains. This pass created `colophon-review-arm64`, shut it down, and deleted it.
  A later `avdmanager list avd` printed no devices. See [Review fixes](#review-fixes).

## Review fixes

Each finding in `docs/review-android-sdk-agy.md` is mapped to the change and the test that fails on the old behavior.

1. Immutable publish (`AtomicFile`). `ensureSame` compares length first and throws `StorageException.Conflict`. Publication goes through `link(2)`, then a cached `renameat2(RENAME_NOREPLACE)` opened with `Function.THROW_LAST_ERROR`, then `Files.copy` (`O_CREAT|O_EXCL`). JVM: `StorageTest.shorterImmutableWriteConflictsInsteadOfLimitExceeded`, `exclusiveFallbackDoesNotReplaceAnExistingRecord`, `hostProcessHasNoAndroidRenameAt2` (this host returns null). Device: `SessionInstrumentedTest.renameAt2ReportsEexistAndShorterConflictsStayPut` (success returns 0, a second publish returns errno 17, `Files.createLink` throws, a shorter write is `Conflict` and the bytes stay).

2. Keystore identity and key failures. `KeystoreKeys.openOrCreate` is lazy. An incomplete alias pair throws `BindingException.KeyProvider` and is left on the device. StrongBox generation falls back to the TEE on `ProviderException` or `InvalidAlgorithmParameterException`, and deletes aliases that attempt created. An unrelated exception does not fall back. `SessionWorker.ensureIdentity` compares the journal's signing and agreement public keys and refuses a replacement unless `rejoin` set `acceptNewIdentity`. `handleCommandError` includes `BindingException`, so a key failure becomes `SessionPhase.Failed`. JVM: `KeystoreFallbackTest.strongBoxPurposeFailureFallsBackToTheTee`, `invalidAlgorithmParameterOnStrongBoxFallsBack`, `unrelatedGenerationFailureDoesNotFallBack`, `providerExceptionDuringTeeFallbackStillDeletesThePartialIdentity`; `SessionReviewTest.keyFailureDuringRestoreAndCommandIsFailed` (phase `Failed`, and the provider thread name starts with `colophon-session`), `commandKeyFailureBecomesFailed`, `replacedIdentityFailsClosedWithoutANewRequest`, `softwareKeyFileIsDeferredAndCorruptMaterialIsKept`. Device: `keystoreMaterialIsDeferredAndAPartialOrMissingIdentityFailsClosed` (no aliases until `signingPublicKey()`; a one-alias pair stays `Failed` with the surviving alias left in place; both aliases missing stays `Failed` and does not enter `WaitingForApproval`; record paths unchanged). `keystoreCreateWriteQueryRevokeAndColdReopen` asserts `encoded == null` and `usedStrongBox == false`.

3. Cancellation. `restore` is one shared `Deferred` on the session scope. Every `catch (Exception)` in `ColophonSession` and `NamespaceStore.load` rethrows `CancellationException`. JVM: `SessionReviewTest.cancelledRestoreDoesNotFailTheSession`, `cancelledLoadDoesNotPoisonTheNamespaceOrSession`.

4. Unreadable directories and internal symlinks. `FileRecordStore` enumerates with NIO and `LinkOption.NOFOLLOW_LINKS`. A symlink is `StorageException.InvalidPath`. An unreadable or indeterminate directory is `StorageException.Unavailable`, and restore stays `Unavailable`. JVM: `StorageTest.symlinkInsideTheLibraryIsRejected`, `unreadableLibraryIsUnavailableRatherThanEmpty`; `SessionReviewTest.unreadableLibraryRestoreIsUnavailable`. Device: `SessionInstrumentedTest.unreadableDirectoryAndInternalSymlinkAreNotAnEmptyLibrary` (POSIX mode `000` on `filesDir`).

5. Consumer R8 rules. `consumer-rules.pro` keeps `*Annotation*,EnclosingMethod,InnerClasses,Signature` and has `-dontwarn java.awt.**`. JVM: `PackagingTest.consumerRulesKeepAnnotationsAndIgnoreAwt`. The release AAR's `proguard.txt` contains both lines.

6. Session lifecycle versus the Apple session. `scheduleExpiry` wakes at `expiryMs + 1` and skips a non-`Ready` phase or a non-positive delay. `close()` cancels the scope and closes the native core. `create` reports `Creating` only while the worker is inside the session dispatcher, and a failed create leaves that phase. `rejoin` invalidates context only after `worker.rejoin` returns. `leave` routes errors through `handleCommandError`. `importRequest` is on `ColophonSession`. `views` is `@Volatile`. `NamespaceStore.results` is used only inside `synchronized(results)`. JVM: `SessionReviewTest.futureGrantExpiryRefreshesWithoutAnotherCall`, `narrowedExpiredAndBudgetedGrantsFailClosed` (notes-only grant is `Denied`; `2000-01-01T00:00:00Z` is `Denied`; `writeBudget` `0uL` is `Ready`, then the write throws `AccessException` and the phase is `Denied`), `leaveAndRejoinWithPendingPublicationDoNotWipeTheLibrary`, `rejoinDoesNotInvalidateWhileAWriteIsInFlight`, `importRequestApprovesAnExternalMember`, `joinRecoveryKeysAndClose`, `failedCreateDoesNotStayCreating`, `queuedPublicationRetriesOnRefresh`, `postCommitFailureIsQueuedAndRefreshKeepsTheWrite`, `publishedViewsAreVisibleToOtherThreads`. `SessionTest.namespaceCachesAndStaleActions` reads the cache from the caller after the session thread clears it. There is no stress test that forces a `LinkedHashMap` race; `HashMap.get` during `clear` does not fail reliably.

7. JNI staging and AAR selection. `jniLibs` is `layout.projectDirectory.dir("native/jni")`, outside `build/`. `checkNativeLibs` fails the merge if either ABI's `libcolophon_ffi.so` is missing. `scripts/build-android.sh` copies `colophon-android-release.aar` by that path. JVM: `PackagingTest.nativeLibrariesAreOutsideTheBuildDirectoryAndTheReleaseAarIsExplicit`. The release build below contains both ABIs.

8. Docs. `docs/android.md` and the Delivered and Gaps sections above now match the code and these runs. The earlier command log stays as the first-pass record. Its AAR byte counts and single instrumented test are not the current artifact.

Still untested, and not claimed as verified:

- The x86_64 `.so` is packaged and 16 KB aligned. It was not executed. No x86_64 system image is installed.
- API 33 was not booted. The device run is API 36.
- `SessionPhase.Migrating` is not entered. `CheckpointCache` is stored and not consumed.
- ECDH's default-provider branch is not exercised. `KeyAgreement.getInstance("ECDH", "AndroidKeyStore")` succeeds on this image.
- StrongBox success was not measured. This image reported `usedStrongBox == false`.
- When both aliases are missing, Keystore may generate a new pair before the journal rejects it. The device test checks phase and record paths. It does not assert that generation was skipped.
- `rejoin` restores the in-memory provider if `refreshLocked` throws. If `remember()` already saved the new public keys, that journal write is not rolled back. Current tests do not hit that order.

### Commands and results

`cargo test --locked` — exit 0, 23.32s. `conformance` 5 passed, `crypto` 2 passed, `domain_books` 19 passed, `domain_listening` 15 passed, `domain_notes` 16 passed and 1 ignored (`indexed_hundred_thousand_cell_notebook`), `domain_saved` 18 passed, `engine` 8 passed, `protocol` 16 passed. Library, FFI, wasm, and doc-test targets ran 0 tests. 99 passed, 1 ignored, 0 failed.

`bash scripts/build-android.sh` — exit 0. Both Rust targets were already installed. `cargo ndk` release builds finished in 0.07s each and copied libraries to `sdk/android/native/jni`. `assembleRelease` `BUILD SUCCESSFUL in 12s`. `unzip -l sdk/android/build/colophon-android-0.2.0.aar`:

| Path | Bytes |
| --- | --- |
| `classes.jar` | 556422 |
| `jni/arm64-v8a/libcolophon_ffi.so` | 5169016 |
| `jni/x86_64/libcolophon_ffi.so` | 5139312 |
| total | 10865355 |

`unzip -p sdk/android/build/colophon-android-0.2.0.aar proguard.txt` printed the keep rules, `-keepattributes *Annotation*,EnclosingMethod,InnerClasses,Signature`, and `-dontwarn java.awt.**`.

`llvm-readelf -l` (NDK `toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf`) on both `sdk/android/native/jni/*/libcolophon_ffi.so`: every `LOAD` is `Align 0x4000`, and `p_offset % p_align == p_vaddr % p_align`.

AVD, created earlier in this task from the installed `system-images;android-36;google_apis;arm64-v8a` image:

```text
printf 'no\n' | "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" create avd -n colophon-review-arm64 -k "system-images;android-36;google_apis;arm64-v8a" -d pixel_6
"$ANDROID_HOME/emulator/emulator" -avd colophon-review-arm64 -no-window -no-audio -no-snapshot -no-boot-anim -gpu swiftshader_indirect
```

Create exited 0. The boot watcher printed `DONE: emulator boot_completed`. Before the instrumented run, `adb devices` showed `emulator-5554 device`.

```text
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home GRADLE_USER_HOME=/Users/mikelxc/projects/colophon-wt/android/.gradle-home sdk/android/gradlew -p sdk/android --no-daemon connectedDebugAndroidTest
```

Exit 0. `BUILD SUCCESSFUL in 14s`. Started and finished 4 tests on `colophon-review-arm64(AVD) - 16`. The result XML reports `tests="4" failures="0" errors="0" skipped="0" time="0.644"`: `keystoreMaterialIsDeferredAndAPartialOrMissingIdentityFailsClosed`, `unreadableDirectoryAndInternalSymlinkAreNotAnEmptyLibrary`, `renameAt2ReportsEexistAndShorterConflictsStayPut`, `keystoreCreateWriteQueryRevokeAndColdReopen`.

`bash scripts/test-android.sh` — exit 0, after the `views` volatility test was added. `cargo build --locked -p colophon-ffi --release` finished in 0.05s. `testDebugUnitTest` `BUILD SUCCESSFUL in 10s`, 38 tests completed, 0 failed. That includes the 10 original session and storage tests, the four `KeystoreFallbackTest`s, both `PackagingTest`s, and the `SessionReviewTest`s named above.

Shutdown and delete:

```text
"$ANDROID_HOME/platform-tools/adb" emu kill
```

Exit 0 (`OK: killing emulator, bye bye` and `OK`). A later `adb devices` listed no devices.

```text
"$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" delete avd -n colophon-review-arm64
```

Exit 0 (`AVD 'colophon-review-arm64' deleted.`). `avdmanager list avd` then printed `Available Android Virtual Devices:` and no entries.

## Second review fixes

These close the two partly fixed findings in `docs/review-android-sdk-agy-2.md` (finding 2, Keystore identity; finding 6, session lifecycle) and the four new problems. The earlier "Still untested" note that `rejoin` does not roll back a journal write after `remember()` saved new keys is superseded for the cases below: a queued request keeps the new identity, and a failure before any request is queued restores the old one.

1. High. `rejoin()` dropped `handleCommandError`, leaked `PendingPublication`, and could wedge `session.json` between the old identity and a queued request. `SessionWorker.rejoin` now reads `signingPublicKey()` and `agreementPublicKey()` before it switches providers or calls `core.close()`. An empty key throws `BindingException.KeyProvider` with the live core still open. `refreshLocked`'s new-request branch calls `recordIdentity` before `persistDelta`. `recordIdentity` writes the three identity fields only; it does not add `knownPaths`, so the unpublished records still go into `journal.pending`. If `refreshLocked` throws and `journal.pending` is already non-empty, the worker keeps the new keys and the new identity. If pending is still empty, it restores the previous keys, `left`, and the three identity fields, then closes the core again. `ColophonSession.rejoin` maps `PendingPublication` to `StorageException.Unavailable`, then `handleCommandError`, then rethrows that public error. `CancellationException` and `SessionException.NotReady` still propagate. `leaveAndRejoinWithPendingPublicationDoNotWipeTheLibrary` now asserts the library id is unchanged and the phase stays `Unavailable`, because the early pending rejection goes through `handleCommandError` and may rewrite the reason string.
   - `SessionReviewTest.rejoinKeyFailureFailsTheSessionBeforeClosingTheCore` (0.015s). A provider that throws `BindingException.KeyProvider` must leave the phase `Failed`, set `lastError`, keep the library id and the store keys, leave the core's close count at 0, and make `projection` throw `SessionException.NotReady`. The old `rejoin` closed the core first and rethrew without `handleCommandError`, so the phase stayed ready and the close count was 1.
   - `SessionReviewTest.rejoinPublicationFailureKeepsTheNewIdentity` (0.064s). After a revoked member's fresh rejoin fails to publish, the caller sees `StorageException.Unavailable`, the phase is `Unavailable`, and `session.json` has `left` false, the fresh public keys, a new member id, and a `requests/` entry in `pending`. Clearing the fault and calling `refresh` reaches `WaitingForApproval`. A cold reopen with the fresh keys stays `WaitingForApproval`. A cold reopen with the revoked keys is `Failed`. The old order wrote the request into `session.json` under the old identity and then reverted the in-memory keys, so refresh opened the revoked member and a cold reopen with the new keys failed in `ensureIdentity`.
   - `SessionReviewTest.rejoinStorageFailureBeforeARequestKeepsTheOldIdentity` (0.027s). A `read()` failure before any request is queued returns `StorageException.Unavailable`, sets `Unavailable` and `lastError`, keeps the original signing key, and a later `refresh` returns `Ready` on that same key. The old catch left the phase ready with a closed core.
   - Device: `SessionInstrumentedTest.rejoinWithIncompleteKeystoreIdentityFailsClosed` (0.056s). An owner library is created with `KeystoreKeys`. A second prefix materializes both aliases, the agreement alias is deleted, and `rejoin` with that incomplete provider throws `BindingException.KeyProvider`. The phase is `Failed`, `lastError` is set, the library id and record paths are unchanged, the surviving signing alias remains, and `projection` throws `SessionException.NotReady`. The old path closed the core before the key read and left the phase ready.

2. Medium. `SessionWorker.create` called `persistDelta` before any identity was stored, so a failed publication wrote `session.json` with `libraryID` and pending authority records and null `signingPublicKey`, `agreementPublicKey`, and `memberID`. A later reopen with a different key file then skipped `ensureIdentity` and entered `WaitingForApproval`. `create` now calls `recordIdentity` on the create snapshot before `persistDelta`. Same constraint as rejoin: identity fields only, so `knownPaths` stays empty and the authority records are still queued.
   - `SessionReviewTest.createRecordsIdentityBeforeAFailedPublication` (0.01s). The journal is loaded before any successful refresh. Signing key, agreement key, and member id are non-null and match the provider, `pending` is non-empty, and no `requests/` path is queued. After the fault clears, `refresh` reaches `Ready`. A second session with different `SoftwareKeys` stays `Failed` and writes no `requests/` record. The old order left the three identity fields null, so the replacement key was accepted as a new member.

3. Medium. `ColophonSession.close` used `runBlocking` on the process-wide `colophon-session` dispatcher, and `ensureUsable` threw `CancellationException`. `close` now sets `worker.markClosed()` immediately. On the session thread it calls `closeCoreNow` without taking the worker mutex (publication observers run while `write` holds that mutex). From any other thread it launches `closeCoreSuspended` on a fresh `SupervisorJob` plus the session dispatcher. `ensureUsable` throws `SessionException.NotReady()`. `NotReady` is a class, a new instance per throw, because a `data object` keeps the first stack and coroutines can fail to catch that same instance again. Catches that used to rethrow `CancellationException` also rethrow `NotReady`, so a closed session is not turned into `Failed`. `launchRefresh` and the expiry job swallow `NotReady` so a watch that fires after `close` is not an uncaught session-scope failure. Public `perform` and `refresh` still propagate it.
   - `SessionReviewTest.closeOnTheSessionThreadReturns` (0.015s). After `create`, the next `perform` publishes through a store `append` that calls `session.close()` on the session thread while the worker mutex is held. `close` must return and the latch must open within 5 seconds. The old `runBlocking(dispatcher)` deadlocks on that thread.
   - `SessionReviewTest.closeReturnsWhileSessionWorkIsInFlight` (0.022s). `core.write` blocks. A caller thread's `close()` must return within 1 second while that write is still inside the dispatcher. The old `runBlocking` waited for the write.
   - `SessionReviewTest.joinRecoveryKeysAndClose` (0.037s) now waits until the core is closed, then `perform` must throw `SessionException.NotReady` and that exception is not a `CancellationException`.

4. Low. `AtomicFile.resolveRenameAt2` probed `"c"` and `"libc.so"` on every JVM. glibc 2.28+ resolves `renameat2`, so `hostProcessHasNoAndroidRenameAt2` would see errno 2 on Linux. `resolveRenameAt2` now returns null unless `isAndroidRuntime` is true (`/system/build.prop`, a VM name containing `Dalvik`, or a runtime name containing `Android`). Desktop hosts keep the `Files.copy` (`O_CREAT|O_EXCL`) fallback. Device publication still uses `renameat2`, because `link(2)` is denied in private app storage. This Mac already returned null before the gate; the Linux host was not run here.
   - `StorageTest.hostProcessHasNoAndroidRenameAt2` (0.001s). `isAndroidRuntime(false, OpenJDK, OpenJDK)` is false, a present build prop is true, and `Dalvik` / `Android Runtime` is true. `renameNoReplace` of two missing paths is null on this host. Removing the gate makes the Linux `assertNull` fail with errno 2.
   - Device: `SessionInstrumentedTest.renameAt2ReportsEexistAndShorterConflictsStayPut` (0.027s) still requires a successful `renameat2` (return 0) and `EEXIST` (17).

### Commands and results

`bash scripts/test-android.sh` — exit 0. `cargo build --locked -p colophon-ffi --release` finished in 0.04s. `testDebugUnitTest` `BUILD SUCCESSFUL in 10s`, 15 actionable tasks, 2 executed, 13 up-to-date. Result XML timestamp `2026-11-07T01:15:16Z` through `2026-11-07T01:15:19Z`: `SessionReviewTest` 23, `SessionTest` 5, `StorageTest` 10, `KeystoreFallbackTest` 4, `PackagingTest` 2. 44 tests, 0 failures, 0 errors, 0 skipped. The eight `SessionReviewTest` methods and `hostProcessHasNoAndroidRenameAt2` listed above are in those files with no `<failure>` element. Pre-existing warnings only: `Storage.kt:58` parameter name `records`, and `PackagingTest` `String?` mismatches.

`cargo test --locked` — exit 0. `Finished test profile in 0.09s`. Per-target `test result: ok`: conformance 5 passed (1.25s), crypto 2 passed (0.02s), domain_books 19 passed (3.69s), domain_listening 15 passed (0.48s), domain_notes 16 passed and 1 ignored (`indexed_hundred_thousand_cell_notebook`, 3.65s), domain_saved 18 passed (4.28s), engine 8 passed (5.65s), protocol 16 passed (0.33s). Library, FFI, wasm, and doc-test targets ran 0 tests. 99 passed, 1 ignored, 0 failed. No Rust sources changed.

`bash scripts/build-android.sh` — exit 0. Both `rust-std` Android targets were already installed. Host release finished in 0.04s. `colophon-ffi` and `uniffi-bindgen` dev profile finished in 2.03s. `cargo ndk` arm64-v8a release 0.06s, x86_64 release 0.05s, copied to `sdk/android/native/jni`. `assembleRelease` `BUILD SUCCESSFUL in 9s`, 29 actionable tasks, 5 executed, 24 up-to-date. `compileReleaseKotlin` printed the existing `Storage.kt:58` warning. `unzip -l sdk/android/build/colophon-android-0.2.0.aar`:

| Path | Bytes |
| --- | --- |
| `classes.jar` | 556554 |
| `jni/arm64-v8a/libcolophon_ffi.so` | 5169016 |
| `jni/x86_64/libcolophon_ffi.so` | 5139312 |
| total | 10865487 |

`llvm-readelf` alignment was not re-run. The `.so` sizes match the previous handoff, and both `cargo ndk` builds finished from cache.

AVD from the installed `system-images;android-36;google_apis;arm64-v8a` image:

```text
printf 'no\n' | "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" create avd -n colophon-review2-arm64 -k "system-images;android-36;google_apis;arm64-v8a" -d pixel_6
```

Exit 0. `Auto-selecting single ABI arm64-v8a`. `avdmanager list avd` showed `colophon-review2-arm64`, device `pixel_6`, path `/Users/mikelxc/.android/avd/colophon-review2-arm64.avd`, Android 16.0 ("Baklava") `google_apis/arm64-v8a`, sdcard 512 MB.

```text
"$ANDROID_HOME/emulator/emulator" -avd colophon-review2-arm64 -no-window -no-audio -no-snapshot -no-boot-anim -gpu swiftshader_indirect
```

Emulator 37.2.12.0, system image `system-images/android-36/google_apis/arm64-v8a`, SwiftShader. `Boot completed in 23182 ms`. The boot watcher printed `DONE: emulator boot_completed`. `adb devices -l` showed `emulator-5554 device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a`.

```text
GRADLE_USER_HOME=/Users/mikelxc/projects/colophon-wt/android/.gradle-home sdk/android/gradlew -p sdk/android --no-daemon connectedDebugAndroidTest
```

Exit 0. `BUILD SUCCESSFUL in 12s`, 50 actionable tasks, 7 executed, 43 up-to-date. Started and finished 5 tests on `colophon-review2-arm64(AVD) - 16`. Result XML `tests="5" failures="0" errors="0" skipped="0" time="0.719" timestamp="2026-11-07T01:20:22"`: `keystoreMaterialIsDeferredAndAPartialOrMissingIdentityFailsClosed` 0.15s, `unreadableDirectoryAndInternalSymlinkAreNotAnEmptyLibrary` 0.0s, `rejoinWithIncompleteKeystoreIdentityFailsClosed` 0.056s, `renameAt2ReportsEexistAndShorterConflictsStayPut` 0.027s, `keystoreCreateWriteQueryRevokeAndColdReopen` 0.211s.

Shutdown and delete:

```text
"$ANDROID_HOME/platform-tools/adb" emu kill
```

Exit 0 (`OK: killing emulator, bye bye` and `OK`). The emulator process then exited 0. A later `adb devices` printed `List of devices attached` and no devices.

```text
"$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" delete avd -n colophon-review2-arm64
```

Exit 0 (`AVD 'colophon-review2-arm64' deleted.`). `avdmanager list avd` then printed `Available Android Virtual Devices:` and no entries.

Not re-verified in this round: x86_64 execution, an API 33 boot, StrongBox success, `SessionPhase.Migrating`, `CheckpointCache` consumption, and the ECDH default-provider branch. `keystoreCreateWriteQueryRevokeAndColdReopen` passed again on this API 36 image; the earlier handoff recorded `usedStrongBox == false` for that test. A glibc host was not run, so the Linux `renameat2` probe is covered by the `isAndroidRuntime` gate and the host assertions above, not by a Linux JVM execution.
