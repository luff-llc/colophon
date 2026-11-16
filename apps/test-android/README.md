# Colophon Test for Android

An internal test tool for the Colophon 0.5 Kotlin and Android SDK, the twin of `apps/test-ios`: create or join an
account, write notes on several devices, and see exactly what the session says. Not a product. Application ID
`works.luff.colophon.testapp` (the iPhone app uses the same). Kotlin with platform views: Jetpack Compose is not on the
dependency allowlist.

**Use it only with invites exchanged in person or over a channel you trust.** An invite is not signed yet: it does not
prove who made it, or that the home and the account are theirs. A signed short invite and the spec's §7.3 pairing
ceremony are being designed in the 0.5 freeze package; until they land in the SDKs, the code the two screens show only
proves that the owner device received this device's request unchanged.

## Build and run

You need JDK 17, the Android SDK, and the JNI libraries the SDK packages (`sdk/android/native/jni/{arm64-v8a,x86_64}`,
the cargo-ndk step of `scripts/build-android.sh`). The app builds `sdk/android` from source as an included build.

```sh
scripts/build-test-android.sh            # app/build/outputs/apk/debug/app-debug.apk (debug-signed on this machine)
scripts/build-test-android.sh --test     # also the instrumented UI test on the running emulator, against a local home
adb install -r apps/test-android/app/build/outputs/apk/debug/app-debug.apk
```

Gradle runs through `sdk/android/gradlew` (no second wrapper is checked in). Nothing signs from the repository: a debug
APK uses the machine's debug key; a release build is not set up.

## Point it at a home

As on iPhone, creating an account needs a home service that provisions the slot for the new account; for this Mac that
is `apps/test-home` (home service on :8791, relay on :8790). The emulator reaches the Mac's loopback through adb:

```sh
swift run --package-path apps/test-home colophon-test-home
adb reverse tcp:8790 tcp:8790 && adb reverse tcp:8791 tcp:8791
```

The setup screen's settings are prefilled from Gradle properties (`-PCOLOPHON_HOME_PREFIX=…`, or the `COLOPHON_*`
environment variables the build script passes through):

| Setting | Default |
| --- | --- |
| Home URL prefix | `https://home.test/v1/libraries/` (the slot `t…` is appended) |
| Reach over | `http://127.0.0.1:8790/v1/libraries/` (plain `http` only to loopback; the network security config allows only that) |
| Home service | `http://127.0.0.1:8791/provision` |
| Home service token | none: the token `colophon-test-home` prints at start-up |
| Relying party (build only) | `id.toolsperson.com` |
| Staging ("Use staging") | `https://colophon.toolsperson.com/v1/libraries/`, reached directly; its home service is not deployed |

## Use it

Tabs: Notes, Devices, Status, Log. The flows and payloads are the iPhone app's (see `apps/test-ios/README.md`): create
with a passkey (Credential Manager with PRF) or, in debug builds only, a **Keystore owner key (test only)** for emulators
that cannot do PRF (it lives in `src/debug`; a release build has no such key);
add a device with an invite and a request (QR via ZXing, Copy, paste, or the links `colophontest://join?p=…` and
`colophontest://request?p=…`). A link, scan or paste only fills a confirmation screen (the home's host, the account ID
in short form); nothing is stored or sent until "Ask to join", and the history must verify in memory as the claimed
account first. A request is shown, imported only when you choose, and approved only after "The codes match"; Reject
discards it, and five failed or rejected attempts in an hour block further ones for the hour; `note.put` notes with a photo (system photo picker, a required blob); the status screen
with the phase, account and key IDs, the home URL, the last head, the last answer and refusal (HTTP status and the home's
`result`, only one the spec's §1 grammar allows; no other byte of a response body is shown, logged or written), the last sync outcome (`complete` only with no fault or issue left), faults, issues, pending changes with Veto,
members with Revoke, Lock, Unlock, Sign out and Reset. The app locks in `onStop` and unlocks in `onStart`, and asks for a
sync every 15 s while it is in front. Debug builds mirror the log and the last invite or request shown to
`files/log.txt` and `files/outbox.txt` (`adb exec-out run-as works.luff.colophon.testapp cat files/log.txt`).

## Passkeys on a real phone

Credential Manager offers a passkey for `id.toolsperson.com` only if that domain lists the app. Mike must host
`https://id.toolsperson.com/.well-known/assetlinks.json`:

```json
[{"relation": ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
  "target": {"namespace": "android_app", "package_name": "works.luff.colophon.testapp",
             "sha256_cert_fingerprints": ["<SHA-256 of the signing certificate, AA:BB:…>"]}}]
```

with the fingerprint of the key that signs the APK people install (a debug key differs per machine: use one shared
signing key for test builds, kept outside the repository). The controller's `authorityOrigins` also name the APK's
`android:apk-key-hash:` origin, which the app computes at run time.

## What is not implemented or not proven

* Passkey creation has not run (no asset links for this app exist; the emulator has no passkey provider set up). The
  Keystore owner key path is what the UI test runs.
* The camera scanner (camera2 and ZXing) was built but not exercised: the emulator's camera is a virtual scene. Paste
  and links were used.
* In 0.5 an invite goes by link or paste: even a new account's invite (about 10 KB) is too large for one QR code, and the
  app says "too large for one QR code" and offers Copy. A short QR invite is planned for 0.6. The request fits a QR code.
* No pull-to-refresh gesture (SwipeRefreshLayout is not allowlisted): the Notes screen has a Sync button, and sync is
  automatic.
* The sign-out confirmation is a dialog; the UI test makes the confirmed call directly.
* A joined device is a member only (no seed transfer to make it a controller).
* The invite is unauthenticated and the pairing code is the SDK's `AccessRequest.pairingCode`, not the §7.3 commitment
  ceremony. Both wait for the freeze package.
