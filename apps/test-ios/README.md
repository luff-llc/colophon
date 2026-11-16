# Colophon Test for iPhone

An internal test tool for the Colophon 0.5 Swift SDK: create or join an account, write notes on several devices, and

**Use it only with invites exchanged in person or over a channel you trust.** An invite is not signed yet: it does not
prove who made it, or that the home and the account are theirs (a signed invite is planned for 0.6). Approving a device
is safe against a relay: the owner device scans the new device's request from its screen, and the SDK approves only the
key that scan paired (spec §7.3, §9.1); no request that arrives any other way can be approved.
see exactly what the session says. Not a product. Bundle ID `works.luff.colophon.testapp` (the Android app uses the same).

## Build and run

You need Xcode 26+, the XCFramework at `sdk/apple/ColophonFFI.xcframework` (`bash scripts/build-apple.sh`), and for a
local home Bun and the home module.

```sh
scripts/build-test-ios.sh                          # simulator build (Debug, arm64), ad-hoc signed
scripts/build-test-ios.sh --test "iPhone Duo"      # also the one-device UI test against a local home
COLOPHON_TEAM_ID=ABCDE12345 scripts/build-test-ios.sh --device   # device build, signed with your team
```

The project (`ColophonTest.xcodeproj`) is checked in and small: the `App` and `UITests` folders are synchronised groups,
so a new Swift file needs no project edit. It depends on the repository's root package (`ColophonSession`,
`ColophonKeys`). No signing team, profile or entitlement is checked in.

## Point it at a home

A 0.5 home slot is provisioned for one account, and the account does not exist until the app creates it. So creating an
account needs a **home service** that provisions the slot and answers with the home's signed member request. For this
Mac that is `apps/test-home`:

```sh
cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm
swift run --package-path apps/test-home colophon-test-home      # home service on :8791, relay on :8790
```

The setup screen has three settings, prefilled from `Config/TestApp.xcconfig` (override any on the xcodebuild command
line or with the `COLOPHON_*` environment variables the build script passes through):

| Setting | Default | Meaning |
| --- | --- | --- |
| Home URL prefix | `https://home.test/v1/libraries/` | The `https` name the account appoints; a new account's slot `t…` is appended. |
| Reach over | `http://127.0.0.1:8790/v1/libraries/` | Where the home's requests go instead (the relay on this Mac). Empty: sent as named. Plain `http` only to loopback. |
| Home service | `http://127.0.0.1:8791/provision` | Provisions a new account's slot. |
| Home service token | (none) | The token `colophon-test-home` prints at start-up; it refuses requests without it. |
| Relying party (build only) | `id.toolsperson.com` | The passkey's WebAuthn relying party. |

"Use staging" fills `https://colophon.toolsperson.com/v1/libraries/` (`COLOPHON_STAGING_PREFIX`), empties "Reach
over" and sets "Home service" to `https://colophon.toolsperson.com/v1/provision` (`COLOPHON_STAGING_PROVISIONER`), which
takes the same `{"slot","base","account"}` request as `apps/test-home` and gives the same answer. Requests carry
`Content-Length` (the staging home refuses a chunked body with 411). These apps have not yet been run against staging.

## Use it

* **Create**: with a passkey, or (simulator and debug builds) a software owner key in the Keychain, labelled "test only".
* **Add a device** (owner): Devices shows an invite (QR and text: the home, the account ID and the account's
  `authority/` history). On the new device, scan it, paste it or open its link: that only fills a confirmation screen
  with the home's host and the account ID in short form. Nothing is stored and nothing is sent until you tap "Ask to
  join"; even then the history is verified in memory first and must name the account the invite claims. The new device
  then shows its request as a QR code. On the owner device, Devices, "Scan its request": the camera reads it from the
  new device's screen, the session pairs that request's key (nothing is stored), and you Approve or Reject it. A pasted
  or linked request is not approved (debug builds take a request link only from the test harness, standing in for the
  camera). Five failed scans in an hour block further ones for the hour (the session's §7.3 limiter). The new device
  learns its approval through the home ("Check for approval", or the automatic sync).
* **Notes**: `note.put` records in `notes`, shared by every device, with an optional photo (a required blob). Each row
  shows the member that wrote it. Pull to sync; the app also asks for a sync every 15 s on this screen.
* **Status**: phase, account ID, this device's key ID, the home URL, the last head (seq and issued time, read from the
  head's body; the engine verifies it), the last answer and the last refusal with the HTTP status and the home's `result` (only a result the spec's §1 grammar
  allows; no other byte of a response body is shown, logged or written),
  the last sync's outcome (`complete` only with no fault or issue left), session error, home faults and issues in full,
  pending changes with their deadlines and Veto, the homes, Lock and Unlock, Sign out, Reset. Devices lists the members
  with Revoke for an owner. The log keeps the last 200 events.
* **Lock** happens when the app goes to the background and unlocks on return. **Sign out** wipes this device's records,
  session state and Keychain items (member, owner and device keys); the home settings stay. **Reset this device** also
  forgets the settings and the log.
* Links: `colophontest://join?p=CTJ1.…` and `colophontest://request?p=CTR1.…` do the same as pasting: they fill a
  screen you confirm, and never join, import or approve by themselves.

No secret is shown or logged: the log holds phases, outcomes, errors, key IDs and URLs. Debug builds also write the log
and the last invite or request shown to `Documents/log.txt` and `Documents/outbox.txt` in the app's container, for
scripted runs.

## Passkeys on a real iPhone

ASAuthorization only offers a passkey for a relying party whose domain lists the app. The association file for
`works.luff.colophon.testapp` is now live on `id.toolsperson.com`
(`https://id.toolsperson.com/.well-known/apple-app-site-association`, served as `application/json`, no redirect), in
this form:

```json
{"webcredentials": {"apps": ["<TEAMID>.works.luff.colophon.testapp"]}}
```

and the app must be signed with that team and carry the entitlement `com.apple.developer.associated-domains =
["webcredentials:id.toolsperson.com"]`. Neither the entitlement nor a team is checked in: add both locally for a device
build. In the Simulator without them, "Create with a passkey" fails with the platform's error, shown in full.

## What is not implemented or not proven

* Passkey creation has not run: the association file is live, but the entitlement and a signing team are not in this
  repository and no signed device build was made. The software owner key path is what the UI test runs.
* The camera scanner (VisionKit) is not available in the Simulator; the scripted run feeds the scanned request through a
  debug-only link, so the camera path itself has not run.
* A joined device is a member only: it cannot approve, revoke or veto (adding it as a second controller with the seed
  transfer is not built).
* The invite is unauthenticated (a signed invite is 0.6). Approval uses the SDK's scan path (§9.1); the six-digit code
  ceremony is in the SDK but these apps have no channel between two phones to carry it, so they do not offer it.
* The invite carries the account's history because a device with nothing cannot fetch it from a home that keeps it for
  members. Even a new account's invite (about 10 KB) is too large for one QR code: the app says "too large for one
  QR code" and offers Copy. In 0.5 an invite goes by link or paste; a short QR invite is planned for 0.6. The request
  (about 760 characters) fits a QR code.
* Delivery routes for notices are not registered (the relay offers none); the app polls.
