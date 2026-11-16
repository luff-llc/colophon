# Colophon Test for iPhone

An internal test tool for the Colophon 0.5 Swift SDK: create or join an account, write notes on several devices, and
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
| Relying party (build only) | `id.toolsperson.com` | The passkey's WebAuthn relying party. |

"Use staging" fills `https://colophon.toolsperson.com/v1/libraries/` (`COLOPHON_STAGING_PREFIX`) and empties "Reach
over". The staging home and its home service are not deployed; until a home service exists there, an account cannot be
created against staging (joining one would work).

## Use it

* **Create**: with a passkey, or (simulator and debug builds) a software owner key in the Keychain, labelled "test only".
* **Add a device** (owner): Devices shows an invite (QR and text: the home, the account ID and the account's
  `authority/` history). On the new device, scan it or paste it and tap Join. The new device shows its request (QR and
  text) and a code. Back on the owner device, scan or paste the request, compare the code, Approve. The new device learns
  its approval through the home ("Check for approval", or the automatic sync).
* **Notes**: `note.put` records in `notes`, shared by every device, with an optional photo (a required blob). Each row
  shows the member that wrote it. Pull to sync; the app also asks for a sync every 15 s on this screen.
* **Status**: phase, account ID, this device's key ID, the home URL, the last head (seq and issued time, read from the
  head's body; the engine verifies it), the last answer and the last refusal with the HTTP status and the home's `result`,
  the last sync's outcome (`complete` only with no fault or issue left), session error, home faults and issues in full,
  pending changes with their deadlines and Veto, the homes, Lock and Unlock, Sign out, Reset. Devices lists the members
  with Revoke for an owner. The log keeps the last 200 events.
* **Lock** happens when the app goes to the background and unlocks on return. **Sign out** wipes this device's records,
  session state and Keychain items (member, owner and device keys); the home settings stay. **Reset this device** also
  forgets the settings and the log.
* Links: `colophontest://join?p=CTJ1.…` and `colophontest://request?p=CTR1.…` do the same as pasting.

No secret is shown or logged: the log holds phases, outcomes, errors, key IDs and URLs. Debug builds also write the log
and the last invite or request shown to `Documents/log.txt` and `Documents/outbox.txt` in the app's container, for
scripted runs.

## Passkeys on a real iPhone

ASAuthorization only offers a passkey for a relying party whose domain lists the app. For `id.toolsperson.com` Mike must
host `https://id.toolsperson.com/.well-known/apple-app-site-association` (served as `application/json`, no redirect):

```json
{"webcredentials": {"apps": ["<TEAMID>.works.luff.colophon.testapp"]}}
```

and the app must be signed with that team and carry the entitlement `com.apple.developer.associated-domains =
["webcredentials:id.toolsperson.com"]`. Neither the entitlement nor a team is checked in: add both locally for a device
build. In the Simulator without them, "Create with a passkey" fails with the platform's error, shown in full.

## What is not implemented or not proven

* Passkey creation has not run: there is no associated domain in this repository, and the Simulator cannot do it without
  one. The software owner key path is what the UI test runs.
* The camera scanner (VisionKit) is not available in the Simulator; only paste and links were exercised.
* A joined device is a member only: it cannot approve, revoke or veto (adding it as a second controller with the seed
  transfer is not built). The pairing is the SDK's request and code (`AccessRequest.pairingCode`), not the §7.3
  commitment ceremony, which the session uses only for seed transfer.
* The invite carries the account's history because a device with nothing cannot fetch it from a home that keeps it for
  members. A long history makes the invite too large for one QR code; the app says so and offers Copy.
* Delivery routes for notices are not registered (the relay offers none); the app polls.
