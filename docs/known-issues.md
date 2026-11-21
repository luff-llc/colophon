# Known issues in 0.5.1

What 0.5.0 does not do as a protocol is [spec §21.1](../spec/colophon-0.5.md#211-what-050-does-not-do),
and the freeze conditions still open are in [§21](../spec/colophon-0.5.md#21-conformance-and-freeze).
This page lists the implementation gaps beside them: none changes a format, and each is closed
in 0.5.x or in a host.

## Sessions

- **The §6.4 warnings come after creation** (§21.1 item 7). An app checks the creation parameters
  itself and warns before it calls `create()`.
  This covers an account that syncs only through a shared folder and is created without a home
  (§18, `createWithoutHome`): the no-home warning comes after creation as `notices.noHome`, and
  the no-theft-safety warning for a separate recovery unit and no home (`recoveryKeys`, which
  `create()` accepts with `createWithoutHome`) is not given by the sessions at all, so the app
  gives both.
- **A revoke keeps only what this device holds.** Keeping everything a revoked member wrote
  names that member's heads in each namespace the revoking device holds. An app syncs only its
  `libraryNamespaces`, so a revoke made from an app with a narrower library, on its own storage,
  drops what the member wrote in the namespaces it does not hold. Revoke from an app or device
  that holds every namespace the member wrote in when keeping matters; making the revoking engine
  fetch every namespace first is a 0.5.x change (no format changes).
- **Resolved in 0.5.1 session maintenance**:
  - Kotlin's existing refresh phase-restoration guard is covered by a refused-command regression
    that waits for that refresh itself, without a second refresh to restore `ready`.
  - Swift, Kotlin and JS check the member's verified expiry, revocation and provisional standing
    before namespace access, including service/identity-only grants and grants with no overlap
    with `libraryNamespaces`. An expired, revoked or provisional member is `denied`.
- **Fixed in 0.5.0** (in its final commit, before any package was published):
  - a session whose `libraryNamespaces` was wider than its member's grant came out `denied`, right
    after `create()` or after an approval that granted fewer namespaces than requested (Swift,
    Kotlin, JS). A session is now `denied` only for access its member lost; a namespace the member
    was never granted is skipped, and revisions are published only for what it can read;
  - the owner's engine was scoped to the app's `libraryNamespaces`, so a revoke made from an app
    with a narrower library dropped what the revoked member wrote in the other namespaces even when
    this device held them (Swift, Kotlin, JS); the owner's engine now reads every namespace this
    device holds (see the next item for what it does not hold);
  - the Swift `approve(_:pairing:grant:)` rebuilt the grant's terms from scratch: a field left nil
    took the approving app's own namespaces and read-write access, per-namespace access and kinds
    were lost, and the core refused the grant after spending the pairing. A grant now narrows the
    request's own terms;
  - the JS session did not load a member's engine when there was nothing to unlock, so a revoked
    member reopening cold came out `failed` instead of `denied`.

## Blobs

- Nothing collects blobs. The core runs no garbage collection, the Swift session's
  `collectBlobGarbage` removes nothing (the Kotlin and JS sessions have no such call), and homes
  never delete blob copies. Zero live references is not permission to delete an original.
- A manifest holds up to 8,192 chunks of 64 KiB (512 MiB, spec §20), but the 1 MiB bound on a
  `colophon.blobPublish` operation's metadata can impose a smaller limit, about 250 MiB; larger
  media must be split into parts by the app.
- Required blob downloads run during sync passes while the process lives. There is no background
  scheduling (BGTask, WorkManager); 64 KiB chunks are the resume unit.
- App extensions (Safari, share) cannot write blobs: the ingress envelope is 32 KiB and has no
  blob path.
- iCloud placeholder chunks surface as inaccessible, not hydrated automatically.

## Platforms and performance

- On a device, opening an account that holds many vetoes is quadratic in their number
  (`derived::effective_objects` calls `check_pending_veto` for each). Not fixed in 0.5.1.
- At head quorum two, a device one forward ahead of a home can get one refused sync pass before
  the next one succeeds.
- Phones, the wasm build and the FFI boundary are not measured, and nothing is proven on a
  physical device (§21.1 items 10 and 11). Sync makes one request per record.
- Libraries of the shipped Swift apps move to 0.5 by a verified succession (`SwiftMove` in
  `ColophonMigration`); there is no Kotlin or JS equivalent.
- The Gradle build has no dependency verification metadata yet ([release packaging](release-packaging.md)).
- **Resolved:** `scripts/build-android.sh` names the AAR and its compatibility alias from the
  Android Gradle project version, and discovers SDK/JDK locations from environment or local installs.

## Tests

- Two tests are timing-sensitive. A relay test of a stopped home with two homes failed once on a
  loaded Linux machine and passed on every other run, including twelve repeats. The Kotlin
  `RevokedReopenTest` (a revoked member's cold reopen with saved state, against the real relay)
  failed once on a Mac during the 0.5.0 release runs and passed in twelve repeats and every full
  run. A failure on one machine is rerun on a second before it is believed.
- The GitHub Actions check fails on one multi-home relay test,
  `a_silent_peer_does_not_hold_up_forwarding_to_the_others` (`v05_relay_h2`), which asserts that a
  second home receives a forwarded transition within 3 seconds. It failed twice on the hosted
  runner on 19 November 2026 with code unchanged since the freeze, whose check passed, and it
  passes on the Macs (in the release workspace run and five repeats). Several homes are
  experimental (§21.1 item 3).
- `scripts/test-js.sh` fails a run whose tests all passed when it finds a relay or browser
  process left behind; on 19 November 2026 two of four runs on a Mac were failed that way and
  the next was clean. The leftovers looked like the headless browser's helpers outliving the run.
- **Covered:** Swift, Kotlin and JS readiness regressions check missing epoch-key access staying
  `unavailable` and provisional members being `denied`, including empty namespace lists. Session
  tests also check expiry with zero granted namespaces or no overlap with the library namespaces.
- Several homes per account are experimental; their open issues are in
  [multi-home-open-issues.md](multi-home-open-issues.md).
