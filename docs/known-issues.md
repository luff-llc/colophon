# Known issues in 0.5.0

What 0.5.0 does not do as a protocol is [spec §21.1](../spec/colophon-0.5.md#211-what-050-does-not-do),
and the freeze conditions still open are in [§21](../spec/colophon-0.5.md#21-conformance-and-freeze).
This page lists the implementation gaps beside them: none changes a format, and each is closed
in 0.5.x or in a host.

## Sessions

- **The §6.4 warnings come after creation** (§21.1 item 7). An app checks the creation parameters
  itself and warns before it calls `create()`.
- **A host must create every account with a home** (§18), and the sessions refuse `create()`
  without one unless `createWithoutHome` is set. That collides with libraries that today sync
  only through a shared folder; whether an import account may start without a home is an open
  host-rule question for 0.5.x, not a format question.
- **Fixed in 0.5.0:** a session whose `libraryNamespaces` was wider than its own `namespaces`
  came out `denied` right after `create()`, in Swift, Kotlin and JS. Readiness now follows the
  member's own namespaces.

## Blobs

- The core runs no garbage collection. A session's `collectBlobGarbage` removes only that
  device's local copies, and on a device with no home that is the only copy: releasing the last
  reference is the app's decision. Homes never delete blob copies.
- A blob is at most 250 MiB per manifest; larger media must be split into parts by the app.
- Required blob downloads run during sync passes while the process lives. There is no background
  scheduling (BGTask, WorkManager); 64 KiB chunks are the resume unit.
- App extensions (Safari, share) cannot write blobs: the ingress envelope is 32 KiB and has no
  blob path.
- iCloud placeholder chunks surface as inaccessible, not hydrated automatically.

## Platforms and performance

- Phones, the wasm build and the FFI boundary are not measured, and nothing is proven on a
  physical device (§21.1 items 10 and 11). Sync makes one request per record.
- Android has no equivalent of the Swift import of a 0.1 library (`performMigration`); the
  imported-baseline mode is a write gate only.
- The Gradle build has no dependency verification metadata yet ([release packaging](release-packaging.md)).
- The AAR built by `scripts/build-android.sh` keeps an old file name
  (`colophon-android-0.3.0.aar`); the release package is named by version.

## Tests

- One relay test of a stopped home with two homes failed once on a loaded Linux machine and
  passed on every other run, including twelve repeats. It is timing-sensitive; a failure on one
  machine is rerun on a second before it is believed.
- Several homes per account are experimental; their open issues are in
  [multi-home-open-issues.md](multi-home-open-issues.md).
