# A new Apple app

1. Build the native artifact once with `bash scripts/build-apple.sh` (see
   [native bindings](native-bindings.md)). Add the root package's **ColophonSession** product.
2. Copy `examples/ColophonSample`, run `python3 generate-project.py`, and change the bundle ID,
   member label, namespaces and private home. Its product views import `ColophonSession` and the shared `ColophonSessionUI` flows.
3. Own one `@State` session at the process entry point and pass it to windows and intents:

   ```swift
   ColophonSession(configuration: .init(
       memberLabel: "My app", namespaces: ["reading.saved"],
       location: .privateContainer(home), privateContainer: home,
       keys: KeychainKeys(service: "com.example.myapp"),
       recoveryKeys: KeychainKeys(service: "com.example.myapp", account: "recovery")))
   ```

   `KeychainKeys` defaults to Secure Enclave. The sample explicitly uses Keychain-protected
   software keys so it can run in simulators. Do not regenerate keys on restoration failure.
4. `await session.restore()` before starting dependent work. Render its phase explicitly;
   only `.ready` opens the product UI. Call `refresh()` on foreground entry and Retry.
5. Keep one `NamespaceStore` per feature. `await load(query)` in a task; `cached(query)` in
   `body`. Await cold completion for widgets too. Rows receive plain projection values.
6. Capture `session.observedRevision` **before** an action starts; pass it to
   `perform(command, observed:)`. On stale revision, review and start again. `.queued` is
   not `.saved`; refresh retries the exact signed records.
7. For sharing, choose `.appGroup(identifier:libraryName:)` or `.iCloud(container:libraryName:)`
   and add the matching entitlements. Keep `privateContainer` in this app's private home.
   Each app keeps its own keys and pairs. Import a signed request, compare its pairing code,
   then call `approve`; use `revoke` to end access. See [session contracts](session.md) for
   the narrowly opt-in device-only starter policy, extensions, and leave/rejoin.

Build the template for both platforms with `bash scripts/build-sample.sh`; restricted builders
use `bash scripts/build-sample.sh --restricted`. No third-party generator is required.

## Shared onboarding and library settings

Add the **ColophonSessionUI** package product. The gate restores the session, refreshes on
foreground entry, and constructs product content only in `.ready`. Add the gate and a settings
link in a few lines; keep one session at the process entry point:

```swift
import SwiftUI
import ColophonSession
import ColophonSessionUI

LibraryGate(session: session,
            presentation: .init(appName: "My App", promise: "Your app’s one-line promise.")) {
    Image("AppMark").resizable().scaledToFit().frame(maxWidth: 120)
} content: {
    NavigationStack {
        MyContentView()
            .toolbar {
                NavigationLink("Library") { LibrarySettingsView(session: session) }
            }
    }
}
```

The app supplies welcome copy, artwork and the ambient tint. System typography, grouped forms,
scrolling and semantic colors adapt to Dynamic Type, VoiceOver, light/dark appearance, iOS and
macOS. `LibraryGate` renders opening, creating, waiting (with a spoken pairing code), denied,
unavailable, migrating and failed phases. Retry calls `session.retry()`, preserving failed-create
and identity-key behavior. Supply `migrationProgress: fraction` when a migration coordinator
has real progress; otherwise the upgrade indicator is indeterminate.

Settings includes signed-request file import, code comparison, approval with narrower areas,
read-only access, expiry and write budget, member kinds/grants in plain words, revocation,
attributed ledger entries, connection choices, recovery kit screens, local leave/rejoin and a
reviewable support report. Authority actions remain subject to the core’s owner checks; opening
the UI never grants approval powers to a migrated app member. Approval and revocation reviews
capture context/revision and refuse changed reviews instead of silently retrying them.

### Host-owned connection, identity and recovery policy

Pass the same `LibraryHostActions` to the gate and settings to enable optional operations:

```swift
let host = LibraryHostActions(rejoinKeys: { persistedMemberKeys })
// LibraryGate(..., host: host) and LibrarySettingsView(session: session, host: host)
```

Reuse a saved provider for local leave/rejoin. A revoked identity needs a fresh, independently
persisted provider; the host must configure that provider on subsequent launches. The UI never
regenerates keys on a failure. In the sample, rejoin reuses its configured provider and therefore
does not repair a revoked identity.

`containers` lists the app’s entitled iCloud Drive and App Group locations. `connect` receives
`.join` or `.connectAnotherDevice` and the selected `StorageLocation`. Folder-picker security
scope stays open during this callback. The host must persist its bookmark, retain access for
future use, safely prepare/copy records where appropriate, and persist/select the resulting
profile. Replace the process session and its feature stores only after successful preparation;
key the gate/settings hierarchy by the selected profile so pending reviews cannot cross profiles.
An App Group shares between apps **on this device**; it is not cross-device synchronization.

`exportRecoveryKit` returns a host-defined kit after authentication; `importRecoveryKit` validates
and applies the supplied kit, persists any replacement identity, and updates the process session.
These callbacks must use the app’s existing, reviewed recovery mechanism. ColophonSession 0.2
has no recovery-format, root-recovery or relocation API; this UI does not invent one or export
`KeychainKeys`/Secure Enclave secrets. Without handlers the screens explain that those operations
are unavailable. Do not treat the default integration as complete cross-device/recovery parity.
Run slow host operations off the main actor and return only after durable completion.

The recovery screen keeps secrets transient, shares only on a deliberate Share action, clears
text when it closes, and never displays raw recovery-provider errors. The support report uses an
allowlist of system version, phase/failure category and counts. It excludes content, names, IDs,
paths, pairing codes, kit material and arbitrary errors; no report is uploaded automatically.
See [the SessionUI handoff](handoff-session-ui.md) for identifiers, checks and remaining gaps.

## Typed 0.2 domains

Add the product for each namespace your app reads. Each depends only on `ColophonSession`;
none imports the 0.1 domain products. The examples below assume `configuration` points at an
existing library with the listed namespace granted. Follow the creation/pairing lifecycle above
before showing these features. `load` awaits session restoration and cold query completion.
Capture the observed revision before presenting a longer edit flow, rather than at its Save button.

### Books — `ColophonBooksKit`

```swift
import Foundation
import ColophonBooksKit
```

```swift
let session = ColophonSession(configuration: configuration) // reading.books
let store = BooksStore(session: session)
let page = try await store.load(BooksQuery(limit: 50)).get()
let observed = session.observedRevision
try await session.perform(AddBook(creator: "Writer", id: UUID().uuidString.lowercased(), title: "Book").domainCommand(), observed: observed)
```

### Listening — `ColophonListeningKit`

```swift
import Foundation
import ColophonListeningKit
```

```swift
let session = ColophonSession(configuration: configuration) // listening.podcasts
let store = ListeningStore(session: session)
let page = try await store.load(ShowsQuery(limit: 50)).get()
let observed = session.observedRevision
try await session.perform(Follow(id: "show", title: "Show", url: "https://example.org/feed").domainCommand(), observed: observed)
```

### Saved reading — `ColophonSavedKit`

```swift
import Foundation
import ColophonSavedKit
```

```swift
let session = ColophonSession(configuration: configuration) // reading.saved
let store = SavedStore(session: session)
let page = try await store.load(ItemsQuery(limit: 50)).get()
let observed = session.observedRevision
try await session.perform(Capture(id: UUID().uuidString.lowercased(), title: "Article", url: "https://example.org/article").domainCommand(), observed: observed)
```

### Notes — `ColophonNotesKit`

```swift
import Foundation
import ColophonNotesKit
```

```swift
let session = ColophonSession(configuration: configuration) // notes
let store = NotesStore(session: session)
let page = try await store.load(NotebooksQuery(limit: 50)).get()
let observed = session.observedRevision
try await session.perform(CreateNotebook(id: UUID().uuidString.lowercased(), title: "Ideas").domainCommand(), observed: observed)
```

Keep each store for the session's lifetime. A view reads `store.cached(query)?.value` and passes
plain `Equatable` rows to row views; it never calls `load` or a whole-state projection in `body`.
Loads cache at most 64 argument-specific results by default. Only a change in that namespace,
loss of readiness, identity change, or explicit `close()` invalidates them. New query entries
may evict cached entries at the capacity limit. The cache's observable
`state` and `revision` report cold completion and namespace changes. A closed store cannot reload.

Use `query.nextPage(after: page)` to continue with identical filters, or `query.firstPage()` to
restart after `.failure(.staleCursor)`. Queue/recording queries wrap their page in `.page`.
Results distinguish `notFound`, `deleted`, `invalidArgument`, `staleCursor`, and unavailable
content; `.get()` throws the domain outcome rather than treating it as an empty page. Access
and storage failures throw through the session. A retained blob descriptor does not prove local
byte availability. Imported podcast session history still returns `unavailable` until a host
import-evidence adapter exists.

Nullable command fields use `nil` for omission, `.null` for an explicit clear/no-head expectation,
and `.value(value)` for a supplied value. For example `EditBook(id: id, isbn: .null)` clears ISBN;
`EditBook(id: id)` leaves it alone. Dates stay wire-format strings (UTC instants or calendar days),
IDs and revision tokens stay opaque strings, and the core enforces ranges, references and roles.
`additionalFields` preserves future payload/model fields without replacing known fields.
The core retains them under its `extensions` rules; don't use result attribution as command data.

The input structs are generated from the core operation/query schemas by
`scripts/generate-swift-domains.py`; typed result contracts live in that generator alongside the
schema mapping. To regenerate, run `cargo run -q -p colophon-core --example swift_schema > /tmp/schemas.json`
then `python3 scripts/generate-swift-domains.py /tmp/schemas.json`. Commit the generated Swift sources
with schema changes. Podcast `EpisodeQuery`/`QueueQuery` and saved `PositionQuery` use the direct
read-only query binding to avoid collisions with operation names.
