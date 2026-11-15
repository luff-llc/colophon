# A new Apple app on Colophon 0.5

You need Xcode 26 with the iOS and visionOS SDKs, Swift 6.2, and a built framework (`bash scripts/build-apple.sh`, see
[native-bindings.md](native-bindings.md)). No third-party Swift dependency. The first app is Later (`reading.saved`).

## 1. Add the package

Depend on the root package `ColophonSDK` and on the products you use: `ColophonSession`, `ColophonSessionUI`, `ColophonKeys`,
one domain kit (`ColophonSavedKit`, `ColophonBooksKit`, `ColophonListeningKit`, `ColophonNotesKit`). The package builds in Swift 6
language mode with strict concurrency and has no warnings on macOS, iOS and visionOS (`scripts/check-apple-swift.sh`).

## 2. One session per process

```swift
@main struct LaterApp: App {
    @State private var session = ColophonSession(configuration: .init(
        memberLabel: "Later", namespaces: ["reading.saved"],
        location: .appGroup(identifier: "group.org.luff.later", libraryName: "Library"),
        privateContainer: privateContainer,
        keys: KeychainKeys(service: "org.luff.later"),
        ownerController: owner,
        homes: [HomeConfiguration(endpoint: homeURL, request: { try await homeService.request(for: $0) })]))
    @State private var saved: SavedStore
    var body: some Scene {
        WindowGroup {
            LibraryGate(session: session, presentation: .init(appName: "Later", promise: "Keep what you read.")) {
                Root().environment(saved)
            }
        }
    }
}
```

* `keys` is the app's member key (Secure Enclave on devices; software on simulators with `KeychainKeys(backend: .software)`).
* `ownerController` is the person's key. A passkey: register it with `PasskeyProvider.register(relyingParty:userID:userName:challenge:authorityOrigins:)`,
  `userID` from `PasskeyProvider.userID(account:)`, keep the returned `KeyDescriptor` (public) and make a `PasskeyProvider(descriptor:)`
  each launch. Set `authorityOrigins` to the authority-ceremony origin, the bare `rp` origin and the app's platform origin (spec §18).
* A host creates every account with a home and warns when there is none (spec §18): pass `homes`, or `createWithoutHome: true` knowing
  `session.notices.noHome` will say so.

## 3. Write and read

```swift
let observed = session.observedRevision                       // when the person BEGINS the action
let receipt = try await session.perform(try .saveLink(url: url, title: title), observed: observed)   // .saved(operationID:)
let page = try await saved.load(ItemsQuery(limit: 50)).get()
```

Views key `task(id:)` on `session.observedRevision` and read `saved.cached(_:)` in `body`. A stale `observed` throws
`SessionError.staleRevision` and signs nothing. Blobs: `putBlob`, `blobAvailability`, `blobData`, `blobFile`.

## 4. The gate and what it shows

`LibraryGate` shows the library only while the session has usable content, and otherwise: welcome (create, join), approval code,
access ended, unavailable, retry, **update required** (newer format), **locked**, and, over the content, `NoticesView`: a
**pending change** with its signers, first-seen entry, veto deadline and a Veto button; an **activation this device did not sign**;
and **"this account has no home"**. Call `session.lock()` when the scene goes to the background.

## 5. A second device

Either it asks (`LibraryGate` shows a code; an owner device approves from settings) or the owner adds its key as a controller and
the two run the pairing ceremony (`transferSeed`, `acceptSeedTransfer`). See [session.md](session.md).

## 6. Tests

`MemoryMedium`, `MemoryDeviceSecrets` and `SoftwareKeys` run the whole session in a unit test with no Keychain and no network. The
repository's tests also use a software passkey and an in-process home (`swift/Tests/ColophonSessionTests/SimHome.swift`, a stand-in
for the relay-as-a-home package) to run two sessions through creation, approval, sync, blobs, a veto and a seed transfer.

## Moving an app from the 0.4 session

1. `SessionConfiguration`: drop `relay`, `migrationMarker`, `migrationWriter`, `importExpires`, `importedFrom`; add `homes` (and `ownerController`
   must be a key the new account can name as a controller).
2. `members` is `[AccountMember]`, `ledger` is `ledger()` (JSON), `requests` is the new `AccessRequest`; `syncConflicts` is `homeFaults`.
3. `perform`, `query`, the blob API, `drain`, `refresh`, `restore`, `syncNow`, `requestSync`, `leave`, `rejoin` keep their names and meaning.
4. Handle `.locked` and call `lock()` on background; show `session.notices` (`LibraryGate` does).
5. Existing 0.4 libraries are not opened by the 0.5 session: the move is the upgrade or the Swift move ([session.md](session.md)).
6. Account IDs are 64 hex (`IngressEnvelope.libraryID`, `CheckpointCache`).
