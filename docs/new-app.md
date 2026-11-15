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

* `keys` is the app's member key: a Secure Enclave key (`KeychainKeys(service:)`). `KeychainKeys(backend: .software)` exists only
  in debug and simulator builds; a release build for a device has no software backend.
* `ownerController` is the person's key. A passkey: register it with `PasskeyProvider.register(relyingParty:userID:userName:challenge:authorityOrigins:)`,
  `userID` from `PasskeyProvider.userID(account:)`, keep the returned `KeyDescriptor` (public) and make a `PasskeyProvider(descriptor:)`
  each launch. Set `authorityOrigins` to the authority-ceremony origin, the bare `rp` origin and the app's platform origin (spec §18).
* A host creates every account with a home and warns when there is none (spec §18): pass `homes`, or `createWithoutHome: true` knowing
  `session.notices.noHome` will say so. **`create()` needs a `HomeConfiguration`**: with `homes` empty and no opt-out it refuses
  with `SessionError.noHome`, and with an endpoint that is not `https` it refuses with `SessionError.insecureHome`.

### Provisioning a home

A `HomeConfiguration` is the app's description of one home:

```swift
HomeConfiguration(
    endpoint: URL(string: "https://relay.toolsperson.com/v1/libraries/<slot>/")!,   // https only
    label: "Toolsperson",
    request: { account in try await homeService.memberRequest(for: account) },     // the home's signed §9.1 request
    bearerToken: storageToken,                                                      // optional, storage access only
    deliveryRoutes: [DeliveryRoute(kind: .push, address: pushToken, reaches: "this iPhone"),
                     DeliveryRoute(kind: .email, address: email, reaches: "mail")],
    registerRoutes: { account, routes in try await homeService.register(routes, for: account) })
```

The app provisions it before the person creates the account: it asks its home service for a slot (the endpoint) and keeps the
endpoint and token in its own configuration (not in the library). `request` is called once, at creation, with the new account's
ID, because a home's member request names the account; the session appoints the home in the same step. A home the account
already names needs only `endpoint` (and `transport` in tests). `deliveryRoutes` are the two ways the home can reach the person
about a pending change (spec §17.5: two, on different devices or services); `registerRoutes` is the app's call to the home's
registration, since 0.5 gives notices no wire format. The relay does not implement notices yet: leave `registerRoutes` nil and the
gate shows that the home cannot send notices (`session.duties.routes`). `allowsLoopbackHTTP: true` is for tests against a home on
this machine only.

## 3. Write and read

```swift
let observed = session.observedRevision                       // when the person BEGINS the action
let receipt = try await session.perform(try .saveLink(url: url, title: title), observed: observed)   // .saved(operationID:)
let page = try await saved.load(ItemsQuery(limit: 50)).get()
```

Views key `task(id:)` on `session.observedRevision` and read `saved.cached(_:)` in `body`. A stale `observed` throws
`SessionError.staleRevision` and signs nothing. Blobs: `putBlob`, `blobAvailability`, `blobData`, `blobFile` (all file work runs
off the main actor; pass `progress:` to show it).

**Shelves.** A saved item's "archived" shelf is SavedKit's `released` retention value: there is no `archived` retention. Archive
with `retention: .released` (`CaptureRetention.released`), list the shelf with `SavedViewFilterRetention.released`; the counts'
`archived` field counts the live items whose retention is `released`.

## 4. The gate and what it shows

`LibraryGate` shows the library only while the session has usable content, and otherwise: welcome (create, join), approval code,
access ended, unavailable, retry, **update required** (newer format), **locked**, and, over the content, `NoticesView`: a
**pending change** with its signers, first-seen entry, veto deadline and a Veto button; an **activation this device did not sign**;
with each home's receipt time; a change that did not take hold (with Sign Again); **"this account has no home"**; the sole-device
warning; and a home that cannot send notices. The gate locks the session when the scene goes inactive or to the background
(`backgroundLock:` `.immediately` by default, `.after(delay)` or `.never`) and unlocks on return.

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
4. Handle `.locked`; `LibraryGate` locks on background and shows `session.notices` and `session.duties`.
5. Existing 0.4 libraries are not opened by the 0.5 session: the move is the upgrade or the Swift move ([session.md](session.md)).
6. Account IDs are 64 hex (`IngressEnvelope.libraryID`, `CheckpointCache`).
