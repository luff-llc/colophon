# Moving Taupe iOS libraries to Colophon 0.5

**Status:** plan, 2026-11-15. Research only; nothing here is built. **Who:** a few friends and
family, each with one real library that must not be lost. **Aim:** as little machinery and as
few taps as the spec allows.

Sources read: this branch (`spec-0.5` at `6266d31`), `origin/home-0.5-h2` at `93b1b94`, and
Marginalia `origin/main` at `30096558`. Marginalia paths below are on that commit and prefixed
`marginalia:`. The Swift authority sources there are unchanged since `c8280332`, the commit
spec §16.3 describes.

## 1. What a library is today, and what 0.5 can carry

Taupe's library is a Swift keyring library (`colophon/swift-keyring/2`, spec §16.3). It is shared
with the other suite apps and with Marginalia's podcast adapter. It starts in the App Group
`group.org.luff.library`. When the person adds a device it moves to iCloud Drive
(`iCloud.org.luff.library`) (`marginalia:apps/suite/Shared/SuiteLibrary.swift`,
`marginalia:apps/suite/README.md`). Devices sync through that folder. The relay is used only for
Taupe Tunnel agent traffic, not for library sync. There is no Colophon home today.

Two shapes exist:

- **Single device (most users).** A root library whose root is a plain software "starter" key,
  `starter-root.json` in the App Group. Its recovery kit waits in the group until a device is
  added (`marginalia:packages/Colophon/Sources/ColophonUI/LibrarySession.swift:860-880`).
- **Several devices.** A keyring library: each device's P-256 key holds `approve`+`control`; a
  passkey (PRF slot) or the recovery kit (sealed slot) holds `recover`
  (`marginalia:.../ColophonUI/KeyringDerivation.swift:73-156`, `AddDeviceView.swift:5-6`).
  `docs/clean-copy.md` (2026-11-08) says Mike's was then the only keyring library.

| Part | Where | 0.5 today | Work |
| --- | --- | --- | --- |
| Authority (keys, members, grants) | `authority/` | **Carried.** Verifier `v05/history/swift.rs`; genesis, `handover`, F and `migration` builders; `account/moving.rs` | None in core |
| Vault and slots | keyring entries | **Carried.** `v05/swift_slots.rs` opens `sealed`, `prf` and `combined` slots; the new vault gets a new seed | Swift: one passkey assertion with two PRF salts, which `AsyncKeyProvider.assert` cannot do yet (`docs/session.md`, "The Swift move") |
| Podcast records, about 24 kinds of `listening.podcasts` (`marginalia:.../ColophonListening/Podcasts.swift:14-23`) | `ops/` | **Carried, once translated.** `v05/swift_copy.rs` copies each admitted record as one `colophon.importBatch`. With no translator the original kind and payload are copied verbatim, which the destination accepts only where they match | **Medium.** A Swift `Translator` (`crates/colophon-ffi/src/v05/api/session.rs:32-42`). Rust already maps every Swift podcast kind (`crates/colophon-core/src/domains/listening/import.rs`, used by the 0.4 `import_legacy_batch`). The Swift side supplies each record's outcome from its own fold |
| Other namespaces (`reading.saved`, `reading.books`, `notes`) | `ops/` | Same path. Rust importers exist for all three | Small if empty (likely: Later, Shelf and Scribenda are not released); the preflight counts them |
| Transcripts and other blobs | `blobs/`: AES-GCM under the namespace epoch key, referenced by `{digest, plain, epoch, size}` (`marginalia:.../ColophonReplica/Replica.swift:883-911`) | **Not carried.** Listed in `CopyResult::blobs_not_copied` (`swift_copy.rs:25-26`). The engine can now write blobs (`v05/engine/blobs.rs`) | **Medium.** Open each blob with the old Swift reader, `putBlob` into the account, and have the translator cite the new manifest. Or drop transcripts and regenerate them on the device |
| Live state: passive playback positions | `state/`, layout 2 only (`marginalia:.../ColophonListening/ListeningPositionService.swift`) | **Not carried.** Omitted as `liveState` (`swift_copy.rs:24-25`, `:797`) | **Small.** After the copy, write each episode's latest position (from the Swift fold) as a 0.5 live write (`v05/engine/live.rs:171`) |
| Members (Taupe and Marginalia per device) | grants | They rejoin, one grant each (§15.3, §16.2) | Small. See decision 7 |
| Taupe Tunnel pairings, relay address | app settings, keyed by library ID (`marginalia:apps/suite/Taupe/WebConnection/TaupeWebConnection.swift:356-372`) | Not library data. The library ID changes (32 hex to 64 hex) | Small. Chat apps pair again, or the app re-keys its pairings once the `migration` entry exists (§15.4) |

Nothing has to be left behind for good. The two known gaps are blobs and live state, and both
have small Swift-side answers.

**The shipped app cannot write F.** Confirmed from source: `AuthorityEntry` has no `successor`
member, and `numbered(_:after:)` drops any member it does not list. `supportedStorageLayout` is
2. Drafts re-stamp `issued` with `.now` (`marginalia:.../ColophonAuthority/AuthorityEntry.swift`,
`AuthorityState.swift:56,96,120-121`, `KeyringHolder.swift:29-34`). The five changes listed in
`docs/handoff-engine-05-write.md` ("What a new Apple app version must do to write F") are all
still needed.

**Versions in users' hands.** The App Store has Taupe 1.0 (25). Taupe 1.1.0 (34) was submitted
with automatic release, and 1.1.2 (37) is on internal TestFlight
(`marginalia:apps/suite/docs/releases/taupe-1.1-release.md:3`, `taupe-1.1.2-release.md:3`).
`layout` support arrived on 2026-11-06 (`b93cc923`), after 1.0 (25). So when 1.0 sees F it stops
with `newerAuthority`, and 1.1.x stops with `unsupportedStorageLayout`. Both stop before they
write, which is the behaviour §16.3 relies on. Marginalia's shipped builds, which share the
library, stop the same way.

## 2. The sequence for one user

There is one app update: **Taupe 2.0**. It contains the 0.5 session (`ColophonSession`,
`ColophonListeningKit`). It also keeps the old Swift Colophon packages, so it can read the
predecessor, translate records and blobs, and append F. Coexistence of the two package sets is
proven (`docs/handoff-restructure.md`). The steps are the engine's (`account/moving.rs:5-25`;
`swift/Sources/ColophonMigration/SwiftMove.swift`).

| # | What happens (no user action unless stated) | Durations from the spec |
| --- | --- | --- |
| 0 | The person runs Taupe 1.x. They install 2.0, probably by automatic update. | |
| 1 | **Preflight, read only.** 2.0 verifies the whole predecessor (`SwiftLibrary::read`). It counts records, blobs and live state, and stops on any failure (§15.3 step 1). | |
| 2 | **Backup** (section 3). | |
| 3 | **Successor genesis** with the same keys, roles exactly as before, a new vault seed and `handover`. Single-device libraries: the starter key signs silently. Keyring libraries: **one Face ID** for the passkey ceremony, plus device-key presence. | |
| 4 | **Home appointed; window opens.** The transition appointing the home opens the succession window. The home must receipt the genesis inside it, so the phone must be online. The predecessor's entries are published to `{base}/predecessor/`. | Window: 300 s (§15.1 step 2) |
| 5 | **Wait.** Other devices may veto. 2.0 shows the library read only, with playback allowed. Positions are journalled locally and written after step 7. | Due at window end + `recoveryDelay`; veto deadline 300 s before due |
| 6 | **The one screen.** "Taupe is moving your library. Older Taupe or Marginalia on your other devices will stop until they're updated." One tap, which §15.3 step 4 requires ("the person has been told"). Then F is appended to the Swift library and published to the home. | |
| 7 | **Copy.** Records go through the translator; then blobs and live positions. 2.0 switches to the 0.5 account. | |
| 8 | **Drain.** Late records from devices that had not seen F are copied. Then the `migration` entry is written. Nothing visible. | Drain window: 7 days default, 0–30 (§15.3, §18) |
| 9 | **Android joins.** Android Taupe on the 0.5 Kotlin SDK asks to join through the home; the person compares a code on the iPhone and approves (`docs/android.md`). | |

**The delay.** `policy.recoveryDelay` defaults to 72 h. With a home it may be as low as 3,600 s
(§18 table). The successor's own genesis sets the value in force (§15.1 step 2), so a 1-hour delay
breaks no rule: the move finishes in about 65 minutes. The window (300 s) and the veto deadline
(300 s before due) are fixed. The drain window is the host's choice, from 0 to 30 days. The
polling rule becomes every 10 minutes (§17.5: `recoveryDelay`/6). Raising the delay to 72 h
afterwards is a transition with consent that waits out the 1-hour delay.

**A second Apple device that is updated** sees F in the iCloud folder, or the successor genesis
before F. It opens the successor, and its device key, still a controller with a rebuilt sealed
slot, unlocks the new vault and grants its own Taupe member. At most one Face ID; no codes. It
must not start a second move (section 3).

**A device that is offline, or never updated**, keeps the old app. Once it syncs F it stops and
shows "update required". That message is right for Taupe, because the update is the successor
app. Anything it wrote before seeing F reaches the iCloud folder and is copied if it arrives
inside the drain window. After that it stays in the frozen library, shown as left behind with a
"copy" action (§15.3).

## 3. Failure and rollback

**The point of no return is F.** Before F, nothing is written to the Swift library: the genesis,
receipts and copies live in the successor. Abandoning the attempt costs nothing. After F, old
apps stop for good, and a verified succession cannot be undone (§15.2). The old library is never
deleted. It stays complete and verifiable, and Taupe 2.0 can still read it read-only (handoff
item 4: F is final for writing, not for reading). So the person always has at least one readable
library.

**Backup before step 3.** Taupe 2.0 copies the whole library folder byte for byte (`authority/`,
`ops/`, `state/`, `blobs/`, `requests/`) into its private container, excluded from iCloud. It
writes a manifest of SHA-256 per file. The backup is verified three ways:

1. The manifest of the copy equals a fresh manifest of the source.
2. The 0.5 preflight passes on the copy.
3. The old Swift reader opens the copy and its podcast fold matches the live one (counts of
   follows, queue, played states, notes, positions).

The backup is kept until the `migration` entry is written and the person has used 2.0 for a
week. It is never uploaded.

| Step | What can go wrong | State of the library | Way back |
| --- | --- | --- | --- |
| 1 Preflight | Malformed entry; iOS signature encoding (§16.3: iOS unverified); a `budget` caveat; a grant without `role`; an iCloud placeholder | Old library untouched | 2.0 stays read-only on the old library and sends a support report. We fix the tool and ship a point release |
| 2 Backup | Disk full; manifest mismatch | Untouched | Retry; don't continue without a verified backup |
| 3–4 Genesis, home | Passkey cancelled; home down; receipt misses the 300 s window (attempt never due) | Untouched; a dead successor at the home | Start again. Before F, a new attempt is unrestricted |
| 5 Wait | A veto (another device, or a stolen key) | Untouched; succession vetoed | Show it; stay on the old library; investigate before retrying |
| 6 F | App killed mid-append; F not published; device clock wrong, so F is premature and never verifies | Frozen. Old apps stop | Resume: append is idempotent on the exact bytes; publish again. If F cannot verify, make a new attempt with a higher layout (§15.1 "Competing attempts"). That needs every earlier attempt's objects, so keep them. Last resort: an unverified copy (§16.2) |
| 7 Copy | Crash; a translator refuses a record; a blob is unreadable | Frozen; successor partly filled | `CopyPlan` rebuilds from predecessor plus destination (`docs/handoff-engine-05-write.md`, E8). Refusals become `omitted` with reasons; the records stay in the frozen library, with a copy action |
| 8 Drain | Copying device gone | Successor live; `migration` not written | Any controller device can finish the drain |

**Two devices racing to move** is the only way to fork the predecessor: two F entries at one seq.
The rule is that a device first publishes its successor genesis to the shared folder and the
home. A device that finds a successor already started for this library follows it and starts
none. Just before F, the freezing device checks again. How iCloud reports two files written to
one `authority/<seq>.json` has to be tested (section 7).

## 4. Work items

| # | Item | Size | Depends on |
| --- | --- | --- | --- |
| W1 | **Taupe on the 0.5 session.** Port Taupe's library layer from `ColophonUI`/`Replica` to `ColophonSession` + `ColophonListeningKit`. This is the release itself, not migration work, but nothing ships without it | Large | ListeningKit parity with Taupe's services (unknown) |
| W2 | **F in the Swift stack.** The five items of the handoff: `successor` member, layout 3, raw-record append, F final for writing, update-required wording (`AuthorityEntry.swift`, `AuthorityState.swift`, `AuthorityHolder.swift`, `KeyringHolder.swift`, `SharedLibraryDiagnostics.swift`) | Small | — |
| W3 | **Podcast translator** in Swift: each record's outcome from `Podcasts.fold`, mapped through the Rust listening importer into a `SwiftBatch` | Medium | W1 |
| W4 | **Translators for the other three namespaces**, only if the preflight finds records | Small each | W3's pattern |
| W5 | **Blobs:** old blob read, `putBlob`, manifest in the batch; or regenerate (decision 5) | Medium | W3 |
| W6 | **Live positions** re-written after the copy; local position journal during the wait | Small | W1 |
| W7 | **Session steps and UI:** two-salt passkey ceremony in `AsyncKeyProvider`; move driver over `swiftMoveNextStep()`; backup; the one screen; read-only predecessor view; left-behind list; race rule | Medium | W2 |
| W8 | **Home:** merge `home-0.5-h2` (predecessor routes, genesis receipts, tested in `crates/colophon-home-wasm/tests/v05_relay_succession.rs`); deploy the relay as a home; slot provisioning and the member request per account. Notices are not implemented (`docs/new-app.md`), so the gate's warning shows | Medium | — |
| W9 | **Tests on shipped-format data.** A generator, built from Marginalia's Swift source at the build-37 commit, makes synthetic libraries for each shape: root starter (layout 1 and 2); keyring with passkey PRF slot and kit; two devices; transcripts; Marginalia bridge imports; a revoked member with `kept`. Run it on an iOS device too, for the signature probe. Each fixture goes end to end: preflight, move, F by W2's code, 1.0 and 1.1 readers stopping, the podcast fold equal to the 0.5 projection. No real data in either repository | Medium | W2, W3, W8 |
| W10 | **Rehearsal on Mike's library** (keyring, the hardest shape), on his own iPhone. Its device keys are in the Secure Enclave and can't move. First, a dry run: preflight and backup only, which is also §21 item 4. Then a full move of a copied folder against a staging home. Keep that F off iCloud and production, because it is a real competing freezing entry made with his keys. Then the real move | Small to run; it gates everything | W1–W9 |

## 5. Options

| | (a) Full succession, as the spec defines | (b) Succession plus re-import of current state | (c) New account, export/import, old library kept |
| --- | --- | --- | --- |
| Keys and devices | Kept (same keys, roles, slots) | Kept | New keys; every device pairs again. Breaks "no new account, no new passkey" (§16.2) and the one-identity rule |
| History | Every record, with original author and time as evidence | Current state only; history stays in the frozen library | Current state; old library separate |
| Old apps | Stop cleanly at F | Stop cleanly at F | Keep writing to the old library: a split that loses writes silently |
| Links (Tunnel, agents, principal bindings) | Can move, with a verified succession and `migration` (§15.4) | Same | No verifiable link |
| Build cost | W1–W10 | W1, W2, W6–W10, plus a state writer per kind instead of W3–W5 | W1, an import tool and re-pairing UI. No W2, no home predecessor routes |
| Risk | The most moving parts, but all on the spec path and tested by the engine | Similar, minus translator coverage. Lossy by design | Lowest protocol risk, highest data risk |

**What the spec requires.** Keeping the keys requires succession: §16.2 says Swift libraries
"move by clean copy". The copy itself need not be complete. `migration` is the owner's assertion,
omissions are allowed with reasons (up to 4,096 of them), and records left behind stay readable.
So (b) is legitimate, and (c) is only the spec's fallback, the "unverified copy".

**Recommendation: (a).** The translators that make (b) look cheaper already exist in Rust for
every podcast kind, so (b) saves little and loses history. (c) recreates the split-library
problem the succession exists to prevent. To keep (a) small, keep the drain and the 1-hour delay.
If blobs slip, ship with transcripts regenerated rather than copied.

## 6. Decisions for Mike, and the checklist

| Decision | Recommended answer |
| --- | --- |
| 1. Approach | (a) |
| 2. Vault seed (§16.2 "Not specified") | New seed, as the reference tool does |
| 3. `recoveryDelay` at genesis | 3,600 s for the move; offer 72 h as a pending transition afterwards |
| 4. Homes | One home, `relay.toolsperson.com`, `headQuorum` 1. §18's two homes is the reference; one is the minimum. Add a second later by transition |
| 5. Transcripts | Copy them (W5). Fallback: regenerate on the device |
| 6. Drain window | 30 days, the maximum. Nothing waits on the `migration` entry |
| 7. Members | Pre-grant each predecessor member's existing key, so other devices need no approval, if the 0.5 `KeychainKeys` can wrap the old member identity. Otherwise each device self-grants with its controller key |
| 8. Where the successor's records live | iCloud container (a new folder beside the frozen library) plus the home. Apple devices find it without the network; Android uses the home |
| 9. `policy.history` | `public` if Android must join with nothing: under `members` a new device can fetch only the head (`docs/session.md`). It discloses authority entries (keys, member labels, times), not content |
| 10. Roles | Kept exactly (§16.2 requires it); show the reference later |
| 11. Marginalia | Ship its matching update, or accept that it stops at F for shared-library users |
| 12. `omitted` reason names beyond `invalidPayload` | Adopt the core's: `liveState`, `notAMember`, `badSignature`, `tooLarge`, `pathMismatch`, `notAPredecessorNamespace` |

**Before the first real user:**

- [ ] W1–W9 merged. The relay is deployed as a home on production, with predecessor routes.
- [ ] Every W9 fixture passes on an iOS device, with old readers stopping at F.
- [ ] The §16.3 iOS signature probe has run.
- [ ] Mike's dry run, the rehearsal on a copy, and his real move all succeeded, with the fold equal.
- [ ] The backup and its three checks work, and a restore of the backup into a scratch folder opens.
- [ ] The race rule is tested with two devices on one iCloud account.
- [ ] A support path exists: a report with counts, never content.
- [ ] Each user's library shape is known from their support report (root or keyring, devices,
      namespaces, blob count) before their 2.0 build goes out.

## 7. Unknown after this research

- How many users there are, and each library's shape and size. Is anyone besides Mike on a
  keyring library, on several devices, or using Marginalia's shared library?
- Whether Taupe 1.1.0 (34) is live on the App Store (submitted with automatic release; not
  confirmed).
- How much of Taupe's service layer `ColophonListeningKit` covers (transcript preparation,
  questions, playlists, chapters). This sizes W1.
- Whether the 0.5 `KeychainKeys` can use the old member identities (decision 7).
- How iCloud surfaces two devices writing one `authority/<seq>.json`, and how the Swift log reads
  a conflict copy.
- The relay's deployment state as a home, how slots are provisioned per account, and when
  notices land.
- Whether Android can join under `policy.history: members` by any route other than a shared
  folder.
- The §16.3 iOS and visionOS signature probe has not run. Libraries signed on iOS are unverified
  until it does.
- Whether the Apple Watch app, widgets or CarPlay read the library directly. If they do, they
  need the same switch as the app.
- Whether Android Taupe users already hold a separate library that would need merging. That is
  out of scope here.
