# Colophon

**An open standard for a personal library that apps and AI agents are invited into.**

Your library lives on your devices. Your keys decide who gets access.

Colophon is a sync and identity protocol for the things a person reads, hears and writes: saved
articles, books, podcasts and notebooks. A library belongs to an **account**, a keyring of
controllers (passkeys, security keys, device owner keys, recovery kits) whose identifier is the
digest of its first authority record. Each app, device or agent joins as a **member**, with its own
key and a grant scoped to the namespaces it needs. Members write signed, encrypted operations, and
every client folds the admitted operations into the same state. A **home** keeps the history and
vouches for its head, but storage and transport never grant access: a home, a folder or iCloud
Drive only moves bytes it cannot read. There is no vendor account.

## Status: 0.5.0

**0.5 ("one portable identity: an account") is released as 0.5.0, spec revision 18.** Its formats
and reader rules are frozen, provisionally: some freeze conditions are still open (missing
vectors, the Swift differential corpus, a dry run on a real library, Galley alignment, physical
devices), and they are closed in 0.5.x without changing any format.

Read [spec §21.1, what 0.5.0 does not do](spec/colophon-0.5.md#211-what-050-does-not-do) before
building on it. The short version: one home per account (several are experimental), no notices,
no guaranteed background sync, one verifier implementation, nothing proven on physical phones,
sync is one request per record, and nothing is published to a package registry.

| Read | For |
| --- | --- |
| [Specification](spec/colophon-0.5.md) | The normative text: records, the account and its keyring, members and grants, homes, succession, conformance (§21) |
| [Guide](spec/colophon-0.5-guide.md) | What 0.5 is for and how the pieces fit, without the normative detail |
| [Changes from 0.4](spec/colophon-0.5-changes.md) | Upgrade paths, review answers and deferred items |
| [Conformance vectors](conformance/0.5/README.md) | 437 cases with exact bytes and one named outcome each, and what covers each required item |
| [Changelog](CHANGELOG.md) | What changed in each release |
| [Known issues](docs/known-issues.md) | Open implementation gaps beside §21.1 |

## Use it

Nothing is published to npm, Maven or a Swift registry. Each GitHub release carries four
packages built from the tagged commit, with checksums and a `manifest.json` that records how they
were built ([release packaging](docs/release-packaging.md)); they are unsigned.

| Package | File | Start with |
| --- | --- | --- |
| Apple XCFramework (macOS, iOS, visionOS) | `ColophonFFI-<version>.xcframework.zip` | [A new Apple app](docs/new-app.md), [the Apple session](docs/session.md), [native bindings](docs/native-bindings.md) |
| Android AAR (Kotlin) | `colophon-android-<version>.aar` | [Android and Kotlin](docs/android.md) |
| JavaScript package | `colophon-core-<version>.tgz` | [The JavaScript session](docs/js-session.md), [JS API](docs/js-api.md) |
| Home bundle (Bun or Node) | `colophon-home-<version>.tar.gz` | [Reference relay and home](relay/README.md), [sync through a relay](docs/sync.md) |

The root Swift package is **ColophonSDK**. It expects the framework at
`sdk/apple/ColophonFFI.xcframework`: unzip the release's framework there, or build it with
`bash scripts/build-apple.sh`. Its products are `ColophonSession`, `ColophonSessionUI`,
`ColophonKeys`, `ColophonKit`, `ColophonKitStorage`, `ColophonMigration`, `ColophonFFI` (the
framework itself) and one kit per domain
(`ColophonSavedKit`, `ColophonBooksKit`, `ColophonListeningKit`, `ColophonNotesKit`).

The four domains are specified in [docs/domains](docs/domains/README.md):
[`reading.saved`](docs/domains/reading.saved.md), [`reading.books`](docs/domains/reading.books.md),
[`listening.podcasts`](docs/domains/listening.podcasts.md) and [`notes`](docs/domains/notes.md).
Libraries of the shipped Swift apps move to 0.5 by a verified succession (spec §15 and §16.3,
the [guide](spec/colophon-0.5-guide.md) §4, `SwiftMove` in `ColophonMigration`);
[migration](docs/migration.md) and [app migration](docs/app-migration.md) keep the 0.4 history.

## Build and test from source

Rust 1.99.1, Bun, Node 24 with npm, wasm-bindgen CLI 0.2.130; Xcode for the Apple parts; JDK 17,
the Android SDK and NDK `30.0.16248370` for Android.

```sh
cargo test --workspace --locked          # the Rust core, FFI, WASM and relay-backed tests
bash scripts/test-home.sh                # the home, with its kill loop
bash scripts/test-swift.sh               # the Apple SDK (builds the home module; needs the framework)
bash scripts/test-kotlin.sh              # the Kotlin SDK, with journeys against the real relay
bash scripts/test-js.sh                  # the JS session under Bun and in headless Chrome
bash scripts/package-release.sh --verify # the four packages, each built twice and compared
```

The scripts say what each needs and fail rather than skip. [Architecture](docs/architecture.md)
covers the crates and dependency pins, [the engine](docs/engine.md) the Rust API, and
[performance](docs/performance.md) the measurements behind §21.1 item 11.

### Layout

| Path | What it is |
| --- | --- |
| `crates/colophon-core` | The sans-IO Rust core: records, the 0.5 verifier and engine, the 0.4 engine, the domain folds |
| `crates/colophon-ffi`, `crates/colophon-wasm` | UniFFI (Swift, Kotlin) and WASM exports of the core |
| `crates/colophon-home-wasm`, `relay/` | The home as a WASM module and the Bun/Node relay that serves it |
| `swift/`, `Package.swift` | The Apple SDK (ColophonSDK) |
| `sdk/kotlin`, `sdk/android` | The Kotlin session and the Android library |
| `js/` | `@colophon/core`, the JavaScript session |
| `conformance/` | Vectors for 0.3, 0.4 and 0.5; the keys in it are test keys, never for a real library |
| `apps/`, `examples/`, `playground/` | Test apps, a sample app and the browser playground |
| `reference/swift` | The independent Swift reference implementation of 0.1, kept for migration |

## Why

Personal AI is only as trustworthy as the place your memory lives. Today that place is
whichever app owns your data, and an agent either scrapes it or doesn't get in. Colophon
makes access explicit instead:

- **Scoped.** An agent can read your listening without seeing your reading.
- **Revocable.** Ending access stops future reads and writes. It doesn't rewrite the past: what
  a member already wrote stays, still attributed to it.
- **Attributed.** Who wrote something comes from their key, never from a field they fill in.
  AI-written notes carry `origin: ai`, so they can't pass for the person's words.
- **Portable.** Every client folds the same operations into the same meaning, so a person can
  change apps without losing what their history means.
- **Honest.** Missing history, keys or files remain visible, retryable states. Nothing is
  reported as an empty library because a member lacks permission.

## Earlier versions

[0.4](spec/colophon-0.4.md) replaced the single root key with a keyring
([keys](spec/colophon-0.4-keys.md)); 0.4 libraries upgrade to 0.5 in place.
[0.3](spec/colophon-0.3.md) separated immutable intent from replaceable playback state.
[0.1](spec/colophon-0.1.md) is the baseline inside LUFF's shipped Swift apps, whose libraries
move to 0.5 by a verified succession. In LUFF's Marginalia repository, "Colophon 0.2"
([note](spec/colophon-0.2.md)) names the Swift layout-2 step that 0.3 absorbed.

## License

Apache License 2.0. See [LICENSE](LICENSE).
