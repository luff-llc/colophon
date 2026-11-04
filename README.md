# Colophon

**An open standard for a personal library that apps and AI agents are invited into.**

Your library lives on your devices. Your keys decide who gets access.

Colophon is a data standard for the things a person reads, hears and writes: saved
articles, books, podcasts and notebooks. Each app or agent that uses a library joins it as
a *member*, with its own key and a grant scoped to the parts it needs. Members write
signed, encrypted operations, and every client folds the admitted operations into the same
state. Storage and transport never grant access: a folder, iCloud Drive or a relay only
moves bytes it can't read. There is no vendor account.

This repository holds the Colophon 0.2 Rust core and JavaScript package, the
playground demo, plus the 0.1 specification, conformance vectors and shipped
Swift reference implementation.

## Try it

The fastest way to see Colophon: the playground runs the real 0.2 Rust core as
WebAssembly in one browser tab, where an AI agent knocks, gets narrow access,
does useful work, and is shown the door.

```sh
# Rust stable; on Homebrew installations:
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
npm ci --prefix js && npm --prefix js run build   # @colophon/core + wasm
cd playground && npm install && npm run dev       # http://localhost:5173
```

Open `http://localhost:5173/?demo` and click Next through knock → grant → act →
end → recover. Without a key the scripted stand-in performs the agent's tool
calls; with `MUSE_API_KEY` in `playground/.env.local`, the live Muse model
answers instead (the key stays on the server; see `playground/README.md`).

## Why

Personal AI is only as trustworthy as the place your memory lives. Today that place is
whichever app owns your data, and an agent either scrapes it or doesn't get in. Colophon
makes access explicit instead:

- **Scoped.** An agent can read your listening without seeing your reading.
- **Revocable.** Ending access stops future reads and writes immediately. It doesn't
  rewrite the past: what a member already wrote stays, still attributed to it.
- **Attributed.** Who wrote something comes from their key, never from a field they fill
  in. AI-written notes carry `origin: ai`, so they can't pass for the person's words.
- **Portable.** Every client folds the same operations into the same meaning, so a person
  can change apps without losing what their history means.
- **Honest.** Missing history, keys or files remain visible, retryable states. Nothing
  is reported as an empty library because a member lacks permission.

## Rust core and JavaScript package (0.2)

The pure Rust core implements records, P-256 host key steps, HPKE, grants, admission, epoch
rotation, recovery, three domain folds, the ledger and generated agent tools. It performs no
I/O and takes time and entropy explicitly. `colophon-wasm` and `@colophon/core` run the same
implementation with non-extractable WebCrypto keys.

```sh
# Rust stable; on Homebrew installations:
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
cargo test
cargo clippy -- -D warnings
cargo build -p colophon-core --target wasm32-unknown-unknown

# Install wasm32 target and wasm-bindgen-cli 0.2.130 if not already available.
# Node 24+, npm; TypeScript is the only npm build dependency.
npm ci --prefix js
npm --prefix js run build       # cargo release + wasm-bindgen --target web + tsc
npm --prefix js test            # WebCrypto smoke and Rust/WASM fixture parity
```

`js/dist/` is the distributable `@colophon/core` package output; serve its wasm alongside its
ES modules. Build artifacts and local dependency caches are not committed. No package has been
published by this worktree.

See the [0.2 spec](spec/colophon-0.2.md), [JavaScript contract](docs/js-api.md),
[architecture and dependency pins](docs/architecture.md), and [0.2 conformance library](conformance/0.2/).
Regenerate the deterministic fixture with
`COLOPHON_UPDATE_VECTORS=1 cargo test -p colophon-core --test conformance`.

Version 0.2 is an implemented preview with clean kinds and no 0.1 compatibility. Persistence,
sync, hardware custody, an online budget sequencer, native FFI and an executable CLI/MCP transport
remain host or follow-up work. The sections below describe the historical Swift 0.1 package.

## Swift modules: take only what you need

| Module | What it is | Depends on |
| --- | --- | --- |
| `ColophonCore` | Records, canonical encoding, identities (Secure Enclave, software), sealed keys, recovery kit | CryptoKit |
| `ColophonStore` | `RecordStore` (folder, memory), `StoreSync`, HTTP relay profile | Core |
| `ColophonAuthority` | Authority history, grants and caveats, revocation, handover, keyring controllers | Core, Store |
| `ColophonReplica` | Operations, admission, `DomainModule`, operation and query specs | Core, Store, Authority |
| `ColophonSaved` | `reading.saved`: read-later links, reading state, metadata | Replica |
| `ColophonBooks` | `reading.books`: reading plans, rereads, progress, book notes | Replica |
| `ColophonListening` | `listening.podcasts`: follows, positions, queue, playlists, chapters, transcripts, notes | Replica |
| `ColophonNotes` | `notes`: notebooks with Markdown, LaTeX, code and recorded outputs | Replica, Listening |
| `ColophonMCP` | An MCP server generated from domain modules | Replica |
| `colophon` (executable) | Join a library as an agent; status, verify; serve MCP on stdio | all |

Cryptography is P-256 ECDSA and ECDH, HKDF-SHA256 and AES-GCM: the primitives built into
CryptoKit, WebCrypto and Android Keystore, so other implementations need no third-party
crypto. The Swift package has no dependencies.

## Connect an agent

```sh
swift build --product colophon
.build/debug/colophon "<library folder>" join --label "Muse on MacBook" --namespaces listening.podcasts,notes
# compare the six-digit code with the app that can approve access, and approve there
.build/debug/colophon "<library folder>" mcp      # MCP over stdio
```

The agent gets a `<namespace>__read` tool per module and one tool per operation, generated
from each module's operation specs. Every write goes through the replica, so admission,
grants and attribution apply unchanged.

## Write a domain module

A module names a namespace, its operation kinds and a deterministic fold:

```swift
public enum SavedLinks: DomainModule {
  public static let namespace = "reading.saved"
  public static let version = 1
  public static let kinds = ["capture.link", "item.setState", "item.editMetadata"]
  public static func fold(_ view: ReplicaView) -> SavedShelf { SavedShelf(view) }
}
```

Folds must be deterministic, must skip kinds they don't know, and must keep payload fields
they don't interpret. Conflicts are recorded, never silently resolved (spec §9).

## Tests and conformance

```sh
COLOPHON_SOFTWARE_KEYS=1 swift test        # software-key suite; hardware acceptance is separate
COLOPHON_SOFTWARE_KEYS=1 COLOPHON_WRITE_VECTORS=1 swift test --filter writeVectors   # regenerate vectors
```

`conformance/` holds a library, the keys that wrote it and `expected.json`. Another
implementation conforms if it reproduces `expected.json` from the records and keys
(spec §11). `conformance/keyring/` is a separate vector for keyring controllers. The keys in
`conformance/` are test keys, published so anyone can check the vectors; never use them for
a real library.

## Swift 0.1 status and limits

Colophon 0.1 is the protocol baseline, and this is its reference implementation, the one inside
LUFF's apps. It is a preview, not yet a stable SDK:

- **Apple platforms only** for now (macOS 14, iOS 17, visionOS 26). The kernel uses only
  primitives other platforms provide. The 0.2 Rust/wasm implementation above is separate.
- **`ColophonSaved` is a subset of `reading.saved`.** It folds capture, state and metadata.
  Deletion and the reading extensions (content, feeds, annotations, browser checkpoints) are
  kept in history but not folded yet, so a shelf here can still list a deleted item.
- **Open protocol questions** (spec §13): compaction for long histories, an online
  sequencer profile, and capability negotiation between module versions.
- **Wire constants.** Some digest seeds and purposes, such as `org.marginalia.reader` and
  `org.luff.taupe.playback-progress`, name the apps that first wrote them. They are part of
  the wire format and must not change.

## Findings that shaped 0.1

1. Recovering the root must also recover the data keys: every epoch key is sealed to the
   recovery identity.
2. Revocation must not punish the past: a revoke lists the operations already seen, and
   they stay.
3. A bridge publishes against what it last saw, or replicas silently diverge.
4. A signature can't date anything: backdated writes from a revoked member are held for a
   person to decide.
5. Root handover must re-share keys before the handover entry; afterwards only the new
   root signs.
6. A presence-protected root must sign a whole action after one Face ID check, and must
   degrade on devices without a passcode.
7. Display order must come from the agreed operation order, never from author timestamps.

## License

Apache License 2.0. See [LICENSE](LICENSE).
