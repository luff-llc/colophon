# Release packaging

`scripts/package-release.sh` builds the four things an app or a host consumes, from one commit,
with checksums. It never signs and never publishes: no npm publish, no Maven, no registry, no
upload. Its output stays on the machine that ran it, in `dist/release/<version>/` (git-ignored).

| Artefact | File | Built by |
| --- | --- | --- |
| Apple XCFramework | `ColophonFFI-<version>.xcframework.zip` | `scripts/build-apple.sh` |
| Android AAR | `colophon-android-<version>.aar` | `scripts/build-android.sh` |
| JS package | `colophon-core-<package version>.tgz` | `npm ci`, `js/scripts/build.sh`, `npm pack` |
| Home bundle | `colophon-home-<version>.tar.gz` | `cargo build -p colophon-home-wasm` (wasm32, release) |

The home bundle is `relay/*.js`, `relay/package.json` and `colophon_home_wasm.wasm` under one
top directory. A host with Bun or Node runs it without a Rust toolchain: point
`COLOPHON_HOME_WASM` (or `home.wasm` in the relay config) at the `.wasm` in the bundle.

Next to each artefact is `<file>.contents.sha256`, the sha256 of every file inside it (and of
every entry of a `.jar` inside the AAR). `SHA256SUMS` lists the artefacts this run built.
`manifest.json` records the commit, the version, whether the tree was dirty, `inputs_sha256` (a
digest over every exported source file), `SOURCE_DATE_EPOCH`, the number of passes, and per
artefact its name, size, sha256, whether it reproduced, how many payload files still contain a
path of the build machine, and the tools used with the sha256 of their binaries.

Each GitHub release carries the four artefacts of a `--verify` run at its tag, with `SHA256SUMS`,
the `.contents.sha256` files and `manifest.json`. Nothing is signed and nothing is published to a
registry.

## Build from a tag

```sh
git clone https://github.com/luff-llc/colophon && cd colophon
git checkout v0.5.0
bash scripts/package-release.sh --verify          # all four, each built twice and compared
bash scripts/package-release.sh --only home       # one artefact (apple, android, js or home)
```

The version is `git describe --tags --match 'v[0-9]*'` without the `v`. The commit is
`git rev-parse HEAD`, and `SOURCE_DATE_EPOCH` is the commit time. Nothing reads the clock.

How a run works:

* It refuses a tree with any change or untracked file. `--allow-dirty` builds the working tree
  with its changes; the version becomes `<describe>-dirty-<first 12 hex of inputs_sha256>` and
  the manifest says `"dirty": true`. Use it only while developing the script.
* Each pass builds from its own export: `git archive` of the commit, or (dirty) the tracked and
  untracked, non-ignored files of the tree. Ignored files (`node_modules`, `target`, build
  output, `local.properties`) never enter. Everything lives in `dist/release/.run.*` and is
  removed on exit, success or not.
* Each pass runs under `env -i` with only a fresh `HOME`, `TMPDIR`, Cargo home, Gradle home and
  npm cache, its own target directory, a `PATH` of the resolved tools plus
  `/usr/bin:/bin:/usr/sbin:/sbin`, `LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH`, `ZERO_AR_DATE=1`,
  `CARGO_INCREMENTAL=0`, the pinned toolchain names, and `ANDROID_HOME`, `ANDROID_NDK_HOME`,
  `JAVA_HOME`, `DEVELOPER_DIR`, `CARGO_BUILD_JOBS` and pressroom's variables when set.
  `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, compiler wrappers, `GRADLE_OPTS`, `JAVA_TOOL_OPTIONS`
  and every ambient `npm_config_*` are gone, and npm gets an empty user and global config.
  Gradle runs with `--no-daemon` and an empty `GRADLE_USER_HOME`, so no init script or signing
  configuration from `~/.gradle` can act.
* Nothing is shared with the machine's Cargo home, so its `config.toml` never applies. Pass a
  fills its own registry with `cargo fetch --locked` (`Cargo.lock` pins every crate with its
  checksum; every build uses `--locked`). Pass b starts from a clone of pass a's registry
  (`cp -Rc` on macOS, `cp -a --reflink=auto` elsewhere) and runs Cargo offline
  (`CARGO_NET_OFFLINE=true`). The registry is a real directory: a symlink in a crate's source
  path breaks proc macros that resolve files relative to it (askama in `uniffi_bindgen`). Gradle
  and npm download again in each pass into their fresh homes.
* `scripts/build-apple.sh` and `scripts/build-android.sh` get `RELEASE_NO_INSTALL=1`: a missing
  Rust target, toolchain or `rust-src` fails the run instead of being installed. A missing tool
  (rustup, the pinned toolchain, wasm-bindgen 0.2.130, node, cargo-ndk, rg, xcodebuild) fails
  before anything builds.
* The build fails if it rewrites the committed generated Swift or Kotlin bindings.
* `--verify` builds each selected artefact a second time from a second export, with its own
  target directory, Cargo home, Gradle home, npm cache and `node_modules`, and fails with a list
  of the payload files that differ.
* `SHA256SUMS` and `manifest.json` are written only after every selected artefact built and
  (with `--verify`) reproduced. The finished set is then moved into `dist/release/<version>/`
  in one step. An existing directory is refused unless `--force`, which replaces it whole;
  nothing is merged. With `--only` the directory holds only that run's artefacts. A failed run
  leaves `dist/release/<version>.FAILED` and no `SHA256SUMS`.
* It refuses a source, home or temporary path that contains whitespace, because the path
  remapping below goes in a whitespace-separated rustflags variable.

## Check the checksums

```sh
cd dist/release/<version>
shasum -a 256 -c SHA256SUMS
```

To compare with another machine's build, compare `SHA256SUMS`. When an archive differs, compare
the `.contents.sha256` files to see which payload files differ.

## What is deterministic

Per-target rustflags `--remap-path-prefix` map the export (`/colophon`), the Cargo homes
(`/cargo`), `RUSTUP_HOME` (`/rustup`) and the target directory (`/target`). They go in
`CARGO_TARGET_<TRIPLE>_RUSTFLAGS`, which Cargo joins with the `aarch64` flags in
`.cargo/config.toml` (`RUSTFLAGS` would replace them). The archives the script writes itself
(the XCFramework zip and the home tar) have a sorted file list, every mtime set to the commit
time, modes 0644 and 0755, owner 0:0 (tar) and no extra attributes (`zip -X`, `--no-xattrs
--no-mac-metadata`, `gzip -n`). The zip step refuses symlinks rather than dropping them.
`npm pack` already writes fixed mtimes and a sorted list. Every Gradle archive task in
`sdk/android` is set to `isPreserveFileTimestamps = false` and `isReproducibleFileOrder = true`.
That covers more than the release AAR; it is harmless for the other tasks, and a narrower setting
was not tested.

`xcodebuild -create-xcframework` writes the `AvailableLibraries` array of `Info.plist` in a
different order on each run (the same five entries). The script sorts that array by
`LibraryIdentifier` in the packaged copy, with `plutil`; nothing else in the plist changes.

Not changed: the release profile has no `strip` setting, and the script does not add one (the
static libraries keep their symbols, as app links need them).

Before 0.5.0 the script was rehearsed on two Macs: all four artefacts reproduced bit for bit once
the plist was sorted, and the hermetic version reproduced the home bundle. The 0.5.0 release run
is recorded in that release's `manifest.json`. Two machines' builds have not been compared.

## Toolchains

| Tool | Version | Pinned or recorded |
| --- | --- | --- |
| Rust | 1.99.1 | pinned (`RELEASE_TOOLCHAIN` default); binary sha256 recorded |
| Rust nightly, visionOS slices only | `nightly-2026-11-05` | pinned by date (`VISIONOS_TOOLCHAIN` default); binary sha256 recorded |
| wasm-bindgen CLI | 0.2.130 | pinned: the script and `js/scripts/build.sh` check the version (default `~/.cargo/tools/wasm-bindgen-0.2.130/bin`); binary sha256 recorded |
| npm dependencies (TypeScript 5.9.3) | | pinned by `js/package-lock.json` integrity hashes, installed with `npm ci` |
| Rust crates | | pinned by `Cargo.lock` checksums, `--locked` |
| Gradle | 8.14.3 | pinned: wrapper properties with the distribution sha256, which is recorded |
| Android Gradle plugin, Kotlin, Android dependencies | 8.7.3, 2.2.21 | versions in `sdk/android/build.gradle.kts`; **no Gradle dependency verification metadata yet** (a follow-up) |
| NDK, JDK | 30.0.16248370, 17 | `scripts/build-android.sh` defaults; recorded |
| Xcode, Node, npm, cargo-ndk, rustup | | only recorded (versions, and the sha256 of node and cargo-ndk) |

`SKIP_VISIONOS=1` leaves out the visionOS slices; the manifest's `visionos_slices` says whether
they are in.

## Signing

Nothing here signs: no code signing identity, no keystore, no GPG key is read. Signing is the
owner's decision. If it is added, it goes after `--verify`, as a separate step over the files in
`dist/release/<version>/`: a detached signature over `SHA256SUMS` (which covers every artefact),
and any platform signature the owner wants. A detached signature (an `.asc` for Maven Central)
leaves the artefact as it is. `codesign` on the XCFramework changes the file, so the signed copy
gets its own checksum, and the unsigned checksums stay the ones anyone can reproduce.
