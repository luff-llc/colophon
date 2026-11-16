# Release packaging

`scripts/package-release.sh` builds the four things an app or a host consumes, from one commit,
with checksums. It never signs and never publishes: no npm publish, no Maven, no registry, no
upload. Its output stays on the machine that ran it, in `dist/release/<version>/` (git-ignored).

| Artefact | File | Built by |
| --- | --- | --- |
| Apple XCFramework | `ColophonFFI-<version>.xcframework.zip` | `scripts/build-apple.sh` |
| Android AAR | `colophon-android-<version>.aar` | `scripts/build-android.sh` |
| JS package | `colophon-core-<package version>.tgz` | `js/scripts/build.sh`, then `npm pack` |
| Home bundle | `colophon-home-<version>.tar.gz` | `cargo build -p colophon-home-wasm` (wasm32, release) |

The home bundle is `relay/*.js`, `relay/package.json` and `colophon_home_wasm.wasm` under one
top directory. A host with Bun or Node runs it without a Rust toolchain: point
`COLOPHON_HOME_WASM` (or `home.wasm` in the relay config) at the `.wasm` in the bundle.

Next to each artefact is `<file>.contents.sha256`: the sha256 of every file inside it (and of
every entry of a `.jar` inside the AAR). `SHA256SUMS` lists the artefacts. `manifest.json` records
the commit, the version, whether the tree was dirty, `SOURCE_DATE_EPOCH`, and per artefact its
name, size, sha256, whether `--verify` reproduced it, how many payload files still contain a path
of the build machine, and the toolchain versions actually used.

**The 0.5 exports change once more before the tag** (a security fix on another branch). The
checksums from the rehearsal runs on the `pkg-0.5` branch are only a rehearsal. The release run is
repeated at the tag.

## Build from a tag

```sh
git clone https://github.com/luff-llc/colophon && cd colophon
git checkout v0.5.0
bash scripts/package-release.sh --verify          # all four, each built twice and compared
bash scripts/package-release.sh --only home       # one artefact (apple, android, js or home)
```

The script refuses a tree with changes or untracked files in its inputs (`.cargo`, `Cargo.toml`,
`Cargo.lock`, `crates`, `js`, `relay`, `sdk`, `swift`, `scripts`, `Package.swift`).
`--allow-dirty` builds anyway, adds `-dirty` to the version and records `"dirty": true`; use it
only while developing the script. It also fails if the build rewrites the committed generated
Swift or Kotlin bindings, since the artefact would then not match the commit.

The version is `git describe --tags --match 'v[0-9]*'` without the `v`; the commit is
`git rev-parse HEAD`; `SOURCE_DATE_EPOCH` is the commit time. Nothing reads the clock.

`--verify` builds each selected artefact twice, from empty target directories
(`$CARGO_TARGET_DIR/package-release/a` and `/b`), into `dist/release/<version>/` and
`dist/release/<version>.verify/`, and fails with a list of the payload files that differ.

## Check the checksums

```sh
cd dist/release/<version>
shasum -a 256 -c SHA256SUMS
```

To compare with another machine's build, compare `SHA256SUMS`; when an archive differs, compare
the `.contents.sha256` files to see which payload files differ.

## What is deterministic

The script sets, for every build: `SOURCE_DATE_EPOCH` (commit time), `TZ=UTC`, `LC_ALL=C`,
`ZERO_AR_DATE=1`, `COPYFILE_DISABLE=1`, and per-target rustflags
`--remap-path-prefix` for the source root (`/colophon`), `CARGO_HOME` (`/cargo`), `RUSTUP_HOME`
(`/rustup`) and the target directory (`/target`). They go in `CARGO_TARGET_<TRIPLE>_RUSTFLAGS`,
which cargo joins with the `aarch64` flags in `.cargo/config.toml` (`RUSTFLAGS` would replace
them). The archives it writes itself (the XCFramework zip and the home tar) have a sorted file
list, every mtime set to the commit time, modes 0644 and 0755, owner 0:0 (tar) and no extra
attributes (`zip -X`, `--no-xattrs --no-mac-metadata`, `gzip -n`). `npm pack` already writes
fixed mtimes and a sorted list. Gradle's archive tasks are set to `isPreserveFileTimestamps = false`
and `isReproducibleFileOrder = true` in `sdk/android/build.gradle.kts`.

`xcodebuild -create-xcframework` writes the `AvailableLibraries` array of `Info.plist` in a
different order on each run (the same five entries). The script sorts that array by
`LibraryIdentifier` in the packaged copy, with `plutil`; nothing else in the plist changes. The
copy in `sdk/apple/` that the root `Package.swift` uses is left as `xcodebuild` wrote it.

Not changed: the release profile has no `strip` setting, and the script does not add one (the
static libraries keep their symbols, as app links need them).

Rehearsal result on the MacBook (macOS 27, Xcode 27.2, rustc 1.99.1, nightly 1.101.0 2026-11-05
for visionOS), 2026-11-16, each artefact built twice from empty target directories:

| Artefact | Bit for bit | Notes |
| --- | --- | --- |
| Home bundle | yes | |
| JS package | yes | |
| Android AAR | yes | all 1,607 payload entries, including every class in `classes.jar` |
| Apple XCFramework | yes, once the plist is sorted | all five static libraries (visionOS too) and headers matched on the first try; only `Info.plist` differed, by entry order |

Every artefact had no payload file containing a path of the build machine. A full `--verify` of
all four at one clean commit was started and stopped for machine load before it finished, so the
four results above come from separate runs (`--only`) at nearby commits with the same build
inputs. Two Macs, or one Mac and another Xcode, have not been compared.

## Toolchains

| Tool | Version | Pinned where |
| --- | --- | --- |
| Rust | 1.99.1 | `RELEASE_TOOLCHAIN` default in `scripts/package-release.sh` |
| Rust nightly (visionOS slices only) | recorded in the manifest | `VISIONOS_TOOLCHAIN` (default `nightly`); not pinned to a date |
| wasm-bindgen CLI | 0.2.130 | `js/scripts/build.sh` checks it and looks first in `~/.cargo/tools/wasm-bindgen-0.2.130/bin`; `Cargo.toml` pins the crate |
| TypeScript | 5.9.3 | `js/package-lock.json` (`npm ci`) |
| Gradle | 8.14.3 | `sdk/android/gradle/wrapper/gradle-wrapper.properties` (with its sha256) |
| Android Gradle plugin, Kotlin | 8.7.3, 2.2.21 | `sdk/android/build.gradle.kts` |
| NDK | 30.0.16248370 | `scripts/build-android.sh` default |
| JDK | 17 | `scripts/build-android.sh` default |
| Xcode, Node, npm, cargo-ndk | not pinned | recorded in the manifest |

`SKIP_VISIONOS=1` leaves out the visionOS slices (they need nightly Rust with `rust-src`); the
manifest's `visionos_slices` says whether they are in.

## Signing

Nothing here signs: no code signing identity, no keystore, no GPG key is read. Signing is the
owner's decision. If it is added, it goes after `--verify`, as a separate step over the files
in `dist/release/<version>/`: a detached signature over `SHA256SUMS` (which covers every
artefact), and any platform signature the owner wants. A detached signature (an `.asc` for Maven
Central) leaves the artefact as it is. `codesign` on the XCFramework changes the file, so the
signed copy gets its own checksum, and the unsigned checksums stay the ones anyone can reproduce.
