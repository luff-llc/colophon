# Smoke programs for the generated 0.5 bindings

They are not part of `cargo test`. Each one drives the real exports from the host language: a
typed error, creation with a host-held P-256 key (typed steps in, typed signatures out; controllers
as typed `ControllerSpec`, the identity as `AccountIdentity`), an engine over a host `HostSource`,
an unlock from the host's ECDH result, an action through `begin_*` and `finish`, a replay refused
as `Consumed`, `lock` and the typed `Locked` refusal, seed transfer, a source callback that throws
(arrives as `Host`, with the host's message), and (Swift and Kotlin) **the successor genesis of a
Swift keyring library**: it reads the repository's `conformance/keyring` fixture (run from the
repository root, or set `COLOPHON_REPO`), makes the one passkey assertion that rebuilds the
passkey's slot and opens the Swift slot, signs the genesis and the handover, and opens an engine
over the stored objects whose `swift_succession()` is `WindowNotOpen`. The JavaScript program
additionally checks that a `Promise`, `undefined` or an `Array` returned by `read` is a `Host`
error naming the callback; it has **not been run** (see the Web section).

## Generate the bindings into a scratch directory (never into `swift/` or `sdk/`)

```sh
export CARGO_TARGET_DIR=/tmp/b1-target OUT=/tmp/b1-bindings
cargo build --locked -p colophon-ffi
cargo build --locked -p colophon-ffi --features bindgen --bin uniffi-bindgen
for l in swift kotlin; do
  $CARGO_TARGET_DIR/debug/uniffi-bindgen generate --library $CARGO_TARGET_DIR/debug/libcolophon_ffi.dylib \
    --language $l --config crates/colophon-ffi/uniffi.toml --out-dir $OUT/$l --no-format
done
```

This is what `scripts/generate-bindings.sh` runs, on the debug library and a scratch directory.

## Swift (macOS, Swift 6)

```sh
LIB=$CARGO_TARGET_DIR/debug
swiftc -swift-version 6 -I $OUT/swift -Xcc -fmodule-map-file=$OUT/swift/ColophonFFI.modulemap \
  $OUT/swift/ColophonBindings.swift crates/colophon-ffi/tests/smoke/swift/main.swift \
  -L $LIB -lcolophon_ffi -Xlinker -rpath -Xlinker $LIB -o /tmp/b1-swift-smoke && /tmp/b1-swift-smoke
```

## Kotlin (JVM)

Run from the repository root (the successor genesis reads `conformance/keyring`). Needs a JDK (17 to 21), a Kotlin compiler (below: 2.2.21, from the Marginalia tooling directory `M`:
`kotlin-compiler-embeddable`, `-stdlib`, `-script-runtime`, `-daemon-embeddable` 2.2.21 and
`kotlin-reflect` 1.6.10, with `annotations`, `trove4j` and `kotlinx-coroutines-core-jvm` 1.6.4 from a
Gradle 8.14.3 `lib/` directory, `GL`) and a JNA jar (5.18.1).

```sh
CP="$M/kotlin-compiler-embeddable-2.2.21.jar:$M/kotlin-stdlib-2.2.21.jar:$M/kotlin-script-runtime-2.2.21.jar:$M/kotlin-reflect-1.6.10.jar:$M/kotlin-daemon-embeddable-2.2.21.jar:$GL/annotations-24.0.1.jar:$GL/trove4j-1.0.20200330.jar:$GL/kotlinx-coroutines-core-jvm-1.6.4.jar"
java -cp "$CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-reflect -no-stdlib -jvm-target 17 \
  -cp $M/kotlin-stdlib-2.2.21.jar:$JNA -d /tmp/b1-kt-out \
  $OUT/kotlin/com/luff/colophon/colophon_ffi.kt crates/colophon-ffi/tests/smoke/kotlin/Smoke.kt
java -Djna.library.path=$CARGO_TARGET_DIR/debug -cp /tmp/b1-kt-out:$M/kotlin-stdlib-2.2.21.jar:$JNA SmokeKt
```

## Web (Node 24 and Bun)

`js/smoke.mjs` needs the wasm-bindgen glue, and the CLI must match the crate's wasm-bindgen exactly (0.2.130).
The matching tool is installed at `~/.cargo/tools/wasm-bindgen-0.2.130/bin/wasm-bindgen` (the 0.2.127 in
`~/.cargo/bin` is for other projects: put the 0.2.130 folder first on `PATH` only for these commands).

```sh
export PATH=$HOME/.cargo/tools/wasm-bindgen-0.2.130/bin:$PATH
wasm-bindgen --version                      # wasm-bindgen 0.2.130
W=/tmp/b2-web
cargo build --locked -p colophon-wasm --target wasm32-unknown-unknown --profile release-wasm
wasm-bindgen --target nodejs --out-dir $W $CARGO_TARGET_DIR/wasm32-unknown-unknown/release-wasm/colophon_wasm.wasm
echo '{"type":"commonjs"}' > $W/package.json
echo '{"type":"module"}' > $W/snippets/package.json   # the inline JS helper is an ES module
node crates/colophon-ffi/tests/smoke/js/smoke.mjs $W
bun  crates/colophon-ffi/tests/smoke/js/smoke.mjs $W
```

It covers an engine over a JS source, an unlock, an action through `begin_*` and `finish`, a replay refused as
`Consumed`, a `Promise`, `undefined` and an `Array` returned by `read` (a `Host` error naming
`JsSource.read`), a throwing source (`Host` with its message), a caught `AccountFault` that is a real `Error`
with `kind`, `code`, `detail` and `reason`, `u64` and `i64` above 2^53 crossing exactly as `bigint`, a
`Number` where a `bigint` is expected (a plain `TypeError`), `lock` and `Locked`, and the zero-on-free
allocator on the wasm heap (a held secret is found in the heap; once freed it is zero). Built without the
allocator (`cargo build ... --no-default-features --features web05`, a second glue directory) the same program
run with `COLOPHON_ALLOCATOR_OFF=1` reports the secret still in the freed heap: the positive control.
