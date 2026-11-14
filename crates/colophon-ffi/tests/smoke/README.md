# Smoke programs for the generated 0.5 bindings

They are not part of `cargo test`. Each one drives the real exports from the host language: a
typed error, creation with a host-held P-256 key (typed steps in, typed signatures out), an
engine over a host `HostSource`, an unlock from the host's ECDH result, an action through
`begin_*` and `finish`, a replay refused as `Consumed`, and a source callback that throws
(arrives as `Host`, with the host's message).

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

Needs a JDK (17 to 21), a Kotlin compiler (below: the one bundled in a Gradle 8.14.3 `lib/`
directory, `GL`) and a JNA jar (5.17 or later).

```sh
CP="$GL/kotlin-compiler-embeddable-2.0.21.jar:$GL/kotlin-stdlib-2.0.21.jar:$GL/kotlin-script-runtime-2.0.21.jar:$GL/kotlin-reflect-2.0.21.jar:$GL/kotlin-daemon-embeddable-2.0.21.jar:$GL/annotations-24.0.1.jar:$GL/trove4j-1.0.20200330.jar:$GL/kotlinx-coroutines-core-jvm-1.6.4.jar"
java -cp "$CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-reflect -no-stdlib -jvm-target 17 \
  -cp $GL/kotlin-stdlib-2.0.21.jar:$JNA -d /tmp/b1-kt-out \
  $OUT/kotlin/com/luff/colophon/colophon_ffi.kt crates/colophon-ffi/tests/smoke/kotlin/Smoke.kt
java -Djna.library.path=$CARGO_TARGET_DIR/debug -cp /tmp/b1-kt-out:$GL/kotlin-stdlib-2.0.21.jar:$JNA SmokeKt
```

## Web (Node 24)

`js/smoke.mjs` needs the wasm-bindgen glue, which needs the CLI to match the crate (0.2.130):

```sh
cargo build --locked -p colophon-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target nodejs --out-dir /tmp/b1-wasm target/wasm32-unknown-unknown/release/colophon_wasm.wasm
echo '{"type":"commonjs"}' > /tmp/b1-wasm/package.json
node crates/colophon-ffi/tests/smoke/js/smoke.mjs /tmp/b1-wasm
```

`wasm-bindgen --version` must print 0.2.130 (`js/scripts/build.sh` checks the same).
