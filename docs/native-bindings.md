# Native bindings: the Apple build (0.5)

`colophon-ffi` is the UniFFI export of the 0.5 core; [bindings-05.md](bindings-05.md) is its contract (types, errors, bounds,
lifecycle, threading). This page is how the Apple side is built and what is committed.

* **Generated Swift** (`swift/Sources/ColophonKit/Generated/ColophonBindings.swift`, `ColophonFFI.h`, the modulemap) is committed.
  `scripts/generate-bindings.sh` regenerates it from the release dylib (`LANGUAGES=swift` leaves `sdk/kotlin` alone;
  `CARGO_TARGET_DIR` is honoured). The 0.4 exports stay in the same file; the 0.5 names are the `Account*` types and the
  generic `Status`, `Report`, `Signature`, `Policy`, `Home`, `Header`, `Conflict`.
* **The XCFramework** (`sdk/apple/ColophonFFI.xcframework`) is built locally and git-ignored (about 760 MB of static
  libraries). `scripts/build-apple.sh` builds macOS arm64, iOS device and simulator, visionOS device and simulator, each in its own
  target directory (`APPLE_TARGET_ROOT`, default `$CARGO_TARGET_DIR/apple`), with the crate's default features: `native05` and
  `zero-on-free`, the allocator that overwrites every freed block (docs/bindings-05.md §4). Never pass `--no-default-features`.
  `APPLE_TOOLCHAIN` selects the rustup toolchain that has the iOS targets; visionOS needs a nightly with `rust-src`
  (`VISIONOS_TOOLCHAIN`, `-Zbuild-std`).

```sh
export PATH="$HOME/.rustup/toolchains/1.99.1-aarch64-apple-darwin/bin:$PATH"
CARGO_TARGET_DIR=$PWD/../colophon-target APPLE_TOOLCHAIN=1.97.0 bash scripts/build-apple.sh
bash scripts/test-swift.sh                 # macOS: swift test with software keys
bash scripts/check-apple-swift.sh          # every product for the iOS and visionOS simulators, zero warnings
```

## How the Swift layer uses the exports

* The engine is always called through `ColophonEngine` (one `DispatchSerialQueue` per engine). The record source callback
  (`HostSource.read`, `readBlob`) runs on that queue inside an engine call: it reads files and returns; it never calls the engine
  (that is `ColophonError.reentered`) and never waits on something that does.
* An action is `begin_*` → `provide_prf` (PRF requests) → sign each step → `finish`; `ColophonEngine.execute(custody:)` does it,
  with the ceremonies outside the engine's queue. The `Written.stores` are written all or none by the medium.
* Signatures: `SignForm.raw` steps get `r||s` from `AsyncKeyProvider.sign`; `webauthn` steps get an assertion (DER, authenticator
  data and client data as bytes) for the step's challenge. PRF requests and `UnlockInput`s are answered by the same providers.
* Errors: `AccountError` becomes `ColophonError` at the engine boundary.
* Records that carry a secret are redacted in `description` and reflection; secrets are `SecretBytes` (owned memory, zeroed on release) lent to an export for one call through `withUnsafeData`.

## Not in the Apple build

Android and JavaScript SDKs, the relay, and the engine speed work live on other branches. A resumed open of 10,000 records is
about 0.7 s today, so the session opens off the main actor and shows `opening`. The 0.4 `NativeEngine` and `Library` wrappers
remain in ColophonKit for tools that read a 0.4 library; the session no longer uses them.
