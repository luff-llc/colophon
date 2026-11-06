# A new Apple app

1. Build the native artifact once with `bash scripts/build-apple.sh` (see
   [native bindings](native-bindings.md)). Add the root package's **ColophonSession** product.
2. Copy `examples/ColophonSample`, run `python3 generate-project.py`, and change the bundle ID,
   member label, namespaces and private home. Its views import only `ColophonSession`.
3. Own one `@State` session at the process entry point and pass it to windows and intents:

   ```swift
   ColophonSession(configuration: .init(
       memberLabel: "My app", namespaces: ["reading.saved"],
       location: .privateContainer(home), privateContainer: home,
       keys: KeychainKeys(service: "com.example.myapp"),
       recoveryKeys: KeychainKeys(service: "com.example.myapp", account: "recovery")))
   ```

   `KeychainKeys` defaults to Secure Enclave. The sample explicitly uses Keychain-protected
   software keys so it can run in simulators. Do not regenerate keys on restoration failure.
4. `await session.restore()` before starting dependent work. Render its phase explicitly;
   only `.ready` opens the product UI. Call `refresh()` on foreground entry and Retry.
5. Keep one `NamespaceStore` per feature. `await load(query)` in a task; `cached(query)` in
   `body`. Await cold completion for widgets too. Rows receive plain projection values.
6. Capture `session.observedRevision` **before** an action starts; pass it to
   `perform(command, observed:)`. On stale revision, review and start again. `.queued` is
   not `.saved`; refresh retries the exact signed records.
7. For sharing, choose `.appGroup(identifier:libraryName:)` or `.iCloud(container:libraryName:)`
   and add the matching entitlements. Keep `privateContainer` in this app's private home.
   Each app keeps its own keys and pairs. Import a signed request, compare its pairing code,
   then call `approve`; use `revoke` to end access. See [session contracts](session.md) for
   the narrowly opt-in device-only starter policy, extensions, and leave/rejoin.

Build the template for both platforms with `bash scripts/build-sample.sh`; restricted builders
use `bash scripts/build-sample.sh --restricted`. No third-party generator is required.
