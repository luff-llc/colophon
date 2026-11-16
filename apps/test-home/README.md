# colophon-test-home (a local test tool)

The home service the Colophon test apps (`apps/test-ios`, `apps/test-android`) use on a developer's Mac. A 0.5 home
slot is provisioned for one account, and the account does not exist until an app creates it. So at creation the app
sends this tool the new account ID with the slot and base it chose. The tool adds the slot to the reference relay
(`bun relay/server.js`, restarted with every slot it has) and answers with the home's signed member request.

**It is a stopgap for testing on one machine, and will be removed** once the home provisions slots itself (a
provisioning request on the home, planned for the next home package). Do not build on it, expose it, or run it
anywhere but your own Mac.

```sh
cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm
swift run --package-path apps/test-home colophon-test-home [--port 8791] [--relay-port 8790] [--data DIR] [--wasm FILE]
# {"listening":{"host":"127.0.0.1","port":8791},"relay":"http://127.0.0.1:8790/v1/libraries/","token":"<64 hex>"}
```

Put the printed token in the app's "Home service token" field (the build scripts pass it to the UI tests themselves).

## What it refuses

It listens on `127.0.0.1` only, and refuses:

- any request without `Authorization: Bearer <token>`, where the token is new on every start;
- any request whose `Host` is not exactly `127.0.0.1:<port>` (DNS rebinding);
- any request with an `Origin` header (a web page);
- a `POST` that is not `Content-Type: application/json` (a CORS-simple form or `text/plain` post).

The home's P-256 signing key is kept in the data directory (default `$TMPDIR/colophon-test-home`) as a private JWK.
On every start the directory must belong to you and is set back to mode 0700 if it is not. A key file that is group- or
world-readable, not a plain file, or someone else's is refused, and the tool does not start. The key never leaves the
Mac and is never printed.

`bun test apps/test-home/test` (after `swift build --package-path apps/test-home`) checks these refusals.
