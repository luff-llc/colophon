# Colophon playground

The interactive introduction to Colophon: one page where a visitor owns a real
library in their browser tab — real keys, real signed records, the real Rust
core running as WebAssembly — and an AI agent knocks, gets narrow access, does
useful work, and is shown the door.

## Run

```sh
cd playground
npm install
npm run dev      # http://localhost:5173
npm run build    # static output in playground/dist
```

`?demo` enables guided demo mode: a bar steps through intro → Knock → Grant →
Act → End → Recover with a Next button. Example: `http://localhost:5173/?demo`.

The playground depends on the real core via `"@colophon/core": "file:../js"`,
so build `js/` first (`npm --prefix js run build`, Rust on PATH). Vite emits
the core's `.wasm` as a build asset; no extra plugins needed.

## Device sessions and recovery

`src/session.ts` wraps the 0.4 SDK with distinct owner controller and member
providers. The demo generates separate non-extractable WebCrypto signing and
agreement keys for each principal. Member keys open content epochs; grant and
revoke open the vault through the owner provider first. `DeviceSession.open`
accepts an external owner provider, including a provider with an existing PRF
route. This package adds no passkey ceremonies.

Creation uses the generated WASM `begin_create_with` transport through the
playground adapter in `src/core.ts`, because the SDK facade's `Library.create`
still exposes only owner-only creation. Both signing rounds stay in the core:
genesis, seq-2 rekey, member request/grant, and layout 2. The demo supplies an
independent recovery-kit controller in genesis, with its own sealed vault slot,
`threshold: 1` and `recoverThreshold: 1`. The kit supplies only public keys during
creation; it never signs creation. Hosts may omit the kit for an owner-only
keyring with `recoverThreshold: 0`.

`DeviceSession.restore` accepts existing kit-enabled 0.4 records: the kit
opens its vault slot and signs a recovery-rule keyring addition, then the new
device controller grants the fresh member all namespaces. Existing controllers,
slots, vault and thresholds stay. When recovery has a lower threshold, the new
controller receives only `approve`. The demo restore uses a raw owner provider;
opening existing sessions accepts other provider forms.

The demo stores CryptoKey handles in IndexedDB separately from the records and
never persists the vault seed. The demo kit handle is
stored alongside the device handles for convenience; this is not an exported
or independently stored recovery kit. The 0.4 storage keys do not reopen older
libraries.

Focused flow tests (requires the already-built local `@colophon/core` package):

```sh
npm test
```

## The agent

Without a key, a scripted stand-in performs the same tool calls a model would,
so the demo always works. With `MUSE_API_KEY` in the server environment, the
live Muse model answers through `Library.tools()` / `Library.call()`:

- Agent settings (top right): model only, default `muse-spark-1.3`.
- The key is never in the browser. The dev and preview servers proxy
  `/api/muse/*` to `https://api.meta.ai/v1` and add
  `Authorization: Bearer $MUSE_API_KEY` there (see `vite.config.ts`).
- Copy `.env.example` to `.env.local` (gitignored) and set `MUSE_API_KEY`
  there, then (re)start the server. The page shows “Muse connected” or
  “Scripted agent (no MUSE_API_KEY)”.

## Layout

- `src/core.ts` — the one import every core call goes through. It re-exports
  the real `@colophon/core`.
- `src/agent.ts` — live Muse path (chat completions with tools, via the
  same-origin `/api/muse` proxy) plus the scripted stand-in. All actions go
  through `Library.call()`; all wire-format details stay in this file.
- `src/app.ts` — intro, colophon page, content tabs, agent device, five verbs,
  demo mode.
- `src/seed.ts` — invented podcast excerpts, saved links, empty notebook.
- `src/session.ts` — controller/member separation, vault unlocks and recovery-rule restore.
- `src/storage.ts` — IndexedDB snapshots of 0.4 records and separate controller,
  member and optional kit key handles.
