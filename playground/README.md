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
- `src/storage.ts` — IndexedDB snapshots of records plus owner/recovery key
  handles for the Recover verb.
