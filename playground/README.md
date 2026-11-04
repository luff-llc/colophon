# Colophon playground

The interactive introduction to Colophon: one page where a visitor owns a real
library in their browser tab — real keys, real signed records — and an AI agent
knocks, gets narrow access, does useful work, and is shown the door.

## Run

```sh
cd playground
npm install
npm run dev      # http://localhost:5173
npm run build    # static output in playground/dist
```

`?demo` enables guided demo mode: a bar steps through intro → Knock → Grant →
Act → End → Recover with a Next button. Example: `http://localhost:5173/?demo`.

## The agent

Without a key, a scripted stand-in performs the same tool calls a model would,
so the demo always works. With a key, a real model answers through
`Library.tools()` / `Library.call()`:

- Agent settings (top right): base URL, model, key.
- Defaults: `https://api.llama.com/compat/v1` with
  `Llama-4-Maverick-17B-128E-Instruct-FP8`; any OpenAI-compatible base URL
  works (e.g. local Ollama).
- The dev server proxies the default base URL to dodge CORS (see
  `vite.config.ts`).
- The key lives in `sessionStorage` only. It is never written to disk, never
  committed, never leaves the tab except to the configured endpoint.

## Layout

- `src/core.ts` — the one import every core call goes through. Today it
  re-exports `./mock-core`; swapping to `@colophon/core` is a one-line change.
- `src/mock-core.ts` — preview core implementing `docs/js-api.md`: real
  WebCrypto P-256 keys/signatures, ECDH-wrapped epoch keys, AES-GCM sealed
  operations, enforced grants, revocation that keeps earlier notes, AI origin
  from member kind, ledger sentences. Clearly marked; the UI shows a
  “preview core” badge while it backs the page.
- `src/agent.ts` — live model path (OpenAI-compatible chat completions with
  tools) plus the scripted stand-in. All actions go through `Library.call()`.
- `src/app.ts` — intro, colophon page, content tabs, agent device, five verbs,
  demo mode.
- `src/seed.ts` — invented podcast excerpts, saved links, empty notebook.
- `src/storage.ts` — IndexedDB snapshots for the Recover verb.

## Swap checklist (mock → real core)

1. `npm install @colophon/core`, point `src/core.ts` at it, delete
   `src/mock-core.ts`.
2. Replace the two mock-only call sites in `src/app.ts` (`noteRequest` for
   filing Knock requests, `operationRecord` for “show the record”) with the
   real package’s equivalents — both already have contract-only fallbacks.
3. Confirm the real fold/tool shapes the UI folds from admitted payloads
   (`show.follow`, `episode.*`, `notebook.create`, `cell.put`,
   `capture.link`, and the five tool names in `src/agent.ts`).
