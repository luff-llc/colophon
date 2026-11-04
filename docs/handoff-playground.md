# Playground handoff

The Colophon playground is built and verified on branch `playground`, in
`playground/`. Two commits: the app, then verification fixes.

## What's done

- **Vite + TypeScript, no UI framework.** Exact-pinned deps (`vite`,
  `typescript`, `@types/node`). `npm run dev`, `npm run build` (static
  `playground/dist`), tiny `playground/README.md`.
- **Core behind one import.** All core calls go through
  `playground/src/core.ts`, which today re-exports `./mock-core`.
  `playground/src/mock-core.ts` implements the `docs/js-api.md` contract with
  real WebCrypto P-256 keys/signatures, ECDH-wrapped epoch keys, AES-GCM
  sealed operations, enforced grants (read/write, expiry, write budget),
  revocation that refuses later writes while keeping earlier notes, AI origin
  derived from member kind, and ledger sentences. The mock is marked in code,
  and the UI shows a gold **preview core** badge while it backs the page.
- **Intro + five verbs** per `docs/playground-design.md`: book intro
  (skippable, ~12s, calm path for reduced motion), colophon page as the main
  surface, Listening/Notes/Reading tabs, agent panel styled as a separate
  device, consent card with matching six-digit codes, grant narrowing
  (read-only, expiry, write budget), “show the record” revealing signed bytes
  plus the verified author, and the agent's view of reading shown as
  `notGranted` rather than empty.
- **Seed content:** 3 invented podcast episodes with original transcript
  excerpts, 3 saved links (Gutenberg, MDN, Wikipedia), 1 empty notebook.
- **Agent** (`src/agent.ts`): with a key, OpenAI-compatible chat completions
  with tools from `Library.tools()`; default base URL
  `https://api.llama.com/compat/v1` with `Llama-4-Maverick-17B-128E-Instruct-FP8`
  (endpoint + model id verified against Meta/Llama docs). Settings panel for
  base URL / model / key; key in `sessionStorage` only; Vite dev proxy for
  the default base URL. Without a key, a scripted stand-in performs the same
  tool calls with typed-out messages. Everything goes through `Library.call()`.
- **Guided demo** (`?demo`): step bar with Next through intro → five verbs.
- **Polish:** Fraunces/Inter/IBM Plex Mono from Google Fonts, paper +
  lamplight themes (follows OS, toggle persisted), `prefers-reduced-motion`
  throughout, single-column sheets under 76rem, labelled controls, tablist
  arrow keys, live-region announcements.

## How to run

```sh
cd playground && npm install && npm run dev   # http://localhost:5173
npm run build                                  # -> playground/dist
```

Demo video: open `http://localhost:5173/?demo`, record, click Next.
Optionally set an API key in Agent settings first for the live model.

## Verification (no browser was available in the sandbox)

Chrome aborts and Firefox can't capture under this session's sandbox, and
listening sockets are blocked, so screenshots could not be taken here:
`playground/screenshots/` is empty (gitignored). Before recording, please run
the screenshot pass on a normal machine (system Chrome + the walkthrough in
`/tmp/shot/run.mjs` is stale scratch — simplest is `npm run dev` and manual
clicks at 1440px and 390px, light + dark).

What *was* verified, all passing:

- `node /tmp/shot/verify-core.mjs` — mock core in Node: key shapes, seeding,
  pairing format, approve, tool gating (`notGranted` on reading), 3 scripted
  writes admitted with AI origin and verifying signatures, ledger sentences,
  read-only/budget/expiry enforcement, revoke → `revoked` with kept notes,
  owner writes after rekey, re-open from copied records with identical views.
  (Scratch files under `/tmp/shot`; not committed.)
- `node /tmp/shot/verify-app.mjs` — jsdom walkthrough of the app bundle:
  skip intro → Knock (codes match on both sides) → Grant (`notGranted`
  proof) → Act (3 AI notes, ledger counts, no failed calls) → show-the-record
  (verified author) → End (struck line, rekey rule, visible `revoked`
  failure) → Recover (identical ledger/notes) → theme toggle → settings
  save → full `?demo` Next-walk. Zero window errors/unhandled rejections.
- `tsc --noEmit` clean, `vite build` clean, CSS-vs-DOM class cross-check.

These caught and fixed three real bugs: cross-author fold ordering (agent
notes folded before the notebook existed), record views filled before append,
and Node-vs-browser ECDSA encoding (mock now accepts both).

## What the swap to the real core needs

1. `npm install @colophon/core`, change the one line in `src/core.ts`,
   delete `src/mock-core.ts`. The `IS_MOCK_CORE` badge auto-clears (the UI
   feature-detects it).
2. Two mock-only call sites in `src/app.ts` already have contract-only
   fallbacks, but deserve real equivalents: `noteRequest` (filing Knock
   requests so they ledger promptly) and `operationRecord` (“show the
   record”; the fallback shows raw bytes and notes the core checked the
   signature on open, without naming the verified author inline).
3. Confirm shapes the UI folds from admitted payloads: `show.follow`,
   `episode.add`, `episode.transcript`, `notebook.create`, `cell.put`,
   `capture.link`, and the five tool names the scripted agent calls.
   The UI folds from `admitted[]` payloads (contract-stable), not from
   `view().state`, so fold-shape drift won't break it.
4. The demo grant is read+write on `listening, notes` (the `Grant` shape is
   namespaces × access, so per-namespace asymmetric access isn't
   expressible). The design's “Read your listening and write notes” line is
   rendered honestly as “Read and write your listening and your notes. Not
   your reading.”

## Known gaps

- No screenshots taken (see above) — visual polish is code-reviewed only.
- The live-model path is written but untested against the real Llama API
  (no key in the sandbox); on failure it announces the error and the
  scripted stand-in takes over, so the demo can't strand.
- Intro runs ~12s, not ~30s — a pace call for the demo video.
- One agent at a time; no decline path (requests wait, per the design);
  no persistence across page loads by design (fresh keys each visit).
- `dist/` and `screenshots/` are gitignored; `package-lock.json` is committed.
