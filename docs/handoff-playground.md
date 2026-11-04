# Playground handoff

The Colophon playground in `playground/` is integrated with the real core on
branch `integrate`. It runs the actual Rust core as WebAssembly
(`@colophon/core`, `file:../js`) — no mock, no "preview core" badge. The mock
(`src/mock-core.ts` on branch `playground`) was deleted; git history keeps it.

## What's done

- **Vite + TypeScript, no UI framework.** Exact-pinned deps (`vite`,
  `typescript`, `@types/node`, `@colophon/core` via `file:../js`).
  `npm run dev`, `npm run build` (static `playground/dist`, wasm emitted as
  an asset, no extra plugins), `playground/README.md`.
- **Real core behind one import.** All core calls go through
  `playground/src/core.ts`, which re-exports `@colophon/core`. Namespaces are
  `listening.podcasts` / `notes` / `reading.saved`; kinds are the clean 0.2
  set (`follow`, `episode`, `createNotebook`, `addNote`, `capture`); tools keep
  namespace dots (`listening.podcasts__read`, `notes__addNote`,
  `reading.saved__read`).
- **Real sync semantics.** After Knock the request record is merged at
  `requests/<id>.json` so it ledgers while waiting. After Act the owner merges
  the agent's records and awaits `ready()` before reading the notes. After End
  the revocation is merged into the agent's replica (synchronous), so its next
  tool call visibly fails with `revoked` while its 3 notes stay attributed.
- **Recovery keys persisted.** `create` returns `recoveryKeys`; owner and
  recovery key handles are structured-cloned into IndexedDB separately from
  the records. Recover drops every in-memory key and replica, restores both
  key sets from storage, and re-opens from the stored records alone.
- **Intro + five verbs** per `docs/playground-design.md`: book intro
  (skippable, ~12s, calm path for reduced motion), colophon page as the main
  surface, Listening/Notes/Reading tabs, agent panel styled as a separate
  device, consent card with matching six-digit codes, grant narrowing
  (read-only, expiry, write budget), “show the record” revealing signed bytes
  (op paths end `-<opId>.json`), and the agent's view of reading shown as
  `notGranted` rather than empty.
- **Seed content:** 3 invented podcast episodes with original transcript
  excerpts, 3 saved links (Gutenberg, MDN, Wikipedia), 1 notebook. Episode
  date/duration ride along as unknown fields the core preserves.
- **Agent** (`src/agent.ts`): “Muse on MacBook” (member kind agent). With
  `MUSE_API_KEY` in the server environment, the live Muse model
  (`https://api.meta.ai/v1`, default `muse-spark-1.3`, overridable in
  settings) answers via chat completions with tools from `Library.tools()`.
  The key is never in the browser: dev and preview servers proxy
  `/api/muse/*` and add `Authorization` there (`playground/.env.local`,
  gitignored; see `playground/.env.example`). No key field in the UI; the page
  shows “Muse connected” or “Scripted agent (no MUSE_API_KEY)”. Without a key,
  the scripted stand-in performs the same tool calls through `Library.call()`.
  All wire-format details stay in `agent.ts`.
- **Guided demo** (`?demo`): step bar with Next through intro → five verbs.
- **Review fixes (demo video):** the moments bar + active card sit above the
  ledger and stick on desktop (a floating thumb bar on narrow screens), while
  the newest fresh ledger line — or the open consent card — glides into view
  (`block: nearest`, smooth unless reduced motion). Consecutive-write grouping
  became whole-ledger grouping by actor+namespace (`src/ledger.ts`, pure, no
  DOM): the core clocks each namespace separately and sorts by
  (clock, author, id), so namespaces interleave and even the agent's 3 notes
  are never adjacent. Seed now reads as creation + 3 write lines ("Ada added
  6 to listening", "Ada saved 3 links", "Ada created 1 notebook"; the 3
  epoch-1 lines above them vanish with the core's ledger change). Groups are
  expandable, carry the AI badge, and group on `namespace`/`kind`/`origin`
  when present, falling back to parsing the current write sentences —
  nothing matches grant/revoke/rekey text. The AI badge is gapped everywhere
  and reads "written by AI". Intro → page is one crossfade (page fades in on
  the same beat, skipped under reduced motion). The header keeps a small
  quiet "WebAssembly core" badge with the tooltip "The Colophon Rust core,
  compiled to WebAssembly, running in this tab." Recover snapshots the ledger
  text before dropping state and reports "✓ The same page, rebuilt from N
  stored records." only when the rebuild is identical. Phone width: narrow
  grid uses `minmax(0, 1fr)`, `overflow-x: clip` backstop, 44px verb/consent
  targets.

## How to run

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
npm ci --prefix js && npm --prefix js run build   # @colophon/core + wasm, once
cd playground && npm install && npm run dev       # http://localhost:5173
```

Demo video: open `http://localhost:5173/?demo`, record, click Next. For the
live model, copy `playground/.env.example` to `playground/.env.local`, set
`MUSE_API_KEY`, and (re)start the server first.

## Verification

- `npm --prefix js test` — WebCrypto smoke and Rust/WASM fixture parity.
- `npm --prefix playground run build` — `tsc --noEmit` clean, `vite build`
  clean, wasm emitted as an asset, bundle references it, no key material in
  the bundle.
- `/tmp/walkthrough.mjs` (scratch, not committed) — Node walkthrough of the
  five verbs against the real core, mirroring the app's exact calls: create +
  seed, knock (request ledgers, six-digit code), grant narrowed (exceeding
  grants rejected), agent reads + writes 3 AI notes, reading view
  `notGranted`, revoke → next agent call `revoked` with notes kept, reopen
  from records with identical views, recovery keys open, read-only narrowing
  enforced. Passing.
- `/tmp/pg-verify.mjs` (scratch) — grouping against the real core: full seed
  folds to exactly 3 write lines, agent's 3 notes group with the AI flag,
  new-field entries (`namespace`/`kind`/`origin`, no member lookup) group
  identically, new plain grant/rekey sentences pass through untouched,
  unparseable writes never merge, identical reopen, and bundle-content checks
  for every UI fix. Passing.
- `/tmp/pgbtest/dom-verify.mjs` (scratch; `jsdom` installed in /tmp only,
  repo deps untouched) — boots the real `src/app.ts` in jsdom with an
  in-memory storage stub and drives all five verbs through the DOM: crossfade
  classes, badge tooltip, moments above ledger, seed groups expand, matching
  consent codes, AI badge names, reading `notGranted`, ruled-through grant,
  identical rebuild with the recovered line. Passing.
- No committed test runner for the playground itself; the walkthroughs above
  are the integration check. No browser was available in the sandbox (as
  before), so layout and motion are verified through the DOM walkthrough plus
  static CSS checks — see gaps.

## Known gaps

- No screenshots taken — visual polish is DOM-walkthrough plus static-check
  only. Phone 390px (no h-scroll, thumb bar) is reasoned from CSS
  (`minmax(0, 1fr)`, `overflow-x: clip`, 44px targets), not measured; check
  on a real phone before the video if one is handy.
- Until the core's ledger change lands, creation still shows 3 epoch-1 lines
  above the 3 seed groups; grouping deliberately leaves non-write events
  alone, so those lines disappear only with the core change.
- The live-Muse path is written but untested against the real Meta API (no key
  in the sandbox); on failure it announces the error and the scripted
  stand-in takes over, so the demo can't strand. If the API's chat-completions
  shape differs, only `src/agent.ts` needs to change.
- Intro runs ~12s, not ~30s — a pace call for the demo video.
- One agent at a time; no decline path (requests wait, per the design);
  no persistence across page loads by design (fresh keys each visit).
- `dist/` is gitignored; `package-lock.json` is committed.
