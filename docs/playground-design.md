# Playground design

The playground is Colophon's introduction and its interaction model. A visitor opens one page,
watches a short intro, and then owns a real library in their browser tab: real keys, real signed
records, the real Rust core running as WebAssembly. An AI agent asks to join, gets narrow access,
does useful work, and is shown the door. Nothing is simulated except the second device.

## The metaphor: every library has a colophon

A book's colophon is the note at the back that says who made it, how and with what. Colophon gives
every library a living colophon page: the plain-language record of who has access and what each
member did. The page is the product's main surface, not a settings screen.

> This library belongs to Ada. It lives in this browser tab.
> Taupe can read and write listening. Since 2:02 PM.
> Llama on MacBook could read listening and write notes. 3 AI notes. Access ended 2:14 PM.

## Visual language

- Book typography: a serif display face (Fraunces or Newsreader from Google Fonts) for headings
  and ledger text, a clean sans (Inter) for controls, a monospace only for keys and record bytes.
- Paper, not dashboard: warm off-white page (`#f6f1e7`), ink near-black, one accent, plum
  (`#6b3a5b`), for the person's own authority. Agents are marked with a small, consistent AI tint
  (a muted teal) everywhere their words appear. Dark mode is "lamplight": deep brown-black paper,
  cream ink.
- Motion is calm and meaningful: new ledger lines are set like type (fade and settle), a revoked
  member's line is ruled through and keeps its words, a rekey draws a thin rule across the page.
  Respect `prefers-reduced-motion`.
- Everything is readable at phone width.

## Intro (about 30 seconds, skippable)

1. A closed book on the page. It opens to its last page; the colophon text sets in, line by line:
   "Set in Fraunces. Printed on paper you own."
2. The text dissolves into: **Your library lives on your devices.** Then: **Your keys decide who
   gets access.**
3. A keypair visibly forms (two small glyphs: a seal and a key) and the line "Generating your keys
   in this tab. They never leave it." The library is created for real at this moment.
4. The page becomes the colophon page of the visitor's new library.

## The five verbs

The demo runs as five moments, each one a button the visitor presses (with a guided "next" for a
recorded demo):

1. **Knock.** An agent ("Llama on MacBook") asks to join. A consent card shows a six-digit code on
   both sides (the agent's panel and the library), the member kind (AI agent) and the scope in plain
   words: "Read your listening and write notes. Not your reading." Undecided requests wait; they
   don't fail.
2. **Grant.** The visitor approves, optionally narrowing: read-only, an expiry, a write budget. The
   ledger records it in a sentence.
3. **Act.** The agent works through generated tools: it reads a podcast episode's transcript
   excerpt, answers a question with citations, and writes notes. Each note appears in the
   notebook signed and marked AI, and the ledger counts it. A "show the record" toggle reveals the
   actual signed, encrypted bytes and the verified author.
4. **End.** One tap ends the agent's access. Its line is ruled through, a rekey rule is drawn, its
   next tool call visibly fails with "Access ended", and its earlier notes stay, still attributed.
5. **Recover.** The visitor closes the tab's in-memory state and opens the library again from the
   stored records with their keys (IndexedDB), showing the same page rebuilt from records alone.

Also visible, quieter: a "reading" namespace with saved links the agent never sees, and a panel
proving it (the agent's view of reading is `notGranted`, not empty).

## Layout

Desktop: the colophon page in the centre; the agent's panel (its chat and tool calls) on the
right, styled as a separate device; the library's content (Listening, Notes, Reading) as tabs on
the left. Phone: the colophon page with the agent and content as sheets.

## The agent

A real model when a key is configured: the Llama API (OpenAI-compatible `chat/completions` with
tool calls) or any OpenAI-compatible base URL, such as a local Ollama running Llama. Without a key,
a scripted agent performs the same tool calls so the demo always works. The agent only ever acts
through `Library.tools()` and `Library.call()`; it holds its own `KeyProvider`.

## Copy

Plain, short, second person. Never "users", "data subject" or "sync". Say "this tab", "your keys",
"access ended". Errors say what happened and what still holds: "Llama's access ended at 2:14 PM.
Its 3 notes stay, marked as written by AI."
