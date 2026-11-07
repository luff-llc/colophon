# Demo script (about 2½ minutes)

Recorded from the playground at `http://localhost:5173/?demo`, 1440×900, paper theme, with
`MUSE_API_KEY` set so the agent is live. Voice-over is in quotes; actions are in brackets.

## 1. The problem (0:00–0:20)

[Black screen, then the closed book.]

"Every personal AI wants your memory: what you read, what you listen to, what you write. Today
it lives inside whichever app owns it, and an agent either scrapes it or never gets in."

## 2. The idea (0:20–0:40)

[The book opens to its colophon page. The two lines set in.]

"A book's colophon tells you who made it. Colophon gives your library one: a living page of who
has access and what they did. Your library lives on your devices. Your keys decide who gets
access."

[Keys form. The colophon page appears.]

"That just happened for real. This tab made a P-256 key pair and created a library, signed and
encrypted by the Colophon core: Rust, compiled to WebAssembly, running right here."

## 3. Knock (0:40–1:00)

[Next. The agent panel lights up; the consent card appears with matching codes.]

"Muse, Meta's model, running as an agent on my MacBook, asks to join. It has its own keys. The
codes match on both sides, and the request is in plain words: read my listening, write notes.
Not my reading."

## 4. Grant (1:00–1:15)

[Narrow: write budget 5. Grant access. The ledger sets a new line.]

"I can narrow it: read-only, an expiry, a write budget. Granting is a signed entry in an
authority history that I hold. No vendor account, no server deciding."

## 5. Act (1:15–1:45)

[Next. Muse reads the Harbour Tape excerpt, answers with a citation, writes three notes. Toggle
"show the record" on one note.]

"Muse works only through tools the core generates from the library's own schemas. It answers
from the episode, with a citation, and saves notes. Each one is signed by its key and marked
written by AI. Not because it says so, but because the core knows what kind of member wrote it.
Here's the actual record: encrypted, signed, verified."

[Point at the Reading panel.]

"And my reading? It doesn't get an empty list. It gets 'not granted'. It can't even see what
it's missing."

## 6. End (1:45–2:05)

[Next. End. The line is ruled through; a rekey rule draws across the page; Muse's next call
fails on screen.]

"One tap ends its access. The core rekeys listening and notes without it, so it can't read
anything written from now on. Its next call fails. Its three notes stay, still attributed: ending
access doesn't rewrite the past."

## 7. Recover (2:05–2:20)

[Next. Recover. The page rebuilds from stored records.]

"Everything you just saw is rebuilt from records and keys alone. Any client holding the same
records computes the same page, in a browser, on an iPhone, on a server."

## 8. Close (2:20–2:35)

[The repo: README, crates/, conformance/0.3, swift/.]

"Colophon is open: a spec, conformance vectors, and one Rust core for the web, Apple, Android
and servers. Two apps already shipped on its first version. Built in public by LUFF, with Muse
Code and Codex as co-builders."

## Recording checklist

- `MUSE_API_KEY` in `playground/.env.local`; header shows "Muse connected".
- Fresh profile or cleared site data so the intro and a new library run.
- Reduced motion off; system dark mode off (or record both themes).
- If the live call fails, the scripted agent takes over with the same tool calls; re-record
  that segment rather than presenting it as live.
