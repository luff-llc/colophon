/**
 * The session frame inside a home stream `session` message, taken out as text, never re-serialised.
 *
 * The home carries a sealed frame verbatim as the `frame` value of `{"type":"session",…,"frame":<frame>}` (stream
 * §5.2), and a receiver accepts only the frame's canonical bytes. Parsing the message and serialising `frame` again
 * would hand the codec bytes the sender never signed whenever the two encodings differ (an escape, a number form,
 * a duplicate name collapsed), and could turn a non-canonical frame into an acceptable one. So the host locates the
 * value's span in the message text and passes exactly those characters on; the codec then judges them.
 */

const WS = new Set([' ', '\t', '\n', '\r']);

class Scan {
  i = 0;
  constructor(readonly s: string) {}
  fail(): never { throw new SyntaxError('not a JSON object message'); }
  ws(): void { while (this.i < this.s.length && WS.has(this.s[this.i] as string)) this.i++; }
  expect(c: string): void { this.ws(); if (this.s[this.i] !== c) this.fail(); this.i++; }
  /** A string starting at `i` (at its quote); returns its decoded value. */
  string(): string {
    if (this.s[this.i] !== '"') this.fail();
    const start = this.i;
    this.i++;
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) this.fail();
      if (c === '"') { this.i++; break; }
      if (c === '\\') { this.i += 2; continue; }
      if (c < ' ') this.fail();
      this.i++;
    }
    return JSON.parse(this.s.slice(start, this.i)) as string;
  }
  /** Skips one value; returns its [start, end) span. */
  value(): [number, number] {
    this.ws();
    const start = this.i;
    const c = this.s[this.i];
    if (c === '"') { this.string(); return [start, this.i]; }
    if (c === '{' || c === '[') {
      const close = c === '{' ? '}' : ']';
      this.i++;
      this.ws();
      if (this.s[this.i] === close) { this.i++; return [start, this.i]; }
      for (;;) {
        if (c === '{') { this.ws(); this.string(); this.expect(':'); }
        this.value();
        this.ws();
        const d = this.s[this.i];
        if (d === ',') { this.i++; continue; }
        if (d === close) { this.i++; return [start, this.i]; }
        this.fail();
      }
    }
    // A number or a literal: up to the next delimiter.
    while (this.i < this.s.length && !WS.has(this.s[this.i] as string) && !',}]'.includes(this.s[this.i] as string)) this.i++;
    if (this.i === start) this.fail();
    return [start, this.i];
  }
}

/**
 * The exact text of the top-level `frame` value of a stream `session` message, or undefined when the message has no
 * `frame` member (or is not one JSON object). A message naming `frame` twice is refused: which one a JSON parser keeps
 * is not defined, so the host cannot know which bytes the home meant.
 */
export function sessionFrameText(message: string): string | undefined {
  const scan = new Scan(message);
  try {
    scan.expect('{');
    scan.ws();
    let found: [number, number] | undefined;
    if (message[scan.i] === '}') return undefined;
    for (;;) {
      scan.ws();
      const name = scan.string();
      scan.expect(':');
      const span = scan.value();
      if (name === 'frame') {
        if (found) return undefined;
        found = span;
      }
      scan.ws();
      const d = message[scan.i];
      if (d === ',') { scan.i++; continue; }
      if (d === '}') { scan.i++; break; }
      scan.fail();
    }
    scan.ws();
    if (scan.i !== message.length) return undefined;
    return found ? message.slice(found[0], found[1]) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Where a frame is for: its outer `namespace` and `cell`, read to route it to a cell's host and nothing else. The bytes
 * handed to the endpoint are always the frame text itself.
 */
export function frameCell(frameText: string): { namespace: string; cell: string } | undefined {
  try {
    const v = JSON.parse(frameText) as { namespace?: unknown; cell?: unknown };
    return typeof v.namespace === 'string' && typeof v.cell === 'string' ? { namespace: v.namespace, cell: v.cell } : undefined;
  } catch {
    return undefined;
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
/** The frame text as the bytes the endpoint receives (UTF-8). */
export const frameBytes = (text: string): Uint8Array => encoder.encode(text);
/** A `Send` effect's bytes as the text `HomeStream.session_frame` carries. */
export const frameText = (bytes: Uint8Array): string => decoder.decode(bytes);
