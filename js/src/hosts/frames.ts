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
/** Deeper than any stream message may nest (a frame's 64 levels and the message's one, stream §5.2). */
const MAX_DEPTH = 66;
const NUMBER = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;
const HEX4 = /^[0-9a-fA-F]{4}$/;

/** A strict JSON scanner (RFC 8259) that reports where values are instead of building them. */
class Scan {
  i = 0;
  constructor(readonly s: string) {}
  fail(): never { throw new SyntaxError('not a JSON message'); }
  ws(): void { while (this.i < this.s.length && WS.has(this.s[this.i] as string)) this.i++; }
  expect(c: string): void { this.ws(); if (this.s[this.i] !== c) this.fail(); this.i++; }
  /** A string at `i` (at its quote), every escape checked; returns its decoded value. */
  string(): string {
    if (this.s[this.i] !== '"') this.fail();
    const start = this.i++;
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) this.fail();
      if (c === '"') { this.i++; break; }
      if (c < ' ') this.fail();
      if (c === '\\') {
        const e = this.s[this.i + 1];
        if (e === 'u') { if (!HEX4.test(this.s.slice(this.i + 2, this.i + 6))) this.fail(); this.i += 6; continue; }
        if (e === undefined || !'"\\/bfnrt'.includes(e)) this.fail();
        this.i += 2;
        continue;
      }
      this.i++;
    }
    return JSON.parse(this.s.slice(start, this.i)) as string;
  }
  /** One value, validated; returns its [start, end) span. */
  value(depth: number): [number, number] {
    if (depth > MAX_DEPTH) this.fail();
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
        this.value(depth + 1);
        this.ws();
        const d = this.s[this.i];
        if (d === ',') { this.i++; continue; }
        if (d === close) { this.i++; return [start, this.i]; }
        this.fail();
      }
    }
    for (const literal of ['true', 'false', 'null']) {
      if (this.s.startsWith(literal, this.i)) { this.i += literal.length; return [start, this.i]; }
    }
    const number = NUMBER.exec(this.s.slice(this.i, this.i + 400));
    if (!number) this.fail();
    this.i += number[0].length;
    return [start, this.i];
  }
}

/**
 * The exact text of the top-level `frame` value of a stream `session` message, or undefined. The whole message must be
 * one strict JSON object (every string, escape, number, literal and nesting level checked, nothing after it); a
 * member named `frame` at another level, or inside a string, is not it. A message naming `frame` twice (in any
 * spelling that decodes to `frame`) is refused: which one a JSON parser keeps is not defined, so the host cannot know
 * which bytes the home meant.
 */
export function sessionFrameText(message: string): string | undefined {
  const scan = new Scan(message);
  try {
    scan.expect('{');
    scan.ws();
    let found: [number, number] | undefined;
    if (message[scan.i] === '}') { scan.i++; } else {
      for (;;) {
        scan.ws();
        const name = scan.string();
        scan.expect(':');
        const span = scan.value(1);
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
