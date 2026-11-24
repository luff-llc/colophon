/**
 * The WebSocket a stream host opens, behind a small interface so that browsers, Bun and Node (whose `WebSocket`
 * differ in what they report) and tests (a fake socket) all fit.
 */
import type { HomeAnswer } from '../session/transport.js';

/** What a socket reports. Each is called at most as the socket's life allows: `open` once, then messages, then one end. */
export interface SocketHandlers {
  open(): void;
  /** One text message, exactly as received. */
  message(text: string): void;
  /** The home refused the upgrade with this HTTP answer. Only runtimes that expose the refused answer call it. */
  refused(answer: HomeAnswer): void;
  /** The socket ended: the close code, or none when the transport failed or the socket never opened. */
  closed(code: number | undefined): void;
}

/** An open (or opening) socket. */
export interface HostSocket {
  send(text: string): void;
  /** Closes with `code` (the runtime may substitute a code it allows). Reports nothing afterwards. */
  close(code: number): void;
}

/** Opens a socket at `url` (which carries the ticket: never log it) and reports to `handlers`. */
export type SocketFactory = (url: string, handlers: SocketHandlers) => HostSocket;

/** The parts of the standard `WebSocket` this uses. */
interface StandardSocket {
  send(data: string): void;
  close(code?: number): void;
  onopen: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: ((event: { code: number }) => void) | null;
  onerror: ((event: unknown) => void) | null;
}
type StandardSocketClass = new (url: string) => StandardSocket;

/**
 * The runtime's standard `WebSocket` (browsers, Bun, Node 22+), or the class given.
 *
 * What it cannot report: a browser's `WebSocket` hides a refused upgrade's HTTP status, so a 401, 403 or 429 from the
 * home arrives as a failed socket (`closed(undefined)`), and the stream backs off instead of reading the refusal. A
 * close code of 1006 (abnormal closure, never sent on the wire) is reported as no code. A browser's `close` accepts only
 * 1000 and 3000–4999: for any other code the socket is closed with 1000, and the stream is told its own code.
 * Binary messages are ignored: the home sends only text.
 */
export function webSocketFactory(socketClass?: StandardSocketClass): SocketFactory {
  return (url, handlers) => {
    const SocketClass = socketClass ?? (globalThis as unknown as { WebSocket?: StandardSocketClass }).WebSocket;
    if (!SocketClass) throw new Error('this runtime has no WebSocket');
    const ws = new SocketClass(url);
    let ended = false;
    const end = (code: number | undefined): void => { if (ended) return; ended = true; handlers.closed(code); };
    ws.onopen = () => { if (!ended) handlers.open(); };
    ws.onmessage = event => { if (!ended && typeof event.data === 'string') handlers.message(event.data); };
    ws.onclose = event => end(event.code === 1006 ? undefined : event.code);
    ws.onerror = () => { /* the close that follows reports it */ };
    return {
      send: text => ws.send(text),
      close: code => {
        ended = true;
        ws.onopen = null; ws.onmessage = null; ws.onclose = null; ws.onerror = null;
        try { ws.close(code); } catch { try { ws.close(1000); } catch { /* already closed */ } }
      },
    };
  };
}
