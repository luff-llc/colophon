import { HomeTransportError } from './errors.js';

export interface HomeHeader { name: string; value: string }
/** A request the engine built for a home (`ExchangeStep.request`), as plain values. */
export interface HomeRequest { method: 'GET' | 'POST' | 'PUT'; url: string; headers: HomeHeader[]; body: Uint8Array }
export interface HomeAnswer { status: number; headers: HomeHeader[]; body: Uint8Array }

/**
 * Performs the HTTP requests the engine returns for a home. The engine owns every decision: this only moves bytes.
 * `signal` is aborted when the pass is cancelled or its deadline passes; an implementation must stop then.
 */
export interface HomeTransport {
  send(request: HomeRequest, signal?: AbortSignal): Promise<HomeAnswer>;
}

/** The bounds a session holds a home to, so that a hostile or broken home cannot take memory or hold a pass. */
export const HomeLimits = {
  /** The most bytes of one response: the signed head 64 KiB, a blob chunk 1 MiB, a record 41 MiB, anything else 32 MiB. */
  responseBytes(url: string): number {
    let path = url;
    try { path = new URL(url).pathname; } catch { /* judged as written */ }
    if (path.endsWith('/head') || path.includes('/records/heads/')) return 64 * 1024;
    if (path.includes('/records/blobs/')) return 1024 * 1024;
    if (path.includes('/records/')) return 41 * 1024 * 1024;
    return 32 * 1024 * 1024;
  },
  /** Steps (requests and calls) in one pass with one home, and passes in one exchange. */
  stepsPerPass: 20_000,
  passes: 4,
  /** The longest one exchange with one home may take, transport included. */
  exchangeTimeMs: 180_000,
  /** The longest one request may take, from the first byte sent to the last byte read. */
  requestTimeMs: 60_000,

  /**
   * `https`, or `http` to a loopback address when `allowingLoopbackHttp` (tests): `localhost`, a literal IPv4 address in
   * `127.0.0.0/8` or the literal `::1`. The URL is parsed and the host compared as a whole, never by prefix: a name
   * such as `127.attacker.example` is a remote host. A URL with a username or password is refused.
   */
  isAllowed(endpoint: string, allowingLoopbackHttp: boolean): boolean {
    let url: URL;
    try { url = new URL(endpoint); } catch { return false; }
    if (url.username !== '' || url.password !== '' || url.hostname === '') return false;
    if (url.protocol === 'https:') return true;
    if (url.protocol !== 'http:' || !allowingLoopbackHttp) return false;
    return HomeLimits.isLoopbackLiteral(url.hostname);
  },
  /** `host` as `URL.hostname` gives it: lowercase, IPv6 in brackets, IPv4 in canonical dotted decimal. */
  isLoopbackLiteral(host: string): boolean {
    const h = host.toLowerCase();
    if (h === 'localhost') return true;
    if (h === '[::1]' || h === '::1') return true;
    const parts = h.split('.');
    if (parts.length !== 4) return false;
    const octets: number[] = [];
    for (const part of parts) {
      if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return false;
      const n = Number(part);
      if (n > 255) return false;
      octets.push(n);
    }
    return octets[0] === 127;
  },
};

export interface FetchTransportOptions {
  /** Testing option: allow plain `http` to a loopback address. */
  allowingLoopbackHttp?: boolean;
  /** The longest one request may take in all (default `HomeLimits.requestTimeMs`). */
  requestTimeMs?: number;
  fetch?: typeof fetch;
}

/**
 * `fetch` with no cookies, no cache, no referrer and no followed redirect. Only `https` is sent unless
 * `allowingLoopbackHttp` permits plain `http` to a loopback address. The response is read in pieces and refused as soon
 * as it passes `HomeLimits.responseBytes`; one deadline covers the whole request, the body included.
 *
 * Redirects: a runtime that shows the 3xx answer (Bun, Node) hands it to the engine, which reports it as a fault. A
 * browser hides it (an opaque redirect): that is `HomeTransportError('redirected')`, and the pass is abandoned.
 */
export class FetchHomeTransport implements HomeTransport {
  private readonly allowingLoopbackHttp: boolean;
  private readonly requestTimeMs: number;
  private readonly fetcher: typeof fetch;
  constructor(options: FetchTransportOptions = {}) {
    this.allowingLoopbackHttp = options.allowingLoopbackHttp ?? false;
    this.requestTimeMs = options.requestTimeMs ?? HomeLimits.requestTimeMs;
    this.fetcher = options.fetch ?? ((input, init) => fetch(input, init));
  }

  async send(request: HomeRequest, signal?: AbortSignal): Promise<HomeAnswer> {
    if (!HomeLimits.isAllowed(request.url, this.allowingLoopbackHttp)) throw new HomeTransportError('insecureEndpoint', `not https: ${request.url}`);
    const limit = HomeLimits.responseBytes(request.url);
    const deadline = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; deadline.abort(); }, this.requestTimeMs);
    const onAbort = () => deadline.abort();
    if (signal?.aborted) deadline.abort(); else signal?.addEventListener('abort', onAbort, { once: true });
    try {
      const headers = new Headers();
      for (const h of request.headers) headers.append(h.name, h.value);
      let response: Response;
      try {
        response = await this.fetcher(request.url, {
          method: request.method, headers,
          body: request.method === 'GET' ? undefined : request.body.slice(),
          redirect: 'manual', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', mode: 'cors',
          signal: deadline.signal,
        });
      } catch (error) {
        throw this.failure(error, timedOut);
      }
      if (response.type === 'opaqueredirect' || response.status === 0) {
        throw new HomeTransportError('redirected', 'the home answered with a redirect, which is never followed');
      }
      const declared = Number(response.headers.get('content-length') ?? '0');
      if (Number.isFinite(declared) && declared > limit) {
        await response.body?.cancel().catch(() => {});
        throw new HomeTransportError('responseTooLarge', `response over ${limit} bytes`, limit);
      }
      let body: Uint8Array;
      try { body = await readBounded(response, limit); } catch (error) {
        if (error instanceof HomeTransportError) throw error;
        throw this.failure(error, timedOut);
      }
      const answerHeaders: HomeHeader[] = [];
      response.headers.forEach((value, name) => { answerHeaders.push({ name, value }); });
      return { status: response.status, headers: answerHeaders, body };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  private failure(error: unknown, timedOut: boolean): HomeTransportError {
    if (timedOut) return new HomeTransportError('timeout', `no answer within ${this.requestTimeMs} ms`);
    return new HomeTransportError('offline', error instanceof Error ? error.message : 'offline', undefined, { cause: error });
  }
}

/** Reads a response body in pieces, refusing it the moment it passes `limit`. */
async function readBounded(response: Response, limit: number): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array(0);
  const pieces: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      throw new HomeTransportError('responseTooLarge', `response over ${limit} bytes`, limit);
    }
    pieces.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const piece of pieces) { out.set(piece, at); at += piece.length; }
  return out;
}

/** Something this host refused about a home on its own account (beside the engine's faults). */
export type HomeProblem =
  /** The configured endpoint is not `https`; the home is not contacted. */
  | { kind: 'insecureEndpoint'; url: string }
  /** A response passed its bound and was refused unread. */
  | { kind: 'responseTooLarge'; limit: number }
  /** A pass with this home took more than `HomeLimits.stepsPerPass` steps; it was stopped. */
  | { kind: 'tooManySteps'; steps: number }
  /** An exchange with this home took longer than its deadline; it was stopped. */
  | { kind: 'tooSlow'; seconds: number }
  /** The home answered with a redirect a browser hides; nothing was followed. */
  | { kind: 'redirected' }
  /** A request needed a call this host cannot bind to its exact request. No call was sent. */
  | { kind: 'callNotBound'; why: string }
  /** This device's own check of the call refused it, by the home's rule over what the device holds. No call was sent. */
  | { kind: 'callRefused'; code: string };

export interface HomeIssue { home: string; problem: HomeProblem }

export type HomeSyncState =
  | { kind: 'disabled' } | { kind: 'idle' } | { kind: 'syncing' } | { kind: 'unauthorized' }
  | { kind: 'offline'; reason: string } | { kind: 'error'; reason: string };
