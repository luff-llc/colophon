// Fakes for the host unit tests: a manual clock with timers, scripted sockets, a ticket transport, and claim stores
// whose writes the test completes, delays or fails.
import { compareAndSet, type ClaimStore, type Fence, type HostClock, type HostSocket, type SocketFactory, type SocketHandlers, type StoredClaim } from '../src/hosts/index.js';
import type { HomeAnswer, HomeRequest, HomeTransport } from '../src/session/index.js';

/** A clock the test moves. Timers fire, in due order, only inside `advance`. */
export class ManualClock implements HostClock {
  mono = 10_000;
  wall = Date.now();
  private timers: { at: number; run: () => void; id: number }[] = [];
  private nextId = 0;
  monoMs(): number { return this.mono; }
  wallMs(): number { return this.wall; }
  setTimer(run: () => void, ms: number): () => void {
    const id = this.nextId++;
    this.timers.push({ at: this.mono + Math.max(0, ms), run, id });
    return () => { this.timers = this.timers.filter(t => t.id !== id); };
  }
  /** Moves both clocks by `ms`, firing every timer that falls due on the way. */
  async advance(ms: number): Promise<void> {
    const end = this.mono + ms;
    for (;;) {
      this.timers.sort((a, b) => a.at - b.at || a.id - b.id);
      const t = this.timers[0];
      if (!t || t.at > end) break;
      this.timers.shift();
      this.wall += t.at - this.mono; this.mono = t.at;
      t.run();
      await settle();
    }
    this.wall += end - this.mono; this.mono = end;
    await settle();
  }
  /** Sets the monotonic clock without firing anything (a reset clock may go back). */
  jump(to: number): void { this.mono = to; }
  get pending(): number { return this.timers.length; }
}

/** Lets promise callbacks and queued microtasks run. */
export async function settle(rounds = 20): Promise<void> { for (let i = 0; i < rounds; i++) await Promise.resolve(); }

export class FakeSocket implements HostSocket {
  readonly sent: string[] = [];
  closedWith: number | undefined;
  constructor(readonly url: string, readonly handlers: SocketHandlers) {}
  send(text: string): void { this.sent.push(text); }
  close(code: number): void { this.closedWith = code; }
}
/** Records every socket the host opens; the test drives them. */
export class Sockets {
  readonly all: FakeSocket[] = [];
  readonly factory: SocketFactory = (url, handlers) => { const s = new FakeSocket(url, handlers); this.all.push(s); return s; };
  get last(): FakeSocket { const s = this.all[this.all.length - 1]; if (!s) throw new Error('no socket'); return s; }
}

/** The home's frames as the stream numbers them. */
export class Frames {
  private n = 0;
  hello(extra: Record<string, unknown> = {}): string {
    this.n = 0;
    return this.frame({ type: 'hello', protocol: 'colophon/home-stream/6', account: 'a'.repeat(64), home: 'h', instance: 'i1', cursor: 'i1.0', head: null, notice: 0,
      principal: 'm', expiresAt: null, namespaces: ['listening.podcasts'], limits: { pingMs: 20_000, idleMs: 60_000 }, ...extra });
  }
  frame(fields: Record<string, unknown>): string { this.n++; return JSON.stringify({ ...fields, n: this.n }); }
}

export const ticket = 'T'.repeat(43);
/** Answers the ticket request with `answer` (default: a ticket) and records what was asked. */
export class TicketTransport implements HomeTransport {
  readonly requests: HomeRequest[] = [];
  answer: () => HomeAnswer | Promise<HomeAnswer> = () => ({ status: 200, headers: [], body: new TextEncoder().encode(JSON.stringify({ ticket, path: '/stream', expires: '2030-01-01T00:00:00Z' })) });
  async send(request: HomeRequest): Promise<HomeAnswer> { this.requests.push(request); return this.answer(); }
}
export const answer = (status: number, body: unknown = {}, headers: { name: string; value: string }[] = []): HomeAnswer =>
  ({ status, headers, body: new TextEncoder().encode(JSON.stringify(body)) });

/**
 * A claim store whose writes complete when the test says (`hold`, `hang`), after a delay, or fail. It applies the
 * compare-and-set when a write lands, as the contract requires, and records how many saves were ever in flight at once.
 */
export class TestStore implements ClaimStore {
  /** The claim last stored (none: nothing, or only a reservation). */
  value: string | undefined;
  heldFence: Fence | undefined;
  /** Fence checks: the next `fenceFailures` reject, and while `fenceHang` is set they never settle. */
  fenceFailures = 0;
  fenceHang = false;
  fenceReads = 0;
  readonly writes: string[] = [];
  readonly fences: Fence[] = [];
  hold = false;
  delayMs = 0;
  failures = 0;
  /** Saves that will each wait for their own release (see `hung`). */
  hang = 0;
  inflight = 0;
  maxInflight = 0;
  refused = 0;
  private waiting: (() => void)[] = [];
  readonly hung: (() => void)[] = [];
  constructor(initial?: StoredClaim, private readonly timer: (run: () => void, ms: number) => void = (run, ms) => { setTimeout(run, ms); }) {
    this.value = initial?.claim ?? undefined; this.heldFence = initial?.fence;
  }
  async load(): Promise<StoredClaim | undefined> { return this.heldFence ? { claim: this.value ?? null, fence: { ...this.heldFence } } : undefined; }
  async fence(): Promise<Fence | undefined> {
    this.fenceReads++;
    if (this.fenceFailures > 0) { this.fenceFailures--; throw new Error('the disk is busy'); }
    if (this.fenceHang) await new Promise<void>(() => {});
    return this.heldFence && { ...this.heldFence };
  }
  async save(record: StoredClaim, expected: Fence | undefined): Promise<'stored' | 'stale'> {
    this.inflight++; this.maxInflight = Math.max(this.maxInflight, this.inflight);
    try {
      if (record.claim !== null) this.writes.push(record.claim);
      this.fences.push(record.fence);
      if (this.failures > 0) { this.failures--; throw new Error('the disk is full'); }
      if (this.hang > 0) { this.hang--; await new Promise<void>(resolve => this.hung.push(resolve)); }
      if (this.hold) await new Promise<void>(resolve => this.waiting.push(resolve));
      if (this.delayMs > 0) await new Promise<void>(resolve => this.timer(resolve, this.delayMs));
      // The compare-and-set, applied when the write lands.
      const next = compareAndSet(await this.load(), record, expected);
      if (!next) { this.refused++; return 'stale'; }
      this.value = next.claim ?? undefined; this.heldFence = next.fence;
      return 'stored';
    } finally {
      this.inflight--;
    }
  }
  /** Completes every held write. */
  release(): void { this.hold = false; for (const w of this.waiting.splice(0)) w(); }
  get heldWrites(): number { return this.waiting.length; }
}
