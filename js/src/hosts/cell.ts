/**
 * A small typed API over one session cell for an application: join, observe the holder, the claim and the state,
 * take, pass, publish, submit, leave. Bytes are `Uint8Array`; claims and events are typed. It decides nothing: every
 * call is a core command, and what it publishes comes from the endpoint.
 */
import { base64, base64url, SessionCellHost, unbase64, type CellHostEvent, type CellHostOptions } from './cell-host.js';

/** A claim (§S4): taken (`rank` 0) or passed (`rank` 1, with `via`). */
export interface Claim { term: number; rank: 0 | 1; holder: string; via?: string }

/** What the application sees of a cell. Replaced, never changed in place, on every change. */
export interface CellState {
  /** The member has joined. */
  joined: boolean;
  /** This member's view of the holder (none: no holder). */
  holder?: string;
  /** This member acts as holder (locally, even while `gated`). */
  isHolder: boolean;
  /**
   * A holder that may not send holder frames yet: it restarted holding its stored claim, or came back after being out
   * of contact, and waits out `askTimeoutMs` before it retakes or yields (sessions §S6).
   */
  gated: boolean;
  /** The greatest claim this member accepted. */
  claim?: Claim;
  /** The cell's state as this member holds it (for `fold: latest`, the last payload or snapshot). */
  state?: Uint8Array;
  /** The position of `state` in the ordered lane. */
  seq: number;
  /** The member holds a `records` entry for the namespace (it may send). */
  entitled: boolean;
  /** The member may hold and submit (`write` access). */
  canWrite: boolean;
}

/** The core's events (§S10), with bytes decoded. */
export type CellEvent =
  | { event: 'becameHolder'; claim: Claim; snapshot: Uint8Array; via: 'pass' | 'take' | 'renew' }
  | { event: 'yielded'; to: Claim }
  | { event: 'holderChanged'; claim?: Claim }
  | { event: 'askReceived'; from: string }
  | { event: 'declined'; from: string }
  | { event: 'message'; claim: Claim; seq: number; origin: string; id: Uint8Array; payload: Uint8Array }
  | { event: 'snapshot'; claim: Claim; seq: number; snapshot: Uint8Array }
  | { event: 'refused'; id: Uint8Array; reason: string }
  | { event: 'presenceChanged'; member: string; payload?: Uint8Array }
  | { event: 'holderLapsed'; holder: string }
  | { event: 'offsetChanged'; peer: string; offset: number; error: number }
  | { event: 'latePass'; from: string; claim: Claim; snapshot: Uint8Array }
  | { event: 'displaced'; from: string; claim: Claim; seq: number; snapshot: Uint8Array }
  | { event: 'submitFailed'; id: Uint8Array }
  | { event: 'rejected'; command: string; reason: string };

const BYTES = new Set(['snapshot', 'payload', 'id']);
/** An event's JSON with its byte fields decoded. */
export function cellEvent(json: { event: string; [field: string]: unknown }): CellEvent {
  const out: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(json)) out[name] = BYTES.has(name) && typeof value === 'string' ? unbase64(value) : value;
  return out as unknown as CellEvent;
}

interface ViewJson { accepted: Claim | null; holder: string | null; holding: boolean; seq: number; state: string | null }

export class CellSession {
  private current: CellState;
  private readonly listeners = new Set<(state: CellState) => void>();
  private readonly eventListeners = new Set<(event: CellEvent) => void>();

  private constructor(readonly host: SessionCellHost) {
    this.current = Object.freeze({ joined: false, isHolder: false, gated: false, seq: 0, entitled: false, canWrite: false });
  }

  /** Joins the cell (`SessionCellHost.open`) and starts publishing its state. */
  static async join(options: CellHostOptions): Promise<CellSession> {
    let session: CellSession | undefined;
    const early: CellHostEvent[] = [];
    const host = await SessionCellHost.open(options, event => { if (session) session.hostEvent(event); else early.push(event); });
    session = new CellSession(host);
    for (const event of early) session.hostEvent(event);
    session.refresh();
    return session;
  }

  /** The cell as this member sees it now. */
  get state(): CellState { return this.current; }
  /** Called after every change of `state`; returns the function that stops it. */
  subscribe(listener: (state: CellState) => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  /** Called with every core event, in order; returns the function that stops it. */
  events(listener: (event: CellEvent) => void): () => void { this.eventListeners.add(listener); return () => { this.eventListeners.delete(listener); }; }

  /** Takes the role as soon as §S5 allows (at once when there is no live holder), from `state` or the cell's own. */
  take(state?: Uint8Array): Promise<void> { return this.host.command('take', { command: 'take', state: state === undefined ? null : base64(state) }); }
  /** Asks the holder for the role. */
  ask(): Promise<void> { return this.host.command('ask', { command: 'ask' }); }
  /** Passes the role to `to`, an asker, with the final state (the application stopped what the role controls first). */
  pass(to: string, snapshot: Uint8Array): Promise<void> { return this.host.command('pass', { command: 'pass', to, snapshot: base64(snapshot) }); }
  /** Declines an asker. */
  decline(to: string): Promise<void> { return this.host.command('decline', { command: 'decline', to }); }
  /** Gives up the role without a successor. */
  release(): Promise<void> { return this.host.command('release', { command: 'release' }); }
  /** Orders a message as holder (for `fold: latest`, the new state). Returns its id. */
  async publish(payload: Uint8Array, id: Uint8Array = randomId()): Promise<Uint8Array> {
    await this.host.command('publish', { command: 'publish', id: base64url(id), payload: base64(payload) });
    return id;
  }
  /** Asks the holder to order a message (delivery is at least once). Returns its id. */
  async submit(payload: Uint8Array, id: Uint8Array = randomId()): Promise<Uint8Array> {
    await this.host.command('submit', { command: 'submit', id: base64url(id), payload: base64(payload) });
    return id;
  }
  /** Publishes this member's presence. */
  presence(payload: Uint8Array): Promise<void> { return this.host.command('presence', { command: 'presence', payload: base64(payload) }); }
  /** Measures the round trip and clock offset to `to` (an `offsetChanged` event follows). */
  ping(to: string): Promise<void> { return this.host.command('ping', { command: 'ping', to }); }
  /** Leaves the session (a holder releases the role) and ends the endpoint. */
  leave(): Promise<void> { return this.host.leave(); }
  /** Stops at once without leaving, as a process that ends would. */
  close(): void { this.host.close(); }

  private hostEvent(event: CellHostEvent): void {
    if (event.type === 'session') {
      const typed = cellEvent(event.event);
      for (const l of [...this.eventListeners]) { try { l(typed); } catch { /* a listener's failure is its own */ } }
    }
    if (event.type === 'session' || event.type === 'account' || event.type === 'rebuilt' || event.type === 'persist') this.refresh();
  }
  private refresh(): void {
    const e = this.host.current;
    if (!e) return;
    let view: ViewJson;
    try { view = JSON.parse(e.view_json()) as ViewJson; } catch { return; }
    const next: CellState = Object.freeze({
      joined: e.joined(), isHolder: e.is_holder(), gated: e.gated(), seq: view.seq, entitled: e.entitled(), canWrite: e.can_write(),
      ...(view.holder !== null ? { holder: view.holder } : {}),
      ...(view.accepted !== null ? { claim: view.accepted } : {}),
      ...(view.state !== null ? { state: unbase64(view.state) } : {}),
    });
    if (sameState(next, this.current)) return;
    this.current = next;
    for (const l of [...this.listeners]) { try { l(next); } catch { /* a listener's failure is its own */ } }
  }
}

const randomId = (): Uint8Array => crypto.getRandomValues(new Uint8Array(16));
function sameState(a: CellState, b: CellState): boolean {
  const bytes = (x?: Uint8Array, y?: Uint8Array): boolean => x === y || (!!x && !!y && x.length === y.length && x.every((v, i) => v === y[i]));
  return a.joined === b.joined && a.holder === b.holder && a.isHolder === b.isHolder && a.gated === b.gated && a.seq === b.seq && a.entitled === b.entitled
    && a.canWrite === b.canWrite && JSON.stringify(a.claim) === JSON.stringify(b.claim) && bytes(a.state, b.state);
}
