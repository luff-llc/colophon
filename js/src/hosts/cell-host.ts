/**
 * The JavaScript host of one 0.6 session cell: it owns a `SessionEndpoint` and runs the reference host loop of
 * docs/bindings-05.md §10 exactly.
 *
 * - Every input (a frame, a timer at `next_deadline`, a carrier change, an application command) is one endpoint call,
 *   and the step it returns is carried out in order: `Send` to the carrier, `Event` to the application, `Persist` to
 *   the store.
 * - A `Persist` is acknowledged (`persisted`) only when its durable write has completed, never on seeing the step. A
 *   failed write is retried and never acknowledged.
 * - `session:staleAccount` installs a fresh view of the engine (`set_account`) and the input is run again.
 * - `session:persistPending` (a command while a write is in progress) keeps the command, in order, until the write
 *   completes.
 * - `session:clockBackwards` and a view of another engine (`session:wrongView`) discard the endpoint and make a new one
 *   from the last claim the store holds, so the restart rules apply (sessions §S6).
 * - Drops, discarded effects and unsent frames are reported, never thrown away silently.
 *
 * Frames reach `receive` as the text the carrier delivered, unchanged. Every timing decision is the core's: the host
 * only calls `tick` at `next_deadline`.
 */
import { isAccountFault, glue, plain } from '../session/wasm.js';
import type { HostAccount } from './account.js';
import { Deadline, systemClock, type HostClock } from './clock.js';
import { frameBytes, frameText } from './frames.js';
import type { StreamCell } from './stream-host.js';

/** Where a cell's persisted claim lives. `save` resolves only once the bytes are durable. */
export interface ClaimStore {
  load(): Promise<string | undefined>;
  save(persistedJson: string): Promise<void>;
}

/** What carries a cell's frames: a `HomeStreamHost`, or anything with the same three calls. */
export interface CellCarrier {
  attach(cell: StreamCell): void;
  detach(cell: StreamCell): void;
  /** Sends one sealed frame verbatim; false when it could not be sent now (loss, to the session). */
  sendSession(frame: string): boolean;
  /** Calls `listener` after every exchange pass the carrier ran (a `HomeStreamHost`'s `Wake`). */
  onPass?(listener: () => void): () => void;
}

/** `SessionStep` as plain values. */
export interface SessionStepValue {
  effects: SessionEffectValue[]; drops: { reason: string; helloTo?: string }[];
  awaitingPersist?: bigint; persistOutstanding: boolean; queued: boolean; discarded: number;
}
/** `SessionEffect` as plain values. */
export interface SessionEffectValue {
  kind: glue.SessionEffectKind; bytes: Uint8Array; to?: string; frameKind?: string; persistedJson?: string; event?: string; eventJson?: string; unsent?: string;
}

/** Why an endpoint was made again. */
export type RebuildReason = 'clockBackwards' | 'wrongView' | 'sessionChanged';

/** What the host reports. Session events carry application state: show them, never log them. */
export type CellHostEvent =
  /** An `Event` effect: the core's event JSON, parsed (tagged by `event`). */
  | { type: 'session'; event: { event: string; [field: string]: unknown } }
  /** A frame was handed to the carrier (`frame` is the sealed text, `kind` its plaintext kind). */
  | { type: 'sent'; kind: string; frame: string }
  /** A frame was not sent: the core could not seal it (`reason` its code), or the carrier was down (`carrier`, with the sealed `frame`). */
  | { type: 'unsent'; kind: string; reason: string; frame?: string }
  /** A received frame was dropped (the §S3 code; `queueFull` when it could not be kept behind a write). */
  | { type: 'drop'; reason: string; helloTo?: string }
  /** Effects decided under an older authority head were dropped instead of released. */
  | { type: 'discarded'; count: number }
  /** An input was kept behind the `Persist` being written. */
  | { type: 'queued'; input: 'frame' | 'tick' | 'link' }
  /** A `Persist` write started, completed (and was acknowledged), or failed (and will be retried). */
  | { type: 'persist'; phase: 'started' | 'stored' | 'failed'; ack: bigint; error?: unknown }
  /** A command waits for the write in progress (`session:persistPending`). */
  | { type: 'commandHeld'; command: string }
  /** The endpoint's view was older than the engine's head (`session:staleAccount`). */
  | { type: 'stale' }
  /** A new view was installed: what this member may do now. */
  | { type: 'account'; entitled: boolean; canWrite: boolean; seq: bigint }
  /** The endpoint was made again from the stored claim. */
  | { type: 'rebuilt'; reason: RebuildReason }
  /** A frame arrived while the endpoint was being made again: not judged (loss). */
  | { type: 'missed' }
  /** Something the host could not do (`code` as the core spells it). */
  | { type: 'error'; code: string; during: string };

export interface CellHostOptions {
  account: HostAccount;
  carrier: CellCarrier;
  namespace: string;
  cell: string;
  store: ClaimStore;
  /** The §S1 policy as JSON (default `session_default_policy()`); every member of a cell uses the same one. */
  policy?: string;
  clock?: HostClock;
  /** The application's state for the cell, given with `join` (a restarted holder retakes with it, §S6). */
  state?: () => Uint8Array | undefined;
  /** How long a delegation is valid (at most 86,400,000 ms; default that). It is renewed an hour before it ends. */
  delegationMs?: number;
  /** How long to wait before writing a `Persist` again after its write failed (default 250 ms). */
  persistRetryMs?: number;
  /** Host randomness (default `crypto.getRandomValues`). The session key and the `fresh` seed are new on every start. */
  random?: (length: number) => Uint8Array;
}

interface HeldCommand { name: string; json: string; resolve(): void; reject(error: unknown): void }

const code = (error: unknown): string => isAccountFault(error) ? error.code : error instanceof Error ? error.name : 'unknown';
const DAY = 86_400_000;
const RENEW_BEFORE = 3_600_000;

export class SessionCellHost implements StreamCell {
  readonly namespace: string;
  readonly cell: string;
  readonly me: string;
  private readonly account: HostAccount;
  private readonly carrier: CellCarrier;
  private readonly store: ClaimStore;
  private readonly policy: string;
  private readonly clock: HostClock;
  private readonly stateOf: () => Uint8Array | undefined;
  private readonly delegationMs: number;
  private readonly persistRetryMs: number;
  private readonly random: (length: number) => Uint8Array;
  private readonly listeners = new Set<(event: CellHostEvent) => void>();
  private readonly tickTimer: Deadline;
  private readonly renewTimer: Deadline;
  private endpoint: glue.SessionEndpoint | undefined;
  /** The authority head (seq and digest) of the view installed last, and this member's session number in it. */
  private installed: { seq: bigint; digest: string; session: bigint | undefined } | undefined;
  /** The last `persisted_json` whose durable write completed: what a new endpoint starts from. */
  private lastStored: string | undefined;
  /** The write in progress, if any. */
  private writing: Promise<void> | undefined;
  private readonly commands: HeldCommand[] = [];
  /** The carrier's link as last reported, applied to every new endpoint. */
  private carrierUp = false;
  private rebuilding = false;
  private attached = false;
  private closed = false;
  private stopPassListener: (() => void) | undefined;
  /** Statistics for tests and diagnostics. */
  readonly stats = { calls: 0, queued: 0, drops: 0, stale: 0, rebuilt: 0, persisted: 0, held: 0 };

  private constructor(options: CellHostOptions) {
    this.account = options.account;
    this.carrier = options.carrier;
    this.namespace = options.namespace;
    this.cell = options.cell;
    this.me = options.account.member;
    this.store = options.store;
    this.policy = options.policy ?? glue.session_default_policy();
    this.clock = options.clock ?? systemClock;
    this.stateOf = options.state ?? (() => undefined);
    this.delegationMs = Math.min(options.delegationMs ?? DAY, DAY);
    this.persistRetryMs = options.persistRetryMs ?? 250;
    this.random = options.random ?? (n => crypto.getRandomValues(new Uint8Array(n)));
    this.tickTimer = new Deadline(this.clock, () => this.tick());
    this.renewTimer = new Deadline(this.clock, () => { void this.delegate().catch(error => this.emit({ type: 'error', code: code(error), during: 'delegation' })); });
  }

  /**
   * Starts a session for this member in the cell: loads the stored claim, makes the endpoint, has the member key sign
   * its delegation, attaches to the carrier and joins with the application's state.
   */
  static async open(options: CellHostOptions, listener?: (event: CellHostEvent) => void): Promise<SessionCellHost> {
    const host = new SessionCellHost(options);
    if (listener) host.on(listener);
    host.lastStored = await host.store.load();
    await host.build();
    host.attached = true;
    host.carrier.attach(host);
    host.stopPassListener = host.carrier.onPass?.(() => host.accountChanged());
    await host.command('join', { command: 'join', state: host.stateValue() });
    return host;
  }

  on(listener: (event: CellHostEvent) => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  private emit(event: CellHostEvent): void { for (const l of [...this.listeners]) { try { l(event); } catch { /* a listener's failure is its own */ } } }

  /** The endpoint's read-only state, or undefined while it is being made again. */
  get current(): glue.SessionEndpoint | undefined { return this.endpoint; }
  /** Whether a `Persist` write is in progress. */
  get writePending(): boolean { return this.writing !== undefined; }
  /** The claim the store last confirmed, as JSON. */
  get storedClaim(): string | undefined { return this.lastStored; }

  // Inputs

  /** An application command (§S10) as the core's JSON, tagged by `command`. Resolves once the endpoint has run it. */
  command(name: string, command: Record<string, unknown>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.closed) { reject(new Error('the cell host is closed')); return; }
      this.commands.push({ name, json: JSON.stringify(command), resolve, reject });
      this.drainCommands();
    });
  }
  deliver(frame: string): void {
    if (this.closed) return;
    if (this.rebuilding || !this.endpoint) { this.emit({ type: 'missed' }); return; }
    const bytes = frameBytes(frame);
    this.run('receive', (e, engine, clock) => e.receive(bytes, engine, clock), 'frame');
  }
  linkUp(): void {
    this.carrierUp = true;
    if (!this.rebuilding && this.endpoint) this.run('linkUp', (e, engine, clock) => e.link_up(engine, clock), 'link');
  }
  linkDown(): void {
    this.carrierUp = false;
    if (!this.rebuilding && this.endpoint) this.run('linkDown', (e, engine, clock) => e.link_down(engine, clock), 'link');
  }
  /** The account's verified head may have moved (after an exchange pass): install a fresh view if it did. */
  accountChanged(): void {
    if (this.closed || this.rebuilding || !this.endpoint) return;
    let seq: bigint; let digest: string;
    try { const engine = this.account.engine(); seq = engine.head_seq(); digest = engine.head_digest(); } catch (error) { this.emit({ type: 'error', code: code(error), during: 'accountChanged' }); return; }
    if (this.installed && this.installed.seq === seq && this.installed.digest === digest) return;
    this.install();
    this.drainCommands();
  }
  private tick(): void {
    if (!this.rebuilding && this.endpoint) this.run('tick', (e, engine, clock) => e.tick(engine, clock), 'tick');
  }

  /**
   * Ends this member's part: `leave` (a holder releases the role), then detaches from the carrier and drops the
   * endpoint, which wipes its session key.
   */
  async leave(): Promise<void> {
    try { await this.command('leave', { command: 'leave' }); } finally { this.close(); }
  }
  /** Stops at once, as a process that ends would: no `leave`; the stored claim is what a restart starts from. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.tickTimer.clear(); this.renewTimer.clear();
    this.stopPassListener?.(); this.stopPassListener = undefined;
    if (this.attached) { this.attached = false; this.carrier.detach(this); }
    for (const c of this.commands.splice(0)) c.reject(new Error('the cell host is closed'));
    const e = this.endpoint; this.endpoint = undefined;
    try { e?.free(); } catch { /* freed */ }
  }

  // The loop

  private clockNow(): glue.SessionClock { return new glue.SessionClock(BigInt(Math.max(0, this.clock.monoMs())), BigInt(this.clock.wallMs())); }

  /**
   * One endpoint call and its step. `session:staleAccount` installs a fresh view and runs the input once more; a
   * backwards clock or another engine's view makes the endpoint again. Any other error is the caller's. Returns
   * whether the input ran (false: it was not run, and will not be).
   */
  private run(during: string, call: (e: glue.SessionEndpoint, engine: glue.AccountEngine, clock: glue.SessionClock) => glue.SessionStep,
    input?: 'frame' | 'tick' | 'link', again = true): boolean {
    const e = this.endpoint;
    if (!e) return false;
    let engine: glue.AccountEngine;
    try { engine = this.account.engine(); } catch (error) { this.emit({ type: 'error', code: code(error), during }); return false; }
    let step: SessionStepValue;
    try {
      this.stats.calls++;
      step = plain<SessionStepValue>(call(e, engine, this.clockNow()));
    } catch (error) {
      const c = code(error);
      if (c === 'session:staleAccount' && again) {
        this.stats.stale++;
        this.emit({ type: 'stale' });
        if (!this.install()) return false;
        return this.run(during, call, input, false);
      }
      if (c === 'session:clockBackwards') { this.rebuild('clockBackwards'); return false; }
      if (c === 'session:wrongView') { this.rebuild('wrongView'); return false; }
      if (input === undefined) throw error;
      this.emit({ type: 'error', code: c, during });
      return false;
    }
    if (input && step.queued) { this.stats.queued++; this.emit({ type: 'queued', input }); }
    this.handle(step);
    return true;
  }

  /** Carries out a step's effects in order, then reports its drops and discards and sets the timer. */
  private handle(step: SessionStepValue): void {
    for (const effect of step.effects) {
      switch (effect.kind) {
        case glue.SessionEffectKind.Send: {
          const frame = frameText(effect.bytes);
          const kind = effect.frameKind ?? '';
          if (this.carrier.sendSession(frame)) this.emit({ type: 'sent', kind, frame });
          else this.emit({ type: 'unsent', kind, reason: 'carrier', frame });
          break;
        }
        case glue.SessionEffectKind.Event: {
          let event: { event: string };
          try { event = JSON.parse(effect.eventJson ?? '') as { event: string }; } catch { event = { event: effect.event ?? 'unknown' }; }
          this.emit({ type: 'session', event });
          break;
        }
        case glue.SessionEffectKind.Persist:
          // A step's effects end at its first Persist; its acknowledgement ID is the step's.
          if (effect.persistedJson !== undefined && step.awaitingPersist !== undefined) this.write(effect.persistedJson, step.awaitingPersist);
          break;
        case glue.SessionEffectKind.Unsent:
          this.emit({ type: 'unsent', kind: effect.frameKind ?? '', reason: effect.unsent ?? 'unknown' });
          break;
      }
    }
    for (const d of step.drops) { this.stats.drops++; this.emit(d.helloTo === undefined ? { type: 'drop', reason: d.reason } : { type: 'drop', reason: d.reason, helloTo: d.helloTo }); }
    if (step.discarded > 0) this.emit({ type: 'discarded', count: step.discarded });
    this.schedule();
  }

  private schedule(): void {
    const e = this.endpoint;
    if (!e || this.closed) { this.tickTimer.clear(); return; }
    const due = e.next_deadline();
    // While a Persist is written the deadline stays the machine's; a tick that fell due is kept as one and runs at the
    // acknowledgement, so a due deadline is not ticked again until then.
    if (due !== undefined && this.writing !== undefined && Number(due) <= this.clock.monoMs()) { this.tickTimer.clear(); return; }
    this.tickTimer.at(due === undefined ? undefined : Number(due));
  }

  /** The durable write of one `Persist`; only its completion acknowledges it. */
  private write(json: string, ack: bigint): void {
    const endpoint = this.endpoint;
    this.emit({ type: 'persist', phase: 'started', ack });
    const done = (async () => {
      for (;;) {
        try { await this.store.save(json); break; } catch (error) {
          this.emit({ type: 'persist', phase: 'failed', ack, error });
          if (this.closed) return;
          await new Promise<void>(resolve => this.clock.setTimer(resolve, this.persistRetryMs));
          if (this.closed) return;
        }
      }
      // Stored: a restart starts from it, whatever happens to this endpoint.
      this.lastStored = json;
      this.writing = undefined;
      if (this.closed || this.endpoint !== endpoint) return;
      this.stats.persisted++;
      this.emit({ type: 'persist', phase: 'stored', ack });
      try {
        this.run('persisted', (e, engine, clock) => e.persisted(ack, engine, clock));
      } catch (error) {
        this.emit({ type: 'error', code: code(error), during: 'persisted' });
      }
      this.drainCommands();
    })();
    this.writing = done;
  }

  /** Runs held commands in order; one refused with `session:persistPending` waits for the write to complete. */
  private drainCommands(): void {
    while (this.commands.length > 0 && !this.closed && !this.rebuilding && this.endpoint) {
      const c = this.commands[0] as HeldCommand;
      let ran: boolean;
      try {
        ran = this.run('command', (e, engine, clock) => e.command(c.json, engine, clock));
      } catch (error) {
        if (code(error) === 'session:persistPending') { this.stats.held++; this.emit({ type: 'commandHeld', command: c.name }); return; }
        this.commands.shift();
        c.reject(error);
        continue;
      }
      // Not run because the endpoint is being made again: it stays first in line.
      if (!ran && (this.rebuilding || !this.endpoint)) return;
      this.commands.shift();
      if (ran) c.resolve(); else c.reject(new Error(`the ${c.name} command could not be run`));
    }
  }

  // Views, delegation and rebuilding

  /** Installs the engine's current view (`set_account`). False when the endpoint is being made again instead. */
  private install(): boolean {
    const e = this.endpoint;
    if (!e) return false;
    let engine: glue.AccountEngine; let view: glue.SessionAccountView;
    try {
      engine = this.account.engine();
      view = engine.session_account(this.namespace, BigInt(this.clock.wallMs()));
    } catch (error) { this.emit({ type: 'error', code: code(error), during: 'install' }); return false; }
    try {
      const session = view.session_of(this.me);
      const seq = engine.head_seq(); const digest = engine.head_digest();
      // A new session number needs a new session key (sessions §S2): a new endpoint.
      if (this.installed && session !== undefined && this.installed.session !== undefined && session !== this.installed.session) {
        this.rebuild('sessionChanged');
        return false;
      }
      let step: SessionStepValue;
      try {
        step = plain<SessionStepValue>(e.set_account(view, engine, this.clockNow()));
      } catch (error) {
        const c = code(error);
        if (c === 'session:clockBackwards') { this.rebuild('clockBackwards'); return false; }
        if (c === 'session:wrongView') { this.rebuild('wrongView'); return false; }
        this.emit({ type: 'error', code: c, during: 'install' });
        return false;
      }
      this.installed = { seq, digest, session: session ?? this.installed?.session };
      this.handle(step);
      this.emit({ type: 'account', entitled: e.entitled(), canWrite: e.can_write(), seq });
      return true;
    } finally {
      view.free();
    }
  }

  /** Makes the endpoint from the stored claim with new randomness, and installs a signed delegation. */
  private async build(): Promise<void> {
    const engine = this.account.engine();
    const view = engine.session_account(this.namespace, BigInt(this.clock.wallMs()));
    let made: glue.SessionEndpoint;
    try {
      const keyRandom = this.random(32); const seed = this.random(16);
      try {
        made = new glue.SessionEndpoint(this.account.account, this.namespace, this.cell, this.me, this.policy, this.lastStored, view, keyRandom, seed, this.clockNow());
      } finally { keyRandom.fill(0); seed.fill(0); }
      this.installed = { seq: engine.head_seq(), digest: engine.head_digest(), session: view.session_of(this.me) };
    } finally {
      view.free();
    }
    this.endpoint = made;
    await this.delegate();
  }

  /** Has the member key sign this endpoint's delegation (now, and again before it ends). */
  private async delegate(): Promise<void> {
    const e = this.endpoint;
    if (!e || this.closed) return;
    const notBefore = this.clock.wallMs() - 60_000;
    const expires = notBefore + this.delegationMs;
    const body = e.begin_delegation(BigInt(notBefore), BigInt(expires));
    const signature = await this.account.signRaw(body);
    if (this.endpoint !== e || this.closed) return;
    e.finish_delegation(body, signature, this.clockNow());
    this.renewTimer.at(this.clock.monoMs() + Math.max(60_000, expires - this.clock.wallMs() - RENEW_BEFORE));
  }

  /**
   * Discards the endpoint and makes a new one from the last stored claim (after the write in progress, if any, ends),
   * then joins again with the application's state. Inputs that arrive meanwhile are not judged (`missed`).
   */
  private rebuild(reason: RebuildReason): void {
    if (this.rebuilding || this.closed) return;
    this.rebuilding = true;
    this.stats.rebuilt++;
    this.emit({ type: 'rebuilt', reason });
    this.tickTimer.clear(); this.renewTimer.clear();
    const old = this.endpoint; this.endpoint = undefined;
    try { old?.free(); } catch { /* freed */ }
    void (async () => {
      try {
        await this.writing;
        if (this.closed) return;
        await this.build();
        if (this.closed) return;
        this.rebuilding = false;
        this.commands.unshift({ name: 'join', json: JSON.stringify({ command: 'join', state: this.stateValue() }), resolve: () => {}, reject: () => {} });
        if (this.carrierUp) this.run('linkUp', (e, engine, clock) => e.link_up(engine, clock), 'link');
        this.drainCommands();
      } catch (error) {
        this.rebuilding = false;
        this.emit({ type: 'error', code: code(error), during: 'rebuild' });
      }
    })();
  }

  private stateValue(): string | null {
    const s = this.stateOf();
    return s === undefined ? null : base64(s);
  }
}

/** Standard base64 with padding, as the core writes `payload`, `snapshot` and `state`. */
export function base64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
/** Bytes of standard or URL-safe base64 (padded or not). */
export function unbase64(text: string): Uint8Array {
  const std = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  const s = atob(padded);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
/** Unpadded base64url, as the core writes `id` and `fresh`. */
export function base64url(bytes: Uint8Array): string { return base64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
