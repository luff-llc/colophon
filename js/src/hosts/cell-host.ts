/**
 * The JavaScript host of one 0.6 session cell: it owns a `SessionEndpoint` and runs the reference host loop of
 * docs/bindings-05.md §10 exactly.
 *
 * - Every input (a frame, a timer at the step's `next_deadline`, a carrier change, an application command, a completed
 *   write) is one job on one queue. Jobs run one at a time and never inside another, and events reach listeners only
 *   between jobs, so no listener, store, socket or timer callback can re-enter the endpoint.
 * - The step a call returns is carried out in order: `Send` to the carrier, `Event` to the application, `Persist` to
 *   the store. A `Persist` is acknowledged (`persisted`) only when its durable write has completed, never on seeing the
 *   step. A failed write is retried and never acknowledged; a store that keeps failing fails the cell (§3 of
 *   docs/hosts-06.md).
 * - `session:staleAccount` installs a fresh view of the engine (`set_account`) and the input is run again.
 * - `session:persistPending` keeps the command, in order, until the write completes. Admission is bounded.
 * - `session:clockBackwards` and a view of another engine (`session:wrongView`) discard the endpoint and make a new one
 *   from the last claim the store holds, so the restart rules apply (sessions §S6).
 * - Drops, discarded effects and unsent frames are reported, never thrown away silently.
 *
 * Frames reach `receive` as the text the carrier delivered, unchanged. Every timing decision is the core's: the host
 * only calls `tick` at the deadline the latest step carries.
 */
import { isAccountFault, glue, plain } from '../session/wasm.js';
import type { HostAccount } from './account.js';
import type { ClaimStore, StoredClaim } from './claim-store.js';
import { Deadline, systemClock, type HostClock } from './clock.js';
import { frameBytes, frameText } from './frames.js';
import type { StreamCell } from './stream-host.js';

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
  awaitingPersist?: bigint; persistOutstanding: boolean; queued: boolean; discarded: number; nextDeadline?: bigint;
}
/** `SessionEffect` as plain values. */
export interface SessionEffectValue {
  kind: glue.SessionEffectKind; bytes: Uint8Array; to?: string; frameKind?: string; persistedJson?: string; event?: string; eventJson?: string; unsent?: string;
}

/** Why an endpoint was made again. */
export type RebuildReason = 'clockBackwards' | 'wrongView' | 'sessionChanged';
/** Why a cell host stopped acting. */
/** `store`: its writes kept failing; `superseded`: the store holds a newer save (another instance owns the cell). */
export type FailReason = 'store' | 'rebuild' | 'superseded';

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
  /**
   * The cell stopped acting: its endpoint is gone, it sends nothing and is detached, and every held or new command is
   * refused. Open a new host to take part again (from the last stored claim, so the restart rules apply).
   */
  | { type: 'failed'; reason: FailReason; error?: unknown }
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
  /** Consecutive failed writes of one `Persist` after which the cell fails (default 20). */
  persistAttempts?: number;
  /** How long one write may take before it counts as failed (default 10,000 ms); a late success is not acknowledged. */
  persistTimeoutMs?: number;
  /** The most commands held at once (default 64); one more is refused with `commandQueueFull`. */
  maxCommands?: number;
  /** Host randomness (default `crypto.getRandomValues`). The session key and the `fresh` seed are new on every start. */
  random?: (length: number) => Uint8Array;
}

/** A command the host refused or could not run. */
export class CellHostError extends Error {
  constructor(readonly code: 'closed' | 'failed' | 'commandQueueFull' | 'notRun' | 'timeout', message: string) { super(message); this.name = 'CellHostError'; }
}

interface HeldCommand { name: string; json: string; resolve(): void; reject(error: unknown): void }
type Phase = 'opening' | 'open' | 'rebuilding' | 'failed' | 'closed';

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
  private readonly persistAttempts: number;
  private readonly persistTimeoutMs: number;
  private readonly maxCommands: number;
  private readonly random: (length: number) => Uint8Array;
  private readonly listeners = new Set<(event: CellHostEvent) => void>();
  private readonly tickTimer: Deadline;
  private readonly renewTimer: Deadline;
  private phase: Phase = 'opening';
  private endpoint: glue.SessionEndpoint | undefined;
  /** The authority head (seq and digest) of the view installed last, and this member's session number in it. */
  private installed: { seq: bigint; digest: string; session: bigint | undefined } | undefined;
  /** The last `persisted_json` whose durable write completed: what a new endpoint starts from. */
  private lastStored: string | undefined;
  /** Settles when the write in progress has ended (stored, or given up); set before any store code runs. */
  private writing: Promise<void> | undefined;
  /** This instance's fencing generation (above what the store held when it opened or rebuilt) and its save count. */
  private generation = 1;
  private seq = 0;
  /** Cancels every retry and deadline timer that is waiting (on close and on failure). */
  private readonly waits = new Set<() => void>();
  /** Commands admitted and not yet settled (bounded by `maxCommands`). */
  private readonly admitted = new Set<HeldCommand>();
  /** Commands that wait, in admission order: one the endpoint refused with `persistPending`, and every later one. */
  private readonly held: HeldCommand[] = [];
  /** The serial queue: every endpoint call runs in one of these jobs, one at a time. */
  private readonly jobs: (() => void)[] = [];
  private readonly outbox: CellHostEvent[] = [];
  private draining = false;
  /** The carrier's link as last reported, applied to every new endpoint. */
  private carrierUp = false;
  private attached = false;
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
    this.persistAttempts = Math.max(1, options.persistAttempts ?? 20);
    this.persistTimeoutMs = Math.max(1, options.persistTimeoutMs ?? 10_000);
    this.maxCommands = Math.max(1, options.maxCommands ?? 64);
    this.random = options.random ?? (n => crypto.getRandomValues(new Uint8Array(n)));
    this.tickTimer = new Deadline(this.clock, () => this.enqueue(() => this.whenOpen(() => this.run('tick', (e, engine, clock) => e.tick(engine, clock), 'tick'))));
    this.renewTimer = new Deadline(this.clock, () => this.enqueue(() => this.whenOpen(() => this.renew())));
  }

  /**
   * Starts a session for this member in the cell: loads the stored claim, makes the endpoint, has the member key sign
   * its delegation, attaches to the carrier and joins with the application's state. If any of that fails the host is
   * closed (detached, its endpoint freed) and the error is thrown.
   */
  static async open(options: CellHostOptions, listener?: (event: CellHostEvent) => void): Promise<SessionCellHost> {
    const host = new SessionCellHost(options);
    if (listener) host.on(listener);
    try {
      const held = await host.store.load();
      host.lastStored = held?.claim ?? undefined;
      host.generation = (held?.fence.generation ?? 0) + 1;
      // Reserve this instance's generation before any claim is saved under it (see claim-store.ts).
      await host.reserve(held?.claim ?? null);
      await host.build();
      if (host.phase !== 'opening') throw new CellHostError('closed', 'the cell host was closed while it opened');
      host.phase = 'open';
      host.attached = true;
      host.carrier.attach(host);
      host.stopPassListener = host.carrier.onPass?.(() => host.accountChanged());
      host.armTick(host.endpoint?.next_deadline());
      await host.command('join', { command: 'join', state: host.stateValue() });
    } catch (error) {
      host.close();
      throw error;
    }
    return host;
  }

  on(listener: (event: CellHostEvent) => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }

  /** The endpoint's read-only state, or undefined while it is being made again (or after the host ended). */
  get current(): glue.SessionEndpoint | undefined { return this.endpoint; }
  /** Whether a `Persist` write is in progress. */
  get writePending(): boolean { return this.writing !== undefined; }
  /** The claim the store last confirmed, as JSON. */
  get storedClaim(): string | undefined { return this.lastStored; }
  /** `opening`, `open`, `rebuilding`, `failed` or `closed`. */
  get state(): Phase { return this.phase; }

  // The queue

  private enqueue(job: () => void): void {
    if (this.phase === 'closed') return;
    this.jobs.push(job);
    this.drain();
  }
  /** Runs jobs one at a time; events reach listeners only between jobs, so a listener's call is a later job. */
  private drain(): void {
    if (this.draining) return;
    this.draining = true;
    try {
      for (;;) {
        const event = this.outbox.shift();
        if (event) {
          for (const l of [...this.listeners]) { try { l(event); } catch { /* a listener's failure is its own */ } }
          continue;
        }
        const job = this.jobs.shift();
        if (!job) break;
        try { job(); } catch (error) { this.outbox.push({ type: 'error', code: code(error), during: 'job' }); }
      }
    } finally {
      this.draining = false;
    }
  }
  private emit(event: CellHostEvent): void { this.outbox.push(event); this.drain(); }
  /** The host closed or failed. */
  private get over(): boolean { return this.phase === 'closed' || this.phase === 'failed'; }
  private whenOpen(body: () => void): void { if (this.phase === 'open' && this.endpoint) body(); }

  // Inputs

  /**
   * An application command (§S10) as the core's JSON, tagged by `command`. Resolves once the endpoint has run it;
   * refused at once when the host is closed or failed, or when `maxCommands` are already held.
   */
  command(name: string, command: Record<string, unknown>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.phase === 'closed' || this.phase === 'failed') { reject(new CellHostError(this.phase, `the cell host is ${this.phase}`)); return; }
      if (this.admitted.size >= this.maxCommands) { reject(new CellHostError('commandQueueFull', `${this.maxCommands} commands are already waiting`)); return; }
      const c: HeldCommand = {
        name, json: JSON.stringify(command),
        resolve: () => { this.admitted.delete(c); resolve(); },
        reject: error => { this.admitted.delete(c); reject(error); },
      };
      this.admitted.add(c);
      // Its place in the one input queue is taken now, among frames, ticks and link changes.
      this.enqueue(() => this.admit(c));
    });
  }
  deliver(frame: string): void {
    this.enqueue(() => {
      if (this.phase === 'rebuilding') { this.emit({ type: 'missed' }); return; }
      const bytes = frameBytes(frame);
      this.whenOpen(() => this.run('receive', (e, engine, clock) => e.receive(bytes, engine, clock), 'frame'));
    });
  }
  linkUp(): void {
    this.enqueue(() => { this.carrierUp = true; this.whenOpen(() => this.run('linkUp', (e, engine, clock) => e.link_up(engine, clock), 'link')); });
  }
  linkDown(): void {
    this.enqueue(() => { this.carrierUp = false; this.whenOpen(() => this.run('linkDown', (e, engine, clock) => e.link_down(engine, clock), 'link')); });
  }
  /** The account's verified head may have moved (after an exchange pass): install a fresh view if it did. */
  accountChanged(): void {
    this.enqueue(() => this.whenOpen(() => {
      let seq: bigint; let digest: string;
      try { const engine = this.account.engine(); seq = engine.head_seq(); digest = engine.head_digest(); } catch (error) { this.emit({ type: 'error', code: code(error), during: 'accountChanged' }); return; }
      if (this.installed && this.installed.seq === seq && this.installed.digest === digest) return;
      this.install();
      this.drainCommands();
    }));
  }

  /**
   * Ends this member's part: `leave` (a holder releases the role), then detaches from the carrier and drops the
   * endpoint, which wipes its session key.
   */
  async leave(): Promise<void> {
    try { await this.command('leave', { command: 'leave' }); } finally { this.close(); }
  }
  /** Stops at once, as a process that ends would: no `leave`; the stored claim is what a restart starts from. */
  close(): void { this.end('closed', new CellHostError('closed', 'the cell host is closed')); }

  private end(phase: 'closed' | 'failed', why: CellHostError): void {
    if (this.phase === 'closed' || this.phase === 'failed') return;
    this.phase = phase;
    this.tickTimer.clear(); this.renewTimer.clear();
    for (const stop of [...this.waits]) stop();
    this.stopPassListener?.(); this.stopPassListener = undefined;
    if (this.attached) { this.attached = false; try { this.carrier.detach(this); } catch { /* the carrier is gone */ } }
    this.held.length = 0;
    for (const c of [...this.admitted]) c.reject(why);
    if (phase === 'closed') this.jobs.length = 0;
    const e = this.endpoint; this.endpoint = undefined;
    try { e?.free(); } catch { /* freed */ }
  }
  private fail(reason: FailReason, error?: unknown): void {
    if (this.phase === 'closed' || this.phase === 'failed') return;
    this.end('failed', new CellHostError('failed', `the cell host failed (${reason})`));
    this.emit(error === undefined ? { type: 'failed', reason } : { type: 'failed', reason, error });
  }

  // The loop (inside jobs only)

  private clockNow(): glue.SessionClock { return new glue.SessionClock(BigInt(Math.max(0, this.clock.monoMs())), BigInt(this.clock.wallMs())); }
  private armTick(due: bigint | undefined): void {
    if (this.phase !== 'open' || !this.endpoint) { this.tickTimer.clear(); return; }
    this.tickTimer.at(due === undefined ? undefined : Number(due));
  }

  /**
   * One endpoint call and its step. `session:staleAccount` installs a fresh view and runs the input once more; a
   * backwards clock or another engine's view makes the endpoint again. A command's other errors are the caller's.
   * Returns whether the input ran.
   */
  private run(during: string, call: (e: glue.SessionEndpoint, engine: glue.AccountEngine, clock: glue.SessionClock) => glue.SessionStep,
    input?: 'frame' | 'tick' | 'link', again = true): boolean {
    const e = this.endpoint;
    if (!e || this.phase !== 'open') return false;
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

  /** Carries out a step's effects in order, reports its drops and discards, and arms the timer from it. */
  private handle(step: SessionStepValue): void {
    for (const effect of step.effects) {
      switch (effect.kind) {
        case glue.SessionEffectKind.Send: {
          const frame = frameText(effect.bytes);
          const kind = effect.frameKind ?? '';
          let sent = false;
          try { sent = this.carrier.sendSession(frame); } catch { sent = false; }
          this.emit(sent ? { type: 'sent', kind, frame } : { type: 'unsent', kind, reason: 'carrier', frame });
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
    // While a Persist is outstanding the step carries no deadline: nothing to tick until its acknowledgement.
    this.armTick(step.nextDeadline);
  }

  /**
   * The durable write of one `Persist`; only its completion, as a later job, acknowledges it. One save is in flight
   * at a time: an attempt that passes its deadline counts as failed, and the next one starts only once it has settled
   * (a save that never settles uses up the attempts and fails the cell without another save being issued). A save that
   * succeeds only after its deadline is not acknowledged: the claim is saved again under the next fence.
   */
  private write(json: string, ack: bigint): void {
    const endpoint = this.endpoint;
    let ended: () => void = () => {};
    // Marked before any store code runs, so nothing can see "no write" while this one is under way.
    this.writing = new Promise<void>(resolve => { ended = resolve; });
    this.emit({ type: 'persist', phase: 'started', ack });
    void (async () => {
      try {
        let failures = 0;
        const failed = (error: unknown): boolean => {
          failures++;
          this.emit({ type: 'persist', phase: 'failed', ack, error });
          if (failures < this.persistAttempts) return false;
          this.enqueue(() => { this.writing = undefined; this.fail('store', error); });
          return true;
        };
        for (;;) {
          if (this.over) return;
          const save = this.save({ claim: json, fence: { generation: this.generation, seq: ++this.seq } });
          let late = false;
          let result: { status: 'stored' | 'stale' } | { error: unknown };
          for (;;) {
            const deadline = this.timer(this.persistTimeoutMs);
            const r = await Promise.race([save, deadline.done]);
            deadline.cancel();
            if (r === 'cancelled') return;
            if (r === 'fired') {
              late = true;
              if (failed(new CellHostError('timeout', `the store did not finish a write within ${this.persistTimeoutMs} ms`))) return;
              continue;
            }
            result = r;
            break;
          }
          if ('error' in result) {
            if (failed(result.error)) return;
            if (await this.timer(this.persistRetryMs).done === 'cancelled') return;
            continue;
          }
          if (result.status === 'stale') { this.enqueue(() => { this.writing = undefined; this.fail('superseded'); }); return; }
          if (late) continue;
          break;
        }
        // Stored: a restart starts from it, whatever happens to this endpoint.
        this.lastStored = json;
        this.enqueue(() => {
          this.writing = undefined;
          if (this.endpoint !== endpoint || this.phase !== 'open') return;
          this.stats.persisted++;
          this.emit({ type: 'persist', phase: 'stored', ack });
          try { this.run('persisted', (e, engine, clock) => e.persisted(ack, engine, clock)); } catch (error) { this.emit({ type: 'error', code: code(error), during: 'persisted' }); }
          this.drainCommands();
        });
      } finally {
        ended();
      }
    })();
  }
  /** Saves `claim` under `{generation, 0}`: this instance's fence is in the store before it saves anything else. */
  private async reserve(claim: string | null): Promise<void> {
    const deadline = this.timer(this.persistTimeoutMs);
    const r = await Promise.race([this.save({ claim, fence: { generation: this.generation, seq: 0 } }), deadline.done]);
    deadline.cancel();
    if (r === 'fired' || r === 'cancelled') throw new CellHostError('timeout', 'the store did not reserve this host\'s fence in time');
    if ('error' in r) throw r.error;
    if (r.status === 'stale') throw new CellHostError('failed', 'another instance of this cell holds a newer fence (superseded)');
  }
  /** One save; never rejects. */
  private save(record: StoredClaim): Promise<{ status: 'stored' | 'stale' } | { error: unknown }> {
    return Promise.resolve().then(() => this.store.save(record)).then(status => ({ status }), (error: unknown) => ({ error }));
  }
  /** A timer that close and failure cancel. */
  private timer(ms: number): { done: Promise<'fired' | 'cancelled'>; cancel(): void } {
    let cancel: () => void = () => {};
    const done = new Promise<'fired' | 'cancelled'>(resolve => {
      if (this.over) { resolve('cancelled'); return; }
      let stopTimer: () => void = () => {};
      const stop = (): void => { stopTimer(); this.waits.delete(stop); resolve('cancelled'); };
      stopTimer = this.clock.setTimer(() => { this.waits.delete(stop); resolve('fired'); }, ms);
      this.waits.add(stop);
      cancel = () => { stopTimer(); this.waits.delete(stop); };
    });
    return { done, cancel };
  }

  /** A command at its place in the input queue: run now, or held behind an earlier held command. */
  private admit(c: HeldCommand): void {
    if (this.over) { c.reject(new CellHostError(this.phase === 'failed' ? 'failed' : 'closed', `the cell host is ${this.phase}`)); return; }
    this.held.push(c);
    if (this.held.length === 1) this.drainCommands();
  }
  /** Runs held commands in order; one refused with `session:persistPending` waits for the write to complete. */
  private drainCommands(): void {
    while (this.held.length > 0 && this.phase === 'open' && this.endpoint) {
      const c = this.held[0] as HeldCommand;
      let ran: boolean;
      try {
        ran = this.run('command', (e, engine, clock) => e.command(c.json, engine, clock));
      } catch (error) {
        if (code(error) === 'session:persistPending') { this.stats.held++; this.emit({ type: 'commandHeld', command: c.name }); return; }
        this.held.shift();
        c.reject(error);
        continue;
      }
      // Not run because the endpoint is being made again (or the host ended): it stays first in line, or was refused.
      if (!ran && this.phase !== 'open') return;
      this.held.shift();
      if (ran) c.resolve(); else c.reject(new CellHostError('notRun', `the ${c.name} command could not be run`));
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
    const notBefore = this.clock.wallMs() - 60_000;
    const body = made.begin_delegation(BigInt(notBefore), BigInt(notBefore + this.delegationMs));
    const signature = await this.account.signRaw(body);
    if (this.endpoint !== made) throw new CellHostError('closed', 'the cell host ended while its delegation was signed');
    made.finish_delegation(body, signature, this.clockNow());
    this.armRenewal(notBefore + this.delegationMs);
  }
  private armRenewal(expires: number): void {
    this.renewTimer.at(this.clock.monoMs() + Math.max(60_000, expires - this.clock.wallMs() - RENEW_BEFORE));
  }
  /** Signs a new delegation for the same session key before the old one ends. */
  private renew(): void {
    const e = this.endpoint;
    if (!e) return;
    const notBefore = this.clock.wallMs() - 60_000;
    const expires = notBefore + this.delegationMs;
    let body: Uint8Array;
    try { body = e.begin_delegation(BigInt(notBefore), BigInt(expires)); } catch (error) { this.emit({ type: 'error', code: code(error), during: 'delegation' }); return; }
    this.account.signRaw(body).then(
      signature => this.enqueue(() => {
        if (this.endpoint !== e || this.phase !== 'open') return;
        try { e.finish_delegation(body, signature, this.clockNow()); this.armRenewal(expires); } catch (error) { this.emit({ type: 'error', code: code(error), during: 'delegation' }); }
      }),
      error => this.emit({ type: 'error', code: code(error), during: 'delegation' }),
    );
  }

  /**
   * Discards the endpoint and makes a new one from the last stored claim (after the write in progress, if any, ends),
   * then joins again with the application's state. Frames that arrive meanwhile are not judged (`missed`). If the new
   * endpoint cannot be made, the cell fails.
   */
  private rebuild(reason: RebuildReason): void {
    if (this.phase !== 'open') return;
    this.phase = 'rebuilding';
    this.stats.rebuilt++;
    this.emit({ type: 'rebuilt', reason });
    this.tickTimer.clear(); this.renewTimer.clear();
    const old = this.endpoint; this.endpoint = undefined;
    try { old?.free(); } catch { /* freed */ }
    // The new endpoint saves under a new generation, above every save this instance has issued.
    this.generation++; this.seq = 0;
    const writing = this.writing;
    void (async () => {
      try {
        await writing;
        if (this.phase !== 'rebuilding') return;
        await this.build();
      } catch (error) {
        this.enqueue(() => { if (this.phase === 'rebuilding') this.fail('rebuild', error); });
        return;
      }
      this.enqueue(() => {
        if (this.phase !== 'rebuilding') return;
        this.phase = 'open';
        this.held.unshift({ name: 'join', json: JSON.stringify({ command: 'join', state: this.stateValue() }), resolve: () => {}, reject: () => {} });
        this.armTick(this.endpoint?.next_deadline());
        if (this.carrierUp) this.run('linkUp', (e, engine, clock) => e.link_up(engine, clock), 'link');
        this.drainCommands();
      });
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
