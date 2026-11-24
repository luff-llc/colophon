/**
 * The JavaScript host of the 0.6 home stream (docs/colophon-0.6-sync-stream.md §2): one per home. It owns the socket,
 * the ticket request and the timer, and does exactly what the core's `HomeStream` says, step by step. Every policy (when
 * to mint, how long to back off, when to ping, when to wake a pass, when to give up) is the core's; nothing here
 * retries, waits or caps on its own.
 *
 * A frame is a hint: `Wake` runs an ordinary exchange pass through the account, and nothing a frame carries reaches
 * the engine. Session cells attach here: the host subscribes them while the stream is live, routes the home's
 * `session` messages to them as the frame's own text, and sends their frames.
 */
import { FetchHomeTransport, type HomeAnswer, type HomeTransport } from '../session/transport.js';
import { glue, isAccountFault, plain } from '../session/wasm.js';
import type { HostAccount } from './account.js';
import { Deadline, systemClock, type HostClock } from './clock.js';
import { frameCell, sessionFrameText } from './frames.js';
import { webSocketFactory, type HostSocket, type SocketFactory } from './socket.js';

/** `StreamStep` as plain values. */
export interface StreamStepValue { kind: glue.StreamStepKind; url?: string; logUrl?: string; text?: string; code?: number; until?: bigint }
/** `StreamEvent` as plain values. */
export interface StreamEventValue {
  kind: glue.StreamEventKind; principal?: string; expiresAt?: bigint; cursor?: string; json?: string; text?: string; code?: string;
  reference?: string; reason?: string; retryAt?: bigint; blocked?: glue.StreamBlockedKind; refused?: string;
}
/** `StreamStatus` as plain values. */
export interface StreamStatusValue { kind: glue.StreamStatusKind; until?: bigint; blocked?: glue.StreamBlockedKind; refused?: string }

/** A session cell as the stream carries it (`SessionCellHost` implements it). */
export interface StreamCell {
  readonly namespace: string;
  readonly cell: string;
  /** A frame for this cell, as the text the home carried. */
  deliver(frame: string): void;
  /** The home carries this cell's frames to and from this device now (subscribed on a live stream). */
  linkUp(): void;
  /** It no longer does. */
  linkDown(): void;
}

/** What the host reports. None of these carries a ticket, an unredacted URL or a frame. */
export type StreamHostEvent =
  /** Every event the core returned, in order (`Session` included, after it was routed). */
  | { type: 'event'; event: StreamEventValue }
  /** The stream's status changed. */
  | { type: 'status'; status: StreamStatusValue }
  /** A socket is being opened; `url` is the core's redacted form. */
  | { type: 'connect'; url: string }
  /** An exchange pass the stream woke finished (`seq`: the verified head after it), or failed. */
  | { type: 'pass'; seq?: bigint; error?: unknown }
  /** The ticket call could not be made or signed; the core was told (`ticket_call_failed`). */
  | { type: 'ticketCallFailed'; code: string }
  /** A `session` message whose frame could not be taken out, or that names no attached cell. */
  | { type: 'unrouted'; reason: 'noFrame' | 'noCell' };

export interface StreamHostOptions {
  account: HostAccount;
  /** The home's member ID. */
  home: string;
  /** Where ticket requests go: the transport the session uses for this home. Default `FetchHomeTransport`. */
  transport?: HomeTransport;
  /** Opens the WebSocket. Default: the runtime's `WebSocket` (`webSocketFactory`). */
  socket?: SocketFactory;
  clock?: HostClock;
  /** Adjusts the documented configuration (`stream_default_config`) before the client is made. */
  configure?: (config: glue.StreamConfig) => void;
  /** The resume cursor saved from an earlier `Cursor` event. */
  cursor?: string;
  /** Persists each `Cursor` event next to the exchange checkpoint (none: forget the saved one). */
  saveCursor?: (cursor: string | undefined) => void | Promise<void>;
  /** The client, when the host does not make it from the engine (tests: `new glue.HomeStream(…)`). */
  client?: glue.HomeStream;
}

const key = (namespace: string, cell: string): string => `${namespace}\n${cell}`;
const toAnswer = (a: HomeAnswer): glue.HttpAnswer => new glue.HttpAnswer(a.status, a.headers.slice(0, 256).map(h => new glue.Header(h.name, h.value)), a.body);
const methodName = (m: glue.HttpMethod): 'GET' | 'POST' | 'PUT' => m === glue.HttpMethod.Get ? 'GET' : m === glue.HttpMethod.Post ? 'POST' : 'PUT';
const codeOf = (error: unknown): string => isAccountFault(error) ? error.code : error instanceof Error ? error.name : 'unknown';

export class HomeStreamHost {
  readonly home: string;
  private readonly account: HostAccount;
  private readonly client: glue.HomeStream;
  private readonly transport: HomeTransport;
  private readonly openSocket: SocketFactory;
  private readonly clock: HostClock;
  private readonly saveCursor: ((cursor: string | undefined) => void | Promise<void>) | undefined;
  private readonly timer: Deadline;
  private readonly listeners = new Set<(event: StreamHostEvent) => void>();
  private readonly cells = new Map<string, StreamCell>();
  /** Cells the home acknowledged a subscription for on the current connection. */
  private readonly subscribed = new Set<string>();
  private socket: HostSocket | undefined;
  /** Bumped whenever the current socket is replaced or closed: events from an older socket are ignored. */
  private generation = 0;
  private started = false;
  private stopped = false;
  private pumping = false;
  private pumpAgain = false;
  private passing = false;
  private passAgain = false;
  /** A ticket call is being signed: the core asks for it (`NeedTicketCall`) until the host answers. */
  private minting = false;
  private lastStatus: glue.StreamStatusKind | undefined;
  private readonly life = new AbortController();

  constructor(options: StreamHostOptions) {
    this.home = options.home;
    this.account = options.account;
    this.transport = options.transport ?? new FetchHomeTransport();
    this.openSocket = options.socket ?? webSocketFactory();
    this.clock = options.clock ?? systemClock;
    this.saveCursor = options.saveCursor;
    this.timer = new Deadline(this.clock, () => this.pump());
    if (options.client) {
      this.client = options.client;
    } else {
      const config = glue.stream_default_config();
      options.configure?.(config);
      this.client = this.account.engine().stream_client(options.home, config, options.cursor);
    }
  }

  /** Starts driving the stream. */
  start(): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.pump();
  }
  /** Stops: closes the socket (1000), cancels the timer and the call in flight, and frees the client. */
  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.life.abort();
    this.timer.clear();
    const socket = this.socket;
    this.socket = undefined; this.generation++;
    try { socket?.close(1000); } catch { /* already closed */ }
    this.allDown();
    try { this.client.free(); } catch { /* freed */ }
  }

  /** Calls `listener` after every exchange pass this host ran (cells install a new view from it). */
  onPass(listener: () => void): () => void { return this.on(e => { if (e.type === 'pass') listener(); }); }
  on(listener: (event: StreamHostEvent) => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  private emit(event: StreamHostEvent): void { for (const l of [...this.listeners]) { try { l(event); } catch { /* a listener's failure is its own */ } } }

  /** Where the stream stands. */
  get status(): StreamStatusValue { return plain<StreamStatusValue>(this.client.status()); }
  /** Whether the app's ordinary poll timer should run (always, unless the stream is live). */
  get polling(): boolean { return this.client.polling(); }
  /** The resume cursor held now. */
  get cursor(): string | undefined { return this.client.cursor(); }
  get live(): boolean { return this.client.status().kind === glue.StreamStatusKind.Live; }

  /** Try again now: foreground entry, a network change or an explicit user action, never a timer (the core bounds it). */
  retryNow(): void { this.client.retry_now(); this.pump(); }
  /** The account's verified history moved outside a pass this host woke (the app's own poll): tell the core. */
  historyChanged(): void {
    try { this.client.on_history(this.account.engine().head_seq()); } catch { /* no engine: nothing to compare */ }
    this.pump();
  }

  // Cells

  /** Carries `cell` on this stream: subscribed whenever the stream is live, its frames delivered to it. */
  attach(cell: StreamCell): void {
    const k = key(cell.namespace, cell.cell);
    if (this.cells.has(k)) throw new Error(`a cell ${cell.namespace}/${cell.cell} is already attached`);
    this.cells.set(k, cell);
    if (this.live) this.sendClient(() => this.client.subscribe(cell.namespace, cell.cell, undefined));
  }
  /** Stops carrying `cell` (unsubscribes when live). */
  detach(cell: StreamCell): void {
    const k = key(cell.namespace, cell.cell);
    if (this.cells.get(k) !== cell) return;
    this.cells.delete(k);
    if (this.subscribed.delete(k)) cell.linkDown();
    if (this.live) this.sendClient(() => this.client.unsubscribe(cell.namespace, cell.cell, undefined));
  }
  /**
   * Sends one sealed session frame (a `Send` effect's bytes as text), carried verbatim. False when the stream is not
   * live or the frame was refused before sending: to the session that is loss, which its own rules repair.
   */
  sendSession(frame: string): boolean {
    if (!this.live || !this.socket) return false;
    return this.sendClient(() => this.client.session_frame(frame, undefined));
  }
  private sendClient(build: () => string): boolean {
    const socket = this.socket;
    if (!socket) return false;
    let text: string;
    try { text = build(); } catch { return false; }
    try { socket.send(text); return true; } catch { return false; }
  }

  // The loop

  private now(): bigint { return BigInt(this.clock.monoMs()); }

  /** Asks the core what to do, does it, and asks again, until it says to wait or sleep. */
  private pump(): void {
    if (!this.started || this.stopped) return;
    if (this.pumping) { this.pumpAgain = true; return; }
    this.pumping = true;
    try {
      do {
        this.pumpAgain = false;
        this.steps();
      } while (this.pumpAgain && !this.stopped);
    } finally {
      this.pumping = false;
    }
    this.checkStatus();
  }
  private steps(): void {
    // Every step but Waiting and Sleep changes the core's state, so this ends; the bound only guards a defect.
    for (let n = 0; n < 1000 && !this.stopped; n++) {
      const step = plain<StreamStepValue>(this.client.next(this.now()));
      switch (step.kind) {
        case glue.StreamStepKind.Wake: this.runPass(); break;
        case glue.StreamStepKind.NeedTicketCall:
          // Level-triggered: the core repeats it until `ticket_request` or `ticket_call_failed`. While the call is
          // being signed (which may wait on a person) the host waits, as it does for `Waiting`.
          if (this.minting) { this.timer.clear(); return; }
          this.mint();
          break;
        case glue.StreamStepKind.Connect: this.connect(step.url ?? '', step.logUrl ?? ''); break;
        case glue.StreamStepKind.Send: if (step.text !== undefined) this.sendClient(() => step.text as string); break;
        case glue.StreamStepKind.Close: this.close(step.code ?? 1000); break;
        case glue.StreamStepKind.Waiting: this.timer.clear(); return;
        case glue.StreamStepKind.Sleep: this.timer.at(step.until === undefined ? undefined : Number(step.until)); return;
      }
      this.checkStatus();
    }
  }

  /** `NeedTicketCall`: sign the call, send the ticket request, hand the core the answer. */
  private mint(): void {
    const signal = this.life.signal;
    this.minting = true;
    void (async () => {
      let call: Uint8Array;
      try {
        call = await this.account.streamCall(this.home, signal);
      } catch (error) {
        this.minting = false;
        if (this.stopped) return;
        this.handle(this.client.ticket_call_failed(this.now()));
        this.emit({ type: 'ticketCallFailed', code: codeOf(error) });
        this.pump();
        return;
      }
      this.minting = false;
      if (this.stopped) return;
      let answer: HomeAnswer | undefined;
      try {
        const request = plain<{ method: glue.HttpMethod; url: string; headers: { name: string; value: string }[]; body: Uint8Array }>(this.client.ticket_request(call, this.now()));
        try {
          answer = await this.transport.send({ method: methodName(request.method), url: request.url, headers: request.headers, body: request.body }, signal);
        } catch {
          answer = undefined;
        }
      } catch (error) {
        // The core refused to build the request (no ticket call outstanding): it is told the call failed.
        if (this.stopped) return;
        this.handle(this.client.ticket_call_failed(this.now()));
        this.emit({ type: 'ticketCallFailed', code: codeOf(error) });
        this.pump();
        return;
      }
      if (this.stopped) return;
      this.handle(this.client.on_ticket(answer ? toAnswer(answer) : undefined, this.now()));
      this.pump();
    })();
  }

  /** `Connect`: open the socket at `url` (never logged) and report what it does. */
  private connect(url: string, logUrl: string): void {
    const generation = ++this.generation;
    const current = (): boolean => generation === this.generation && !this.stopped;
    this.emit({ type: 'connect', url: logUrl });
    const ended = (): void => { this.socket = undefined; this.generation++; this.allDown(); };
    try {
      this.socket = this.openSocket(url, {
        open: () => { if (!current()) return; this.client.on_open(this.now()); this.pump(); },
        message: text => { if (!current()) return; this.handle(this.client.on_frame(text, this.now())); this.pump(); },
        refused: answer => { if (!current()) return; ended(); this.handle(this.client.on_refused(toAnswer(answer), this.now())); this.pump(); },
        closed: code => { if (!current()) return; ended(); this.handle(this.client.on_closed(code, this.now())); this.pump(); },
      });
    } catch {
      // A socket that cannot even be made is a transport failure, reported after this step as any other.
      queueMicrotask(() => { if (!current()) return; ended(); this.handle(this.client.on_closed(undefined, this.now())); this.pump(); });
    }
  }

  /** `Close`: close the socket, then tell the core. */
  private close(code: number): void {
    const socket = this.socket;
    this.socket = undefined; this.generation++;
    try { socket?.close(code); } catch { /* already closed */ }
    this.allDown();
    this.handle(this.client.on_closed(code, this.now()));
  }

  /** `Wake`: one ordinary exchange pass, then `on_history`. A wake during a pass runs one more after it. */
  private runPass(): void {
    if (this.passing) { this.passAgain = true; return; }
    this.passing = true;
    void (async () => {
      let seq: bigint | undefined; let failure: unknown;
      try { await this.account.exchange(this.life.signal); } catch (error) { failure = error; }
      if (this.stopped) return;
      try { seq = this.account.engine().head_seq(); this.client.on_history(seq); } catch (error) { failure ??= error; }
      this.passing = false;
      this.emit(failure === undefined ? { type: 'pass', seq } : { type: 'pass', seq, error: failure });
      if (this.passAgain) { this.passAgain = false; this.runPass(); }
      this.pump();
    })();
  }

  /** The core's events, in order. */
  private handle(events: glue.StreamEvent[]): void {
    for (const event of plain<StreamEventValue[]>(events)) {
      switch (event.kind) {
        case glue.StreamEventKind.Connected:
          // The hello arrived: the stream is live. Subscribe every attached cell.
          this.subscribed.clear();
          for (const cell of this.cells.values()) this.sendClient(() => this.client.subscribe(cell.namespace, cell.cell, undefined));
          break;
        case glue.StreamEventKind.Cursor:
          void Promise.resolve(this.saveCursor?.(event.cursor)).catch(() => { /* kept by the client; saved next time */ });
          break;
        case glue.StreamEventKind.Session: this.route(event.text ?? ''); break;
        case glue.StreamEventKind.Ack: this.acknowledged(event.json); break;
        default: break;
      }
      this.emit({ type: 'event', event });
    }
  }
  private acknowledged(json: string | undefined): void {
    let v: { type?: unknown; namespace?: unknown; cell?: unknown };
    try { v = JSON.parse(json ?? '') as typeof v; } catch { return; }
    if (typeof v.namespace !== 'string' || typeof v.cell !== 'string') return;
    const k = key(v.namespace, v.cell);
    const cell = this.cells.get(k);
    if (!cell) return;
    if (v.type === 'subscribed' && !this.subscribed.has(k)) { this.subscribed.add(k); cell.linkUp(); }
    if (v.type === 'unsubscribed' && this.subscribed.delete(k)) cell.linkDown();
  }
  /** A `session` message: its frame's own text to the cell it names. */
  private route(message: string): void {
    const frame = sessionFrameText(message);
    if (frame === undefined) { this.emit({ type: 'unrouted', reason: 'noFrame' }); return; }
    const where = frameCell(frame);
    const cell = where ? this.cells.get(key(where.namespace, where.cell)) : undefined;
    if (!cell) { this.emit({ type: 'unrouted', reason: 'noCell' }); return; }
    cell.deliver(frame);
  }

  private allDown(): void {
    const up = [...this.subscribed];
    this.subscribed.clear();
    for (const k of up) this.cells.get(k)?.linkDown();
  }
  private checkStatus(): void {
    if (this.stopped) return;
    const status = this.status;
    if (status.kind === this.lastStatus) return;
    this.lastStatus = status.kind;
    if (status.kind !== glue.StreamStatusKind.Live) this.allDown();
    this.emit({ type: 'status', status });
  }
}
