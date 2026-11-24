// The end-to-end world: a real home (relay/server.js on Bun with the Rust home module, as test05 starts it), an
// account with two members A and B entitled to write `listening.podcasts`, each with its own `ColophonSession`, a
// `HomeStreamHost` over a real WebSocket, and a `now-playing` cell. A's network can be cut and restored.
import { accountOf, CellSession, HomeStreamHost, transportOf, webSocketFactory, type CellEvent, type CellHostEvent, type CellHostOptions, type SocketFactory } from '../src/hosts/index.js';
import { glue, HomeTransportError, MemoryMedium, plain, type Home, type HomeTransport } from '../src/session/index.js';
import { authorityOnly, settle, untilApproved } from '../test05/journey.ts';
import { BunRelayHost } from '../test05/relay-bun.ts';
import { approveByScan, assert, Device, equal, RelayHome } from '../test05/support.ts';
import { TestStore } from './fakes.ts';

export const NAMESPACE = 'listening.podcasts';
export const CELL = 'now-playing';

/** A device's network: when down, sockets fail and requests are offline. */
export class Network {
  up = true;
  private readonly open = new Set<{ end(): void }>();
  /** A socket factory reaching `relay` on loopback for the account's `https` name. */
  sockets(relay: RelayHome): SocketFactory {
    const inner = webSocketFactory();
    return (url, handlers) => {
      const local = url.replace(/^wss:\/\//, 'ws://').replace(relay.base.replace(/^https:\/\//, ''), relay.host.local(relay.port).replace(/^http:\/\//, ''));
      if (!this.up) { queueMicrotask(() => handlers.closed(undefined)); return { send: () => { throw new Error('offline'); }, close: () => {} }; }
      let ended = false;
      const entry = { end: () => { if (ended) return; ended = true; socket.close(1000); this.open.delete(entry); handlers.closed(undefined); } };
      const socket = inner(local, { ...handlers, closed: code => { if (ended) return; ended = true; this.open.delete(entry); handlers.closed(code); } });
      this.open.add(entry);
      return { send: text => { if (!this.up) throw new Error('offline'); socket.send(text); }, close: code => { ended = true; this.open.delete(entry); socket.close(code); } };
    };
  }
  transport(inner: HomeTransport): HomeTransport {
    return { send: (request, signal) => this.up ? inner.send(request, signal) : Promise.reject(new HomeTransportError('offline', 'the network is down')) };
  }
  down(): void { this.up = false; for (const s of [...this.open]) s.end(); }
  restore(): void { this.up = true; }
}

/** One member: its session, network, stream host and (once joined) its cell. */
export class Member {
  stream!: HomeStreamHost;
  cell!: CellSession;
  readonly network = new Network();
  readonly store: TestStore;
  readonly log: { at: number; event: CellHostEvent }[] = [];
  readonly events: { at: number; event: CellEvent }[] = [];
  /** The application's own state (its last anchor), kept to supply on join after a restart (§S12). */
  appState: Uint8Array | undefined;
  constructor(readonly name: string, readonly device: Device, readonly relay: RelayHome) { this.store = new TestStore(); }
  get id(): string { return this.device.session.memberId as string; }
  startStream(): void {
    const session = this.device.session;
    const home = plain<Home[]>(session.worker.requireEngine().run(e => e.exchange_homes()))[0];
    assert(home, 'the account has a home');
    const transport = transportOf(session, home.id);
    assert(transport, 'the home has a transport');
    this.stream = new HomeStreamHost({ account: accountOf(session), home: home.id, transport: this.network.transport(transport), socket: this.network.sockets(this.relay) });
    this.stream.start();
  }
  async join(policy?: string): Promise<CellSession> {
    const options: CellHostOptions = { account: accountOf(this.device.session), carrier: this.stream, namespace: NAMESPACE, cell: CELL, store: this.store, state: () => this.appState };
    if (policy !== undefined) options.policy = policy;
    this.cell = await CellSession.join(options);
    this.cell.host.on(event => this.log.push({ at: performance.now(), event }));
    this.cell.events(event => this.events.push({ at: performance.now(), event }));
    return this.cell;
  }
  /** Resolves with the first event (after `since`) matching `match`, waiting up to `ms`. */
  async until<T extends CellEvent['event']>(name: T, since = 0, ms = 10_000, match: (e: Extract<CellEvent, { event: T }>) => boolean = () => true): Promise<{ at: number; event: Extract<CellEvent, { event: T }> }> {
    const end = performance.now() + ms;
    for (;;) {
      const found = this.events.find(e => e.at >= since && e.event.event === name && match(e.event as Extract<CellEvent, { event: T }>));
      if (found) return found as { at: number; event: Extract<CellEvent, { event: T }> };
      if (performance.now() > end) throw new Error(`${this.name}: no ${name} within ${ms} ms; saw ${this.events.filter(e => e.at >= since).map(e => e.event.event).join(', ')}`);
      await new Promise(resolve => setTimeout(resolve, 5));
    }
  }
  /** Waits for `condition`, up to `ms`. */
  async when(what: string, condition: () => boolean, ms = 10_000): Promise<number> {
    const end = performance.now() + ms;
    while (!condition()) {
      if (performance.now() > end) throw new Error(`${this.name}: ${what} did not happen within ${ms} ms`);
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    return performance.now();
  }
  /** Plaintext kinds of the frames this member handed to the carrier after `since`. */
  sentKinds(since: number): string[] { return this.log.filter(l => l.at >= since && l.event.type === 'sent').map(l => (l.event as { kind: string }).kind); }
  close(): void { try { this.cell?.close(); } catch { /* closed */ } try { this.stream?.stop(); } catch { /* stopped */ } this.device.close(); }
}

/**
 * A home and two members of one account, both write-entitled to `listening.podcasts`. B holds the same owner key as A
 * (one person's two devices), so B can revoke A. The history is public, so a revoked A can still read its revocation.
 */
export async function world(host: BunRelayHost): Promise<{ relay: RelayHome; a: Member; b: Member; stop(): Promise<void> }> {
  const tag = crypto.randomUUID().slice(0, 8);
  const relay = await RelayHome.make(host, `https://home-0.test/v1/accounts/js06-${tag}`);
  // The relay runs on a test clock set by each request; keep it moving so its rate buckets refill and timers run.
  const clockTimer = setInterval(() => { void host.touchClock(relay.port); }, 20);
  const first = await Device.make({ namespaces: [NAMESPACE], history: 'public', homes: [{ endpoint: `${relay.base}/`, label: 'Relay', transport: relay.transport(),
    request: async account => { await relay.start(account, []); return relay.memberRequest(account); } }] });
  await first.session.create();
  first.session.stopSync();
  equal(first.session.phase.kind, 'ready', `A is ready: ${first.describe()}`);
  assert(await settle(first), () => first.describe());
  const second = await Device.make({ medium: authorityOnly(first.medium as MemoryMedium), owner: first.owner, namespaces: [NAMESPACE],
    homes: [{ endpoint: `${relay.base}/`, transport: relay.transport() }] });
  await second.session.restore();
  second.session.stopSync();
  await approveByScan(second.session, first.session);
  assert(await settle(first), () => first.describe());
  await untilApproved(second);
  assert(await settle(second), () => second.describe());
  const a = new Member('A', first, relay); const b = new Member('B', second, relay);
  return {
    relay, a, b,
    stop: async () => { clearInterval(clockTimer); a.close(); b.close(); },
  };
}

/** The `now-playing` anchor (sessions §S12). */
export interface Anchor { episode: string; show: string; positionMs: number; ratePermille: number; playing: boolean; at: number }
export const anchor = (a: Anchor): Uint8Array => new TextEncoder().encode(JSON.stringify(a));
export const readAnchor = (bytes: Uint8Array | undefined): Anchor | undefined => bytes ? JSON.parse(new TextDecoder().decode(bytes)) as Anchor : undefined;
/** A member's projected position (§S12): `offset` is the holder's clock minus this member's (0 for the holder itself). */
export const project = (a: Anchor, now: number, offset: number): number => a.playing ? a.positionMs + Math.floor(a.ratePermille * (now + offset - a.at) / 1000) : a.positionMs;

/** A fast policy for scenarios that wait out timeouts: the default with shorter timers. */
export function fastPolicy(): string {
  const p = JSON.parse(glue.session_default_policy()) as Record<string, unknown>;
  return JSON.stringify({ ...p, beatMs: 400, holderTimeoutMs: 1500, askTimeoutMs: 300, presenceTimeoutMs: 1500 });
}
