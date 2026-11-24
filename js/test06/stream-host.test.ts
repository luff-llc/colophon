// The stream host against the core's real `HomeStream` (made directly, no engine), with a fake socket, ticket
// transport and clock: every step kind, refusals and close codes, the polling fallback, session routing, and that no
// ticket leaves except in the socket URL.
import { beforeAll, describe, expect, test } from 'bun:test';
import { HomeStreamHost, type HostAccount, type StreamCell, type StreamHostEvent } from '../src/hosts/index.js';
import { glue, init } from '../src/session/index.js';
import { answer, Frames, ManualClock, settle, Sockets, ticket, TicketTransport } from './fakes.ts';

beforeAll(async () => { await init(); });

const BASE = 'https://home.test/v1/accounts/x';

function rig(options: { streamCall?: () => Promise<Uint8Array>; cursor?: string } = {}) {
  const clock = new ManualClock();
  const sockets = new Sockets();
  const transport = new TicketTransport();
  let seq = 5n;
  const passes: number[] = [];
  const account: HostAccount = {
    account: 'a'.repeat(64), member: 'm',
    engine: () => ({ head_seq: () => seq }) as unknown as glue.AccountEngine,
    streamCall: options.streamCall ?? (async () => new TextEncoder().encode('{"a call":1}')),
    exchange: async () => { passes.push(clock.mono); },
    signRaw: async () => new Uint8Array(64),
  };
  const cursors: (string | undefined)[] = [];
  const host = new HomeStreamHost({ account, home: 'h', transport, socket: sockets.factory, clock, saveCursor: c => { cursors.push(c); },
    client: new glue.HomeStream('h', BASE, glue.stream_default_config(), options.cursor) });
  const events: StreamHostEvent[] = [];
  host.on(e => events.push(e));
  const frames = new Frames();
  const kinds = (): glue.StreamEventKind[] => events.flatMap(e => e.type === 'event' ? [e.event.kind] : []);
  /** Mints, connects and says hello. */
  const live = async (): Promise<void> => {
    await settle();
    sockets.last.handlers.open();
    sockets.last.handlers.message(frames.hello());
    await settle();
  };
  return { clock, sockets, transport, account, host, events, frames, passes, cursors, kinds, live, setSeq: (s: bigint) => { seq = s; } };
}

describe('the stream host', () => {
  test('NeedTicketCall, Connect, Wake: mints, connects with the ticket, wakes a pass on the first hello', async () => {
    const r = rig();
    expect(r.host.polling).toBe(true);
    r.host.start();
    await settle();
    expect(r.transport.requests.length).toBe(1);
    const request = r.transport.requests[0]!;
    expect([request.method, request.url]).toEqual(['POST', `${BASE}/stream/ticket`]);
    expect(r.sockets.all.length).toBe(1);
    expect(r.sockets.last.url).toBe(`wss://home.test/v1/accounts/x/stream?ticket=${ticket}`);
    const connect = r.events.find(e => e.type === 'connect');
    expect(connect && connect.type === 'connect' && connect.url.includes(ticket)).toBe(false);
    r.sockets.last.handlers.open();
    r.sockets.last.handlers.message(r.frames.hello());
    await settle();
    expect(r.host.live).toBe(true);
    expect(r.host.polling).toBe(false);
    expect(r.kinds()).toContain(glue.StreamEventKind.Connected);
    // The first hello wakes a pass, coalesced over 250 ms; then `on_history`.
    expect(r.passes.length).toBe(0);
    await r.clock.advance(250);
    expect(r.passes.length).toBe(1);
    expect(r.events.some(e => e.type === 'pass' && e.seq === 5n)).toBe(true);
    // No event, status or log line carries the ticket.
    expect(JSON.stringify(r.events, (_, v) => typeof v === 'bigint' ? String(v) : v)).not.toContain(ticket);
    r.host.stop();
  });

  test('Send: an application ping after pingMs of silence; Close 1001 after idleMs, then backoff and a new ticket', async () => {
    const r = rig();
    r.host.start();
    await r.live();
    await r.clock.advance(20_000);
    expect(r.sockets.last.sent.some(t => JSON.parse(t).type === 'ping')).toBe(true);
    await r.clock.advance(40_001);
    expect(r.sockets.last.closedWith).toBe(1001);
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Backoff);
    expect(r.host.polling).toBe(true);
    // Sleep until the backoff ends, then mint again (the core's schedule, not the host's).
    const until = Number(r.host.status.until);
    expect(until).toBeGreaterThan(r.clock.mono);
    await r.clock.advance(until - r.clock.mono);
    expect(r.transport.requests.length).toBe(2);
    expect(r.sockets.all.length).toBe(2);
    r.host.stop();
  });

  test('a gap in frame numbers closes with 1002 (a protocol violation)', async () => {
    const r = rig();
    r.host.start();
    await r.live();
    r.sockets.last.handlers.message(JSON.stringify({ type: 'head', home: 'h', seq: 9, digest: 'd', n: 5 }));
    await settle();
    expect(r.kinds()).toContain(glue.StreamEventKind.Violation);
    expect(r.sockets.last.closedWith).toBe(1002);
    r.host.stop();
  });

  test('close codes: 1008 blocks until the history changes; 1012 and 1000 back off and reconnect', async () => {
    const r = rig();
    r.host.start();
    await r.live();
    r.sockets.last.handlers.closed(1008);
    await settle();
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Blocked);
    expect(r.host.status.blocked).toBe(glue.StreamBlockedKind.AccessEnded);
    expect(r.host.polling).toBe(true);
    await r.clock.advance(600_000);
    expect(r.transport.requests.length).toBe(1);
    // The same history: still blocked. A changed one: tried again.
    r.host.historyChanged();
    await settle();
    expect(r.transport.requests.length).toBe(1);
    r.setSeq(6n);
    r.host.historyChanged();
    await settle();
    expect(r.transport.requests.length).toBe(2);
    await r.live();
    r.sockets.last.handlers.closed(1012);
    await settle();
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Backoff);
    await r.clock.advance(Number(r.host.status.until) - r.clock.mono);
    expect(r.transport.requests.length).toBe(3);
    await r.live();
    r.sockets.last.handlers.closed(1000);
    await settle();
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Backoff);
    r.host.stop();
  });

  test('a transport failure (no close code) backs off', async () => {
    const r = rig();
    r.host.start();
    await settle();
    r.sockets.last.handlers.closed(undefined);
    await settle();
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Backoff);
    expect(r.kinds()).toContain(glue.StreamEventKind.Down);
    r.host.stop();
  });

  test('refusals: an upgrade refused 403 refused:revoked ends access; 429 backs off at least Retry-After', async () => {
    const r = rig();
    r.host.start();
    await settle();
    r.sockets.last.handlers.refused(answer(429, { result: 'refused:rateLimited' }, [{ name: 'retry-after', value: '30' }]));
    await settle();
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Backoff);
    expect(Number(r.host.status.until) - r.clock.mono).toBeGreaterThanOrEqual(30_000);
    await r.clock.advance(Number(r.host.status.until) - r.clock.mono);
    r.sockets.last.handlers.refused(answer(403, { result: 'refused:revoked' }));
    await settle();
    expect(r.host.status.blocked).toBe(glue.StreamBlockedKind.AccessEnded);
    r.host.stop();
  });

  test('ticket answers: 404 means unsupported (keep polling); 403 is refused; a failed call backs off', async () => {
    const unsupported = rig();
    unsupported.transport.answer = () => answer(404, {});
    unsupported.host.start();
    await settle();
    expect(unsupported.host.status.blocked).toBe(glue.StreamBlockedKind.Unsupported);
    expect(unsupported.host.polling).toBe(true);
    expect(unsupported.sockets.all.length).toBe(0);
    unsupported.host.stop();

    const refused = rig();
    refused.transport.answer = () => answer(403, { result: 'refused:revoked' });
    refused.host.start();
    await settle();
    expect(refused.host.status.blocked).toBe(glue.StreamBlockedKind.Refused);
    expect(refused.host.status.refused).toBe('refused:revoked');
    refused.host.stop();

    const failing = rig({ streamCall: async () => { throw Object.assign(new Error('no fresh head'), { name: 'AccountFault', kind: 'Unavailable', code: 'unavailable' }); } });
    failing.host.start();
    await settle();
    expect(failing.events.some(e => e.type === 'ticketCallFailed' && e.code === 'unavailable')).toBe(true);
    expect(failing.host.status.kind).toBe(glue.StreamStatusKind.Backoff);
    expect(failing.transport.requests.length).toBe(0);
    failing.host.stop();
  });

  test('NeedTicketCall repeats while the call is signed: the host signs once and waits', async () => {
    let calls = 0; let sign: (call: Uint8Array) => void = () => {};
    const r = rig({ streamCall: () => { calls++; return new Promise<Uint8Array>(resolve => { sign = resolve; }); } });
    r.host.start();
    await settle();
    await r.clock.advance(5_000);
    expect(calls).toBe(1);
    expect(r.transport.requests.length).toBe(0);
    sign(new TextEncoder().encode('{"a call":1}'));
    await settle();
    expect(calls).toBe(1);
    expect(r.transport.requests.length).toBe(1);
    expect(r.sockets.all.length).toBe(1);
    r.host.stop();
  });

  test('Waiting arms the timer from wake_at: a call never signed counts as failed after the core\'s timeout', async () => {
    let calls = 0;
    const r = rig({ streamCall: () => { calls++; return new Promise<Uint8Array>(() => {}); } });
    r.host.start();
    await settle();
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Connecting);
    await r.clock.advance(59_000);
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Connecting);
    await r.clock.advance(1_100);
    expect(calls).toBe(1);
    expect(r.host.status.kind).toBe(glue.StreamStatusKind.Backoff);
    r.host.stop();
  });

  test('stop from a listener: no ticket-bearing socket is left open, kept or opened afterwards', async () => {
    const r = rig();
    r.host.on(e => { if (e.type === 'connect') r.host.stop(); });
    r.host.start();
    await settle();
    expect(r.sockets.all.length).toBe(1);
    expect(r.sockets.last.closedWith).toBe(1000);
    await r.clock.advance(120_000);
    expect(r.sockets.all.length).toBe(1);

    // Stopped from inside the socket factory's own callback, before the factory returned.
    const s = rig();
    const inner = s.sockets.factory;
    let made: { closedWith?: number } | undefined;
    const host = new HomeStreamHost({ account: s.account, home: 'h', transport: s.transport, clock: s.clock,
      socket: (url, handlers) => { const socket = inner(url, handlers); made = socket as unknown as { closedWith?: number }; host.stop(); return socket; },
      client: new glue.HomeStream('h', BASE, glue.stream_default_config(), undefined) });
    const events: string[] = [];
    host.on(e => events.push(e.type));
    host.start();
    await settle();
    expect(made?.closedWith).toBe(1000);
    expect(events).not.toContain('connect');
  });

  test('listeners that call back into the host from every event do not break the loop', async () => {
    const r = rig();
    r.host.on(() => { void r.host.status; void r.host.polling; r.host.historyChanged(); });
    r.host.start();
    await r.live();
    await r.clock.advance(250);
    expect(r.host.live).toBe(true);
    expect(r.passes.length).toBeGreaterThan(0);
    r.host.stop();
  });

  test('cursors are saved and presented on reconnect', async () => {
    const r = rig({ cursor: 'i1.3' });
    r.host.start();
    await settle();
    expect(r.sockets.last.url).toContain('after=i1.3');
    r.sockets.last.handlers.open();
    r.sockets.last.handlers.message(r.frames.hello());
    r.sockets.last.handlers.message(r.frames.frame({ type: 'change', cursor: 'i1.4', entry: { path: 'records/x', size: 1, sha256: '0'.repeat(64) } }));
    await settle();
    expect(r.cursors).toContain('i1.4');
    expect(r.host.cursor).toBe('i1.4');
    r.host.stop();
  });

  test('cells: subscribed when live, link up on the ack, frames routed as their own text, link down when the socket ends', async () => {
    const r = rig();
    const log: string[] = [];
    const delivered: string[] = [];
    const cell: StreamCell = { namespace: 'listening.podcasts', cell: 'now-playing', deliver: f => { delivered.push(f); }, linkUp: () => log.push('up'), linkDown: () => log.push('down') };
    r.host.attach(cell);
    expect(r.host.sendSession('{}')).toBe(false);
    r.host.start();
    await r.live();
    const subscribe = r.sockets.last.sent.map(t => JSON.parse(t)).find(m => m.type === 'subscribe');
    expect(subscribe).toMatchObject({ type: 'subscribe', namespace: 'listening.podcasts', cell: 'now-playing' });
    expect(log).toEqual([]);
    r.sockets.last.handlers.message(r.frames.frame({ type: 'subscribed', namespace: 'listening.podcasts', cell: 'now-playing' }));
    await settle();
    expect(log).toEqual(['up']);
    // The frame inside the message, character for character, spacing and all.
    const frame = '{"account":"' + 'a'.repeat(64) + '","cell":"now-playing","namespace":"listening.podcasts","n":1}';
    r.sockets.last.handlers.message(`{"type":"session","frame":${frame},"retained":true,"n":3}`);
    await settle();
    expect(delivered).toEqual([frame]);
    // A frame for a cell nobody attached is reported, not delivered.
    r.sockets.last.handlers.message(r.frames.frame({ type: 'session', frame: { namespace: 'listening.podcasts', cell: 'other' } }).replace('"n":3', '"n":4'));
    await settle();
    expect(r.events.some(e => e.type === 'unrouted')).toBe(true);
    expect(r.host.sendSession(frame)).toBe(true);
    const carried = r.sockets.last.sent[r.sockets.last.sent.length - 1]!;
    expect(carried).toBe(`{"type":"session","frame":${frame}}`);
    r.sockets.last.handlers.closed(1011);
    await settle();
    expect(log).toEqual(['up', 'down']);
    expect(r.host.sendSession(frame)).toBe(false);
    r.host.stop();
  });

  test('a pass woken during a pass runs once more after it', async () => {
    const r = rig();
    let release: () => void = () => {};
    let running = 0;
    r.account.exchange = () => { running++; return new Promise<void>(resolve => { release = () => { running--; resolve(); }; }); };
    r.host.start();
    await r.live();
    await r.clock.advance(250);
    expect(running).toBe(1);
    r.sockets.last.handlers.message(r.frames.frame({ type: 'head', home: 'h', seq: 6, digest: 'd' }));
    await r.clock.advance(250);
    expect(running).toBe(1);
    release();
    await settle();
    expect(running).toBe(1);
    release();
    await settle();
    expect(r.events.filter(e => e.type === 'pass').length).toBe(2);
    r.host.stop();
  });
});
