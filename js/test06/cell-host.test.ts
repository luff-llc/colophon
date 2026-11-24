// The cell host's reference loop against real endpoints of two members of a local account, over an in-memory carrier,
// with a manual clock and stores whose writes the test completes: effects in order, the acknowledgement only after the
// durable write, inputs kept and commands held while a write is in progress, a failed write retried, a stale view
// replaced, a backwards clock recovered from the stored claim, and frames handed on as their own text.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { accountOf, CellHostError, sessionFrameText, SessionCellHost, type CellCarrier, type CellHostEvent, type CellHostOptions, type StreamCell } from '../src/hosts/index.js';
import { init } from '../src/session/index.js';
import { approveByScan, Device } from '../test05/support.ts';
import { ManualClock, settle, TestStore } from './fakes.ts';

const NS = 'listening.podcasts';
const CELL = 'now-playing';

/** Every frame one cell sends reaches every other attached cell, in order, a moment later. */
class LoopCarrier implements CellCarrier {
  readonly cells = new Set<StreamCell>();
  readonly carried: { from: StreamCell; frame: string }[] = [];
  paused = false;
  private backlog: (() => void)[] = [];
  private sender: StreamCell | undefined;
  /** A carrier view for one cell, so the carrier knows who sent each frame. */
  for(): CellCarrier {
    let mine: StreamCell | undefined;
    return {
      attach: cell => { mine = cell; this.cells.add(cell); queueMicrotask(() => cell.linkUp()); },
      detach: cell => { this.cells.delete(cell); },
      sendSession: frame => { this.sender = mine; this.send(frame); return true; },
    };
  }
  attach(cell: StreamCell): void { this.cells.add(cell); }
  detach(cell: StreamCell): void { this.cells.delete(cell); }
  sendSession(frame: string): boolean { this.send(frame); return true; }
  private send(frame: string): void {
    const from = this.sender as StreamCell;
    this.carried.push({ from, frame });
    const deliver = (): void => { for (const c of [...this.cells]) if (c !== from) c.deliver(frame); };
    if (this.paused) this.backlog.push(deliver); else queueMicrotask(deliver);
  }
  resume(): void { this.paused = false; for (const d of this.backlog.splice(0)) d(); }
}

let first: Device; let second: Device;
beforeAll(async () => {
  await init();
  first = await Device.make({ namespaces: [NS] });
  await first.session.create();
  second = await Device.make({ medium: first.medium, namespaces: [NS] });
  await second.session.restore();
  await approveByScan(second.session, first.session);
  await second.session.refresh();
  if (second.session.phase.kind !== 'ready') throw new Error(second.describe());
});
afterAll(() => { first.close(); second.close(); });

async function pair(clock = new ManualClock(), extra: Partial<CellHostOptions> = {}) {
  const carrier = new LoopCarrier();
  const stores = { a: new TestStore(undefined, (run, ms) => { clock.setTimer(run, ms); }), b: new TestStore(undefined, (run, ms) => { clock.setTimer(run, ms); }) };
  const logs = { a: [] as CellHostEvent[], b: [] as CellHostEvent[] };
  const open = (device: Device, which: 'a' | 'b'): Promise<SessionCellHost> => SessionCellHost.open({ account: accountOf(device.session), carrier: carrier.for(), namespace: NS, cell: CELL,
    store: stores[which], clock, ...(which === 'a' ? extra : {}) }, e => logs[which].push(e));
  const a = await open(first, 'a'); const b = await open(second, 'b');
  await settle();
  return { clock, carrier, stores, logs, a, b, open, close: () => { a.close(); b.close(); } };
}
const shape = (e: CellHostEvent): string => e.type === 'session' ? `event:${e.event.event}` : e.type === 'sent' ? `sent:${e.kind}` : e.type === 'persist' ? `persist:${e.phase}` : e.type;

describe('the cell host', () => {
  test('a Persist holds back what follows it until its durable write completes; then it is acknowledged, in order', async () => {
    const r = await pair();
    r.stores.a.hold = true;
    const mark = r.logs.a.length;
    await r.a.command('take', { command: 'take', state: btoa('anchor-0') });
    await settle();
    expect(r.logs.a.slice(mark).map(shape)).toEqual(['persist:started']);
    expect(r.stores.a.heldWrites).toBe(1);
    expect(r.a.current!.awaiting_persist()).toBeDefined();
    r.stores.a.release();
    await settle();
    expect(r.logs.a.slice(mark).map(shape).filter(s => s !== 'event:holderChanged').slice(0, 5)).toEqual(['persist:started', 'persist:stored', 'sent:take', 'sent:state', 'event:becameHolder']);
    expect(r.a.current!.awaiting_persist()).toBeUndefined();
    expect(r.a.storedClaim).toBe(r.stores.a.value);
    expect(r.logs.b.some(e => e.type === 'session' && e.event.event === 'holderChanged')).toBe(true);
    r.close();
  });

  test('while a write is in progress, frames and a tick are kept and a command is held; all run after it, in order', async () => {
    const r = await pair();
    r.stores.a.hold = true;
    await r.a.command('take', { command: 'take', state: null });
    // A frame from B arrives meanwhile, a tick falls due, and the app publishes.
    await r.b.command('presence', { command: 'presence', payload: btoa('{"label":"Kitchen"}') });
    await settle();
    const publishing = r.a.command('publish', { command: 'publish', id: 'AAAAAAAAAAAAAAAAAAAAAA', payload: btoa('anchor-1') });
    await settle();
    await r.clock.advance(6_000);
    const kept = r.logs.a.filter(e => e.type === 'queued').map(e => (e as { input: string }).input);
    expect(kept).toContain('frame');
    expect(kept.filter(k => k === 'tick').length).toBeLessThanOrEqual(1);
    expect(r.logs.a.some(e => e.type === 'commandHeld' && e.command === 'publish')).toBe(true);
    expect(r.logs.a.some(e => e.type === 'sent' && e.kind === 'msg')).toBe(false);
    const mark = r.logs.a.length;
    r.stores.a.release();
    await publishing;
    await settle();
    const after = r.logs.a.slice(mark).map(shape);
    expect(after.indexOf('persist:stored')).toBe(0);
    expect(after.indexOf('event:becameHolder')).toBeLessThan(after.indexOf('event:presenceChanged'));
    expect(after.indexOf('event:presenceChanged')).toBeLessThan(after.indexOf('sent:msg'));
    expect(r.logs.a.filter(e => e.type === 'drop')).toEqual([]);
    r.close();
  });

  test('a failed write is retried and never acknowledged until it succeeds', async () => {
    const r = await pair();
    r.stores.a.failures = 2;
    await r.a.command('take', { command: 'take', state: null });
    await settle();
    expect(r.logs.a.filter(e => e.type === 'persist' && e.phase === 'failed').length).toBe(1);
    expect(r.logs.a.some(e => e.type === 'sent' && e.kind === 'take')).toBe(false);
    await r.clock.advance(250);
    expect(r.logs.a.filter(e => e.type === 'persist' && e.phase === 'failed').length).toBe(2);
    expect(r.a.current!.awaiting_persist()).toBeDefined();
    await r.clock.advance(250);
    expect(r.logs.a.filter(e => e.type === 'persist' && e.phase === 'stored').length).toBe(1);
    expect(r.logs.a.some(e => e.type === 'sent' && e.kind === 'take')).toBe(true);
    expect(r.stores.a.writes.length).toBe(3);
    r.close();
  });

  test('a stale view is replaced (set_account) and the input runs', async () => {
    const r = await pair();
    // A third member is approved on A's device: A's engine has a new authority head.
    const third = await Device.make({ medium: first.medium, namespaces: [NS] });
    await third.session.restore();
    await approveByScan(third.session, first.session);
    const mark = r.logs.a.length;
    await r.b.command('presence', { command: 'presence', payload: btoa('{"label":"Car"}') });
    await settle();
    const after = r.logs.a.slice(mark).map(shape);
    expect(after.indexOf('stale')).toBeGreaterThanOrEqual(0);
    expect(after.indexOf('account')).toBeGreaterThan(after.indexOf('stale'));
    expect(after).toContain('event:presenceChanged');
    expect(r.a.stats.stale).toBe(1);
    third.close();
    r.close();
  });

  test('a clock that goes back rebuilds the endpoint from the stored claim; a restarted holder is gated', async () => {
    const r = await pair();
    await r.a.command('take', { command: 'take', state: btoa('anchor-0') });
    await settle();
    expect(r.a.current!.is_holder()).toBe(true);
    const key = r.a.current!.key_id();
    r.clock.jump(r.clock.mono - 5_000);
    await r.b.command('presence', { command: 'presence', payload: btoa('{}') });
    await new Promise(resolve => setTimeout(resolve, 100));
    await settle();
    expect(r.logs.a.some(e => e.type === 'rebuilt' && e.reason === 'clockBackwards')).toBe(true);
    expect(r.a.current!.key_id()).not.toBe(key);
    expect(r.a.current!.joined()).toBe(true);
    expect(JSON.parse(r.a.current!.view_json()).gated).toBe(true);
    // It waits out askTimeoutMs, then retakes.
    await r.clock.advance(2_000);
    expect(JSON.parse(r.a.current!.view_json()).gated).toBe(false);
    expect(r.a.current!.is_holder()).toBe(true);
    r.close();
  });

  test('frames reach the endpoint as the text the carrier delivered; a re-serialised frame would differ and is refused', async () => {
    const r = await pair();
    await r.a.command('take', { command: 'take', state: btoa('anchor-0') });
    await settle();
    const sent = r.carrier.carried.filter(c => c.from === r.a).map(c => c.frame);
    expect(sent.length).toBeGreaterThan(0);
    const frame = sent[sent.length - 1]!;
    // Out of a home message, wherever `frame` sits among the other members.
    expect(sessionFrameText(`{"type":"session","frame":${frame},"retained":true}`)).toBe(frame);
    expect(sessionFrameText(`{"n":7, "type":"session", "frame" : ${frame} }`)).toBe(frame);
    expect(sessionFrameText(`{"type":"session","frame":${frame},"frame":${frame}}`)).toBeUndefined();
    expect(sessionFrameText(`{"type":"session"}`)).toBeUndefined();
    // A frame whose text is not canonical (an escape a JSON parser decodes): re-serialising would hand the codec other
    // bytes than were carried, and would make it canonical. The host hands on the carried text; the codec refuses it.
    const escaped = frame.replace('"cell":"now-playing"', '"cell":"now\\u002dplaying"');
    expect(escaped).not.toBe(frame);
    const message = `{"type":"session","frame":${escaped}}`;
    expect(sessionFrameText(message)).toBe(escaped);
    expect(JSON.stringify((JSON.parse(message) as { frame: unknown }).frame)).toBe(frame);
    const drops = r.b.stats.drops;
    r.b.deliver(sessionFrameText(message)!);
    expect(r.b.stats.drops).toBe(drops + 1);
    r.close();
  });

  test('listeners that call back into the host from every event never re-enter the endpoint', async () => {
    const r = await pair();
    let lastFrame: string | undefined;
    let calls = 0;
    r.a.on(e => {
      // Everything a listener can do, synchronously, from every event: each becomes a later job.
      calls++;
      if (e.type === 'sent') lastFrame = e.frame;
      r.a.accountChanged();
      r.a.linkUp();
      if (lastFrame && calls < 200) r.b.deliver(lastFrame);
      if (calls < 20) void r.a.command('presence', { command: 'presence', payload: btoa('{}') }).catch(() => {});
      if (e.type === 'persist' && e.phase === 'started') {
        // A backwards clock and an input while the write is under way: the rebuild waits for that write.
        r.clock.jump(r.clock.mono - 1_000);
        r.a.deliver(lastFrame ?? '{}');
      }
    });
    r.stores.a.hold = true;
    await r.a.command('take', { command: 'take', state: btoa('anchor-0') });
    await settle();
    expect(r.a.writePending).toBe(true);
    expect(r.logs.a.some(e => e.type === 'rebuilt')).toBe(true);
    // Rebuilt only once the write completes, and from the claim it stored.
    expect(r.a.current).toBeUndefined();
    r.stores.a.release();
    await new Promise(resolve => setTimeout(resolve, 100));
    await settle();
    expect(r.a.state).toBe('open');
    expect(JSON.parse(r.a.storedClaim!).claim.holder).toBe(first.session.memberId);
    expect(JSON.parse(r.a.current!.claim_json()!).holder).toBe(first.session.memberId);
    expect(r.logs.a.filter(e => e.type === 'error')).toEqual([]);
    r.close();
  });

  test('a delegation that cannot be signed: open fails, and nothing stays attached or allocated', async () => {
    const carrier = new LoopCarrier();
    const account = { ...accountOf(first.session), signRaw: async () => { throw new Error('the key is unavailable'); } };
    let failed: unknown;
    try { await SessionCellHost.open({ account, carrier, namespace: NS, cell: CELL, store: new TestStore(), clock: new ManualClock() }); } catch (error) { failed = error; }
    expect(failed).toBeInstanceOf(Error);
    expect(carrier.cells.size).toBe(0);
  });

  test('a rebuild that fails leaves the cell failed: held and new commands are refused, not left waiting', async () => {
    const clock = new ManualClock();
    let signing = true;
    const r = await pair(clock);
    const real = accountOf(first.session);
    // The next delegation (the rebuild's) cannot be signed.
    (r.a as unknown as { account: typeof real }).account = { ...real, signRaw: async body => { if (signing) throw new Error('the key is unavailable'); return real.signRaw(body); } };
    r.clock.jump(r.clock.mono - 1_000);
    const held = r.a.command('presence', { command: 'presence', payload: btoa('{}') }).then(() => undefined, (error: CellHostError) => error.code);
    await new Promise(resolve => setTimeout(resolve, 50));
    await settle();
    expect(r.logs.a.some(e => e.type === 'failed' && e.reason === 'rebuild')).toBe(true);
    expect(r.a.state).toBe('failed');
    expect(await held).toBe('failed');
    let code: string | undefined;
    try { await r.a.command('ask', { command: 'ask' }); } catch (error) { code = (error as CellHostError).code; }
    expect(code).toBe('failed');
    expect(r.carrier.cells.has(r.a)).toBe(false);
    signing = false;
    r.close();
  });

  test('a store that keeps failing fails the cell: it stops acting and says so', async () => {
    const r = await pair(new ManualClock(), { persistAttempts: 3 });
    r.stores.a.failures = 1_000;
    await r.a.command('take', { command: 'take', state: null });
    const waiting = r.a.command('publish', { command: 'publish', id: 'AAAAAAAAAAAAAAAAAAAAAA', payload: btoa('x') }).then(() => undefined, (error: CellHostError) => error.code);
    await settle();
    await r.clock.advance(250);
    await r.clock.advance(250);
    expect(r.logs.a.filter(e => e.type === 'persist' && e.phase === 'failed').length).toBe(3);
    expect(r.logs.a.some(e => e.type === 'failed' && e.reason === 'store')).toBe(true);
    expect(r.logs.a.some(e => e.type === 'sent' && e.kind === 'take')).toBe(false);
    expect(await waiting).toBe('failed');
    expect(r.a.current).toBeUndefined();
    r.close();
  });

  test('command admission is bounded and keeps the order of what it accepted', async () => {
    const r = await pair(new ManualClock(), { maxCommands: 2 });
    r.stores.a.hold = true;
    await r.a.command('take', { command: 'take', state: null });
    const one = r.a.command('publish', { command: 'publish', id: 'AAAAAAAAAAAAAAAAAAAAAA', payload: btoa('1') });
    const two = r.a.command('publish', { command: 'publish', id: 'AQAAAAAAAAAAAAAAAAAAAA', payload: btoa('2') });
    let code: string | undefined;
    try { await r.a.command('publish', { command: 'publish', id: 'AgAAAAAAAAAAAAAAAAAAAA', payload: btoa('3') }); } catch (error) { code = (error as CellHostError).code; }
    expect(code).toBe('commandQueueFull');
    r.stores.a.release();
    await one; await two;
    await settle();
    const messages = r.logs.a.filter(e => e.type === 'session' && e.event.event === 'message').map(e => (e as unknown as { event: { payload: string } }).event.payload);
    expect(messages).toEqual([btoa('1'), btoa('2')]);
    r.close();
  });

  // The receiver's side of revocation, at unit level: the end-to-end test shows the same over the home's wire.
  test('after a new head that removes a member, its frames are dropped and change nothing', async () => {
    const r = await pair();
    const third = await Device.make({ medium: first.medium, namespaces: [NS] });
    await third.session.restore();
    await approveByScan(third.session, first.session);
    await third.session.refresh();
    await second.session.refresh();
    const thirdHost = await SessionCellHost.open({ account: accountOf(third.session), carrier: r.carrier.for(), namespace: NS, cell: CELL, store: new TestStore(), clock: r.clock });
    await settle();
    await first.session.revoke(third.session.memberId!);
    await second.session.refresh();
    r.b.accountChanged();
    await settle();
    const drops = r.b.stats.drops;
    const view = r.b.current!.view_json();
    await thirdHost.command('presence', { command: 'presence', payload: btoa('{"label":"Old phone"}') });
    await settle();
    expect(r.b.stats.drops).toBeGreaterThan(drops);
    expect(r.b.current!.view_json()).toBe(view);
    expect(r.logs.b.some(e => e.type === 'session' && e.event.event === 'presenceChanged' && e.event.member === third.session.memberId)).toBe(false);
    thirdHost.close(); third.close();
    r.close();
  });
});

