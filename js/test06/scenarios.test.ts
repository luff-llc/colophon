// The session rules that matter when devices come and go, end to end through the JavaScript hosts and a real home: a
// holder restarted from what it stored, a holder that goes offline past the holder timeout and returns, a pass while
// both stores are slow and frames keep arriving, and a member revoked mid-session. A fast policy (beat 400 ms, holder
// timeout 1.5 s, ask timeout 300 ms) keeps the waits short; the rules are the same as with the defaults.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { glue, init } from '../src/session/index.js';
import { settle } from '../test05/journey.ts';
import { BunRelayHost } from '../test05/relay-bun.ts';
import { anchor, fastPolicy, project, readAnchor, world, type Member } from './world.ts';

const host = new BunRelayHost();
beforeAll(async () => { BunRelayHost.module(); await init(); });
afterAll(async () => { await host.stopAll(); });

const HOLDER_FRAMES = ['state', 'beat', 'msg', 'refuse', 'pass', 'decline'];
const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));
const holderFramesSent = (m: Member, from: number, to = Infinity): string[] => m.log.filter(l => l.at >= from && l.at < to && l.event.type === 'sent'
  && HOLDER_FRAMES.includes(l.event.kind)).map(l => (l.event as { kind: string }).kind);

test('restart, offline past the timeout, a slow store during a pass, and revocation, over a real home', async () => {
  const w = await world(host);
  const { a, b } = w;
  const policy = fastPolicy();
  const ask = 300;
  try {
    a.startStream(); b.startStream();
    await a.when('A\'s stream is live', () => a.stream.live);
    await b.when('B\'s stream is live', () => b.stream.live);
    await a.join(policy); await b.join(policy);

    // A plays.
    const first = { episode: 'ep-2', show: 'show-1', positionMs: 60_000, ratePermille: 1000, playing: true, at: Math.floor(performance.now()) };
    a.appState = anchor(first);
    await a.cell.take(a.appState);
    await a.until('becameHolder');
    await b.until('holderChanged', 0, 10_000, e => e.claim?.holder === a.id);

    // 1. A restarts from its stored claim (a new process: new endpoint, new session key, new randomness). It does not
    //    send as holder at once: it holds locally, gated, waits out askTimeoutMs, then retakes with the state its
    //    application kept (§S6).
    const stored = a.store.value;
    expect(stored && JSON.parse(stored).claim.holder).toBe(a.id);
    a.cell.close();
    const restarted = performance.now();
    await a.join(policy);
    expect(a.cell.state.gated).toBe(true);
    const retook = await a.until('becameHolder', restarted, 10_000);
    expect(retook.event.via).toBe('take');
    expect(a.cell.state.gated).toBe(false);
    expect(retook.at - restarted).toBeGreaterThanOrEqual(ask);
    // Its first frames are a hello; the first holder frame follows its take.
    const takeSent = a.log.find(l => l.at >= restarted && l.event.type === 'sent' && l.event.kind === 'take')!;
    expect(takeSent.at - restarted).toBeGreaterThanOrEqual(ask);
    expect(holderFramesSent(a, restarted, takeSent.at)).toEqual([]);
    expect(readAnchor(retook.event.snapshot)).toEqual(first);
    await b.until('holderChanged', restarted, 10_000, e => e.claim?.holder === a.id && e.claim.term > 1);
    console.log(`restart: A rejoined from its stored claim and retook after ${(retook.at - restarted).toFixed(0)} ms (askTimeoutMs ${ask})`);

    // 2. A goes offline while holder, past the holder timeout. B sees the holder lapse and takes; A returns, says it
    //    was out of contact, and yields to B's greater claim without acting as holder.
    const offline = performance.now();
    a.network.down();
    const lapsed = await b.until('holderLapsed', offline, 10_000, e => e.holder === a.id);
    expect(lapsed.at - offline).toBeGreaterThanOrEqual(1400);
    const pressed = performance.now();
    await b.cell.take();
    const tookOver = await b.until('becameHolder', pressed);
    console.log(`lapse: B saw A lapse ${(lapsed.at - offline).toFixed(0)} ms after A went offline; B's take -> B holding ${(tookOver.at - pressed).toFixed(1)} ms`);
    expect(tookOver.event.via).toBe('take');
    expect(readAnchor(tookOver.event.snapshot)).toEqual(first);
    // A, cut off, still acts locally as holder (sessions §S0 rule 1).
    expect(a.cell.state.isHolder).toBe(true);
    await sleep(500);
    a.network.restore();
    const back = performance.now();
    a.stream.retryNow();
    const yielded = await a.until('yielded', back, 15_000);
    expect(holderFramesSent(a, back)).toEqual([]);
    expect(a.cell.state.isHolder).toBe(false);
    expect(a.cell.state.holder).toBe(b.id);
    const hellos = a.log.filter(l => l.at >= back && l.event.type === 'sent' && l.event.kind === 'hello');
    expect(hellos.length).toBeGreaterThan(0);
    // What A held reaches B's application (G11).
    await b.until('displaced', back, 10_000, e => e.from === a.id);
    console.log(`return: A yielded ${(yielded.at - back).toFixed(0)} ms after its network came back, sending no holder frame`);

    // 3. A pass while both stores take 500 ms per write, with frames arriving during the writes. B's application
    //    passes to A when A asks; nothing a Persist holds back is released before its write completes.
    a.store.delayMs = 500; b.store.delayMs = 500;
    b.appState = anchor({ ...first, positionMs: 90_000, at: Math.floor(performance.now()) });
    let passed = 0;
    b.cell.events(event => {
      if (event.event !== 'askReceived' || !b.cell.state.isHolder || passed > 0) return;
      passed = performance.now();
      const playing = readAnchor(b.appState)!;
      const now = Math.floor(performance.now());
      b.appState = anchor({ ...playing, positionMs: project(playing, now, 0), playing: false, at: now });
      void b.cell.pass(event.from, b.appState);
      // A command while that pass is being written waits for the write (session:persistPending).
      void b.cell.presence(new TextEncoder().encode('{"label":"Kitchen","playing":false}'));
    });
    const asked = performance.now();
    await a.cell.ask();
    const gotIt = await a.until('becameHolder', asked, 15_000);
    expect(gotIt.event.via).toBe('pass');
    expect(gotIt.event.snapshot).toEqual(b.appState!);
    const bPersist = b.log.find(l => l.at >= passed && l.event.type === 'persist' && l.event.phase === 'started')!;
    const bStored = b.log.find(l => l.at >= bPersist.at && l.event.type === 'persist' && l.event.phase === 'stored')!;
    const bPassSent = b.log.find(l => l.at >= passed && l.event.type === 'sent' && l.event.kind === 'pass')!;
    expect(bStored.at - bPersist.at).toBeGreaterThanOrEqual(490);
    expect(bPassSent.at).toBeGreaterThanOrEqual(bStored.at);
    const aPersist = a.log.find(l => l.at >= asked && l.event.type === 'persist' && l.event.phase === 'started')!;
    const aStored = a.log.find(l => l.at >= aPersist.at && l.event.type === 'persist' && l.event.phase === 'stored')!;
    const aAck = a.log.find(l => l.at >= aPersist.at && l.event.type === 'sent' && l.event.kind === 'ack')!;
    expect(aAck.at).toBeGreaterThanOrEqual(aStored.at);
    const kept = (m: Member, from: number, to: number): string => {
      const q = m.log.filter(l => l.at >= from && l.at <= to && l.event.type === 'queued').map(l => (l.event as { input: string }).input);
      return ['frame', 'tick', 'link'].map(k => `${q.filter(x => x === k).length} ${k}`).join(', ');
    };
    const framesKept = (m: Member, from: number, to: number): number => m.log.filter(l => l.at >= from && l.at <= to && l.event.type === 'queued' && l.event.input === 'frame').length;
    const queuedA = framesKept(a, aPersist.at, aStored.at); const queuedB = framesKept(b, bPersist.at, bStored.at);
    const ticksKept = [...a.log, ...b.log].filter(l => l.event.type === 'queued' && l.event.input === 'tick' && l.at >= asked).length;
    expect(ticksKept).toBeLessThan(10);
    const held = b.log.filter(l => l.at >= passed && l.event.type === 'commandHeld').length;
    console.log(`slow store: B's pass waited ${(bPassSent.at - bPersist.at).toFixed(0)} ms for its write; inputs kept behind the writes: A ${kept(a, aPersist.at, aStored.at)}; B ${kept(b, bPersist.at, bStored.at)}; commands held: ${held}; A holding ${(gotIt.at - asked).toFixed(0)} ms after asking`);
    expect(queuedA + queuedB).toBeGreaterThan(0);
    expect(held).toBeGreaterThan(0);
    await b.until('presenceChanged', passed, 10_000).catch(() => undefined);
    expect([...a.log, ...b.log].filter(l => l.event.type === 'drop' && l.event.reason === 'queueFull')).toEqual([]);
    expect(b.cell.state.isHolder).toBe(false);
    a.store.delayMs = 0; b.store.delayMs = 0;
    await sleep(300);

    // 4. B revokes A mid-session (A holds the cell), by a real authority change on B's device. Nothing is injected:
    //    a. B holds the new head before the home does. A, which has not seen it, still sends over its socket; the home
    //       still carries the frame (it does not hold the revocation yet), and B's endpoint, under the new head, drops
    //       it on arrival, changing nothing.
    //    b. Once the home holds the revocation it ends A's stream: A's frames no longer leave the device.
    //    c. A's own poll brings the revocation in: its endpoint reports the stale view and, with the new one
    //       installed, A is no longer entitled.
    const revoking = performance.now();
    await b.device.session.revoke(a.id);
    b.cell.host.accountChanged();
    const bAccount = b.log.find(l => l.at >= revoking && l.event.type === 'account');
    expect(bAccount).toBeDefined();
    expect(a.stream.live).toBe(true);
    const dropsBefore = b.cell.host.stats.drops;
    const viewBefore = b.cell.host.current!.view_json();
    const overTheWire = performance.now();
    const late = anchor({ ...first, positionMs: 95_000, at: Math.floor(performance.now()) });
    await a.cell.publish(late);
    const carried = a.log.find(l => l.at >= overTheWire && l.event.type === 'sent' && l.event.kind === 'msg');
    expect(carried).toBeDefined();
    await b.when('B drops A\'s frame', () => b.cell.host.stats.drops > dropsBefore, 10_000);
    const refusal = b.log.filter(l => l.at >= overTheWire && l.event.type === 'drop').map(l => (l.event as { reason: string }).reason);
    expect(b.cell.host.current!.view_json()).toBe(viewBefore);
    expect(b.events.some(e => e.at >= overTheWire && e.event.event === 'message')).toBe(false);
    // b. The home learns the revocation and ends A's stream.
    expect(await settle(b.device)).toBe(true);
    await a.when('A\'s stream stops being live', () => !a.stream.live, 15_000);
    const streamStatus = a.stream.status;
    const afterHome = performance.now();
    await a.cell.publish(anchor({ ...first, positionMs: 97_000, at: Math.floor(performance.now()) }));
    expect(a.log.filter(l => l.at >= afterHome && l.event.type === 'sent').length).toBe(0);
    expect(a.log.some(l => l.at >= afterHome && l.event.type === 'unsent' && l.event.reason === 'carrier')).toBe(true);
    // c. A's poll (the app's own timer; the stream is not live) brings the revocation in.
    const polled = performance.now();
    await a.device.session.syncNow();
    await a.cell.publish(anchor({ ...first, positionMs: 99_000, at: Math.floor(performance.now()) })).catch(() => undefined);
    const stale = a.log.find(l => l.at >= polled && l.event.type === 'stale');
    const account = a.log.find(l => l.at >= polled && l.event.type === 'account');
    expect(stale).toBeDefined();
    expect(account).toBeDefined();
    expect(account!.at).toBeGreaterThanOrEqual(stale!.at);
    expect((account!.event as { entitled: boolean }).entitled).toBe(false);
    expect(a.cell.state.entitled).toBe(false);
    console.log(`revocation: A's frame crossed the home and B dropped it (${refusal.join(',')}); then the home ended A's stream (${glue.StreamStatusKind[streamStatus.kind]}${streamStatus.blocked !== undefined ? `/${glue.StreamBlockedKind[streamStatus.blocked]}` : ''}); A reported stale, then entitled=${(account!.event as { entitled: boolean }).entitled}`);
  } finally {
    await w.stop();
  }
}, 240_000);
