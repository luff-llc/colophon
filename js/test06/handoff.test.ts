// The flagship behaviour of 0.6, end to end: two members of one account, each through its own JavaScript stream host
// over a real WebSocket to a real home, hand a `now-playing` cell over. A plays and publishes its anchor; B, on its
// "play", takes over with A's last state and continues from A's position; A sees it is no longer holder and stops.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { init } from '../src/session/index.js';
import { BunRelayHost } from '../test05/relay-bun.ts';
import { anchor, project, readAnchor, world } from './world.ts';

const host = new BunRelayHost();
beforeAll(async () => { BunRelayHost.module(); await init(); });
afterAll(async () => { await host.stopAll(); });

const HOLDER_FRAMES = ['state', 'beat', 'msg', 'refuse', 'pass', 'decline'];

test('handoff on now-playing: B takes over from A at A\'s position, A yields and stops (default policy)', async () => {
  const w = await world(host);
  const { a, b } = w;
  try {
    a.startStream(); b.startStream();
    await a.when('A\'s stream is live', () => a.stream.live);
    await b.when('B\'s stream is live', () => b.stream.live);
    await a.join(); await b.join();
    await a.when('A is subscribed', () => a.log.some(l => l.event.type === 'sent' && l.event.kind === 'hello'));

    // A plays: it takes the cell and publishes its anchor on its own clock.
    const start = { episode: 'ep-1', show: 'show-1', positionMs: 1_234_567, ratePermille: 1250, playing: true, at: Math.floor(performance.now()) };
    a.appState = anchor(start);
    await a.cell.take(a.appState);
    await a.until('becameHolder');
    expect(a.cell.state.isHolder).toBe(true);
    await b.until('holderChanged', 0, 10_000, e => e.claim?.holder === a.id);
    const last = { ...start, positionMs: 1_240_000, at: Math.floor(performance.now()) };
    a.appState = anchor(last);
    await a.cell.publish(a.appState);
    await b.until('message', 0, 10_000, e => readAnchor(e.payload)?.positionMs === last.positionMs);
    expect(readAnchor(b.cell.state.state)).toEqual(last);

    // B measures its clock offset to A, to project A's position on its own clock.
    await b.cell.ping(a.id);
    const offset = (await b.until('offsetChanged', 0, 10_000, e => e.peer === a.id)).event;

    // A's application, as §S12 has it: when another device asks to play, A pauses and passes its stopped position.
    let stopped: ReturnType<typeof readAnchor>;
    a.cell.events(event => {
      if (event.event !== 'askReceived' || !a.cell.state.isHolder) return;
      const now = Math.floor(performance.now());
      const playing = readAnchor(a.appState)!;
      stopped = { ...playing, positionMs: project(playing, now, 0), playing: false, at: now };
      a.appState = anchor(stopped);
      void a.cell.pass(event.from, a.appState);
    });

    // B's "play": it asks the holder for the role, and takes on its own if the holder does not answer in time (§S5:
    // a take never displaces a holder that is live and answering).
    const pressed = performance.now();
    await b.cell.ask();
    await b.cell.take();
    const held = await b.until('becameHolder', pressed);
    const seen = await a.until('yielded', pressed);
    const toHolding = held.at - pressed; const toObserved = seen.at - pressed;
    console.log(`handoff (default policy, real home over WebSocket): B's play (ask) -> A observes it is no longer holder ${toObserved.toFixed(1)} ms; -> B holding ${toHolding.toFixed(1)} ms`);

    // B starts from exactly A's last state: A's stopped position, which B now plays on from.
    expect(held.event.via).toBe('pass');
    const resumed = readAnchor(held.event.snapshot);
    expect(resumed).toEqual(stopped);
    expect(resumed!.positionMs).toBeGreaterThanOrEqual(last.positionMs);
    expect(b.cell.state.isHolder).toBe(true);
    expect(b.cell.state.holder).toBe(b.id);
    const playingOnB = { ...resumed!, playing: true, at: Math.floor(performance.now()) };
    b.appState = anchor(playingOnB);
    await b.cell.publish(b.appState);
    // A follows B's anchor and projects B's position on its own clock.
    const followed = await a.until('message', seen.at, 10_000, e => readAnchor(e.payload)?.playing === true);
    expect(readAnchor(followed.event.payload)!.positionMs).toBe(resumed!.positionMs);
    expect(project(readAnchor(followed.event.payload)!, Math.floor(performance.now()), -offset.offset)).toBeGreaterThanOrEqual(resumed!.positionMs);

    // A is no longer holder and acts as none: no holder frame after it passed, other than resending its pass.
    expect(a.cell.state.isHolder).toBe(false);
    expect(a.cell.state.holder).toBe(b.id);
    await new Promise(resolve => setTimeout(resolve, 1500));
    const after = a.sentKinds(seen.at).filter(k => HOLDER_FRAMES.includes(k) && k !== 'pass');
    expect(after).toEqual([]);
    expect(a.log.filter(l => l.event.type === 'drop').map(l => l.event)).toEqual([]);
    expect(toHolding).toBeLessThan(1000);
    expect(toObserved).toBeLessThan(2000);
  } finally {
    await w.stop();
  }
}, 120_000);
