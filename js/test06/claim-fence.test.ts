// The fence across independent store clients: two clients of the same underlying storage racing to open (in every
// interleaving of their transactions a fake can produce), a rebuild racing an open, a private store without an atomic
// update refused, a superseded holder stopping within one beat, and fences that are not safe integers refused.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { accountOf, compareAndSet, MemoryClaimStore, privateClaimStore, SessionCellHost, type CellCarrier, type CellHostEvent, type ClaimStore, type StreamCell } from '../src/hosts/index.js';
import { init, MemoryPrivateStore, type AtomicPrivateStore } from '../src/session/index.js';
import { FilePrivateStore } from '../src/session/node.js';
import { Device } from '../test05/support.ts';
import { ManualClock, settle } from './fakes.ts';

const NS = 'listening.podcasts';
const CELL = 'now-playing';
const BEAT = 400;
const policy = (): string => JSON.stringify({ beatMs: BEAT, holderTimeoutMs: 1500, askTimeoutMs: 300, presenceTimeoutMs: 1500, retainMs: 60000, tail: 256, maxPayload: 8192, fold: 'latest', take: 'free' });

/** A carrier that carries nothing (these tests are about the store). */
const nowhere = (): CellCarrier => ({ attach: (c: StreamCell) => { queueMicrotask(() => c.linkUp()); }, detach: () => {}, sendSession: () => true });

/**
 * One underlying storage and any number of client handles on it. Each read and each update is one transaction, applied
 * atomically when the scheduler lets it run; transactions of different handles interleave in the order the test picks.
 */
class SteppedStorage {
  readonly files = new Map<string, Uint8Array>();
  gated = true;
  readonly pending: { tag: string; run: () => void }[] = [];
  handle(tag: string): AtomicPrivateStore {
    const step = <T>(body: () => T): Promise<T> => new Promise<T>((resolve, reject) => {
      const run = (): void => { try { resolve(body()); } catch (error) { reject(error); } };
      if (this.gated) this.pending.push({ tag, run }); else run();
    });
    return {
      read: name => step(() => this.files.get(name)?.slice()),
      write: async (name, bytes) => step(() => { this.files.set(name, bytes.slice()); }),
      remove: async name => step(() => { this.files.delete(name); }),
      update: (name, decide) => step(() => { const next = decide(this.files.get(name)?.slice()); if (next === undefined) return false; this.files.set(name, next.slice()); return true; }),
    };
  }
  /** Runs one pending transaction of `tag`, waiting for it to be issued. */
  async release(tag: string): Promise<void> {
    for (let n = 0; n < 2000; n++) {
      const k = this.pending.findIndex(p => p.tag === tag);
      if (k >= 0) { this.pending.splice(k, 1)[0]!.run(); await settle(); return; }
      await new Promise(resolve => setTimeout(resolve, 2));
    }
    throw new Error(`${tag} issued no transaction`);
  }
  free(): void { this.gated = false; for (const p of this.pending.splice(0)) p.run(); }
}

/** Every order of `a` copies of A and `b` copies of B. */
function interleavings(a: number, b: number): string[][] {
  if (a === 0) return [Array(b).fill('B')];
  if (b === 0) return [Array(a).fill('A')];
  return [...interleavings(a - 1, b).map(o => ['A', ...o]), ...interleavings(a, b - 1).map(o => ['B', ...o])];
}

let device: Device;
beforeAll(async () => {
  await init();
  device = await Device.make({ namespaces: [NS] });
  await device.session.create();
});
afterAll(() => { device.close(); });

const open = (store: ClaimStore, clock: ManualClock, log?: CellHostEvent[]): Promise<SessionCellHost> =>
  SessionCellHost.open({ account: accountOf(device.session), carrier: nowhere(), namespace: NS, cell: CELL, store, clock, policy: policy() }, e => log?.push(e));
/** The hosts still acting once every watch has had a beat to look. */
async function survivors(clock: ManualClock, hosts: SessionCellHost[]): Promise<SessionCellHost[]> {
  // Opens and rebuilds finish (their delegations are signed for real), then each watch gets a beat.
  for (let n = 0; n < 100 && hosts.some(h => h.state === 'opening' || h.state === 'rebuilding'); n++) await new Promise(resolve => setTimeout(resolve, 5));
  await clock.advance(BEAT + 1);
  await new Promise(resolve => setTimeout(resolve, 20));
  await settle();
  return hosts.filter(h => h.state === 'open');
}

describe('the claim fence across independent clients', () => {
  for (const order of interleavings(2, 2)) {
    test(`two clients open at once, transactions ${order.join(' ')}: exactly one holds the cell`, async () => {
      const storage = new SteppedStorage();
      const clock = new ManualClock();
      const results = [open(privateClaimStore(storage.handle('A'), 'cell'), clock), open(privateClaimStore(storage.handle('B'), 'cell'), clock)]
        .map(p => p.then(h => h, () => undefined));
      // Each open's first two transactions (its load and its reservation) run in this order; then everything runs.
      for (const tag of order) await storage.release(tag);
      storage.free();
      const hosts = (await Promise.all(results)).filter((h): h is SessionCellHost => h !== undefined);
      const left = await survivors(clock, hosts);
      expect(left.length).toBe(1);
      for (const h of hosts) h.close();
    });
  }

  for (const order of interleavings(1, 2)) {
    test(`a rebuild races an open, transactions ${order.join(' ')}: exactly one holds the cell`, async () => {
      const storage = new SteppedStorage();
      storage.gated = false;
      const clock = new ManualClock();
      const a = await open(privateClaimStore(storage.handle('A'), 'cell'), clock);
      storage.gated = true;
      // A rebuilds (its clock went back), reserving a new generation, while B opens.
      clock.jump(clock.mono - 1_000);
      a.linkDown();
      const b = open(privateClaimStore(storage.handle('B'), 'cell'), clock).then(h => h, () => undefined);
      for (const tag of order) await storage.release(tag);
      storage.free();
      const hosts = [a, await b].filter((h): h is SessionCellHost => h !== undefined);
      // The manual clock went back 1 s; timers set before that are due 1 s later on it (real timers are relative).
      await new Promise(resolve => setTimeout(resolve, 50));
      await clock.advance(1_000);
      const left = await survivors(clock, hosts);
      expect(left.length).toBe(1);
      for (const h of hosts) h.close();
    });
  }

  test('a private store without an atomic update (the file store) cannot back a claim store', () => {
    const folder = mkdtempSync(join(tmpdir(), 'colophon-js-claims-'));
    let message = '';
    try { privateClaimStore(new FilePrivateStore(folder) as unknown as AtomicPrivateStore, 'cell'); } catch (error) { message = (error as Error).message; }
    expect(message).toContain('file-backed claim persistence is not available yet');
    expect(message).toContain('supply a ClaimStore');
  });

  test('a superseded holder stops within one beat and sends nothing after', async () => {
    const store = new MemoryClaimStore();
    const clock = new ManualClock();
    const log: CellHostEvent[] = [];
    const a = await open(store, clock, log);
    await a.command('take', { command: 'take', state: null });
    await settle();
    const replaced = clock.mono;
    const b = await open(store, clock);
    await clock.advance(BEAT);
    await settle();
    const failed = log.findIndex(e => e.type === 'failed' && e.reason === 'superseded');
    expect(failed).toBeGreaterThanOrEqual(0);
    expect(clock.mono - replaced).toBeLessThanOrEqual(BEAT);
    for (let k = 0; k < 10; k++) await clock.advance(BEAT);
    expect(log.slice(failed).filter(e => e.type === 'sent')).toEqual([]);
    expect(a.state).toBe('failed');
    expect(b.state).toBe('open');
    a.close(); b.close();
  });

  test('fences that are not non-negative safe integers are refused', async () => {
    const bad = [Number.NaN, 2 ** 53, -1, 1.5, Infinity];
    for (const v of bad) {
      expect(() => compareAndSet(undefined, { claim: null, fence: { generation: v, seq: 0 } }, undefined)).toThrow();
      expect(() => compareAndSet(undefined, { claim: null, fence: { generation: 1, seq: v } }, undefined)).toThrow();
    }
    expect(() => compareAndSet(undefined, { claim: null, fence: { generation: '1', seq: 0 } as never }, undefined)).toThrow();
    // A stored record with a bad fence is refused on load.
    const files = new MemoryPrivateStore();
    await files.write('cell', new TextEncoder().encode(JSON.stringify({ claim: null, fence: { generation: 2 ** 60, seq: 0 } })));
    let refused = false;
    try { await privateClaimStore(files, 'cell').load(); } catch { refused = true; }
    expect(refused).toBe(true);
  });
});
