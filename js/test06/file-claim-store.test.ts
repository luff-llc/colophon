// FileClaimStore's lock-free compare-and-set, with two real handles on one directory: every interleaving of two savers'
// three steps (forced with hooks between the first listing, the link and the second listing), crashes, EEXIST, an
// intermediate fence, a malformed highest file, and many savers racing round after round.
import { describe, expect, test } from 'bun:test';
import { mkdtempSync, readdirSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Fence } from '../src/hosts/index.js';
import { FileClaimStore } from '../src/hosts/node.js';

const folder = (): string => mkdtempSync(join(tmpdir(), 'colophon-js-claims-'));
const name = (f: Fence): string => `claim-${String(f.generation).padStart(16, '0')}-${String(f.seq).padStart(16, '0')}.json`;
const E: Fence = { generation: 1, seq: 0 };

/** Two savers' steps: 1 the first listing, 2 the write and the link, 3 the second listing and the verdict. */
function orders(): string[][] {
  const out: string[][] = [];
  const walk = (a: number, b: number, acc: string[]): void => {
    if (a === 3 && b === 3) { out.push(acc); return; }
    if (a < 3) walk(a + 1, b, [...acc, 'A']);
    if (b < 3) walk(a, b + 1, [...acc, 'B']);
  };
  walk(0, 0, []);
  return out;
}

/** A store whose save waits, before each of its three steps, for the test to let it go on. */
function gated(directory: string): { store: FileClaimStore; go(): void; waiting(): boolean } {
  let release: (() => void) | undefined;
  const store = new FileClaimStore(directory, {
    onStep: step => step === 'begin' || step === 'listed' || step === 'linked' ? new Promise<void>(resolve => { release = resolve; }) : undefined,
  });
  return { store, go: () => { const r = release; release = undefined; r?.(); }, waiting: () => release !== undefined };
}
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 1));

async function race(order: string[], na: Fence, nb: Fence): Promise<{ results: string[]; held: Fence | undefined }> {
  const dir = folder();
  await new FileClaimStore(dir).save({ claim: 'e', fence: E }, undefined);
  const a = gated(dir); const b = gated(dir);
  const pa = a.store.save({ claim: 'a', fence: na }, E); const pb = b.store.save({ claim: 'b', fence: nb }, E);
  const done = { A: false, B: false };
  void pa.then(() => { done.A = true; }); void pb.then(() => { done.B = true; });
  for (const who of order) {
    const g = who === 'A' ? a : b;
    for (let n = 0; n < 200 && !g.waiting() && !done[who as 'A' | 'B']; n++) await tick();
    g.go();
    await tick();
  }
  for (let n = 0; n < 50; n++) { a.go(); b.go(); await tick(); }
  const results = await Promise.all([pa, pb]);
  return { results, held: await new FileClaimStore(dir).fence() };
}

describe('FileClaimStore', () => {
  test('two savers from one fence, with different new fences, in all 20 interleavings: at most one stored, and it is held', async () => {
    let one = 0;
    for (const order of orders()) {
      const na = { generation: 1, seq: 1 }; const nb = { generation: 1, seq: 2 };
      const { results, held } = await race(order, na, nb);
      const stored = results.filter(r => r === 'stored').length;
      expect({ order: order.join(''), atMostOne: stored <= 1 }).toEqual({ order: order.join(''), atMostOne: true });
      if (stored === 1) { one++; expect(held).toEqual(results[0] === 'stored' ? na : nb); } else expect(held).toEqual(E);
    }
    console.log(`file claim store: ${one} of 20 interleavings had one winner, ${20 - one} none (each saver saw the other); none had two`);
    // Serial orders always have a winner; fully overlapping ones may leave none (both saw each other), never two.
    expect(one).toBeGreaterThan(0);
  });

  test('two savers of the same new fence, in all 20 interleavings: exactly one stored (the link refuses the second)', async () => {
    for (const order of orders()) {
      const n = { generation: 2, seq: 0 };
      const { results, held } = await race(order, n, n);
      expect({ order: order.join(''), stored: results.filter(r => r === 'stored').length }).toEqual({ order: order.join(''), stored: 1 });
      expect(held).toEqual(n);
    }
  });

  test('many savers race from one fence, round after round: never two stored, and the held fence moves only with a winner', async () => {
    const dir = folder();
    const handles = Array.from({ length: 6 }, () => new FileClaimStore(dir));
    let held: Fence | undefined;
    let winners = 0;
    for (let round = 0; round < 40; round++) {
      const results = await Promise.all(handles.map((h, k) => h.save({ claim: `r${round}-${k}`, fence: { generation: 1, seq: round * 10 + k + 1 } }, held)));
      const stored = results.flatMap((r, k) => (r === 'stored' ? [k] : []));
      expect(stored.length).toBeLessThanOrEqual(1);
      if (stored.length === 1) { winners++; held = { generation: 1, seq: round * 10 + stored[0]! + 1 }; }
      expect(await handles[0]!.fence()).toEqual(held);
      const loaded = await handles[1]!.load();
      if (held) expect(loaded?.fence).toEqual(held);
    }
    console.log(`file claim store: ${winners} of 40 rounds had exactly one winner; none had two`);
    expect(winners).toBeGreaterThan(0);
  });

  test('a crash between the temporary write and the link leaves the old claim; old temporaries are aged out', async () => {
    const dir = folder();
    const store = new FileClaimStore(dir);
    await store.save({ claim: 'e', fence: E }, undefined);
    const crashing = new FileClaimStore(dir, { onStep: step => { if (step === 'written') throw new Error('crash'); } });
    let crashed = false;
    try { await crashing.save({ claim: 'n', fence: { generation: 1, seq: 1 } }, E); } catch { crashed = true; }
    expect(crashed).toBe(true);
    expect((await store.load())?.claim).toBe('e');
    // A temporary a crashed writer left behind is ignored, and removed once it is an hour old.
    const stray = join(dir, '.tmp-left-behind');
    writeFileSync(stray, '{"claim":"x","fence":{"generation":9,"seq":9}}');
    expect(await store.fence()).toEqual(E);
    utimesSync(stray, Date.now() / 1000 - 7200, Date.now() / 1000 - 7200);
    expect(await store.save({ claim: 'n', fence: { generation: 1, seq: 1 } }, E)).toBe('stored');
    expect(readdirSync(dir).includes('.tmp-left-behind')).toBe(false);
  });

  test('a crash after the link, before the check: the new file is complete and held', async () => {
    const dir = folder();
    const store = new FileClaimStore(dir);
    await store.save({ claim: 'e', fence: E }, undefined);
    const crashing = new FileClaimStore(dir, { onStep: step => { if (step === 'linked') throw new Error('crash'); } });
    try { await crashing.save({ claim: 'n', fence: { generation: 1, seq: 1 } }, E); } catch { /* the crash */ }
    expect(await store.load()).toEqual({ claim: 'n', fence: { generation: 1, seq: 1 } });
  });

  test('EEXIST, a stale expected fence and an intermediate fence are all stale, and leave the held fence', async () => {
    const dir = folder();
    const store = new FileClaimStore(dir);
    await store.save({ claim: 'e', fence: E }, undefined);
    const n = { generation: 1, seq: 5 };
    // The file appears between the first listing and the link.
    const racing = new FileClaimStore(dir, { onStep: step => { if (step === 'listed') writeFileSync(join(dir, name(n)), JSON.stringify({ claim: 'other', fence: n })); } });
    expect(await racing.save({ claim: 'mine', fence: n }, E)).toBe('stale');
    expect((await store.load())?.claim).toBe('other');
    expect(await store.save({ claim: 'old view', fence: { generation: 1, seq: 9 } }, E)).toBe('stale');
    // An intermediate fence appears between the link and the second listing: the saver removes its own file.
    const m = { generation: 1, seq: 8 };
    const squeezed = new FileClaimStore(dir, { onStep: step => { if (step === 'linked') writeFileSync(join(dir, name({ generation: 1, seq: 7 })), JSON.stringify({ claim: 'between', fence: { generation: 1, seq: 7 } })); } });
    expect(await squeezed.save({ claim: 'm', fence: m }, n)).toBe('stale');
    expect(readdirSync(dir).includes(name(m))).toBe(false);
  });

  test('a malformed highest file fails closed instead of lowering the held fence', async () => {
    const dir = folder();
    const store = new FileClaimStore(dir);
    await store.save({ claim: 'e', fence: E }, undefined);
    writeFileSync(join(dir, name({ generation: 3, seq: 0 })), '{not json');
    let failed = false;
    try { await store.load(); } catch { failed = true; }
    expect(failed).toBe(true);
    expect(await store.fence()).toEqual({ generation: 3, seq: 0 });
    // A file whose content names another fence is refused too.
    writeFileSync(join(dir, name({ generation: 4, seq: 0 })), JSON.stringify({ claim: 'x', fence: { generation: 1, seq: 0 } }));
    failed = false;
    try { await store.load(); } catch { failed = true; }
    expect(failed).toBe(true);
  });

  test('unfenced claims are refused: 0.6 never stored one', async () => {
    const dir = folder();
    writeFileSync(join(dir, name({ generation: 1, seq: 0 })), JSON.stringify({ claim: { term: 1, rank: 0, holder: 'a' } }));
    let failed = false;
    try { await new FileClaimStore(dir).load(); } catch { failed = true; }
    expect(failed).toBe(true);
  });
});
