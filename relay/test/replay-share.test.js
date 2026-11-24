// The replay share a home slot counts for a principal before it asks the module's `access`
// (§12.4): the host counts the rows the module would count (`retained`) and sends the two numbers,
// not every row. The count must be the module's own, at the boundary, for rows from a clock that
// stepped back, and for `at` values the module cannot read as an integer.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { HomeModule, HomeSlot, retainedAt } from '../home.js';
import { ready, wasm } from './stream-support.js';

test('the host counts a principal\'s replay rows exactly as the module keeps them', { skip: ready ? false : 'module not built' }, async () => {
  const module = await HomeModule.load(wasm);
  const { retentionMs } = module.call({ op: 'limits' });
  const now = 1_800_000_000_000;
  const ats = [
    now, now - 1, now - retentionMs, now - retentionMs + 1, now - retentionMs - 1, now - 2 * retentionMs,
    now + 1, now + 3_600_000, // a clock that stepped back since the row was written
    0, -1, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2 ** 62, 2 ** 63 - 1024, 2 ** 63, -(2 ** 63), -(2 ** 63) - 4096, 1e300, -1e300,
    now - 0.5, now + 0.25, 1.5, Number.NaN, Infinity, -Infinity, '1', null, undefined, true, {}, [],
  ];
  const rows = ats.map((at, i) => ({ key: `k${i}`, at }));
  // The module's own rule over the same rows, as JSON carries them.
  const keep = new Set(module.call({ op: 'replay_keep', now, rows }).keep);
  for (const { key, at } of rows) assert.equal(retainedAt(at, now, retentionMs), keep.has(key), `at ${String(at)}`);
  assert.ok(keep.size >= 6 && keep.size < rows.length, `${keep.size} kept`);

  // A slot's count for one principal (its rows among others').
  const slot = { wasm: module, rows: new Map(), bySigner: new Map() };
  for (const [i, { key, at }] of rows.entries()) HomeSlot.prototype.addRow.call(slot, key, { at, digest: 'd', signer: i % 3 ? 'member:a' : 'member:b' });
  const share = HomeSlot.prototype.signerShare.call(slot, 'member:a', now);
  const mine = rows.filter((_, i) => i % 3);
  const live = mine.filter((r) => keep.has(r.key));
  assert.equal(share.live, live.length);
  assert.equal(share.oldest, Math.min(...live.map((r) => r.at)));
  assert.deepEqual(share.expired, mine.filter((r) => !keep.has(r.key)).map((r) => r.key));
  assert.deepEqual(HomeSlot.prototype.signerShare.call(slot, 'member:nobody', now), { live: 0, oldest: null, expired: [] });
});
