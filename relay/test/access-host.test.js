// The host side of `access` (§12.4), the module stubbed: what home.js sends the module for a
// caller's replay rows, and when it reads the clock. A module that does not say it takes counts
// is sent every row; the clock is read after the call's key and rows are looked up, once.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { HomeSlot } from '../home.js';

const RETENTION = 7_260_000;
const KEY = 'acct\naud\nkey\npurpose\nrid';

/** A slot whose module answers `limits` with `limits` and allows every access. `sent` gets the
 * access request; `events` the order of clock readings and module calls. */
function slot({ limits = { retentionMs: RETENTION, replayCounts: true }, rows = [], start = 100_000_000 } = {}) {
  const h = Object.create(HomeSlot.prototype);
  const events = [];
  let t = start;
  h.clock = () => { t += 1; events.push(['clock', t]); return t; };
  h.state = 's';
  h.base = 'https://home.example';
  h.slot = { name: 'home' };
  h.limits = { replayRows: 65_536 };
  h.deps = { HttpError: class extends Error {} };
  h.replayLock = async (f) => f();
  h.rows = new Map(); h.bySigner = new Map();
  for (const [i, at] of rows.entries()) h.addRow(`r${i}`, { at, digest: 'd', signer: 'member:a' });
  h.wasm = {
    call: (req) => {
      events.push([req.op, req.now]);
      if (req.op === 'limits') return limits;
      if (req.op === 'call_key') return { parsed: true, key: KEY, signer: 'member:a' };
      if (req.op === 'access') { h.sent = req; return { allowed: true, via: 'call', drop: [] }; }
      throw new Error(`unexpected op ${req.op}`);
    },
  };
  h.events = events;
  return h;
}
const request = { method: 'GET', url: '/v1/libraries/home/records/x.json', headers: {} };

describe('the replay rows a host sends with access', () => {
  test('a module that does not advertise counts is sent every row', async () => {
    const h = slot({ limits: { retentionMs: RETENTION }, rows: [100_000_000, 0] });
    await h.access(request, 'records', 'x.json', null, Buffer.alloc(0), 'call');
    assert.equal(h.sent.signerLive, undefined);
    assert.deepEqual(h.sent.signerRows, [{ key: 'r0', at: 100_000_000 }, { key: 'r1', at: 0 }]);
  });

  test('a module that takes counts is sent the counts', async () => {
    const h = slot({ rows: [100_000_000, 0] });
    await h.access(request, 'records', 'x.json', null, Buffer.alloc(0), 'call');
    assert.equal(h.sent.signerRows, undefined);
    assert.deepEqual([h.sent.signerLive, h.sent.signerOldest], [1, 100_000_000]);
    assert.ok(!h.rows.has('r1'), 'the expired row is dropped');
  });

  test('a clock or a row time that is not a safe integer is sent as rows', async () => {
    for (const [rows, start] of [[[2 ** 60, 100_000_000], 100_000_000], [[1], 2 ** 60]]) {
      const h = slot({ rows, start });
      await h.access(request, 'records', 'x.json', null, Buffer.alloc(0), 'call');
      assert.equal(h.sent.signerLive, undefined, JSON.stringify(rows));
      assert.equal(h.sent.signerRows.length, rows.length);
    }
  });

  test('the clock is read once, after the call key is looked up', async () => {
    const h = slot({ rows: [100_000_000] });
    await h.access(request, 'records', 'x.json', null, Buffer.alloc(0), 'call');
    const clocks = h.events.filter(([e]) => e === 'clock');
    assert.equal(clocks.length, 1, JSON.stringify(h.events));
    const order = h.events.map(([e]) => e).filter((e) => e !== 'limits');
    assert.deepEqual(order, ['call_key', 'clock', 'access']);
    assert.equal(h.sent.now, clocks[0][1]);
  });
});
