// The replay log (§12.4) of a home slot, the host side alone: a real directory, the module
// stubbed. A compaction is as durable as an append, never stages through a file it did not
// create, and keeps a write's reservation pending until the write ends; a write that fails is
// recorded as the recovery at start-up would record it, never as completed.
import assert from 'node:assert/strict';
import { constants as fsc, promises as fsp } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { HomeSlot } from '../home.js';

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

/** A home slot over `root` with the module stubbed: every row is kept, and recovery says
 * completed when the effect is there (as the module does). */
async function slotAt(root) {
  await fsp.mkdir(path.join(root, 'tmp'), { recursive: true });
  const h = Object.create(HomeSlot.prototype);
  h.slot = { name: 'home', root, current: new Map() };
  h.rows = new Map();
  h.bySigner = new Map();
  h.logLines = 0;
  h.clock = () => 1_000_000;
  h.deps = { HttpError, send() {} };
  let tail = Promise.resolve();
  const chain = (fn) => { const run = tail.then(fn, fn); tail = run.catch(() => {}); return run; };
  h.lock = chain;
  let replayTail = Promise.resolve();
  h.replayLock = (fn) => { const run = replayTail.then(fn, fn); replayTail = run.catch(() => {}); return run; };
  h.wasm = {
    call: (req) => {
      if (req.op === 'replay_keep') return { keep: req.rows.map((r) => r.key) };
      if (req.op === 'replay_recover') return { states: req.rows.map((r) => ({ key: r.key, state: r.present ? 'completed' : 'abandoned' })) };
      throw new Error(`unexpected op ${req.op}`);
    },
  };
  return h;
}

const lines = async (root) => (await readFile(path.join(root, 'replay.log'), 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l));
const row = (key) => ({ key, digest: 'd'.repeat(64), at: 1_000_000, signer: 'member:m' });

describe('the replay log', () => {
  let root;
  beforeEach(async () => { root = await mkdtemp(path.join(tmpdir(), 'colophon-replay-')); });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  test('a compaction stages a file of its own and makes its rename durable', async () => {
    const h = await slotAt(root);
    await h.reserve(row('k1'), null);
    const events = [];
    const open = fsp.open; const rename = fsp.rename;
    fsp.open = async (file, flags, ...rest) => {
      const handle = await open.call(fsp, file, flags, ...rest);
      events.push(['open', file, flags]);
      const sync = handle.sync.bind(handle);
      handle.sync = async () => { events.push(['sync', file]); return sync(); };
      return handle;
    };
    fsp.rename = async (from, to) => { events.push(['rename', from, to]); return rename.call(fsp, from, to); };
    try { await h.compactReplay(); } finally { fsp.open = open; fsp.rename = rename; }
    const staged = events.find(([e, f]) => e === 'open' && path.dirname(f) === path.join(root, 'tmp'));
    assert.ok(staged, JSON.stringify(events));
    assert.equal(typeof staged[2], 'number', `the staged file is opened with explicit flags, not ${JSON.stringify(staged[2])}`);
    assert.ok(staged[2] & fsc.O_EXCL, 'created, never an existing file');
    assert.ok(staged[2] & fsc.O_NOFOLLOW, 'never through a link');
    const renamed = events.findIndex(([e, , to]) => e === 'rename' && to === path.join(root, 'replay.log'));
    assert.ok(renamed >= 0, JSON.stringify(events));
    assert.ok(events.slice(renamed + 1).some(([e, f]) => e === 'sync' && f === root), `the slot directory is synced after the rename: ${JSON.stringify(events)}`);
    assert.deepEqual((await lines(root)).map((l) => l.r), ['k1']);
  });

  test('a write reserved when the log is compacted stays pending with its effect', async () => {
    const h = await slotAt(root);
    const effect = { path: 'ops/m/notes/1.json', prior: null };
    // The next reservation compacts the log.
    h.logLines = 5_000;
    await h.reserve(row('w1'), effect);
    const written = (await lines(root)).find((l) => l.r === 'w1');
    assert.deepEqual(written.e, effect, JSON.stringify(written));
    assert.equal(written.t, undefined, 'not completed before its effect');
    // A crash now: at start-up the write is found not to have happened.
    const again = await slotAt(root);
    await again.openReplay();
    const recovered = (await lines(root)).filter((l) => l.c === 'w1');
    assert.deepEqual(recovered.map((l) => l.t), ['abandoned']);
  });

  test('a write that fails is recorded as recovery would record it, not as completed', async () => {
    for (const [stored, expected] of [[false, 'abandoned'], [true, 'completed']]) {
      await rm(path.join(root, 'replay.log'), { force: true });
      const h = await slotAt(root);
      const p = 'ops/m/notes/1.json';
      h.access = async (req, section, rest, effect) => {
        assert.deepEqual(effect, { path: p, prior: null });
        await h.reserve(row('w2'), effect);
        return { reserve: row('w2') };
      };
      h.putRecord = async () => {
        if (stored) h.slot.current.set(p, { size: 1, sha256: 'e'.repeat(64) });
        throw new Error('the disk failed');
      };
      const req = { headers: {}, method: 'PUT' };
      await assert.rejects(h.lockedWrite(req, {}, new URL('http://relay.invalid/'), 'records', p, Buffer.from('x')), /the disk failed/);
      const done = (await lines(root)).filter((l) => l.c === 'w2').map((l) => l.t);
      assert.deepEqual(done, [expected], `stored: ${stored}`);
    }
  });
});
