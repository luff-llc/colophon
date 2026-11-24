// The replay log (§12.4) of a home slot, the host side alone: a real directory, the module
// stubbed. A compaction is as durable as an append, never stages through a file it did not
// create, and keeps a write's reservation pending until the write ends; a write that fails is
// recorded as the recovery at start-up would record it, never as completed.
import assert from 'node:assert/strict';
import { constants as fsc, promises as fsp } from 'node:fs';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { HomeSlot } from '../home.js';
import { ProvisionReplay } from '../provision.js';

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

/** A home slot over `root` with the module stubbed: every row is kept, and recovery says
 * completed when the effect is there (as the module does). */
const opened = [];
async function slotAt(root) {
  await fsp.mkdir(path.join(root, 'tmp'), { recursive: true });
  const h = Object.create(HomeSlot.prototype);
  opened.push(h);
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
  afterEach(async () => {
    for (const h of opened.splice(0)) await (h.closeReplay?.() ?? h.close?.());
    await rm(root, { recursive: true, force: true });
  });

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
    const recovered = (await lines(root)).filter((l) => l.c === 'w1' || (l.r === 'w1' && l.t));
    assert.deepEqual(recovered.map((l) => l.t), ['abandoned']);
  });

  test('a write that fails stays pending, and the next start decides by what is on disk', async () => {
    // The file may be durable though the write failed after it (its index line could not be
    // logged): only the effect's own record can say, at the next start.
    for (const [stored, expected] of [[false, 'abandoned'], [true, 'completed']]) {
      await rm(path.join(root, 'replay.log'), { force: true });
      const h = await slotAt(root);
      const p = 'ops/m/notes/1.json';
      h.access = async (req, section, rest, effect) => {
        assert.deepEqual(effect, { path: p, prior: null });
        await h.reserve(row('w2'), effect);
        return { reserve: row('w2') };
      };
      h.putRecord = async () => { throw new Error('the disk failed'); };
      const req = { headers: {}, method: 'PUT' };
      await assert.rejects(h.lockedWrite(req, {}, new URL('http://relay.invalid/'), 'records', p, Buffer.from('x')), /the disk failed/);
      assert.deepEqual((await lines(root)).filter((l) => l.c === 'w2'), [], 'no completion is recorded for it');
      await h.compactReplay();
      assert.deepEqual((await lines(root)).find((l) => l.r === 'w2').e, { path: p, prior: null }, 'still pending after a compaction');
      const again = await slotAt(root);
      if (stored) again.slot.current.set(p, { size: 1, sha256: 'e'.repeat(64) });
      await again.openReplay();
      assert.deepEqual((await lines(root)).filter((l) => l.c === 'w2' || (l.r === 'w2' && l.t)).map((l) => l.t), [expected], `stored: ${stored}`);
    }
  });

  test('a compaction keeps each row\'s outcome, and a completion that could not be written leaves it pending', async () => {
    const h = await slotAt(root);
    await h.reserve(row('x1'), { path: 'ops/a.json', prior: null });
    await h.complete('x1', 'abandoned');
    await h.compactReplay();
    assert.equal((await lines(root)).find((l) => l.r === 'x1').t, 'abandoned', 'an abandoned row stays abandoned');
    await h.reserve(row('x2'), { path: 'ops/b.json', prior: null });
    const append = h.appendReplay;
    h.appendReplay = async () => { throw new Error('no space left on device'); };
    await assert.rejects(h.complete('x2', 'completed'), /no space/);
    h.appendReplay = append;
    await h.compactReplay();
    const x2 = (await lines(root)).find((l) => l.r === 'x2');
    assert.deepEqual(x2.e, { path: 'ops/b.json', prior: null }, 'its completion was not written: still pending');
    assert.equal(x2.t, undefined);
  });

  test('provisioning: a reservation that compacts the log stays pending with its effect', async () => {
    const r = await ProvisionReplay.open(root, { wasm: stubWasm, clock: () => 1_000_000, table: { get: () => undefined } });
    opened.push(r);
    r.logLines = 5_000;
    await r.reserve(row('p1'), { slot: 'tslot00000a' });
    const written = (await lines(path.join(root, 'provision-replay'))).find((l) => l.r === 'p1');
    assert.deepEqual(written.e, { slot: 'tslot00000a' }, JSON.stringify(written));
    assert.equal(written.t, undefined);
    await r.complete('p1', 'completed');
    await r.compact();
    assert.equal((await lines(path.join(root, 'provision-replay'))).find((l) => l.r === 'p1').t, 'completed');
  });

  // Loading: only a log that is not there yet is empty, and only an unterminated last line (an
  // interrupted append) is dropped. A log that cannot be read, or holds a damaged complete line,
  // refuses to open: compacting it as empty would forget calls already taken.
  const linesWith = (effect) => [
    JSON.stringify({ r: 'k1', d: 'd'.repeat(64), s: 'member:m', at: 1_000_000, t: 'completed' }),
    JSON.stringify({ r: 'k2', d: 'd'.repeat(64), s: 'member:m', at: 1_000_000, e: effect }),
    JSON.stringify({ c: 'k2', t: 'completed' }),
  ];
  const stubWasm = {
    call: (req) => {
      if (req.op === 'limits') return { retentionMs: 7_260_000 };
      if (req.op === 'replay_keep') return { keep: req.rows.map((r) => r.key) };
      if (req.op === 'replay_recover') return { states: req.rows.map((r) => ({ key: r.key, state: r.present ? 'completed' : 'abandoned' })) };
      throw new Error(`unexpected op ${req.op}`);
    },
  };
  const loaders = {
    home: { effect: { path: 'ops/x.json', prior: null }, file: (dir) => path.join(dir, 'replay.log'), open: async (dir) => { const h = await slotAt(dir); await h.openReplay(); return h; } },
    provisioning: {
      effect: { slot: 'tslot00000a' },
      file: (dir) => path.join(dir, 'provision-replay', 'replay.log'),
      open: async (dir) => { const r = await ProvisionReplay.open(dir, { wasm: stubWasm, clock: () => 1_000_000, table: { get: () => undefined } }); opened.push(r); return r; },
    },
  };
  for (const [name, loader] of Object.entries(loaders)) {
    const goodLines = linesWith(loader.effect);
    const prepare = async (text) => {
      const file = loader.file(root);
      await fsp.mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, text);
      return file;
    };
    test(`${name}: an absent log is empty, and an unterminated last line is dropped`, async () => {
      const fresh = await loader.open(root);
      assert.equal(fresh.rows.size, 0);
      await prepare(goodLines.join('\n') + '\n{"r":"k3","d":');
      const r = await loader.open(root);
      assert.deepEqual([...r.rows.keys()].sort(), ['k1', 'k2']);
    });
    test(`${name}: a log that cannot be read refuses to open and is left as it was`, async () => {
      const text = goodLines.join('\n') + '\n';
      const file = await prepare(text);
      await chmod(file, 0o000);
      try {
        await assert.rejects(loader.open(root));
      } finally { await chmod(file, 0o600); }
      assert.equal(await readFile(file, 'utf8'), text, 'the log was not rewritten');
    });
    for (const [what, bad] of [['not JSON', '{"r":"k9",'], ['not a row', '{"x":1}'], ['a row of the wrong shape', '{"r":"k9","d":7,"s":"member:m","at":"soon"}']]) {
      test(`${name}: a damaged complete line (${what}) refuses to open`, async () => {
        const text = [goodLines[0], bad, goodLines[1]].join('\n') + '\n';
        const file = await prepare(text);
        await assert.rejects(loader.open(root), /replay/i);
        assert.equal(await readFile(file, 'utf8'), text, 'the log was not rewritten');
      });
    }
  }
});
