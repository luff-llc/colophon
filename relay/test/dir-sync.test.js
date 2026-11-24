// Directory syncs: a home slot's checkpoint (and every other file it renames into place) is
// acknowledged only once its directory is synced, with no error tolerated; a directory the
// relay creates is made durable in its parent.
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { HomeSlot } from '../home.js';
import { startRelay } from '../relay.js';

/** Opens are recorded; a directory's sync fails with `code` when given. */
function watchOpens(code) {
  const open = fsp.open;
  const events = [];
  fsp.open = async (file, ...rest) => {
    const handle = await open.call(fsp, file, ...rest);
    const st = await handle.stat();
    const sync = handle.sync.bind(handle);
    handle.sync = async () => {
      events.push(['sync', String(file)]);
      if (code && st.isDirectory()) throw Object.assign(new Error(`sync: ${code}`), { code });
      return sync();
    };
    return handle;
  };
  return { events, restore: () => { fsp.open = open; } };
}

describe('directory syncs', () => {
  let root;
  beforeEach(async () => { root = await mkdtemp(path.join(tmpdir(), 'colophon-dirsync-')); });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  for (const code of ['EINVAL', 'EPERM']) {
    test(`a home slot's checkpoint is not acknowledged when its directory sync fails (${code})`, async () => {
      await fsp.mkdir(path.join(root, 'tmp'));
      const h = Object.create(HomeSlot.prototype);
      h.slot = { root };
      const w = watchOpens(code);
      try { await assert.rejects(h.writeJson('home-state.json', 'state'), new RegExp(code)); } finally { w.restore(); }
    });
  }

  test('a slot directory the relay creates is synced in its parent', async () => {
    const w = watchOpens();
    let running;
    try {
      running = await startRelay({ port: 0, dataDir: root, libraries: { test: { open: true } } });
      const res = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/test/records/ops/a/b/1.json`, { method: 'PUT', body: 'x', headers: { 'if-none-match': '*' } });
      assert.equal(res.status, 201);
    } finally { w.restore(); await running?.close(); }
    const synced = new Set(w.events.filter(([e]) => e === 'sync').map(([, f]) => path.resolve(f)));
    for (const parent of [root, path.join(root, 'test'), path.join(root, 'test', 'records'), path.join(root, 'test', 'records', 'ops'), path.join(root, 'test', 'records', 'ops', 'a')]) {
      assert.ok(synced.has(path.resolve(parent)), `${parent} was not synced after a directory was made in it`);
    }
  });
});
