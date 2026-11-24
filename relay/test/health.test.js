// `GET /healthz`: `{"ok":true}` while every registered check passes (the container entry point
// registers its lock's heartbeat); 503 naming the failing checks otherwise.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { addHealthCheck } from '../health.js';
import { startRelay } from '../relay.js';

describe('the health check', () => {
  let dir; let running; let root;
  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-health-'));
    running = await startRelay({ port: 0, dataDir: dir, libraries: { test: { open: true } } });
    root = `http://127.0.0.1:${running.port}`;
  });
  after(async () => { await running.close(); await rm(dir, { recursive: true, force: true }); });

  test('is ok while every check passes, and 503 naming the failing ones otherwise', async () => {
    const healthy = await fetch(`${root}/healthz`);
    assert.equal(healthy.status, 200);
    assert.equal(await healthy.text(), '{"ok":true}');

    let beat = { ok: false, lastBeatAt: 0, failures: 3, error: 'read-only file system' };
    const remove = addHealthCheck('container lock', () => beat);
    try {
      const sick = await fetch(`${root}/healthz`);
      assert.equal(sick.status, 503);
      assert.deepEqual(await sick.json(), { ok: false, failing: ['container lock'] });
      beat = { ok: true, lastBeatAt: 1, failures: 0, error: null };
      const again = await fetch(`${root}/healthz`);
      assert.equal(again.status, 200);
      assert.equal(await again.text(), '{"ok":true}');
      // A check that throws is a failing check.
      beat = null;
      const broken = addHealthCheck('broken', () => { throw new Error('no answer'); });
      try { assert.equal((await fetch(`${root}/healthz`)).status, 503); } finally { broken(); }
    } finally { remove(); }
    assert.equal((await fetch(`${root}/healthz`)).status, 200);
  });
});
