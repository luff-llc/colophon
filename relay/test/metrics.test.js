// `GET /metrics`: off unless the operator sets a token's SHA-256; then a few cheap counters,
// answered only to that bearer token, naming no slot or account.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, test } from 'node:test';
import { addHealthCheck } from '../health.js';
import { startRelay } from '../relay.js';

const TOKEN = 'metrics-token-0123456789abcdef';
const sha = (text) => createHash('sha256').update(text).digest('hex');

async function relay(options, fn) {
  const dir = await mkdtemp(path.join(tmpdir(), 'colophon-metrics-'));
  const running = await startRelay({ port: 0, dataDir: dir, libraries: { 'private-slot-name': { open: true } }, ...options });
  try { await fn(`http://127.0.0.1:${running.port}`); } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
}

describe('metrics', () => {
  test('are not served unless configured', () => relay({}, async (root) => {
    const res = await fetch(`${root}/metrics`, { headers: { authorization: `Bearer ${TOKEN}` } });
    assert.equal(res.status, 404);
  }));

  test('refuse a bad configuration', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-metrics-'));
    try {
      await assert.rejects(startRelay({ port: 0, dataDir: dir, libraries: { a: { open: true } }, metrics: { tokenSha256: 'nope' } }), /metrics.tokenSha256/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  test('answer the operator\'s token only, with counters and no names', () => relay({ metrics: { tokenSha256: sha(TOKEN) } }, async (root) => {
    for (const authorization of [undefined, 'Bearer wrong-token-0123456789', `Basic ${TOKEN}`]) {
      const res = await fetch(`${root}/metrics`, { headers: authorization ? { authorization } : {} });
      assert.equal(res.status, 401, String(authorization));
      assert.equal(res.headers.get('www-authenticate'), 'Bearer');
    }
    assert.equal((await fetch(`${root}/metrics`, { method: 'POST', headers: { authorization: `Bearer ${TOKEN}` } })).status, 405);
    const remove = addHealthCheck('container lock', () => ({ ok: true, lastBeatAt: Date.now() - 4_000, failures: 0, error: null }));
    try {
      const res = await fetch(`${root}/metrics`, { headers: { authorization: `Bearer ${TOKEN}` } });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('cache-control'), 'no-store, no-transform');
      const text = await res.text();
      assert.equal(text.includes('private-slot-name'), false, 'no slot names');
      const m = JSON.parse(text);
      assert.deepEqual(Object.keys(m).sort(), ['containerLockAgeSeconds', 'eventLoopLagMs', 'moduleMemoryBytes', 'moduleResets',
        'requestsInFlight', 'rssBytes', 'slots', 'stoppedSlots', 'uptimeSeconds'].sort());
      assert.ok(m.rssBytes > 0);
      assert.equal(m.slots, 1);
      assert.equal(m.stoppedSlots, 0);
      assert.equal(m.moduleMemoryBytes, 0, 'no module loaded');
      assert.equal(m.moduleResets, 0);
      assert.equal(m.requestsInFlight, 0, 'other requests (not this one)');
      assert.ok(m.eventLoopLagMs >= 0);
      assert.ok(m.containerLockAgeSeconds >= 4 && m.containerLockAgeSeconds < 60, String(m.containerLockAgeSeconds));
    } finally { remove(); }
    const without = await (await fetch(`${root}/metrics`, { headers: { authorization: `Bearer ${TOKEN}` } })).json();
    assert.equal(without.containerLockAgeSeconds, null, 'not in a container');
  }));
});
