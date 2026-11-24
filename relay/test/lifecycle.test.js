// Shutdown, request by request: a request that arrives while the relay closes is answered 503
// with Retry-After; work already admitted finishes its file work; a long poll that reaches its
// wait after shutdown began is answered at once instead of registering on a slot nobody wakes.
import assert from 'node:assert/strict';
import { createECDH, hkdfSync, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, test } from 'node:test';
import { sha256, startRelay } from '../relay.js';
import fixture from './fixtures/home-batch.json';

async function withRelay(options, fn) {
  const dir = await mkdtemp(path.join(tmpdir(), 'colophon-life-'));
  const running = await startRelay({ port: 0, dataDir: dir, ...options });
  try { await fn(running, `http://127.0.0.1:${running.port}`); } finally { await running.close().catch(() => {}); await rm(dir, { recursive: true, force: true }); }
}

describe('a relay that is closing', () => {
  test('answers a new request 503 with Retry-After', () => withRelay({ libraries: { test: { open: true } } }, async (running, root) => {
    const closing = running.relay.close();
    for (const url of [`${root}/v1/libraries/test/changes`, `${root}/healthz`]) {
      const res = await fetch(url);
      assert.equal(res.status, 503, url);
      assert.equal(res.headers.get('retry-after'), '1', url);
    }
    await closing;
  }));

  test('lets admitted work finish its file work, and refuses it only for a slot being released', () => withRelay({ libraries: { test: { open: true } } }, async (running) => {
    const s = await running.relay.slot('test');
    s.closing = true; // as shutdown marks it once requests are no longer admitted
    s.active = 1; // a request admitted before, still in flight
    assert.equal(await s.putImmutable('ops/a/1.json', Buffer.from('x')), 201);
    s.releasing = true;
    await assert.rejects(s.putImmutable('ops/a/2.json', Buffer.from('y')), /closing/);
    s.releasing = false; s.active = 0;
    await assert.rejects(s.putImmutable('ops/a/3.json', Buffer.from('z')), /closing/, 'nothing admitted: refused');
    s.closing = false;
  }));
});

const wasm = process.env.COLOPHON_HOME_WASM ?? new URL('../../target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm', import.meta.url).pathname;
describe('a home long poll at shutdown', { skip: existsSync(wasm) ? false : 'build colophon-home-wasm first' }, () => {
  // The fixture's device from seed 31 may read listening.podcasts (a test key).
  const identity = async (seed) => {
    const d = Buffer.from(hkdfSync('sha256', Buffer.alloc(32, seed), 'colophon/entropy/3', Buffer.alloc(8), 32));
    const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(d);
    const point = ecdh.getPublicKey();
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', d: d.toString('base64url'), x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') },
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    return { id: sha256(point).slice(0, 32), point, key };
  };
  const sign = async (who, p) => {
    const call = Buffer.from(JSON.stringify({
      account: fixture.account, args: { body: sha256(''), method: 'GET', path: p },
      asOf: { digest: fixture.asOf.digest, seq: fixture.asOf.seq }, audience: fixture.base,
      created: new Date(fixture.now).toISOString().replace(/\.\d{3}Z$/, 'Z'), key: who.point.toString('base64'),
      protocol: 'colophon/call/5', purpose: 'colophon.home.read', requestId: randomBytes(32).toString('base64url'), signer: { member: who.id },
    }));
    const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, who.key, call));
    return `Colophon ${Buffer.from(JSON.stringify({ body: call.toString('base64'), signature: signature.toString('base64') })).toString('base64url')}`;
  };

  test('is answered 503 when shutdown began while it was being judged', async () => {
    let armed = false; let reached; let resume;
    const atJudgement = new Promise((r) => { reached = r; });
    const gate = new Promise((r) => { resume = r; });
    const hook = async (point) => { if (armed && point === 'access changes') { armed = false; reached(); await gate; } };
    await withRelay({ clock: () => fixture.now, tracing: true, hook, libraries: { home: { home: true, base: fixture.base, account: fixture.account } },
      home: { wasm, key: fixture.key }, limits: { requestsPerMinute: 0 } }, async (running, root) => {
      const base = `${root}/v1/libraries/home`;
      const up = await fetch(`${base}/authority`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ from: 1, entries: fixture.entries, receipts: [] }) });
      assert.equal(up.status, 200);
      const member = await identity(31);
      const list = await fetch(`${base}/changes`, { headers: { authorization: await sign(member, '/changes') } });
      assert.equal(list.status, 200, await list.clone().text());
      const { cursor } = await list.json();
      const p = `/changes?after=${cursor}&wait=30`;
      armed = true;
      const poll = fetch(`${base}${p}`, { headers: { authorization: await sign(member, p) } });
      await atJudgement;
      const closing = running.relay.close();
      resume();
      const res = await poll;
      assert.equal(res.status, 503);
      assert.equal(res.headers.get('retry-after'), '1');
      await closing;
    });
  });
});
