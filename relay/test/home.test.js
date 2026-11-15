// The 0.5 home slot, as far as it can be exercised without an account: what the relay does with
// requests before any history exists, the bounds it enforces before it reads a body, the path
// grammar, and that it holds no key in the open. Account-level cases (receipts, vetoes, quorum,
// calls, restart, the engine's journeys) need real histories built by the Rust core and live in
// crates/colophon-home-wasm/tests, which start this relay as a process.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startRelay } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const WASM = process.env.COLOPHON_HOME_WASM ?? process.env.CARGO_TARGET_DIR
  ? path.join(process.env.CARGO_TARGET_DIR ?? '', 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm')
  : path.join(here, '../../target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const wasm = process.env.COLOPHON_HOME_WASM ?? WASM;
const ready = existsSync(wasm);
const BASE = 'https://home-a.example';
const TOKEN = 'test-token-0123456789abcdef';

describe('a 0.5 home slot', { skip: ready ? false : `build the module first: cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm (${wasm})` }, () => {
  let dir; let running; let home; let jwk;
  const url = (p) => `${home}${p}`;
  const json = { 'content-type': 'application/json' };

  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-home-'));
    // A key made for this test: it protects nothing.
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    running = await startRelay({
      port: 0, dataDir: dir, tickMs: 0,
      libraries: { home: { token: TOKEN, home: true, base: BASE }, plain: { token: TOKEN } },
      home: { wasm, key: jwk },
      limits: { requestsPerMinute: 0, authorityBodyBytes: 4096, pendingBodyBytes: 4096 },
    });
    home = `http://127.0.0.1:${running.port}/v1/libraries/home`;
  });
  after(async () => { await running.close(); await rm(dir, { recursive: true, force: true }); });

  test('GET {base} names the home and keeps the 0.3 protocol marker', async () => {
    const r = await fetch(url(''));
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.protocol, 'colophon/relay/3');
    assert.match(body.home.member, /^[0-9a-f]{32}$/);
    assert.equal(body.limits.authorityBodyBytes, undefined, 'home-only limits are not published');
    // A slot that is not a home says nothing of one.
    const plain = await (await fetch(`${home.replace('/home', '/plain')}`, { headers: { authorization: `Bearer ${TOKEN}` } })).json();
    assert.equal(plain.home, undefined);
  });

  test('the member ID is the key ID of the configured key and the private key is never served', async () => {
    const body = await (await fetch(url(''))).json();
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    const { createHash } = await import('node:crypto');
    assert.equal(body.home.member, createHash('sha256').update(point).digest('hex').slice(0, 32));
    for (const p of ['', '/head', '/authority', '/pending', '/changes']) {
      const text = await (await fetch(url(p), { headers: { authorization: `Bearer ${TOKEN}` } })).text();
      assert.ok(!text.includes(jwk.d), `${p} must not carry the key`);
    }
  });

  test('before any history: no head, empty history and pending feed, nothing to read', async () => {
    assert.equal((await fetch(url('/head'))).status, 404);
    const a = await fetch(url('/authority?after=0&limit=64'));
    assert.deepEqual(await a.json(), { entries: [], receipts: [], more: false });
    const p = await fetch(url('/pending?after=0&limit=64'));
    assert.deepEqual(await p.json(), { objects: [], more: false });
    assert.equal((await fetch(url('/pending/' + '0'.repeat(64)))).status, 404);
  });

  test('a body that is not strict JSON, or not the shape of the endpoint, is 422 malformed and stores nothing', async () => {
    for (const body of ['not json', '{}', '{"from":1,"entries":[]}', '{"from":1,"entries":[{}],"extra":1}']) {
      const r = await fetch(url('/authority'), { method: 'POST', headers: json, body });
      assert.equal(r.status, 422, body);
      assert.equal((await r.json()).result, 'malformed');
    }
    const r = await fetch(url('/pending'), { method: 'POST', headers: json, body: '{"objects":[]}' });
    assert.equal(r.status, 422);
    assert.equal((await fetch(url('/head'))).status, 404, 'nothing was signed or stored');
  });

  test('an entry that does not verify is refused with its §1 result and nothing is stored', async () => {
    const forged = { body: Buffer.from('{"protocol":"colophon/authority/5","seq":1}').toString('base64'), signature: 'AAAA' };
    const r = await fetch(url('/authority'), { method: 'POST', headers: json, body: JSON.stringify({ from: 1, entries: [forged], receipts: [] }) });
    assert.equal(r.status, 422);
    assert.match((await r.json()).result, /^(malformed|badSignature)/);
    const changes = await (await fetch(url('/changes'), { headers: { authorization: `Bearer ${TOKEN}` } })).json();
    assert.deepEqual(changes.entries, []);
  });

  test('bounds are checked before a body is read: no length 411, too long 413', async () => {
    const noLength = await new Promise((resolve) => {
      import('node:http').then(({ default: http }) => {
        const req = http.request(url('/authority'), { method: 'POST', headers: { 'transfer-encoding': 'chunked' } }, (res) => { res.resume(); resolve(res.statusCode); });
        req.write('{'); req.end();
      });
    });
    assert.equal(noLength, 411);
    const big = await fetch(url('/authority'), { method: 'POST', headers: json, body: 'x'.repeat(5000) });
    assert.equal(big.status, 413);
  });

  test('the path grammar and the methods of the home paths', async () => {
    const auth = { authorization: `Bearer ${TOKEN}` };
    assert.equal((await fetch(url('/records/.hidden'), { headers: auth })).status, 400);
    assert.equal((await fetch(url('/records/requests/a.json'), { headers: auth })).status, 400, 'requests/ is not a 0.5 path');
    // History files are written by admission only.
    const put = await fetch(url('/records/authority/00000001.json'), { method: 'PUT', headers: { ...auth, 'if-none-match': '*' }, body: '{}' });
    assert.equal(put.status, 405);
    assert.equal((await fetch(url('/head'), { method: 'POST', body: '{}' })).status, 405);
    assert.equal((await fetch(url('/pending'), { method: 'DELETE' })).status, 405);
  });

  test('records need storage access: a token, or a call; no credential is 401', async () => {
    const r = await fetch(url('/records/blobs/' + '0'.repeat(64)));
    assert.equal(r.status, 401);
    const w = await fetch(url('/records/blobs/' + '0'.repeat(64)), { method: 'PUT', headers: { 'if-none-match': '*' }, body: 'x' });
    assert.equal(w.status, 401);
    assert.equal((await fetch(url('/changes'))).status, 401);
  });

  test('a head from another home is refused unless it is a head', async () => {
    const r = await fetch(url('/records/heads/' + '1'.repeat(32) + '.json'), { method: 'PUT', body: 'garbage' });
    assert.equal(r.status, 400);
  });
});

describe('the request rate limit', { skip: ready ? false : 'module not built' }, () => {
  test('a home slot answers 429 with Retry-After beyond the limit', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-home-'));
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const running = await startRelay({
      port: 0, dataDir: dir, tickMs: 0, libraries: { home: { home: true, base: BASE } },
      home: { wasm, key: await crypto.subtle.exportKey('jwk', pair.privateKey) }, limits: { requestsPerMinute: 5 },
    });
    try {
      const statuses = [];
      let retry;
      for (let i = 0; i < 8; i += 1) {
        const r = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/home/head`);
        statuses.push(r.status);
        if (r.status === 429) retry = r.headers.get('retry-after');
      }
      assert.deepEqual(statuses.slice(0, 5), [404, 404, 404, 404, 404]);
      assert.ok(statuses.slice(5).every((s) => s === 429), statuses.join());
      assert.equal(retry, '60');
    } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
  });
});
