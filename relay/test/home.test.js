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
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
// Tests that cannot run must not pass by skipping: on CI a missing module fails the run; on a
// workstation the skip is said out loud.
if (!ready) {
  if (process.env.CI) throw new Error(`CI: the home module is missing (${wasm}); run scripts/test-home.sh, which builds it`);
  console.error(`SKIPPED: the home tests need the module: cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm (${wasm})`);
}
const BASE = 'https://home-a.example';
const TOKEN = 'test-token-0123456789abcdef';
// A synthetic account ID: nothing here uploads a history.
const ACCOUNT = 'ab'.repeat(32);

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
      libraries: { home: { home: true, base: BASE, account: ACCOUNT }, plain: { token: TOKEN } },
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
    assert.deepEqual(body.layouts, [2]);
    assert.equal(body.limits.authorityBodyBytes, undefined, 'home-only limits are not published');
    // A slot that is not a home says nothing of one.
    const plain = await (await fetch(`${home.replace('/home', '/plain')}`, { headers: { authorization: `Bearer ${TOKEN}` } })).json();
    assert.equal(plain.home, undefined);
    assert.equal(plain.layouts, undefined);
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

  test('before it is appointed a home serves nothing but its identity: every read is 404', async () => {
    for (const p of ['/head', '/authority?after=0&limit=64', '/pending?after=0&limit=64', '/pending/' + '0'.repeat(64),
      '/changes', '/records/authority/00000001.json', '/records/blobs/' + '0'.repeat(64), '/predecessor/authority/00000001.json']) {
      assert.equal((await fetch(url(p))).status, 404, p);
    }
    assert.equal((await fetch(url(''))).status, 200);
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
    assert.equal((await fetch(url('/records/authority/00000001.json'))).status, 404, 'nothing held');
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
    const auth = {};
    assert.equal((await fetch(url('/records/.hidden'), { headers: auth })).status, 400);
    assert.equal((await fetch(url('/records/requests/a.json'), { headers: auth })).status, 400, 'requests/ is not a 0.5 path');
    // History files are written by admission only.
    const put = await fetch(url('/records/authority/00000001.json'), { method: 'PUT', headers: { ...auth, 'if-none-match': '*' }, body: '{}' });
    assert.equal(put.status, 405);
    assert.equal((await fetch(url('/head'), { method: 'POST', body: '{}' })).status, 405);
    assert.equal((await fetch(url('/pending'), { method: 'DELETE' })).status, 405);
  });

  test('a bearer token authorizes nothing at a home slot', async () => {
    const auth = { authorization: `Bearer ${TOKEN}` };
    for (const p of ['/changes', '/records/blobs/' + '0'.repeat(64)]) assert.equal((await fetch(url(p), { headers: auth })).status, 404, p);
    const w = await fetch(url('/records/blobs/' + '0'.repeat(64)), { method: 'PUT', headers: { ...auth, 'if-none-match': '*' }, body: 'x' });
    assert.equal(w.status, 404);
  });

  test('a head from another home is refused unless it is a head', async () => {
    const r = await fetch(url('/records/heads/' + '1'.repeat(32) + '.json'), { method: 'PUT', body: 'garbage' });
    assert.equal(r.status, 422);
    assert.equal((await r.json()).result, 'unavailable', 'nothing held yet');
  });
});

describe('the request rate limit', { skip: ready ? false : 'module not built' }, () => {
  test('a home slot answers 429 with Retry-After beyond the limit', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-home-'));
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const running = await startRelay({
      port: 0, dataDir: dir, tickMs: 0, libraries: { home: { home: true, base: BASE, account: ACCOUNT } },
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

describe('provisioning and the test clock', { skip: ready ? false : 'module not built' }, () => {
  test('a home slot needs the account it is provisioned for', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-home-'));
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    try {
      await assert.rejects(startRelay({ port: 0, dataDir: dir, tickMs: 0, libraries: { home: { home: true, base: BASE } },
        home: { wasm, key: await crypto.subtle.exportKey('jwk', pair.privateKey) } }), /account/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  test('a home key whose x and y are not the public half of d is refused', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-home-'));
    const a = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).privateKey);
    const b = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).privateKey);
    try {
      await assert.rejects(startRelay({ port: 0, dataDir: dir, tickMs: 0, libraries: { home: { home: true, base: BASE, account: ACCOUNT } },
        home: { wasm, key: { ...a, x: b.x, y: b.y } } }), /public half|Invalid keyData/); // Bun's importKey refuses it already; the probe covers runtimes that do not
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  test('COLOPHON_RELAY_CLOCK_FILE without --test-clock: the relay refuses to start', async () => {
    const { spawnSync } = await import('node:child_process');
    const r = spawnSync(process.execPath, [path.join(here, '../server.js')], {
      env: { ...process.env, COLOPHON_RELAY_CLOCK_FILE: '/nonexistent', COLOPHON_RELAY_OPEN: 'x', COLOPHON_RELAY_PORT: '0' },
      encoding: 'utf8', timeout: 20_000,
    });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /--test-clock/);
  });
});
