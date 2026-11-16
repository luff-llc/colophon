// Provisioning (operator behaviour of the reference relay, not protocol): the door at
// POST /v1/provision, its gate and bounds, the durable table, the release of unclaimed slots on
// the relay's clock, and the client address behind a proxy. No test here waits on real time:
// every relay runs on a clock the test sets.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { SHARED_BUCKET, clientAddressConfig, clientAddressResolver, provisionConfig } from '../provision.js';
import { createRelay, startRelay } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready) {
  if (process.env.CI) throw new Error(`CI: the home module is missing (${wasm}); run scripts/test-home.sh, which builds it`);
  console.error(`SKIPPED: the provisioning tests need the module: cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm (${wasm})`);
}

const PREFIX = 'https://home.example/v1/libraries/';
const T0 = Date.parse('2026-11-16T00:00:00Z');
const HOUR = 3_600_000;
const TOKEN = 'test-token-0123456789abcdef';
const ORIGIN = 'https://taupe.toolsperson.com';
// Synthetic account IDs: nothing here uploads a history.
const ACCOUNT = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const sha = (b) => createHash('sha256').update(b).digest('hex');

/** One request over node:http, headers exactly as given (no defaults added). */
function raw(port, urlPath, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const h = { ...headers };
    if (body !== undefined && h['content-length'] === undefined && h['transfer-encoding'] === undefined) h['content-length'] = Buffer.byteLength(body);
    const req = http.request({ host: '127.0.0.1', port, path: urlPath, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}
const json = (r) => JSON.parse(r.body.toString('utf8'));
const JSON_TYPE = { 'content-type': 'application/json' };
const ask = (port, slot, { account = ACCOUNT, base = PREFIX + slot, headers = {} } = {}) =>
  raw(port, '/v1/provision', { method: 'POST', headers: { ...JSON_TYPE, ...headers }, body: JSON.stringify({ slot, base, account }) });

async function homeKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { jwk: await crypto.subtle.exportKey('jwk', pair.privateKey), pub: pair.publicKey };
}

/** A relay with provisioning on, on a clock the test moves. */
async function provisioned({ dir, key, provision = {}, libraries = {}, clock, ...rest }) {
  return startRelay({
    port: 0, dataDir: dir, tickMs: 0, libraries, clock,
    home: { wasm, key: key.jwk },
    provision: { enabled: true, prefix: PREFIX, ...provision },
    limits: { requestsPerMinute: 0 },
    ...rest,
  });
}

async function table(dir) {
  try { return JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8')); } catch { return null; }
}

describe('provisioning off', () => {
  test('the relay answers byte for byte as without the setting', async () => {
    const dirs = [await mkdtemp(path.join(tmpdir(), 'colophon-prov-')), await mkdtemp(path.join(tmpdir(), 'colophon-prov-'))];
    const libraries = { lib: { token: TOKEN } };
    const a = await startRelay({ port: 0, dataDir: dirs[0], libraries });
    const b = await startRelay({ port: 0, dataDir: dirs[1], libraries, provision: { enabled: false, maxSlots: 3 } });
    try {
      const cases = [
        ['/v1/provision', { method: 'POST', headers: JSON_TYPE, body: JSON.stringify({ slot: 'tabcdef0123', base: `${PREFIX}tabcdef0123`, account: ACCOUNT }) }],
        ['/v1/provision', {}],
        ['/v1/libraries/nothere', {}],
        ['/v1/libraries/nothere/head', { headers: { authorization: `Bearer ${TOKEN}` } }],
        ['/v1/libraries/UPPER', {}],
        ['/v1/libraries/lib', { headers: { authorization: 'Bearer wrong-token-0123456789' } }],
        ['/v1/libraries/lib', { headers: { authorization: `Bearer ${TOKEN}` } }],
      ];
      for (const [p, opts] of cases) {
        const [x, y] = [await raw(a.port, p, opts), await raw(b.port, p, opts)];
        const strip = (h) => Object.fromEntries(Object.entries(h).filter(([k]) => k !== 'date'));
        assert.equal(y.status, x.status, p);
        assert.deepEqual(strip(y.headers), strip(x.headers), p);
        assert.equal(y.body.toString(), x.body.toString(), p);
      }
      // And what that answer is: the 0.3 answers.
      const unknown = await raw(b.port, '/v1/libraries/nothere');
      assert.equal(unknown.status, 401);
      assert.equal(unknown.headers['www-authenticate'], 'Bearer');
      assert.deepEqual(json(unknown), { error: 'Unauthorized' });
      const door = await raw(b.port, '/v1/provision', { method: 'POST', headers: JSON_TYPE, body: '{}' });
      assert.equal(door.status, 404);
      assert.deepEqual(json(door), { error: 'Not found' });
      assert.equal(existsSync(path.join(dirs[1], 'provisioned.json')), false);
    } finally { await a.close(); await b.close(); for (const d of dirs) await rm(d, { recursive: true, force: true }); }
  });
});

describe('the provision and clientAddress settings', () => {
  test('bad settings refuse start-up', async () => {
    const bad = [
      { enabled: true }, // no prefix
      { enabled: true, prefix: 'https://home.example/v1/libraries' }, // no trailing slash
      { enabled: true, prefix: 'ftp://home.example/' },
      { enabled: true, prefix: PREFIX, gate: 'subscription' },
      { enabled: true, prefix: PREFIX, gate: 'token' }, // no tokenSha256
      { enabled: true, prefix: PREFIX, gate: 'token', tokenSha256: 'AB'.repeat(32) },
      { enabled: true, prefix: PREFIX, tokenSha256: sha(TOKEN) }, // a hash without gate token
      { enabled: true, prefix: PREFIX, maxSlots: 0 },
      { enabled: true, prefix: PREFIX, perAddressPerHour: 1.5 },
      { enabled: true, prefix: PREFIX, unclaimedHours: -1 },
      { enabled: true, prefix: PREFIX, slotPattern: '(' },
      { enabled: 'yes', prefix: PREFIX },
      { enabled: true, prefix: PREFIX, open: true },
      [],
    ];
    for (const p of bad) assert.throws(() => provisionConfig(p), Error, JSON.stringify(p));
    assert.equal(provisionConfig(undefined).enabled, false);
    assert.equal(provisionConfig({ enabled: true, prefix: PREFIX, gate: 'token', tokenSha256: sha(TOKEN) }).gate, 'token');
    for (const c of [{}, { header: 'CF-Connecting-IP' }, { header: 'CF-Connecting-IP', trustedPeers: [] },
      { header: 'CF Connecting', trustedPeers: ['127.0.0.1'] }, { header: 'X', trustedPeers: ['localhost'] }, { header: 'X', trustedPeers: ['127.0.0.1'], extra: 1 }]) {
      assert.throws(() => clientAddressConfig(c), Error, JSON.stringify(c));
    }
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-prov-'));
    try {
      await assert.rejects(createRelay({ dataDir: dir, libraries: {}, provision: { enabled: true, prefix: PREFIX, gate: 'subscription' } }), /not built/);
      await assert.rejects(createRelay({ dataDir: dir, libraries: {}, provision: { enabled: true, prefix: PREFIX } }), /home\.wasm/);
      const config = path.join(dir, 'config.json');
      await writeFile(config, JSON.stringify({ provision: { enabled: true, prefix: PREFIX, gate: 'token' }, dataDir: path.join(dir, 'data'), port: 0 }));
      const r = spawnSync(process.execPath, [path.join(here, '../server.js'), '--config', config], { encoding: 'utf8', timeout: 20_000, env: { ...process.env, COLOPHON_RELAY_PORT: '0' } });
      assert.equal(r.status, 2, r.stderr);
      assert.match(r.stderr, /tokenSha256/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});

describe('the client address', () => {
  const req = (peer, headers = {}) => ({ socket: { remoteAddress: peer }, headers });
  test('without the setting it is the socket address, as before', () => {
    const f = clientAddressResolver(null);
    assert.equal(f(req('10.0.0.1', { 'cf-connecting-ip': '1.2.3.4' })), '10.0.0.1');
    assert.equal(f({ socket: {}, headers: {} }), '');
  });
  test('the header is read only from a trusted peer; anything unusable is one shared bucket', () => {
    const f = clientAddressResolver(clientAddressConfig({ header: 'CF-Connecting-IP', trustedPeers: ['127.0.0.1', '::1'] }));
    assert.equal(f(req('127.0.0.1', { 'cf-connecting-ip': '203.0.113.7' })), '203.0.113.7');
    assert.equal(f(req('::ffff:127.0.0.1', { 'cf-connecting-ip': '203.0.113.7' })), '203.0.113.7', 'an IPv4-mapped peer is that peer');
    assert.equal(f(req('::1', { 'cf-connecting-ip': '2001:DB8::1' })), '2001:db8::1', 'IPv6, lower case');
    assert.equal(f(req('::1', { 'cf-connecting-ip': ' 203.0.113.7 ' })), '203.0.113.7');
    assert.equal(f(req('198.51.100.9', { 'cf-connecting-ip': '203.0.113.7' })), '198.51.100.9', 'ignored from another peer');
    for (const spoof of ['203.0.113.7, 198.51.100.1', '203.0.113.7,198.51.100.1', 'unknown', '', '203.0.113.7:443', '[2001:db8::1]']) {
      assert.equal(f(req('127.0.0.1', { 'cf-connecting-ip': spoof })), SHARED_BUCKET, JSON.stringify(spoof));
    }
    assert.equal(f(req('127.0.0.1', {})), SHARED_BUCKET, 'absent');
  });
});

describe('the provisioning door', { skip: ready ? false : `build the module first (${wasm})` }, () => {
  let dir; let key; let running; let now;
  const clock = () => now;
  before(async () => { key = await homeKey(); });
  const fresh = async (opts = {}) => {
    if (running) await running.close();
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-prov-'));
    now = T0;
    running = await provisioned({ dir, key, clock, ...opts });
    return running.port;
  };
  after(async () => { if (running) await running.close(); if (dir) await rm(dir, { recursive: true, force: true }); });

  test('answers the home\'s signed member request, durably, and serves the slot at once', async () => {
    const port = await fresh();
    const slot = 'tabcdef0123';
    const r = await ask(port, slot);
    assert.equal(r.status, 200, r.body.toString());
    assert.equal(r.headers['content-type'], 'application/json');
    assert.equal(Number(r.headers['content-length']), r.body.length);
    const env = json(r);
    assert.deepEqual(Object.keys(env).sort(), ['body', 'signature']);
    const bodyBytes = Buffer.from(env.body, 'base64');
    const body = JSON.parse(bodyBytes.toString('utf8'));
    const point = Buffer.from(await crypto.subtle.exportKey('raw', key.pub));
    assert.equal(body.protocol, 'colophon/request/5');
    assert.equal(body.account, ACCOUNT);
    assert.equal(body.member.signing, point.toString('base64'));
    assert.equal(Buffer.from(body.member.agreement, 'base64').length, 65);
    assert.equal(body.kind, 'server');
    assert.deepEqual(body.terms, { serves: ['home'] });
    assert.deepEqual(body.service, { endpoints: [`${PREFIX}${slot}/`] });
    assert.equal(Date.parse(body.created), T0 - 5_000);
    assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key.pub, Buffer.from(env.signature, 'base64'), bodyBytes), 'signed by the home key');
    // Durable: the row is on disk with the answered bytes.
    const t = await table(dir);
    assert.deepEqual(Object.keys(t), [slot]);
    assert.equal(t[slot].account, ACCOUNT);
    assert.equal(t[slot].base, PREFIX + slot);
    assert.equal(t[slot].at, T0);
    assert.equal(Buffer.from(t[slot].request, 'base64').toString(), r.body.toString());
    // The slot is a home now, without a restart.
    const id = await raw(port, `/v1/libraries/${slot}`);
    assert.equal(id.status, 200);
    assert.equal(json(id).home.member, createHash('sha256').update(point).digest('hex').slice(0, 32));
    assert.equal((await raw(port, `/v1/libraries/${slot}/head`)).status, 404, 'nothing uploaded yet');
    assert.ok(existsSync(path.join(dir, slot, 'home-state.json')));
    // The scheduler covers it: tickAll reads the slot table on every pass.
    const s = await running.relay.slot(slot);
    let ticked = 0;
    const tick = s.home.tick.bind(s.home);
    s.home.tick = async () => { ticked += 1; return tick(); };
    await running.relay.tickAll();
    assert.equal(ticked, 1);
  });

  test('the same slot and account again answers the same bytes; another account is 409', async () => {
    const port = await fresh();
    const first = await ask(port, 'tabcdef0123');
    now += 60_000;
    const again = await ask(port, 'tabcdef0123');
    assert.equal(again.status, 200);
    assert.equal(again.body.toString(), first.body.toString());
    const other = await ask(port, 'tabcdef0123', { account: OTHER });
    assert.equal(other.status, 409);
    assert.equal(Object.keys(await table(dir)).length, 1);
    assert.equal((await table(dir)).tabcdef0123.account, ACCOUNT);
  });

  test('bounds: the slot pattern, the base, the account, the body shape', async () => {
    const port = await fresh();
    for (const [slot, opts] of [
      ['short', {}], ['Tabcdef0123', {}], ['-tabcdef0123', {}], ['t'.repeat(65), {}], ['provisioned.json', {}],
      ['tabcdef0123', { base: `${PREFIX}other12345` }], ['tabcdef0123', { base: `${PREFIX}tabcdef0123/` }],
      ['tabcdef0123', { base: `https://elsewhere.example/v1/libraries/tabcdef0123` }],
      ['tabcdef0123', { account: ACCOUNT.toUpperCase() }], ['tabcdef0123', { account: 'ab' }],
    ]) {
      const r = await ask(port, slot, opts);
      assert.equal(r.status, 400, `${slot} ${JSON.stringify(opts)}`);
      assert.deepEqual(json(r), { result: 'malformed' });
    }
    for (const body of ['not json', '[]', '{}', JSON.stringify({ slot: 'tabcdef0123', base: `${PREFIX}tabcdef0123`, account: ACCOUNT, extra: 1 }),
      JSON.stringify({ slot: 1, base: `${PREFIX}tabcdef0123`, account: ACCOUNT })]) {
      const r = await raw(port, '/v1/provision', { method: 'POST', headers: JSON_TYPE, body });
      assert.equal(r.status, 400, body);
    }
    assert.equal(await table(dir), null, 'nothing provisioned');
  });

  test('a full home is 507 and an address over its hourly share is 429 until the hour passes', async () => {
    let port = await fresh({ provision: { maxSlots: 1 } });
    assert.equal((await ask(port, 'tslot000001')).status, 200);
    const full = await ask(port, 'tslot000002');
    assert.equal(full.status, 507);
    assert.deepEqual(json(full), { result: 'refused:overQuota' });
    assert.equal((await ask(port, 'tslot000001')).status, 200, 'its own slot again still answers');

    port = await fresh({ provision: { perAddressPerHour: 2 } });
    assert.equal((await ask(port, 'tslot000001')).status, 200);
    assert.equal((await ask(port, 'tslot000001')).status, 200, 'a repeat is not a new slot and is not counted');
    now += 10 * 60_000;
    assert.equal((await ask(port, 'tslot000002')).status, 200);
    const over = await ask(port, 'tslot000003');
    assert.equal(over.status, 429);
    assert.deepEqual(json(over), { result: 'refused:overQuota' });
    assert.equal(over.headers['retry-after'], String(50 * 60), 'until the first counted request is an hour old');
    now = T0 + HOUR;
    assert.equal((await ask(port, 'tslot000003')).status, 200, 'the first one has left the hour');
    assert.equal(Object.keys(await table(dir)).length, 3);
  });

  test('only application/json is taken, before the body is read; a page on an unlisted origin is refused', async () => {
    const port = await fresh({ cors: { origins: [ORIGIN] } });
    const body = JSON.stringify({ slot: 'tabcdef0123', base: `${PREFIX}tabcdef0123`, account: ACCOUNT });
    for (const type of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', 'application/jsonp', undefined]) {
      const r = await raw(port, '/v1/provision', { method: 'POST', headers: type ? { 'content-type': type } : {}, body });
      assert.equal(r.status, 415, String(type));
    }
    for (const origin of ['https://elsewhere.example', 'null', `${ORIGIN}.evil.example`]) {
      const r = await raw(port, '/v1/provision', { method: 'POST', headers: { ...JSON_TYPE, origin }, body });
      assert.equal(r.status, 403, origin);
    }
    assert.equal(await table(dir), null);
    assert.equal(existsSync(path.join(dir, 'tabcdef0123')), false, 'nothing created');
    // A listed origin's preflight succeeds, and its request is answered with the CORS headers.
    const pre = await raw(port, '/v1/provision', { method: 'OPTIONS', headers: { origin: ORIGIN, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type, authorization' } });
    assert.equal(pre.status, 204);
    assert.equal(pre.headers['access-control-allow-origin'], ORIGIN);
    const ok = await raw(port, '/v1/provision', { method: 'POST', headers: { 'content-type': 'application/json; charset=utf-8', origin: ORIGIN }, body });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers['access-control-allow-origin'], ORIGIN);
    assert.equal(ok.headers['cache-control'], 'no-store, no-transform');
    // Lengths and methods.
    assert.equal((await raw(port, '/v1/provision', { method: 'POST', headers: { ...JSON_TYPE, 'transfer-encoding': 'chunked' }, body })).status, 411);
    assert.equal((await raw(port, '/v1/provision', { method: 'POST', headers: JSON_TYPE, body: 'x'.repeat(5000) })).status, 413);
    const get = await raw(port, '/v1/provision');
    assert.equal(get.status, 405);
    assert.equal(get.headers.allow, 'POST');
  });

  test('gate token: a missing or wrong token is 403 and counted; over the share even the right token is 429', async () => {
    const port = await fresh({ provision: { gate: 'token', tokenSha256: sha(TOKEN), perAddressPerHour: 3 } });
    const missing = await ask(port, 'tslot000001');
    assert.equal(missing.status, 403);
    assert.deepEqual(json(missing), { result: 'refused:noEntitlement' });
    const wrong = await ask(port, 'tslot000001', { headers: { authorization: `Bearer ${TOKEN}x` } });
    assert.equal(wrong.status, 403);
    assert.equal((await ask(port, 'tslot000001', { headers: { authorization: `Basic ${TOKEN}` } })).status, 403, 'the third refusal uses the last of the share');
    assert.equal(await table(dir), null);
    const right = await ask(port, 'tslot000001', { headers: { authorization: `Bearer ${TOKEN}` } });
    assert.equal(right.status, 429, 'over the share, the token is not even looked at');
    now += HOUR;
    assert.equal((await ask(port, 'tslot000001', { headers: { authorization: `Bearer ${TOKEN}` } })).status, 200);
  });

  test('a slot this home does not hold is refused:notProvisioned; a configured slot keeps its answers', async () => {
    const port = await fresh({ libraries: { library0: { token: TOKEN } } });
    for (const p of ['/v1/libraries/nothere', '/v1/libraries/nothere/head', '/v1/libraries/UPPER']) {
      const r = await raw(port, p);
      assert.equal(r.status, 404, p);
      assert.deepEqual(json(r), { result: 'refused:notProvisioned' });
      assert.equal(r.headers['www-authenticate'], undefined);
    }
    const wrong = await raw(port, '/v1/libraries/library0', { headers: { authorization: 'Bearer wrong-token-0123456789' } });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.headers['www-authenticate'], 'Bearer');
    assert.equal((await raw(port, '/v1/libraries/library0', { headers: { authorization: `Bearer ${TOKEN}` } })).status, 200);
    // The door does not take a configured slot's name, nor a directory already on disk.
    assert.equal((await ask(port, 'library0', { base: `${PREFIX}library0` })).status, 409);
    assert.equal(existsSync(path.join(dir, 'nothere')), false);
  });

  test('a restart keeps provisioned slots and answers the same bytes', async () => {
    const port = await fresh();
    const first = await ask(port, 'tabcdef0123');
    await running.close();
    running = await provisioned({ dir, key, clock });
    assert.equal((await raw(running.port, '/v1/libraries/tabcdef0123')).status, 200);
    const again = await ask(running.port, 'tabcdef0123');
    assert.equal(again.body.toString(), first.body.toString());
    // Off after a restart (the table file is there, so the prefix is kept): the door is gone,
    // the slot is still served.
    await running.close();
    running = await startRelay({ port: 0, dataDir: dir, tickMs: 0, libraries: {}, clock, home: { wasm, key: key.jwk }, provision: { enabled: false, prefix: PREFIX } });
    await running.close();
    await assert.rejects(startRelay({ port: 0, dataDir: dir, tickMs: 0, libraries: {}, clock, home: { wasm, key: key.jwk } }), /provision\.prefix/);
    running = await startRelay({ port: 0, dataDir: dir, tickMs: 0, libraries: {}, clock, home: { wasm, key: key.jwk }, provision: { enabled: false, prefix: PREFIX } });
    assert.equal((await raw(running.port, '/v1/libraries/tabcdef0123')).status, 200);
    assert.equal((await ask(running.port, 'tabcdef0123')).status, 404);
  });

  test('a configured slot and a provisioned one that disagree refuse start-up', async () => {
    await fresh();
    assert.equal((await ask(running.port, 'tabcdef0123')).status, 200);
    await running.close(); running = null;
    const base = `${PREFIX}tabcdef0123`;
    await assert.rejects(provisioned({ dir, key, clock, libraries: { tabcdef0123: { home: true, base, account: OTHER } } }), /must agree/);
    await assert.rejects(provisioned({ dir, key, clock, libraries: { tabcdef0123: { token: TOKEN } } }), /must agree/);
    running = await provisioned({ dir, key, clock, libraries: { tabcdef0123: { home: true, base, account: ACCOUNT } } });
    assert.equal((await raw(running.port, '/v1/libraries/tabcdef0123')).status, 200);
  });

  test('a slot nobody claimed is released after unclaimedHours, at the next provision or start-up', async () => {
    const port = await fresh({ provision: { unclaimedHours: 24 } });
    assert.equal((await ask(port, 'tslot00000a')).status, 200);
    now = T0 + 24 * HOUR - 1;
    assert.equal((await ask(port, 'tslot00000b')).status, 200);
    assert.deepEqual(Object.keys(await table(dir)).sort(), ['tslot00000a', 'tslot00000b'], 'not yet');
    now = T0 + 24 * HOUR;
    assert.equal((await ask(port, 'tslot00000c')).status, 200);
    assert.deepEqual(Object.keys(await table(dir)).sort(), ['tslot00000b', 'tslot00000c']);
    assert.equal(existsSync(path.join(dir, 'tslot00000a')), false, 'its directory is removed');
    const gone = await raw(port, '/v1/libraries/tslot00000a');
    assert.equal(gone.status, 404);
    assert.deepEqual(json(gone), { result: 'refused:notProvisioned' });
    now = T0 + 30 * HOUR;
    // Released, the name can be provisioned again, for anyone.
    assert.equal((await ask(port, 'tslot00000a', { account: OTHER })).status, 200);
    // At start-up.
    await running.close();
    now = T0 + 48 * HOUR;
    running = await provisioned({ dir, key, clock, provision: { unclaimedHours: 24 } });
    assert.deepEqual(Object.keys(await table(dir)).sort(), ['tslot00000a'], 'b and c were released at start-up');
    assert.equal(existsSync(path.join(dir, 'tslot00000b')), false);
  });

  test('both limits count the client address behind a trusted proxy', async () => {
    const port = await fresh({ provision: { perAddressPerHour: 1 }, clientAddress: { header: 'CF-Connecting-IP', trustedPeers: ['127.0.0.1', '::1'] } });
    const from = (ip) => (ip ? { 'cf-connecting-ip': ip } : {});
    assert.equal((await ask(port, 'tslot000001', { headers: from('203.0.113.1') })).status, 200);
    assert.equal((await ask(port, 'tslot000002', { headers: from('203.0.113.1') })).status, 429);
    assert.equal((await ask(port, 'tslot000002', { headers: from('203.0.113.2') })).status, 200, 'another client has its own share');
    assert.equal((await ask(port, 'tslot000003', { headers: from('203.0.113.3, 203.0.113.4') })).status, 200, 'a list: the shared bucket');
    assert.equal((await ask(port, 'tslot000004')).status, 429, 'no header: the same shared bucket, never unlimited');
    // The home's per-address request limit uses the same address.
    await running.close();
    running = await provisioned({ dir, key, clock, limits: { requestsPerMinute: 2 }, clientAddress: { header: 'CF-Connecting-IP', trustedPeers: ['127.0.0.1'] } });
    const head = (ip) => raw(running.port, '/v1/libraries/tslot000001/head', { headers: from(ip) });
    assert.deepEqual([(await head('203.0.113.1')).status, (await head('203.0.113.1')).status, (await head('203.0.113.1')).status], [404, 404, 429]);
    assert.equal((await head('203.0.113.9')).status, 404, 'another client is not limited by the first');
  });
});

/** A table file as the relay writes it. */
const tableText = (rows) => {
  const out = {};
  for (const [slot, e] of Object.entries(rows).sort(([a], [b]) => (a < b ? -1 : 1))) out[slot] = { account: e.account, base: e.base, at: e.at, request: e.request };
  return JSON.stringify(out) + '\n';
};

describe('releasing an unclaimed slot', { skip: ready ? false : 'module not built' }, () => {
  let dir; let key; let now;
  const clock = () => now;
  before(async () => { key = await homeKey(); });
  const begin = async (hook) => {
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-prov-'));
    now = T0;
    return provisioned({ dir, key, clock, tracing: true, hook });
  };
  const settle = () => new Promise((resolve) => setImmediate(resolve));

  test('a request paused after its access check, a release and a provision of the name for another account', async () => {
    // The pause point: right after the home's access check, in A's upload. The release's drain
    // point tells the test the provision of B is waiting on A.
    let resume; const gate = new Promise((r) => { resume = r; });
    let paused; const pausedAt = new Promise((r) => { paused = r; });
    let draining; const drainingAt = new Promise((r) => { draining = r; });
    let armed = true;
    const running = await begin((point) => {
      if (point === 'access authority' && armed) { armed = false; paused(); return gate; }
      if (point.startsWith('release draining')) draining();
      return undefined;
    });
    const slot = 'tslot00000a';
    try {
      assert.equal((await ask(running.port, slot)).status, 200);
      const a = raw(running.port, `/v1/libraries/${slot}/authority`, { method: 'POST', headers: JSON_TYPE,
        body: JSON.stringify({ from: 1, entries: [{}], receipts: [] }) });
      await pausedAt;
      now = T0 + 25 * HOUR;
      const b = ask(running.port, slot, { account: OTHER });
      await drainingAt;
      // Closing: out of dispatch at once, and its directory still there while A is in flight.
      const during = await raw(running.port, `/v1/libraries/${slot}`);
      assert.equal(during.status, 404);
      assert.deepEqual(json(during), { result: 'refused:notProvisioned' });
      assert.ok(existsSync(path.join(dir, slot, 'home-state.json')), 'not removed while A is in flight');
      resume();
      const [ra, rb] = [await a, await b];
      assert.equal(ra.status, 422, 'A held nothing (not a genesis), so the release went on after it');
      assert.equal(rb.status, 200, rb.body.toString());
      const s = await running.relay.slot(slot);
      assert.equal(s.home.status().account, OTHER, 'B\'s slot is B\'s');
      assert.equal(s.home.status().held, 0, 'nothing of A in it');
      assert.equal((await table(dir))[slot].account, OTHER);
    } finally { await running.close(); }
    // A restart finds no account mismatch.
    const again = await provisioned({ dir, key, clock });
    try { assert.equal((await raw(again.port, `/v1/libraries/${slot}`)).status, 200); } finally { await again.close(); await rm(dir, { recursive: true, force: true }); }
  });

  test('a long poll waiting on the slot is woken and ended by the release', async () => {
    const running = await begin(undefined);
    const slot = 'tslot00000a';
    try {
      assert.equal((await ask(running.port, slot)).status, 200);
      // A home serves its change feed only to a caller its module allows; this test stands in
      // for that allowance, so the relay's own long poll runs on the slot.
      const s = await running.relay.slot(slot);
      s.home.handle = async () => false;
      const first = json(await raw(running.port, `/v1/libraries/${slot}/changes`));
      const poll = raw(running.port, `/v1/libraries/${slot}/changes?after=${encodeURIComponent(first.cursor)}&wait=30`);
      while (s.waiters.size === 0) await settle();
      now = T0 + 25 * HOUR;
      assert.equal((await ask(running.port, 'tslot00000b')).status, 200, 'its provision released the first slot');
      const ended = await poll;
      assert.equal(ended.status, 404);
      assert.deepEqual(json(ended), { result: 'refused:notProvisioned' });
      assert.equal(existsSync(path.join(dir, slot)), false);
      assert.equal(s.active, 0);
      // A late use of the released Slot fails closed.
      await assert.rejects(s.putImmutable('authority/00000001.json', Buffer.from('x')), /released/);
      assert.equal(existsSync(path.join(dir, slot)), false);
    } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
  });

  test('a release racing two provisions of the name by the same account: both answer the same new bytes', async () => {
    const running = await begin(undefined);
    const slot = 'tslot00000a';
    try {
      const original = await ask(running.port, slot);
      now = T0 + 25 * HOUR;
      const [x, y] = await Promise.all([ask(running.port, slot), ask(running.port, slot)]);
      assert.equal(x.status, 200);
      assert.equal(y.status, 200);
      assert.equal(x.body.toString(), y.body.toString());
      assert.notEqual(x.body.toString(), original.body.toString(), 'released, then provisioned anew');
      const t = await table(dir);
      assert.deepEqual(Object.keys(t), [slot]);
      assert.equal(t[slot].at, T0 + 25 * HOUR);
      assert.equal((await raw(running.port, `/v1/libraries/${slot}`)).status, 200);
    } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
  });
});

describe('the provisioning table at start-up', { skip: ready ? false : 'module not built' }, () => {
  let key; let other; const now = T0; const clock = () => now;
  before(async () => { key = await homeKey(); other = await homeKey(); });

  /** A table with two good rows, made by the door; `edit` changes it; start-up must refuse. */
  async function refuses(edit, pattern, opts = {}) {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-prov-'));
    try {
      const r = await provisioned({ dir, key, clock });
      assert.equal((await ask(r.port, 'tslot00000a')).status, 200);
      assert.equal((await ask(r.port, 'tslot00000b', { account: OTHER })).status, 200);
      await r.close();
      const file = path.join(dir, 'provisioned.json');
      const rows = JSON.parse(await readFile(file, 'utf8'));
      const text = await edit(rows);
      await writeFile(file, text ?? tableText(rows));
      await assert.rejects(provisioned({ dir, key: opts.key ?? key, clock, ...(opts.provision ? { provision: opts.provision } : {}) }), pattern);
    } finally { await rm(dir, { recursive: true, force: true }); }
  }

  test('a row whose base is not prefix + slot', () => refuses((t) => { t.tslot00000a.base = 'https://evil.example/'; }, /"tslot00000a": base/));
  test('a request that is not base64', () => refuses((t) => { t.tslot00000a.request = '!!!'; }, /"tslot00000a": request is not base64/));
  test('a request that is not a member request', () => refuses((t) => { t.tslot00000a.request = Buffer.from('{"body":"e30=","signature":""}').toString('base64'); }, /"tslot00000a": request: home module/));
  test('a request for another account', () => refuses((t) => { t.tslot00000a.account = OTHER; }, /"tslot00000a": request: .*another account/));
  test('a request for another endpoint', () => refuses((t) => { t.tslot00000c = { ...t.tslot00000a, base: `${PREFIX}tslot00000c` }; delete t.tslot00000a; }, /"tslot00000c": request: .*another endpoint/));
  test('a request signed by another home key', () => refuses(() => undefined, /"tslot00000a": request: .*not this home/, { key: other }));
  test('a slot that breaks slotPattern', () => refuses(() => undefined, /"tslot00000a": the slot does not match/, { provision: { enabled: true, prefix: PREFIX, slotPattern: '^z' } }));
  test('a row with another field', () => refuses((t) => { t.tslot00000a.extra = 1; return JSON.stringify(t) + '\n'; }, /"tslot00000a" is not exactly/));
  test('a prototype key', () => refuses((t) => `{"__proto__":${JSON.stringify(t.tslot00000a)}}\n`, /"__proto__" is not a slot name/));
  test('a duplicate key', () => refuses((t) => tableText(t).replace('{"tslot00000a":', `{"tslot00000a":${JSON.stringify(t.tslot00000b)},"tslot00000a":`), /not as this relay writes it/));
  test('a hand edit', () => refuses((t) => JSON.stringify(t, null, 2), /not as this relay writes it/));
  test('not JSON', () => refuses(() => '{', /not JSON/));
  test('a table over its bound', () => refuses(() => ' '.repeat(10 * 1024 * 1024), /over its bound/));
});

describe('provisioning off leaves provisioned.json alone', () => {
  test('a 0.3 slot named provisioned.json starts and serves; staging-like files are not touched', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-prov-'));
    const libraries = { 'provisioned.json': { token: TOKEN } };
    const auth = { authorization: `Bearer ${TOKEN}` };
    try {
      let r = await startRelay({ port: 0, dataDir: dir, libraries });
      const put = await raw(r.port, '/v1/libraries/provisioned.json/records/authority/00000001.json',
        { method: 'PUT', headers: { ...auth, 'if-none-match': '*' }, body: 'genesis' });
      assert.equal(put.status, 201);
      await r.close();
      await writeFile(path.join(dir, '.provisioned.json.0123'), 'not ours to remove');
      for (const provision of [undefined, { enabled: false }, { enabled: false, prefix: PREFIX }]) {
        r = await startRelay({ port: 0, dataDir: dir, libraries, provision });
        const get = await raw(r.port, '/v1/libraries/provisioned.json/records/authority/00000001.json', { headers: auth });
        assert.equal(get.status, 200);
        assert.equal(get.body.toString(), 'genesis');
        await r.close();
      }
      assert.ok(existsSync(path.join(dir, '.provisioned.json.0123')), 'nothing scanned or removed');
      // Turning provisioning on with that slot there is refused, with a message.
      await assert.rejects(startRelay({ port: 0, dataDir: dir, libraries: {}, provision: { enabled: true, prefix: PREFIX } }), /not a regular file/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  test('prefix: https, or plain http only to a loopback host', () => {
    assert.throws(() => provisionConfig({ enabled: true, prefix: 'http://home.example/' }), /https/);
    assert.throws(() => provisionConfig({ enabled: false, prefix: 'http://home.example/' }), /https/);
    for (const prefix of ['http://127.0.0.1:8080/v1/libraries/', 'http://localhost/', 'http://[::1]:9/', 'https://home.example/']) {
      assert.equal(provisionConfig({ enabled: true, prefix }).prefix, prefix);
    }
  });
});
