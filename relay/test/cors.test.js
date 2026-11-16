// Cross-origin answers and uncompressed answers (operator behaviour of the reference relay, not
// protocol). Every answer to a listed origin carries the CORS headers, whatever its status and
// whoever wrote it; an unlisted origin gets none; a preflight is answered before any slot,
// authorization or rate work; no answer is compressed or transformable. No test here waits on
// real time.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { corsOrigins, createRelay, startRelay } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready) {
  if (process.env.CI) throw new Error(`CI: the home module is missing (${wasm}); run scripts/test-home.sh, which builds it`);
  console.error(`SKIPPED: the home-slot CORS tests need the module: cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm (${wasm})`);
}

const ORIGIN = 'https://taupe.toolsperson.com';
const OTHER = 'http://127.0.0.1:5173';
const TOKEN = 'test-token-0123456789abcdef';
const AUTH = { authorization: `Bearer ${TOKEN}` };
const BASE = 'https://home-a.example';
const ACCOUNT = 'ab'.repeat(32); // synthetic: nothing here uploads a history
const sha = (b) => createHash('sha256').update(b).digest('hex');

/** One request over node:http, so the headers are exactly what the relay sent (no decoding, no
 * forbidden-header rules). Every request asks for compression; the relay must ignore that. */
function raw(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const h = { 'accept-encoding': 'gzip, br', ...headers };
    if (body !== undefined && h['content-length'] === undefined && h['transfer-encoding'] === undefined) h['content-length'] = Buffer.byteLength(body);
    const req = http.request(url, { method, headers: h }, (res) => {
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

const corsNames = (headers) => Object.keys(headers).filter((n) => n.startsWith('access-control-'));

/** Every answer: uncompressed, no-transform, never credentials. */
function assertPlain(r, what) {
  assert.equal(r.headers['content-encoding'], undefined, `${what}: no Content-Encoding`);
  assert.equal(r.headers['cache-control'], 'no-store, no-transform', `${what}: Cache-Control`);
  assert.equal(r.headers['access-control-allow-credentials'], undefined, `${what}: never credentials`);
  if (r.headers['content-length'] !== undefined) assert.equal(Number(r.headers['content-length']), r.body.length, `${what}: body is the length sent`);
}

function assertListed(r, origin, what) {
  assertPlain(r, what);
  assert.equal(r.headers['access-control-allow-origin'], origin, `${what}: Allow-Origin`);
  assert.equal(r.headers['access-control-expose-headers'], 'ETag, Retry-After, WWW-Authenticate', `${what}: Expose-Headers`);
  assert.equal(r.headers.vary, 'Origin', `${what}: Vary`);
}

function assertUnlisted(r, what, { vary = true } = {}) {
  assertPlain(r, what);
  assert.deepEqual(corsNames(r.headers), [], `${what}: no Access-Control-* header`);
  assert.equal(r.headers.vary, vary ? 'Origin' : undefined, `${what}: Vary`);
}

describe('CORS on a plain relay with an origin list', () => {
  let dir; let running; let root; let slot;
  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-cors-'));
    running = await startRelay({
      port: 0, dataDir: dir, cors: { origins: [ORIGIN, OTHER] },
      libraries: { home: { token: TOKEN }, full: { token: TOKEN }, broken: { token: TOKEN }, untouched: { token: TOKEN } },
      limits: { recordBytes: 64, slotBytes: 0 },
    });
    root = `http://127.0.0.1:${running.port}`;
    slot = `${root}/v1/libraries/home`;
    // A slot whose storage is a file, not a directory: opening it fails, an internal error.
    await writeFile(path.join(dir, 'broken'), 'not a directory');
  });
  after(async () => { await running.close(); await rm(dir, { recursive: true, force: true }); });

  /** The answers of this relay, one per status, each written by a different call site. */
  let round = 0;
  async function answers(headers) {
    const out = [];
    round += 1;
    const op = `${slot}/records/ops/a/${String(round).padStart(12, '0')}-x.json`;
    const ask = async (status, url, opts = {}) => {
      const r = await raw(url, { ...opts, headers: { ...headers, ...(opts.headers ?? {}) } });
      assert.equal(r.status, status, `${opts.method ?? 'GET'} ${url}: ${r.body}`);
      out.push([`${status} ${opts.method ?? 'GET'} ${url.slice(root.length)}`, r]);
      return r;
    };
    const rec = `${slot}/records/authority/00000001.json`;
    const put = (body, extra = {}) => ({ method: 'PUT', body, headers: { ...AUTH, 'if-none-match': '*', ...extra } });
    await ask(200, `${root}/healthz`);
    await ask(200, slot, { headers: AUTH });
    const created = await ask(201, op, put('one'));
    assert.equal(created.headers.etag, `"${sha('one')}"`);
    const read = await ask(200, op, { headers: AUTH });
    assert.equal(read.body.toString(), 'one');
    await ask(200, op, put('one')); // idempotent re-put
    await ask(201, `${slot}/records/requests/r.json`, { method: 'PUT', body: 'q', headers: AUTH });
    await ask(204, `${slot}/records/requests/r.json`, { method: 'DELETE', headers: AUTH });
    await ask(400, `${slot}/records/.hidden`, { headers: AUTH });
    const unauth = await ask(401, slot);
    assert.equal(unauth.headers['www-authenticate'], 'Bearer');
    await ask(401, `${root}/v1/libraries/nobody`);
    await ask(404, `${root}/nowhere`);
    await ask(404, `${slot}/records/ops/a/999999999999-x.json`, { headers: AUTH });
    await ask(405, `${slot}/changes`, { method: 'POST', body: '', headers: AUTH });
    await ask(410, `${slot}/changes?after=nope.1`, { headers: AUTH });
    await ask(411, rec, { method: 'PUT', headers: { ...AUTH, 'if-none-match': '*', 'transfer-encoding': 'chunked' }, body: 'x' });
    await ask(412, op, put('two'));
    await ask(413, rec, put('x'.repeat(65)));
    await ask(428, `${slot}/records/ops/a/000000000002-x.json`, { method: 'PUT', body: 'z', headers: AUTH });
    await ask(500, `${root}/v1/libraries/broken`, { headers: AUTH });
    return out;
  }

  test('a listed origin gets the CORS headers on every answer, whatever its status', async () => {
    for (const origin of [ORIGIN, OTHER]) {
      for (const [what, r] of await answers({ origin })) assertListed(r, origin, what);
    }
  });

  test('an unlisted origin, or none, gets no Access-Control-* header but still Vary: Origin', async () => {
    for (const [what, r] of await answers({})) assertUnlisted(r, `no Origin: ${what}`);
    for (const [what, r] of await answers({ origin: 'https://elsewhere.example' })) assertUnlisted(r, `unlisted: ${what}`);
  });

  test('the origin is compared whole, byte for byte', async () => {
    const near = [
      'https://TAUPE.toolsperson.com', 'HTTPS://taupe.toolsperson.com', // case
      'https://taupe.toolsperson.com:443', 'https://taupe.toolsperson.com:8443', // port
      'http://taupe.toolsperson.com', // scheme
      'https://taupe.toolsperson.com.', // trailing dot
      'https://taupe.toolsperson.com.evil.example', 'https://evil-taupe.toolsperson.com', 'https://taupe.toolsperson.co', // suffix, prefix
      'https://taupe.toolsperson.com/', 'null', '*', `${ORIGIN}, ${OTHER}`,
    ];
    for (const origin of near) {
      for (const url of [`${root}/healthz`, slot]) assertUnlisted(await raw(url, { headers: { origin } }), `${origin} ${url}`);
    }
    // Two Origin headers are not one listed origin.
    assertUnlisted(await raw(`${root}/healthz`, { headers: { origin: [ORIGIN, ORIGIN] } }), 'two Origin headers');
  });

  test('the Origin header decides nothing: the same request has the same status with any origin', async () => {
    for (const [url, headers] of [[slot, {}], [slot, AUTH], [`${root}/nowhere`, {}], [`${slot}/changes?after=bad.1`, AUTH]]) {
      const statuses = [];
      for (const origin of [undefined, ORIGIN, 'https://elsewhere.example', 'null']) {
        statuses.push((await raw(url, { headers: { ...headers, ...(origin ? { origin } : {}) } })).status);
      }
      assert.equal(new Set(statuses).size, 1, `${url}: ${statuses}`);
    }
  });

  test('507 over the slot quota carries the headers too', async () => {
    const d = await mkdtemp(path.join(tmpdir(), 'colophon-cors-'));
    const r = await startRelay({ port: 0, dataDir: d, cors: { origins: [ORIGIN] }, libraries: { q: { token: TOKEN } }, limits: { slotBytes: 4 } });
    try {
      const a = await raw(`http://127.0.0.1:${r.port}/v1/libraries/q/records/ops/a/000000000001-x.json`,
        { method: 'PUT', body: 'too big', headers: { ...AUTH, 'if-none-match': '*', origin: ORIGIN } });
      assert.equal(a.status, 507);
      assertListed(a, ORIGIN, '507');
    } finally { await r.close(); await rm(d, { recursive: true, force: true }); }
  });

  test('a preflight is 204 with the methods, headers and max age, before any slot or bearer work', async () => {
    const before = (await readdir(dir)).sort();
    for (const url of [`${root}/v1/libraries/untouched/records/ops/a/000000000001-x.json`, `${root}/v1/libraries/untouched`,
      `${root}/v1/libraries/nobody/head`, `${root}/healthz`, `${root}/anything/at/all`]) {
      for (const method of ['GET', 'PUT', 'POST', 'DELETE']) {
        const r = await raw(url, { method: 'OPTIONS', headers: { origin: ORIGIN, 'access-control-request-method': method,
          'access-control-request-headers': 'authorization, content-type, if-match' } });
        assert.equal(r.status, 204, `${method} ${url}`);
        assertListed(r, ORIGIN, `preflight ${method} ${url}`);
        assert.equal(r.headers['access-control-allow-methods'], 'GET, POST, PUT, OPTIONS');
        assert.equal(r.headers['access-control-allow-headers'], 'Authorization, Content-Type, If-Match, If-None-Match');
        assert.equal(r.headers['access-control-max-age'], '600');
        assert.equal(r.headers['www-authenticate'], undefined, 'a preflight never asks for credentials');
        assert.equal(r.body.length, 0);
      }
    }
    assert.deepEqual((await readdir(dir)).sort(), before, 'no slot directory was created');
  });

  test('a preflight from an unlisted origin is 204 with no Access-Control-* header', async () => {
    for (const origin of ['https://elsewhere.example', 'null', 'https://taupe.toolsperson.com.evil.example']) {
      const r = await raw(`${root}/v1/libraries/untouched/head`, { method: 'OPTIONS', headers: { origin, 'access-control-request-method': 'PUT' } });
      assert.equal(r.status, 204);
      assertUnlisted(r, `preflight from ${origin}`);
      assert.equal(r.headers.allow, undefined);
    }
    assert.equal(existsSync(path.join(dir, 'untouched')), false);
  });

  test('OPTIONS without the preflight headers is 204 with Allow and does no work', async () => {
    const plain = await raw(`${root}/v1/libraries/untouched`, { method: 'OPTIONS' });
    assert.equal(plain.status, 204);
    assert.equal(plain.headers.allow, 'GET, HEAD, POST, PUT, DELETE, OPTIONS');
    assertUnlisted(plain, 'plain OPTIONS');
    // A listed origin without Access-Control-Request-Method is not a preflight, but its answer
    // still carries rule 2's headers.
    const listed = await raw(`${root}/v1/libraries/untouched`, { method: 'OPTIONS', headers: { origin: ORIGIN } });
    assert.equal(listed.status, 204);
    assert.equal(listed.headers.allow, 'GET, HEAD, POST, PUT, DELETE, OPTIONS');
    assertListed(listed, ORIGIN, 'OPTIONS with an origin');
    assert.equal(listed.headers['access-control-allow-methods'], undefined);
    assert.equal(existsSync(path.join(dir, 'untouched')), false);
  });
});

describe('a relay with no origin list', () => {
  test('sends no CORS header and no Vary, but every answer is still no-transform', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-cors-'));
    const running = await startRelay({ port: 0, dataDir: dir, libraries: { home: { token: TOKEN } } });
    const root = `http://127.0.0.1:${running.port}`;
    try {
      for (const origin of [undefined, ORIGIN]) {
        const headers = origin ? { origin } : {};
        for (const [status, url, opts] of [
          [200, `${root}/healthz`, {}], [401, `${root}/v1/libraries/home`, {}], [404, `${root}/x`, {}],
          [201, `${root}/v1/libraries/home/records/ops/a/00000000000${origin ? 2 : 1}-x.json`, { method: 'PUT', body: 'b', headers: { ...AUTH, 'if-none-match': '*' } }],
          [204, `${root}/v1/libraries/home`, { method: 'OPTIONS', headers: { 'access-control-request-method': 'GET' } }],
        ]) {
          const r = await raw(url, { ...opts, headers: { ...headers, ...(opts.headers ?? {}) } });
          assert.equal(r.status, status, url);
          assertUnlisted(r, `${status} ${url}`, { vary: false });
        }
      }
    } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
  });
});

describe('the origin list at start-up', () => {
  const bad = ['*', 'null', '', ' https://a.example', 'https://a.example ', 'https://A.example', 'HTTPS://a.example',
    'https://a.example/', 'https://a.example/path', 'https://a.example?x', 'https://a.example#x', 'https://a.example.',
    'https://*.example', 'https://a.example:443', 'http://a.example:80', 'https://a.example:0', 'https://a.example:08443',
    'https://a.example:99999', 'ftp://a.example', 'file://a', 'a.example', '//a.example', 'https://user@a.example',
    'https://a..example', 'https://-a.example', 'https://xn--bcher-kva.example/', 'https://bücher.example', 1, null, {}];
  const good = [ORIGIN, OTHER, 'http://localhost:3000', 'http://[::1]:8080', 'https://xn--bcher-kva.example', 'https://a.example:8443'];

  test('each entry must be exactly scheme://host[:port]', async () => {
    for (const entry of bad) assert.throws(() => corsOrigins([entry]), /Invalid CORS origin/, JSON.stringify(entry));
    assert.throws(() => corsOrigins(ORIGIN), /array/);
    assert.deepEqual([...corsOrigins(good)], good);
    assert.equal(corsOrigins(undefined).size, 0);
  });

  test('createRelay refuses a bad entry before it opens anything', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-cors-'));
    try {
      for (const entry of ['*', 'null', 'https://A.example', 'https://a.example/']) {
        await assert.rejects(createRelay({ dataDir: path.join(dir, 'data'), libraries: { home: { token: TOKEN } }, cors: { origins: [ORIGIN, entry] } }), /Invalid CORS origin/);
      }
      await assert.rejects(createRelay({ dataDir: path.join(dir, 'data'), libraries: {}, cors: [ORIGIN] }), /cors must be an object/);
      assert.equal(existsSync(path.join(dir, 'data')), false, 'nothing was created');
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  test('server.js refuses a bad entry from the environment or the config file', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-cors-'));
    const script = path.join(here, '../server.js');
    try {
      const config = path.join(dir, 'config.json');
      await writeFile(config, JSON.stringify({ cors: { origins: ['null'] }, libraries: { home: { open: true } }, dataDir: path.join(dir, 'data'), port: 0 }));
      for (const [args, env] of [
        [[], { COLOPHON_RELAY_CORS_ORIGINS: `${ORIGIN},*` }],
        [[], { COLOPHON_RELAY_CORS_ORIGINS: `${ORIGIN},,${OTHER}` }],
        [['--config', config], {}],
      ]) {
        const r = spawnSync(process.execPath, [script, ...args], {
          env: { ...process.env, COLOPHON_RELAY_OPEN: 'x', COLOPHON_RELAY_PORT: '0', COLOPHON_RELAY_DATA: path.join(dir, 'data'), ...env },
          encoding: 'utf8', timeout: 20_000,
        });
        assert.equal(r.status, 2, `${JSON.stringify(env)} ${r.stderr}`);
        assert.match(r.stderr, /Invalid CORS origin/);
      }
      assert.equal(existsSync(path.join(dir, 'data')), false);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  test('server.js serves the origins from COLOPHON_RELAY_CORS_ORIGINS', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-cors-'));
    const child = spawn(process.execPath, [path.join(here, '../server.js')], {
      env: { ...process.env, COLOPHON_RELAY_PORT: '0', COLOPHON_RELAY_DATA: dir, COLOPHON_RELAY_TOKENS: `home=${TOKEN}`,
        COLOPHON_RELAY_CORS_ORIGINS: ` ${ORIGIN} , ${OTHER}` },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    try {
      const line = await new Promise((resolve) => child.stdout.once('data', (d) => resolve(d.toString())));
      const { listening } = JSON.parse(line.split('\n')[0]);
      const r = await raw(`http://127.0.0.1:${listening.port}/v1/libraries/home`, { headers: { origin: OTHER } });
      assert.equal(r.status, 401);
      assertListed(r, OTHER, 'server.js 401');
    } finally { child.kill(); await rm(dir, { recursive: true, force: true }); }
  });
});

describe('CORS on a 0.5 home slot', { skip: ready ? false : `build the module first (${wasm})` }, () => {
  let dir; let running; let home; let root;
  const json = { 'content-type': 'application/json' };
  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-cors-home-'));
    // A key made for this test: it protects nothing.
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    running = await startRelay({
      port: 0, dataDir: dir, tickMs: 0, cors: { origins: [ORIGIN] },
      libraries: { home: { home: true, base: BASE, account: ACCOUNT } },
      home: { wasm, key: await crypto.subtle.exportKey('jwk', pair.privateKey) },
      limits: { requestsPerMinute: 0, authorityBodyBytes: 4096, pendingBodyBytes: 4096 },
    });
    root = `http://127.0.0.1:${running.port}`;
    home = `${root}/v1/libraries/home`;
  });
  after(async () => { await running.close(); await rm(dir, { recursive: true, force: true }); });

  test('every answer the home writes carries the headers for a listed origin, and none for another', async () => {
    const cases = [
      [200, '', {}],
      [404, '/head', {}],
      [404, '/records/blobs/' + '0'.repeat(64), {}],
      [400, '/records/.hidden', {}],
      [405, '/head', { method: 'POST', body: '{}' }],
      [405, '/records/authority/00000001.json', { method: 'PUT', body: '{}', headers: { 'if-none-match': '*' } }],
      [411, '/authority', { method: 'POST', body: '{', headers: { 'transfer-encoding': 'chunked' } }],
      [413, '/authority', { method: 'POST', body: 'x'.repeat(5000), headers: json }],
      [422, '/authority', { method: 'POST', body: 'not json', headers: json }],
      [422, '/pending', { method: 'POST', body: '{"objects":[]}', headers: json }],
      [422, '/records/heads/' + '1'.repeat(32) + '.json', { method: 'PUT', body: 'garbage' }],
    ];
    for (const [origin, check] of [[ORIGIN, (r, w) => assertListed(r, ORIGIN, w)], ['https://elsewhere.example', (r, w) => assertUnlisted(r, w)]]) {
      for (const [status, p, opts] of cases) {
        const r = await raw(`${home}${p}`, { ...opts, headers: { origin, ...(opts.headers ?? {}) } });
        assert.equal(r.status, status, `${opts.method ?? 'GET'} ${p}: ${r.body}`);
        check(r, `${origin} ${status} ${opts.method ?? 'GET'} ${p}`);
      }
    }
  });

  test('a preflight on a home path is 204 and touches nothing', async () => {
    const before = (await readdir(path.join(dir, 'home'))).sort();
    for (const p of ['/authority', '/pending', '/records/state/a/x/slot.json', '/head']) {
      const r = await raw(`${home}${p}`, { method: 'OPTIONS', headers: { origin: ORIGIN, 'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization, content-type' } });
      assert.equal(r.status, 204, p);
      assertListed(r, ORIGIN, `preflight ${p}`);
      assert.equal(r.headers['access-control-allow-methods'], 'GET, POST, PUT, OPTIONS');
    }
    assert.deepEqual((await readdir(path.join(dir, 'home'))).sort(), before);
  });
});

describe('the rate limit and preflights', { skip: ready ? false : 'module not built' }, () => {
  test('preflights are not counted, and the 429 carries the headers and Retry-After', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-cors-home-'));
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    // A fixed clock: the per-minute window never resets, however slowly the requests arrive.
    const now = Date.parse('2026-11-16T00:00:00Z');
    const running = await startRelay({
      port: 0, dataDir: dir, tickMs: 0, clock: () => now, cors: { origins: [ORIGIN] }, libraries: { home: { home: true, base: BASE, account: ACCOUNT } },
      home: { wasm, key: await crypto.subtle.exportKey('jwk', pair.privateKey) }, limits: { requestsPerMinute: 3 },
    });
    const url = `http://127.0.0.1:${running.port}/v1/libraries/home/head`;
    try {
      for (let i = 0; i < 20; i += 1) {
        const r = await raw(url, { method: 'OPTIONS', headers: { origin: ORIGIN, 'access-control-request-method': 'GET' } });
        assert.equal(r.status, 204);
      }
      const statuses = [];
      let limited;
      for (let i = 0; i < 4; i += 1) {
        const r = await raw(url, { headers: { origin: ORIGIN } });
        statuses.push(r.status);
        if (r.status === 429) limited = r;
      }
      assert.deepEqual(statuses, [404, 404, 404, 429], 'the three allowed requests were all still there after twenty preflights');
      assertListed(limited, ORIGIN, '429');
      assert.equal(limited.headers['retry-after'], '60');
    } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
  });
});
