// The operator API (operator behaviour of the reference relay, not protocol): suspending and
// resuming a home slot at /v1/operator/slots/<slot>, its authentication by the provisioning
// token, its own rate limit, and what a suspended (read-only) slot answers. No test here waits
// on real time: every relay runs on a clock the test sets.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { provisionConfig } from '../provision.js';
import { startRelay } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready) {
  if (process.env.CI) throw new Error(`CI: the home module is missing (${wasm}); run scripts/test-home.sh, which builds it`);
  console.error(`SKIPPED: the operator tests need the module: cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm (${wasm})`);
}

const PREFIX = 'https://home.example/v1/libraries/';
const T0 = Date.parse('2026-11-16T00:00:00Z');
const HOUR = 3_600_000;
const TOKEN = 'operator-token-0123456789abcdef';
// Synthetic account IDs: nothing here uploads a history.
const ACCOUNT = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const SLOT = 'tslot00000a';
const sha = (b) => createHash('sha256').update(b).digest('hex');
const BEARER = { authorization: `Bearer ${TOKEN}` };
const LAPSED = { result: 'refused:subscriptionLapsed' };
const AUTHOR = 'a'.repeat(32); // a member ID
const OP = `/records/ops/${AUTHOR}/listening.podcasts/000000000001-${AUTHOR}.json`;

/** One request over node:http, headers exactly as given (no defaults added). */
function raw(port, urlPath, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const h = { ...headers };
    if (body !== undefined && h['content-length'] === undefined) h['content-length'] = Buffer.byteLength(body);
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
const json = (r) => (r.body.length ? JSON.parse(r.body.toString('utf8')) : null);
const JSON_TYPE = { 'content-type': 'application/json' };
const ask = (port, slot, { account = ACCOUNT, headers = BEARER } = {}) =>
  raw(port, '/v1/provision', { method: 'POST', headers: { ...JSON_TYPE, ...headers }, body: JSON.stringify({ slot, base: PREFIX + slot, account }) });
const op = (port, slot, action, { headers = BEARER, method = action ? 'POST' : 'GET' } = {}) =>
  raw(port, `/v1/operator/slots/${slot}${action ? `/${action}` : ''}`, { method, headers });

async function homeKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) };
}

/** The data writes a home takes with no call, each as a request a home can judge without an
 * account: a predecessor entry (before the first upload) and a forwarded head. */
const WRITES = [
  ['PUT', '/predecessor/authority/00000001.json', {}, '{}'],
  ['PUT', '/records/heads/' + '1'.repeat(32) + '.json', {}, 'garbage'],
];
/** The account's authority history: a history upload (member, keyring and home changes) and
 * pending objects (transitions, vetoes, receipts). Never held back by a suspension, so a lapsed
 * account can appoint another home and revoke this one (v05_relay_suspend.rs uploads a real
 * member change to a suspended slot). */
const AUTHORITY = [
  ['POST', '/authority', JSON_TYPE, '{"from":1,"entries":[],"receipts":[]}'],
  ['POST', '/pending', JSON_TYPE, '{"objects":[]}'],
];
/** Writes that need a call: a record, a live value, a blob chunk, and a delete. Sent with no call,
 * they are judged first and answered as always, suspended or not: the slot's state is told only to
 * a caller the home admits (crates/colophon-home-wasm/tests/v05_relay_suspend.rs sends them with
 * calls, from a real account). */
const CALLED_WRITES = [
  ['PUT', OP, { 'if-none-match': '*' }, '{}'],
  ['PUT', '/records/state/' + AUTHOR + '/listening.podcasts/x.json', { 'if-match': `"${'0'.repeat(64)}"` }, '{}'],
  ['PUT', '/records/blobs/' + sha('x'), { 'if-none-match': '*' }, 'x'],
  ['DELETE', OP, {}, undefined],
];
/** Reads: the slot's description, its head, its history, its pending list, the change feed, a
 * record, a blob chunk and a predecessor entry. */
const READS = [
  ['GET', ''],
  ['GET', '/head'],
  ['GET', '/authority'],
  ['GET', '/pending'],
  ['GET', '/changes'],
  ['GET', '/changes?wait=1'],
  ['GET', OP],
  ['HEAD', '/records/blobs/' + sha('x')],
  ['GET', '/predecessor/authority/00000001.json'],
];
const write = (port, slot, [method, p, headers, body]) => raw(port, `/v1/libraries/${slot}${p}`, { method, headers, body });
const read = (port, slot, [method, p]) => raw(port, `/v1/libraries/${slot}${p}`, { method });
const answer = (r) => ({ status: r.status, body: r.body.toString('utf8') });

describe('the operator API settings', () => {
  test('operatorPerMinute is a positive integer, and only with gate token', () => {
    const token = { enabled: true, prefix: PREFIX, gate: 'token', tokenSha256: sha(TOKEN) };
    assert.equal(provisionConfig(token).operatorPerMinute, 60);
    assert.equal(provisionConfig({ ...token, operatorPerMinute: 5 }).operatorPerMinute, 5);
    for (const bad of [{ ...token, operatorPerMinute: 0 }, { ...token, operatorPerMinute: 1.5 }, { enabled: true, prefix: PREFIX, operatorPerMinute: 5 }]) {
      assert.throws(() => provisionConfig(bad), Error, JSON.stringify(bad));
    }
  });
});

describe('the operator API', { skip: ready ? false : `build the module first (${wasm})` }, () => {
  let dir; let key; let running; let now;
  const clock = () => now;
  before(async () => { key = await homeKey(); });
  const start = (provision = {}, rest = {}) => startRelay({
    port: 0, dataDir: dir, tickMs: 0, clock, home: { wasm, key: key.jwk },
    provision: { enabled: true, prefix: PREFIX, gate: 'token', tokenSha256: sha(TOKEN), ...provision },
    limits: { requestsPerMinute: 0 },
    ...rest,
  });
  const fresh = async (provision, rest) => {
    if (running) await running.close();
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-op-'));
    now = T0;
    running = await start(provision, rest);
    return running.port;
  };
  const restart = async (provision, rest) => { await running.close(); running = await start(provision, rest); return running.port; };
  after(async () => { if (running) await running.close(); if (dir) await rm(dir, { recursive: true, force: true }); });

  test('without gate token the endpoints do not exist: 404, as any unknown path', async () => {
    for (const provision of [{ gate: 'open', tokenSha256: undefined }, { enabled: false, gate: 'open', tokenSha256: undefined }]) {
      const port = await fresh(provision);
      const unknown = await raw(port, '/v1/nothing');
      for (const r of [await op(port, SLOT), await op(port, SLOT, 'suspend'), await op(port, SLOT, 'resume'), await op(port, SLOT, 'suspend', { headers: {} })]) {
        assert.equal(r.status, 404);
        assert.deepEqual(answer(r), answer(unknown));
      }
    }
  });

  test('authentication: a missing, wrong or non-bearer token is 403 refused:noEntitlement, and changes nothing', async () => {
    const port = await fresh();
    assert.equal((await ask(port, SLOT)).status, 200);
    for (const headers of [{}, { authorization: 'Bearer wrong-token-0123456789' }, { authorization: `Bearer ${TOKEN}x` },
      { authorization: `bearer ${TOKEN}` }, { authorization: `Bearer  ${TOKEN}` }, { authorization: `Colophon ${TOKEN}` }, { authorization: TOKEN }]) {
      for (const action of [undefined, 'suspend', 'resume']) {
        const r = await op(port, SLOT, action, { headers });
        assert.equal(r.status, 403, JSON.stringify(headers));
        assert.deepEqual(json(r), { result: 'refused:noEntitlement' });
      }
    }
    // Authentication comes before the slot is looked up: an unknown slot answers the same.
    assert.deepEqual(json(await op(port, 'tnothere000', 'suspend', { headers: {} })), { result: 'refused:noEntitlement' });
    assert.equal(json(await op(port, SLOT)).suspended, false, 'nothing was suspended');
    assert.equal(existsSync(path.join(dir, SLOT, 'suspended.json')), false);
  });

  test('an unknown slot is 404 refused:notProvisioned; methods are checked; the state is read', async () => {
    const port = await fresh({}, { libraries: { configured0: { home: true, base: `${PREFIX}configured0`, account: OTHER }, plain00000: { token: 'plain-token-0123456789' } } });
    for (const name of ['tnothere000', 'plain00000', 'UPPER', 'provisioned.json']) {
      for (const action of [undefined, 'suspend', 'resume']) {
        const r = await op(port, name, action);
        assert.equal(r.status, 404, `${name} ${action}`);
        assert.deepEqual(json(r), { result: 'refused:notProvisioned' }, `${name} ${action}`);
      }
    }
    assert.equal((await ask(port, SLOT)).status, 200);
    assert.deepEqual(json(await op(port, SLOT)), { slot: SLOT, provisioned: true, suspended: false });
    assert.deepEqual(json(await op(port, 'configured0')), { slot: 'configured0', provisioned: false, suspended: false }, 'a configured home slot is held, not provisioned');
    const wrong = [[SLOT, undefined, 'POST', 'GET'], [SLOT, 'suspend', 'GET', 'POST'], [SLOT, 'resume', 'PUT', 'POST']];
    for (const [name, action, method, allow] of wrong) {
      const r = await op(port, name, action, { method });
      assert.equal(r.status, 405);
      assert.equal(r.headers.allow, allow);
    }
    assert.equal((await raw(port, `/v1/operator/slots/${SLOT}/delete`, { method: 'POST', headers: BEARER })).status, 404);
    assert.equal((await raw(port, `/v1/operator/slots/${SLOT}?x=1`, { headers: BEARER })).status, 400);
    // A page is not an operator's tool.
    assert.equal((await op(port, SLOT, 'suspend', { headers: { ...BEARER, origin: 'https://page.example' } })).status, 403);
    assert.equal(json(await op(port, SLOT)).suspended, false);
  });

  test('suspended, every data write is 403 refused:subscriptionLapsed and stores nothing; reads and authority uploads answer as before', async () => {
    const port = await fresh({}, { libraries: { configured0: { home: true, base: `${PREFIX}configured0`, account: OTHER } } });
    assert.equal((await ask(port, SLOT)).status, 200);
    for (const name of [SLOT, 'configured0']) {
      const writesBefore = []; const readsBefore = [];
      for (const w of WRITES) writesBefore.push(answer(await write(port, name, w)));
      for (const r of [...READS, ...CALLED_WRITES, ...AUTHORITY]) readsBefore.push(answer(await (r.length > 2 ? write : read)(port, name, r)));
      for (const [i, a] of writesBefore.entries()) assert.notEqual(a.status, 403, `${name} ${WRITES[i][0]} ${WRITES[i][1]} before`);

      const r = await op(port, name, 'suspend');
      assert.equal(r.status, 204);
      assert.equal(r.body.length, 0);
      assert.deepEqual(json(await op(port, name)), { slot: name, provisioned: name === SLOT, suspended: true });
      const file = JSON.parse(await readFile(path.join(dir, name, 'suspended.json'), 'utf8'));
      assert.deepEqual(file, { suspended: true, at: T0 });
      assert.equal((await op(port, name, 'suspend')).status, 204, 'suspending again is the same');
      const changes = json(await read(port, name, ['GET', '/changes'])) ?? null;

      for (const w of WRITES) {
        const a = await write(port, name, w);
        assert.equal(a.status, 403, `${name} ${w[0]} ${w[1]}`);
        assert.deepEqual(json(a), LAPSED, `${name} ${w[0]} ${w[1]}`);
      }
      for (const [i, r2] of [...READS, ...CALLED_WRITES, ...AUTHORITY].entries()) {
        assert.deepEqual(answer(await (r2.length > 2 ? write : read)(port, name, r2)), readsBefore[i], `${name} ${r2[0]} ${r2[1]}`);
      }
      assert.deepEqual(json(await read(port, name, ['GET', '/changes'])) ?? null, changes, 'nothing was stored');

      assert.equal((await op(port, name, 'resume')).status, 204);
      assert.deepEqual(json(await op(port, name)), { slot: name, provisioned: name === SLOT, suspended: false });
      assert.equal(existsSync(path.join(dir, name, 'suspended.json')), false, 'resume removes the suspension');
      assert.equal((await op(port, name, 'resume')).status, 204, 'resuming again is the same');
      for (const [i, w] of WRITES.entries()) assert.deepEqual(answer(await write(port, name, w)), writesBefore[i], `${name} ${w[0]} ${w[1]} after resume`);
    }
  });

  test('a write admitted before a suspension ends before it; none is judged after it', async () => {
    // The pause point: a predecessor put, judged, holds the slot's lock. The suspension waits for it.
    let resume; const gate = new Promise((r) => { resume = r; });
    let paused; const pausedAt = new Promise((r) => { paused = r; });
    let armed = false;
    const hook = (point) => { if (point === 'access predecessor' && armed) { armed = false; paused(); return gate; } return undefined; };
    const port = await fresh({}, { tracing: true, hook });
    assert.equal((await ask(port, SLOT)).status, 200);
    const before = answer(await write(port, SLOT, WRITES[0]));
    armed = true;
    const upload = write(port, SLOT, WRITES[0]);
    await pausedAt;
    let suspended = false;
    const suspension = op(port, SLOT, 'suspend').then((r) => { suspended = true; return r; });
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(suspended, false, 'the suspension waits for the write that holds the lock');
    resume();
    assert.deepEqual(answer(await upload), before, 'the admitted write is answered as without the suspension');
    assert.equal((await suspension).status, 204);
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED);
  });

  test('a suspension survives a restart, and a resume does too', async () => {
    let port = await fresh();
    assert.equal((await ask(port, SLOT)).status, 200);
    assert.equal((await op(port, SLOT, 'suspend')).status, 204);
    port = await restart();
    assert.deepEqual(json(await op(port, SLOT)), { slot: SLOT, provisioned: true, suspended: true });
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED);
    assert.equal((await read(port, SLOT, ['GET', ''])).status, 200);
    // With the token gate turned off, the API is gone, and the slot stays read-only.
    port = await restart({ gate: 'open', tokenSha256: undefined });
    assert.equal((await op(port, SLOT)).status, 404);
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED);
    port = await restart();
    assert.equal((await op(port, SLOT, 'resume')).status, 204);
    port = await restart();
    assert.deepEqual(json(await op(port, SLOT)), { slot: SLOT, provisioned: true, suspended: false });
    assert.notEqual((await write(port, SLOT, WRITES[0])).status, 403);
  });

  test('a suspended slot is never released as unclaimed; once resumed, an unclaimed one is', async () => {
    let port = await fresh({ unclaimedHours: 24 });
    assert.equal((await ask(port, SLOT)).status, 200);
    assert.equal((await ask(port, 'tslot00000b')).status, 200);
    assert.equal((await op(port, SLOT, 'suspend')).status, 204);
    now = T0 + 25 * HOUR;
    assert.equal((await ask(port, 'tslot00000c')).status, 200, 'a provision runs the release');
    const rows = async () => Object.keys(JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8'))).sort();
    assert.deepEqual(await rows(), [SLOT, 'tslot00000c'], 'the unclaimed b went, the suspended slot stayed');
    assert.equal(existsSync(path.join(dir, SLOT, 'suspended.json')), true);
    // At start-up too.
    now = T0 + 50 * HOUR;
    port = await restart({ unclaimedHours: 24 });
    assert.deepEqual(await rows(), [SLOT]);
    assert.deepEqual(json(await op(port, SLOT)), { slot: SLOT, provisioned: true, suspended: true });
    // Resumed, it is an unclaimed slot like any other.
    assert.equal((await op(port, SLOT, 'resume')).status, 204);
    assert.equal((await ask(port, 'tslot00000d')).status, 200);
    assert.deepEqual(await rows(), ['tslot00000d']);
    assert.equal(existsSync(path.join(dir, SLOT)), false);
    assert.deepEqual(json(await op(port, SLOT)), { result: 'refused:notProvisioned' });
  });

  test('operator requests have their own per-address share, apart from the door\'s', async () => {
    const port = await fresh({ operatorPerMinute: 3, perAddressPerHour: 2 });
    assert.equal((await ask(port, SLOT)).status, 200);
    assert.equal((await op(port, SLOT, 'suspend', { headers: {} })).status, 403, 'a refused token counts');
    assert.equal((await op(port, SLOT)).status, 200);
    assert.equal((await op(port, SLOT, 'resume')).status, 204);
    const over = await op(port, SLOT);
    assert.equal(over.status, 429, 'over the share even the right token is refused');
    assert.deepEqual(json(over), { result: 'refused:overQuota' });
    assert.equal(over.headers['retry-after'], '60');
    assert.equal((await ask(port, 'tslot00000b')).status, 200, 'the door\'s share is its own');
    now = T0 + 60_000;
    assert.equal((await op(port, SLOT)).status, 200, 'a minute later the share is back');
  });
});
