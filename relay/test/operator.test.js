// The operator API (operator behaviour of the reference relay, not protocol): suspending and
// resuming a home slot at /v1/operator/slots/<slot>, its authentication by the provisioning
// token, its own rate limit, and what a suspended (read-only) slot answers. No test here waits
// on real time: every relay runs on a clock the test sets.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { isPrivateHost, parsePrivateListen, provisionConfig } from '../provision.js';
import { HomeSlot, PeerAnswerTooLarge, readCapped } from '../home.js';
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
    // `port` may be a Unix socket's path.
    const to = typeof port === 'string' ? { socketPath: port } : { host: '127.0.0.1', port };
    const req = http.request({ ...to, path: urlPath, method, headers: h }, (res) => {
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
const op = (port, slot, action, { headers = BEARER, method = action ? 'POST' : 'GET', query = action ? '?generation=x' : '' } = {}) =>
  raw(port, `/v1/operator/slots/${slot}${action ? `/${action}` : ''}${query}`, { method, headers });
/** The slot's state as the operator reads it, and its generation apart. */
async function state(port, slot) {
  const r = await op(port, slot);
  const body = json(r);
  if (r.status !== 200) return body;
  const { generation, ...rest } = body;
  assert.match(generation, /^[0-9a-f]{32}$/, 'an opaque generation');
  return rest;
}
const generationOf = async (port, slot) => json(await op(port, slot)).generation;
/** Suspend or resume with the slot's current generation, as the provisioner does. */
const act = async (port, slot, action) => op(port, slot, action, { query: `?generation=${await generationOf(port, slot)}` });

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
  test('operatorPerMinute and operatorRefusedPerMinute are positive integers, and only with gate token', () => {
    const token = { enabled: true, prefix: PREFIX, gate: 'token', tokenSha256: sha(TOKEN) };
    assert.equal(provisionConfig(token).operatorPerMinute, 600);
    assert.equal(provisionConfig(token).operatorRefusedPerMinute, 10);
    assert.equal(provisionConfig({ ...token, operatorPerMinute: 5 }).operatorPerMinute, 5);
    for (const k of ['operatorPerMinute', 'operatorRefusedPerMinute']) {
      for (const bad of [{ ...token, [k]: 0 }, { ...token, [k]: 1.5 }, { enabled: true, prefix: PREFIX, [k]: 5 }]) {
        assert.throws(() => provisionConfig(bad), Error, JSON.stringify(bad));
      }
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
      for (const r of [await op(port, SLOT), await act(port, SLOT, 'suspend'), await act(port, SLOT, 'resume'), await op(port, SLOT, 'suspend', { headers: {} })]) {
        assert.equal(r.status, 404);
        assert.deepEqual(answer(r), answer(unknown));
      }
    }
  });

  test('authentication: a missing, wrong or non-bearer token is 403 refused:noEntitlement, and changes nothing', async () => {
    const port = await fresh({ operatorRefusedPerMinute: 100 });
    assert.equal((await ask(port, SLOT)).status, 200);
    for (const headers of [{},{ authorization: 'Bearer wrong-token-0123456789' }, { authorization: `Bearer ${TOKEN}x` },
      { authorization: `bearer ${TOKEN}` }, { authorization: `Bearer  ${TOKEN}` }, { authorization: `Colophon ${TOKEN}` }, { authorization: TOKEN }]) {
      for (const action of [undefined, 'suspend', 'resume']) {
        const r = await op(port, SLOT, action, { headers });
        assert.equal(r.status, 403, JSON.stringify(headers));
        assert.deepEqual(json(r), { result: 'refused:noEntitlement' });
      }
    }
    // Authentication comes before the slot is looked up: an unknown slot answers the same.
    assert.deepEqual(json(await op(port, 'tnothere000', 'suspend', { headers: {} })), { result: 'refused:noEntitlement' });
    assert.equal((await state(port, SLOT)).suspended, false, 'nothing was suspended');
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
    assert.deepEqual(await state(port, SLOT), { slot: SLOT, provisioned: true, suspended: false });
    assert.deepEqual(await state(port, 'configured0'), { slot: 'configured0', provisioned: false, suspended: false }, 'a configured home slot is held, not provisioned');
    const wrong = [[SLOT, undefined, 'POST', 'GET'], [SLOT, 'suspend', 'GET', 'POST'], [SLOT, 'resume', 'PUT', 'POST']];
    for (const [name, action, method, allow] of wrong) {
      const r = await op(port, name, action, { method });
      assert.equal(r.status, 405);
      assert.equal(r.headers.allow, allow);
    }
    assert.equal((await raw(port, `/v1/operator/slots/${SLOT}/delete`, { method: 'POST', headers: BEARER })).status, 404);
    assert.equal((await raw(port, `/v1/operator/slots/${SLOT}?x=1`, { headers: BEARER })).status, 400);
    // A change names the generation it is meant for: none, or anything else in the query, is 400.
    for (const query of ['', '?generation=', '?x=1', `?generation=${await generationOf(port, SLOT)}&x=1`, '?generation=a&generation=b']) {
      assert.equal((await op(port, SLOT, 'suspend', { query })).status, 400, query);
    }
    // A page is not an operator's tool.
    assert.equal((await op(port, SLOT, 'suspend', { headers: { ...BEARER, origin: 'https://page.example' } })).status, 403);
    assert.equal((await state(port, SLOT)).suspended, false);
  });

  test('suspended, every data write is 403 refused:subscriptionLapsed and stores nothing; reads and authority uploads answer as before', async () => {
    const port = await fresh({}, { libraries: { configured0: { home: true, base: `${PREFIX}configured0`, account: OTHER } } });
    assert.equal((await ask(port, SLOT)).status, 200);
    for (const name of [SLOT, 'configured0']) {
      const writesBefore = []; const readsBefore = [];
      for (const w of WRITES) writesBefore.push(answer(await write(port, name, w)));
      for (const r of [...READS, ...CALLED_WRITES, ...AUTHORITY]) readsBefore.push(answer(await (r.length > 2 ? write : read)(port, name, r)));
      for (const [i, a] of writesBefore.entries()) assert.notEqual(a.status, 403, `${name} ${WRITES[i][0]} ${WRITES[i][1]} before`);

      const r = await act(port, name, 'suspend');
      assert.equal(r.status, 204);
      assert.equal(r.body.length, 0);
      assert.deepEqual(await state(port, name), { slot: name, provisioned: name === SLOT, suspended: true });
      const file = JSON.parse(await readFile(path.join(dir, name, 'suspended.json'), 'utf8'));
      assert.deepEqual(file, { suspended: true, at: T0 });
      assert.equal((await act(port, name, 'suspend')).status, 204, 'suspending again is the same');
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

      assert.equal((await act(port, name, 'resume')).status, 204);
      assert.deepEqual(await state(port, name), { slot: name, provisioned: name === SLOT, suspended: false });
      assert.equal(existsSync(path.join(dir, name, 'suspended.json')), false, 'resume removes the suspension');
      assert.equal((await act(port, name, 'resume')).status, 204, 'resuming again is the same');
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
    const suspension = act(port, SLOT, 'suspend').then((r) => { suspended = true; return r; });
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
    assert.equal((await act(port, SLOT, 'suspend')).status, 204);
    port = await restart();
    assert.deepEqual(await state(port, SLOT), { slot: SLOT, provisioned: true, suspended: true });
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED);
    assert.equal((await read(port, SLOT, ['GET', ''])).status, 200);
    // With the token gate turned off, the API is gone, and the slot stays read-only.
    port = await restart({ gate: 'open', tokenSha256: undefined });
    assert.equal((await op(port, SLOT)).status, 404);
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED);
    port = await restart();
    assert.equal((await act(port, SLOT, 'resume')).status, 204);
    port = await restart();
    assert.deepEqual(await state(port, SLOT), { slot: SLOT, provisioned: true, suspended: false });
    assert.notEqual((await write(port, SLOT, WRITES[0])).status, 403);
  });

  test('a suspended slot is never released as unclaimed; once resumed, an unclaimed one is', async () => {
    let port = await fresh({ unclaimedHours: 24 });
    assert.equal((await ask(port, SLOT)).status, 200);
    assert.equal((await ask(port, 'tslot00000b')).status, 200);
    assert.equal((await act(port, SLOT, 'suspend')).status, 204);
    now = T0 + 25 * HOUR;
    assert.equal((await ask(port, 'tslot00000c')).status, 200, 'a provision runs the release');
    const rows = async () => Object.keys(JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8'))).sort();
    assert.deepEqual(await rows(), [SLOT, 'tslot00000c'], 'the unclaimed b went, the suspended slot stayed');
    assert.equal(existsSync(path.join(dir, SLOT, 'suspended.json')), true);
    // At start-up too.
    now = T0 + 50 * HOUR;
    port = await restart({ unclaimedHours: 24 });
    assert.deepEqual(await rows(), [SLOT]);
    assert.deepEqual(await state(port, SLOT), { slot: SLOT, provisioned: true, suspended: true });
    // Resumed, it is an unclaimed slot like any other.
    assert.equal((await act(port, SLOT, 'resume')).status, 204);
    assert.equal((await ask(port, 'tslot00000d')).status, 200);
    assert.deepEqual(await rows(), ['tslot00000d']);
    assert.equal(existsSync(path.join(dir, SLOT)), false);
    assert.deepEqual(await state(port, SLOT), { result: 'refused:notProvisioned' });
  });

  test('authenticated operator requests have their own share: refused ones from any address never spend or crowd it out', async () => {
    const port = await fresh({ operatorPerMinute: 3, operatorRefusedPerMinute: 2, perAddressPerHour: 2 });
    assert.equal((await ask(port, SLOT)).status, 200);
    // Unauthenticated traffic from the operator's own address: refused, then over its share.
    assert.equal((await op(port, SLOT, 'suspend', { headers: {} })).status, 403);
    assert.equal((await op(port, SLOT, 'suspend', { headers: {} })).status, 403);
    const refused = await op(port, SLOT, 'suspend', { headers: {} });
    assert.equal(refused.status, 429, 'refused requests over their share');
    assert.deepEqual(json(refused), { result: 'refused:overQuota' });
    // The operator, from the same address, is not affected.
    assert.equal((await op(port, SLOT)).status, 200);
    assert.equal((await act(port, SLOT, 'suspend')).status, 204);
    const over = await op(port, SLOT);
    assert.equal(over.status, 429, 'the operator\'s own share, three a minute');
    assert.equal(over.headers['retry-after'], '60');
    assert.equal((await ask(port, 'tslot00000b')).status, 200, 'the door\'s share is its own');
    now = T0 + 60_000;
    assert.equal((await op(port, SLOT)).status, 200, 'a minute later the share is back');
  });

  test('a full table of refused addresses never refuses the operator', async () => {
    const port = await fresh({ operatorRefusedPerMinute: 1 }, { clientAddress: { header: 'X-Client', trustedPeers: ['127.0.0.1'] } });
    assert.equal((await ask(port, SLOT)).status, 200);
    for (let i = 0; i < 10_001; i += 1) {
      const ip = `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
      await op(port, SLOT, undefined, { headers: { 'x-client': ip } });
    }
    const fresh0 = await op(port, SLOT, undefined, { headers: { 'x-client': '192.0.2.1' } });
    assert.equal(fresh0.status, 429, 'a new unauthenticated address is refused while the table is full');
    assert.equal((await op(port, SLOT, undefined, { headers: { ...BEARER, 'x-client': '192.0.2.2' } })).status, 200, 'the operator from a new address is served');
  });

  test('a delayed command for a released name never reaches the slot that reuses it: 409 refused:staleGeneration', async () => {
    let port = await fresh({ unclaimedHours: 24 });
    assert.equal((await ask(port, SLOT)).status, 200);
    const first = await generationOf(port, SLOT);
    assert.equal(await generationOf(port, SLOT), first, 'stable');
    port = await restart({ unclaimedHours: 24 });
    assert.equal(await generationOf(port, SLOT), first, 'stable across a restart');
    // Released unclaimed, then provisioned again for another account.
    now = T0 + 25 * HOUR;
    assert.equal((await ask(port, SLOT, { account: OTHER })).status, 200);
    const second = await generationOf(port, SLOT);
    assert.notEqual(second, first, 'a new generation');
    const stale = await op(port, SLOT, 'suspend', { query: `?generation=${first}` });
    assert.equal(stale.status, 409);
    assert.deepEqual(json(stale), { result: 'refused:staleGeneration' });
    assert.equal((await state(port, SLOT)).suspended, false, 'the new library is untouched');
    assert.equal(existsSync(path.join(dir, SLOT, 'suspended.json')), false);
    assert.equal((await op(port, SLOT, 'suspend', { query: `?generation=${second}` })).status, 204);
    assert.equal((await op(port, SLOT, 'resume', { query: `?generation=${first}` })).status, 409);
    assert.equal((await state(port, SLOT)).suspended, true);
  });

  test('an unauthenticated provision runs no cleanup: suspend and resume are not held up by a release that drains', async () => {
    // A slow request on an unclaimed, expired slot: its release would wait for it to drain.
    let resume; const gate = new Promise((r) => { resume = r; });
    let paused; const pausedAt = new Promise((r) => { paused = r; });
    let draining = 0;
    let armed = false;
    const hook = (point) => {
      if (point === 'access predecessor' && armed) { armed = false; paused(); return gate; }
      if (point.startsWith('release draining')) draining += 1;
      return undefined;
    };
    const port = await fresh({ unclaimedHours: 24 }, { tracing: true, hook });
    assert.equal((await ask(port, 'tslot00000b')).status, 200);
    now = T0 + 2 * HOUR; // the operator's slot is younger: not released below
    assert.equal((await ask(port, SLOT)).status, 200);
    armed = true;
    const slow = write(port, 'tslot00000b', WRITES[0]);
    await pausedAt;
    now = T0 + 25 * HOUR;
    // Without the token, the door refuses before any cleanup.
    for (const headers of [{}, { authorization: 'Bearer wrong-token-0123456789' }]) {
      const r = await ask(port, 'tslot00000c', { headers });
      assert.equal(r.status, 403);
    }
    assert.equal(draining, 0, 'no release started');
    // With it, the release starts and drains outside the lock: the operator is served meanwhile.
    const provision = ask(port, 'tslot00000c');
    while (draining === 0) await new Promise((r) => setImmediate(r));
    assert.equal((await act(port, SLOT, 'suspend')).status, 204, 'not held up by the draining release');
    assert.equal((await state(port, SLOT)).suspended, true);
    resume();
    await slow;
    assert.equal((await provision).status, 200);
    assert.deepEqual(Object.keys(JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8'))).sort(), [SLOT, 'tslot00000c']);
  });

  test('a failed directory sync keeps data writes refused until the state is reconciled; a retry is answered only once it is durable', async () => {
    let fail = null;
    const hook = (point) => { if (point === fail) { fail = null; throw new Error('simulated sync failure'); } return undefined; };
    const port = await fresh({}, { tracing: true, hook });
    assert.equal((await ask(port, SLOT)).status, 200);
    const before = answer(await write(port, SLOT, WRITES[0]));
    // Sent with the generation it already holds, as a retrying provisioner does (a read of the
    // state would reconcile it first).
    const g = await generationOf(port, SLOT);
    const go = (action) => op(port, SLOT, action, { query: `?generation=${g}` });
    // A suspend whose rename landed but whose sync failed: not acknowledged, and a retry redoes
    // every step (memory still says writable), acknowledged only once synced.
    fail = 'suspension renamed';
    assert.equal((await go('suspend')).status, 500);
    const s = await running.relay.slot(SLOT);
    assert.equal(s.home.suspensionUncertain, true);
    assert.equal(s.home.suspended, false, 'memory still says writable');
    fail = 'suspension renamed';
    assert.equal((await go('suspend')).status, 500, 'a retry that fails again is not acknowledged');
    assert.equal(s.home.suspensionUncertain, true);
    assert.equal((await go('suspend')).status, 204, 'acknowledged once synced');
    assert.equal(s.home.suspensionUncertain, false);
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED);
    // A failed suspend, then a data write: reconciled from the disk first (the marker is there),
    // so the write is refused, never taken on the cached flag.
    assert.equal((await go('resume')).status, 204);
    fail = 'suspension renamed';
    assert.equal((await go('suspend')).status, 500);
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED, 'reconciled from disk: suspended');
    assert.equal(s.home.suspensionUncertain, false);
    assert.equal((await state(port, SLOT)).suspended, true);
    // A failed resume, then a data write: reconciled (the marker is gone), so it is taken.
    fail = 'suspension removed';
    assert.equal((await go('resume')).status, 500);
    assert.equal(s.home.suspended, true, 'memory still says suspended');
    assert.deepEqual(answer(await write(port, SLOT, WRITES[0])), before);
    assert.equal((await state(port, SLOT)).suspended, false);
    // An uncertain state whose reconciliation fails answers 503, never a write.
    assert.equal((await go('suspend')).status, 204);
    fail = 'suspension removed';
    assert.equal((await go('resume')).status, 500);
    s.home.reconcileSuspensionLocked = async () => { throw new Error('the disk is gone'); };
    const r = await write(port, SLOT, WRITES[0]);
    assert.equal(r.status, 503);
    assert.deepEqual(json(r), { result: 'unavailable' });
  });

  test('with a private listener, provisioning and the operator API are served there only', async () => {
    const port = await fresh({}, { privateListen: { host: '127.0.0.1', port: 0 } });
    const priv = running.privatePort;
    assert.ok(priv && priv !== port);
    const unknown = answer(await raw(port, '/v1/nothing'));
    // Public: 404 as any unknown path, before any check or body read.
    assert.deepEqual(answer(await ask(port, SLOT)), unknown);
    assert.deepEqual(answer(await op(port, SLOT)), unknown);
    assert.deepEqual(answer(await op(port, SLOT, 'suspend')), unknown);
    // Private: the door and the operator.
    assert.equal((await ask(priv, SLOT)).status, 200);
    assert.equal((await act(priv, SLOT, 'suspend')).status, 204);
    assert.equal((await state(priv, SLOT)).suspended, true);
    // The library itself is public only.
    assert.equal((await raw(port, `/v1/libraries/${SLOT}`)).status, 200);
    assert.deepEqual(json(await write(port, SLOT, WRITES[0])), LAPSED);
    assert.equal((await raw(priv, `/v1/libraries/${SLOT}`)).status, 404);
    assert.equal((await raw(priv, '/healthz')).status, 200);
  });

  test('a provision answers the slot\'s generation with the member request, in the same decision', async () => {
    const port = await fresh();
    const r = await ask(port, SLOT);
    assert.equal(r.status, 200);
    const g = r.headers['colophon-slot-generation'];
    assert.match(g, /^[0-9a-f]{32}$/);
    assert.equal(g, await generationOf(port, SLOT));
    JSON.parse(r.body.toString('utf8')); // the body is the member request, as before
    const again = await ask(port, SLOT);
    assert.equal(again.headers['colophon-slot-generation'], g, 'the same answer again');
    assert.equal(again.body.toString(), r.body.toString());
    assert.equal((await op(port, SLOT, 'suspend', { query: `?generation=${g}` })).status, 204, 'usable at once, with no read');
  });

  test('a slot whose suspension is uncertain, or whose marker is on disk, is never released', async () => {
    let fail = null;
    const hook = (point) => { if (point === fail) { fail = null; throw new Error('simulated sync failure'); } return undefined; };
    const port = await fresh({ unclaimedHours: 24 }, { tracing: true, hook });
    const r = await ask(port, SLOT);
    const g = r.headers['colophon-slot-generation'];
    fail = 'suspension renamed';
    assert.equal((await op(port, SLOT, 'suspend', { query: `?generation=${g}` })).status, 500);
    const s = await running.relay.slot(SLOT);
    assert.equal(s.home.suspended, false);
    assert.equal(s.home.suspensionUncertain, true);
    now = T0 + 25 * HOUR;
    assert.equal((await ask(port, 'tslot00000b')).status, 200);
    assert.ok(existsSync(path.join(dir, SLOT, 'suspended.json')), 'uncertain: kept');
    // Memory certain and wrong (as after a lost update): the marker on disk still keeps it.
    s.home.suspensionUncertain = false;
    assert.equal((await ask(port, 'tslot00000c')).status, 200);
    assert.ok(existsSync(path.join(dir, SLOT, 'suspended.json')), 'the marker on disk: kept');
    const rows = Object.keys(JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8'))).sort();
    assert.ok(rows.includes(SLOT));
  });

  test('with gate grant,token, a grant request that fails its stateless judgement starts no sweep', async () => {
    let draining = 0;
    const hook = (point) => { if (point.startsWith('release draining')) draining += 1; return undefined; };
    const port = await fresh({ unclaimedHours: 24, gate: ['grant', 'token'], operator: { account: OTHER, slot: 'operator0000' },
      audience: 'https://home.example/v1/provision' }, { tracing: true, hook });
    assert.equal((await ask(port, SLOT)).status, 200);
    now = T0 + 25 * HOUR;
    for (const authorization of ['Colophon AAAA', 'Colophon ' + Buffer.from('{"not":"a call"}').toString('base64url')]) {
      const r = await ask(port, 'tslot00000b', { headers: { authorization } });
      assert.notEqual(r.status, 200);
    }
    assert.equal(draining, 0, 'no release started');
    assert.ok(existsSync(path.join(dir, SLOT)));
    assert.equal((await ask(port, 'tslot00000b')).status, 200, 'the token path sweeps');
    assert.equal(draining, 1);
    assert.equal(existsSync(path.join(dir, SLOT)), false);
  });

  test('a full home waits for a release under way, outside the lock, before it answers 507', async () => {
    let resume; const gate = new Promise((r) => { resume = r; });
    let paused; const pausedAt = new Promise((r) => { paused = r; });
    let draining; const drainingAt = new Promise((r) => { draining = r; });
    let armed = false;
    const hook = (point) => {
      if (point === 'access predecessor' && armed) { armed = false; paused(); return gate; }
      if (point.startsWith('release draining')) draining();
      return undefined;
    };
    const port = await fresh({ unclaimedHours: 24, maxSlots: 1 }, { tracing: true, hook });
    assert.equal((await ask(port, SLOT)).status, 200);
    armed = true;
    const slow = write(port, SLOT, WRITES[0]);
    await pausedAt;
    now = T0 + 25 * HOUR;
    // A token request that starts the release (and is then refused for its body) ...
    const starter = raw(port, '/v1/provision', { method: 'POST', headers: { ...JSON_TYPE, ...BEARER },
      body: JSON.stringify({ slot: 'tslot00000c', base: 'https://elsewhere.example/', account: ACCOUNT }) });
    await drainingAt;
    // ... and another while the slot drains: the home is full until the release ends.
    const waiting = ask(port, 'tslot00000d');
    await new Promise((r) => setTimeout(r, 50));
    resume();
    await slow;
    assert.equal((await starter).status, 400);
    const r = await waiting;
    assert.equal(r.status, 200, r.body.toString());
    assert.deepEqual(Object.keys(JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8'))), ['tslot00000d']);
    assert.ok(!(await import('node:fs/promises').then((f) => f.readdir(dir))).some((n) => n.startsWith('.released-')), 'the released directory is gone');
  });

  test('the private listener on a Unix socket, made 0600; a public address is refused unless allowed', async () => {
    const sock = path.join(await mkdtemp(path.join(tmpdir(), 'colophon-sock-')), 'private.sock');
    const port = await fresh({}, { privateListen: { path: sock } });
    assert.equal(running.privatePath, sock);
    assert.equal(statSync(sock).mode & 0o777, 0o600);
    assert.equal((await ask(port, SLOT)).status, 404, 'not on the public listener');
    const r = await ask(sock, SLOT);
    assert.equal(r.status, 200);
    assert.equal((await op(sock, SLOT, 'suspend', { query: `?generation=${r.headers['colophon-slot-generation']}` })).status, 204);
    // A restart replaces the socket an earlier run left.
    await running.close();
    running = await start({}, { privateListen: { path: sock } });
    assert.equal((await state(sock, SLOT)).suspended, true);
    await running.close(); running = null;
    for (const host of ['0.0.0.0', '::', '203.0.113.7']) {
      await assert.rejects(start({}, { privateListen: { host, port: 0 } }), /not a loopback or private address/, host);
    }
    running = await start({}, { privateListen: { host: '0.0.0.0', port: 0 }, privateListenAllowPublic: true });
    assert.ok(running.privatePort > 0, 'allowed explicitly');
    assert.deepEqual(parsePrivateListen('unix:/run/colophon/private.sock'), { path: '/run/colophon/private.sock' });
    assert.deepEqual(parsePrivateListen('[fd00::2]:8788'), { host: 'fd00::2', port: 8788 });
    for (const bad of ['unix:relative.sock', '8788', 'host:']) assert.throws(() => parsePrivateListen(bad), Error, bad);
    for (const [h, ok] of [['127.0.0.1', true], ['10.1.2.3', true], ['172.20.0.2', true], ['192.168.1.1', true], ['::1', true], ['fd00::2', true], ['0.0.0.0', false], ['::', false], ['8.8.8.8', false], ['2001:db8::1', false]]) {
      assert.equal(isPrivateHost(h), ok, h);
    }
  });

  test('GET /v1/operator/slots lists every home slot, a page at a time, behind the same gate', async () => {
    const port = await fresh({ operatorRefusedPerMinute: 100 }, { libraries: { configured0: { home: true, base: `${PREFIX}configured0`, account: OTHER } } });
    const names = ['tslot00000c', 'tslot00000a', 'tslot00000b'];
    const gens = {};
    for (const n of names) gens[n] = (await ask(port, n)).headers['colophon-slot-generation'];
    assert.equal((await act(port, 'tslot00000b', 'suspend')).status, 204);
    const list = (q = '', headers = BEARER) => raw(port, `/v1/operator/slots${q}`, { headers });
    const all = json(await list());
    assert.deepEqual(all, { next: null, slots: [
      { slot: 'configured0', provisioned: false, suspended: false, generation: await generationOf(port, 'configured0') },
      { slot: 'tslot00000a', provisioned: true, suspended: false, generation: gens.tslot00000a },
      { slot: 'tslot00000b', provisioned: true, suspended: true, generation: gens.tslot00000b },
      { slot: 'tslot00000c', provisioned: true, suspended: false, generation: gens.tslot00000c },
    ] });
    // Pages, by cursor.
    const one = json(await list('?limit=2'));
    assert.deepEqual(one.slots.map((x) => x.slot), ['configured0', 'tslot00000a']);
    assert.equal(one.next, 'tslot00000a');
    const two = json(await list(`?limit=2&after=${one.next}`));
    assert.deepEqual(two.slots.map((x) => x.slot), ['tslot00000b', 'tslot00000c']);
    assert.equal(two.next, null);
    // The same gate and the same answers to a bad request.
    assert.deepEqual(json(await list('', {})), { result: 'refused:noEntitlement' });
    assert.equal((await raw(port, '/v1/operator/slots', { method: 'POST', headers: BEARER })).status, 405);
    assert.equal((await list('?x=1')).status, 400);
    assert.equal((await list('?limit=a')).status, 400);
    assert.equal((await list('', { ...BEARER, origin: 'https://page.example' })).status, 403);
  });

  test('re-provisioning an existing slot spends no new-slot share, and no share refuses it', async () => {
    const sock = path.join(await mkdtemp(path.join(tmpdir(), 'colophon-sock-')), 'private.sock');
    await fresh({ perAddressPerHour: 1 }, { privateListen: { path: sock } });
    const first = await ask(sock, SLOT);
    assert.equal(first.status, 200);
    for (let i = 0; i < 5; i += 1) {
      const again = await ask(sock, SLOT);
      assert.equal(again.status, 200, 'the same slot again, over the socket\'s one bucket');
      assert.equal(again.body.toString(), first.body.toString());
    }
    const other = await ask(sock, 'tslot00000b');
    assert.equal(other.status, 429, 'a new slot is over the share');
    assert.deepEqual(json(other), { result: 'refused:overQuota' });
    assert.equal((await ask(sock, SLOT)).status, 200, 'and the existing one still answers');
  });

  test('slotBytes counts a home slot\'s data only, and is published', async () => {
    const port = await fresh({}, { limits: { requestsPerMinute: 0, slotBytes: 1 } });
    assert.equal((await ask(port, SLOT)).status, 200);
    assert.equal(json(await raw(port, `/v1/libraries/${SLOT}`)).quotaBytes, 1);
    // History the module stores (a staged predecessor entry here) is never refused by it.
    const s = await running.relay.slot(SLOT);
    assert.equal(s.isData('authority/00000001.json'), false);
    assert.equal(s.isData('predecessor/authority/00000001.json'), false);
    for (const p of ['ops/a/b/c.json', 'history/a/b/c.json', 'state/a/b/c.json', 'blobs/' + '0'.repeat(64)]) assert.equal(s.isData(p), true, p);
    assert.doesNotThrow(() => s.checkQuota(1000, 'authority/00000001.json'));
    assert.throws(() => s.checkQuota(2, 'ops/a/b/c.json'), (e) => e.status === 507 && e.body?.result === 'refused:overQuota');
  });
});

describe('forwarding is bounded', () => {
  const body = (chunks) => new ReadableStream({ pull(c) { const n = chunks.shift(); if (n === undefined) c.close(); else c.enqueue(new Uint8Array(n)); } });

  test('a peer\'s answer is read up to its bound, then cancelled', async () => {
    assert.equal((await readCapped(new Response(body([10, 10])), 20)).length, 20);
    let cancelled = false;
    const big = new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(1024)); }, cancel() { cancelled = true; } });
    await assert.rejects(readCapped(new Response(big), 4096), PeerAnswerTooLarge);
    assert.equal(cancelled, true, 'an endless answer is cancelled, not held');
    const declared = new Response('x'.repeat(10), { headers: { 'content-length': '100000' } });
    await assert.rejects(readCapped(declared, 1000), PeerAnswerTooLarge, 'a declared length over the bound is refused before reading');
    assert.equal((await readCapped(new Response(null), 10)).length, 0);
  });

  test('passes per slot and for the whole home are bounded; the rest wait for a later tick', async () => {
    const forwarding = { running: 0, max: 5 };
    const slotOf = (n) => {
      const h = Object.create(HomeSlot.prototype);
      Object.assign(h, {
        deps: { forwarding }, limits: { forwardPeersPerSlot: 3 }, forward: { peers: {} }, said: new Map(),
        key: { memberId: 'f'.repeat(32) }, clock: () => 0, stopping: new AbortController(),
        lock: async (fn) => fn(), isQuiet: () => false,
        status: () => ({ peers: Array.from({ length: n }, (_, i) => ({ id: `peer${i}`, endpoints: [`https://peer${i}.example/`] })) }),
        forwardTo: () => new Promise(() => {}), // a peer that never answers
      });
      h.note = () => {};
      return h;
    };
    const a = slotOf(10); const b = slotOf(10);
    await a.forwardAll();
    assert.equal(a.passes.size, 3, 'at most forwardPeersPerSlot for one slot');
    await b.forwardAll();
    assert.equal(b.passes.size, 2, 'the home-wide bound');
    assert.equal(forwarding.running, 5);
    await a.forwardAll();
    assert.equal(a.passes.size, 3, 'nothing more starts while they run');
  });
});
