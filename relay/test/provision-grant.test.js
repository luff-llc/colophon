// Provisioning by a grant from the operator's keyring (operator behaviour of the reference relay,
// not protocol): the settings and start-up refusals of gate "grant", a gate that lists several
// paths, and what the door does with a call before any operator account is set up. The journeys
// with a real operator account and its grant (a member with services terms) are the Rust tests
// in crates/colophon-home-wasm/tests/v05_relay_grant.rs. No test here waits on real time: every
// relay runs on a clock the test sets.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { provisionConfig, provisionRoute } from '../provision.js';
import { createRelay, startRelay } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready) {
  if (process.env.CI) throw new Error(`CI: the home module is missing (${wasm}); run scripts/test-home.sh, which builds it`);
  console.error(`SKIPPED: the grant provisioning tests need the module: cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm (${wasm})`);
}

const PREFIX = 'https://home.example/v1/libraries/';
const AUDIENCE = 'https://home.example/v1/provision';
const T0 = Date.parse('2026-11-16T00:00:00Z');
const HOUR = 3_600_000;
const TOKEN = 'test-token-0123456789abcdef';
// Synthetic IDs: nothing here uploads a history.
const OPERATOR = 'ab'.repeat(32);
const ACCOUNT = 'cd'.repeat(32);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const GRANT = { gate: 'grant', operator: { account: OPERATOR, slot: 'operator' }, audience: AUDIENCE };

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
const json = (r) => JSON.parse(r.body.toString('utf8'));
const ask = (port, slot, { account = ACCOUNT, base = PREFIX + slot, authorization } = {}) => raw(port, '/v1/provision', {
  method: 'POST', headers: { 'content-type': 'application/json', ...(authorization ? { authorization } : {}) },
  body: JSON.stringify({ slot, base, account }),
});

async function homeKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) };
}

/** JSON with every object's keys sorted (the call bodies here are ASCII and integers only). */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

/** A well-formed call (§12.2) signed by a fresh key that is nobody's member: it passes parse and
 * possession, so only the door's own checks and the operator account's history can refuse it. */
async function strangerCall({ account = OPERATOR, audience = AUDIENCE, purpose = 'home.provision', args, now }) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const point = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey));
  const body = Buffer.from(canonical({
    protocol: 'colophon/call/5', account, asOf: { seq: 1, digest: 'ef'.repeat(32) },
    signer: { member: sha(point).slice(0, 32) }, key: point.toString('base64'), audience, purpose, args,
    requestId: randomBytes(32).toString('base64url'), created: new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  }));
  const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, body));
  const envelope = Buffer.from(canonical({ body: body.toString('base64'), signature: signature.toString('base64') }));
  return `Colophon ${envelope.toString('base64url')}`;
}
const argsFor = (slot, account = ACCOUNT) => ({ account, base: PREFIX + slot, slot });

async function table(dir) {
  try { return JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8')); } catch { return null; }
}

describe('the grant settings', () => {
  test('the gate is one value or a list; bad lists and missing grant settings refuse start-up', () => {
    const on = { enabled: true, prefix: PREFIX };
    const bad = [
      { ...on, gate: [] },
      { ...on, gate: ['open', 'token'], tokenSha256: sha(TOKEN) }, // open admits all token would
      { ...on, gate: ['grant', 'grant'], operator: GRANT.operator, audience: AUDIENCE },
      { ...on, gate: ['grant', 'subscription'], operator: GRANT.operator, audience: AUDIENCE },
      { ...on, gate: 'grant' }, // no operator, no audience
      { ...on, gate: 'grant', audience: AUDIENCE },
      { ...on, gate: 'grant', operator: GRANT.operator },
      { ...on, gate: 'grant', operator: { account: OPERATOR }, audience: AUDIENCE },
      { ...on, gate: 'grant', operator: { slot: 'operator' }, audience: AUDIENCE },
      { ...on, gate: 'grant', operator: { account: 'AB'.repeat(32), slot: 'operator' }, audience: AUDIENCE },
      { ...on, gate: 'grant', operator: { account: OPERATOR, slot: 'provision-replay' }, audience: AUDIENCE },
      { ...on, gate: 'grant', operator: { account: OPERATOR, slot: 'operator', extra: 1 }, audience: AUDIENCE },
      { ...on, ...GRANT, audience: `${PREFIX}doorslot` }, // a slot base, not the door's own
      { ...on, ...GRANT, grantMaxSlots: 0 },
      { ...on, ...GRANT, grantPerHour: 1.5 },
      { ...on, ...GRANT, replayRows: -1 },
      { ...on, ...GRANT, grantAttemptsPerAddressPerHour: '120' },
      { ...on, ...GRANT, grants: { ['ab'.repeat(32)]: { maxSlots: 1 } } }, // a member ID is 32 hex
      { ...on, ...GRANT, grants: { ['ab'.repeat(16)]: { slots: 1 } } },
      { ...on, ...GRANT, grants: { ['ab'.repeat(16)]: { perHour: 0 } } },
      { ...on, operator: GRANT.operator, audience: AUDIENCE }, // grant settings without gate grant
      { ...on, grantMaxSlots: 3 },
    ];
    for (const p of bad) assert.throws(() => provisionConfig(p), Error, JSON.stringify(p));
    const c = provisionConfig({ ...on, ...GRANT, gate: ['grant', 'open'], grants: { ['ab'.repeat(16)]: { perHour: 5 } } });
    assert.deepEqual([...c.gates], ['grant', 'open']);
    assert.equal(c.grantMaxSlots, 20);
    assert.equal(c.grantPerHour, 30);
    assert.equal(c.grantAttemptsPerAddressPerHour, 120);
    assert.equal(c.replayRows, 4096);
    assert.deepEqual([...provisionConfig({ ...on, ...GRANT, gate: ['grant', 'token'], tokenSha256: sha(TOKEN) }).gates], ['grant', 'token']);
    assert.equal(provisionConfig({ ...on, gate: 'token', tokenSha256: sha(TOKEN) }).gate, 'token', 'the single value is kept as it was');
  });

  test('the path a request takes is chosen by its Authorization alone', () => {
    const cfg = (gate) => provisionConfig({ enabled: true, prefix: PREFIX, ...(gate.includes('grant') ? GRANT : {}), gate, ...(gate.includes('token') ? { tokenSha256: sha(TOKEN) } : {}) });
    const go = cfg(['grant', 'open']);
    assert.equal(provisionRoute(go, 'Colophon abc'), 'grant');
    assert.equal(provisionRoute(go, `Bearer ${TOKEN}`), 'open', 'token is not listed: a bearer is the open path');
    assert.equal(provisionRoute(go, undefined), 'open');
    const gt = cfg(['grant', 'token']);
    assert.equal(provisionRoute(gt, 'Colophon abc'), 'grant');
    assert.equal(provisionRoute(gt, `Bearer ${TOKEN}`), 'token');
    assert.equal(provisionRoute(gt, undefined), 'none');
    assert.equal(provisionRoute(cfg(['grant']), `Bearer ${TOKEN}`), 'none');
    assert.equal(provisionRoute(cfg(['open']), 'Colophon abc'), 'open', 'grant not listed: a call is the open path');
  });
});

describe('gate grant at start-up', { skip: ready ? false : 'module not built' }, () => {
  let key;
  const clock = () => T0;
  before(async () => { key = await homeKey(); });
  const start = (dir, provision, libraries = {}) => createRelay({ dataDir: dir, libraries, clock, tickMs: 0,
    home: { wasm, key: key.jwk }, provision: { enabled: true, prefix: PREFIX, ...GRANT, ...provision } });
  const refuses = async (pattern, provision = {}, libraries = {}, prepare = async () => {}) => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-grant-'));
    try { await prepare(dir); await assert.rejects(start(dir, provision, libraries), pattern); } finally { await rm(dir, { recursive: true, force: true }); }
  };

  test('an audience that is not a §10.1 audience', async () => {
    for (const audience of ['http://home.example/v1/provision', 'https://home.example:8443/v1/provision', 'https://home.example/v1/provision?x=1', 'door']) {
      await refuses(/is not an audience/, { audience });
    }
  });
  test('an audience that is a slot\'s base', () => refuses(/is the base of slot door/, { audience: 'https://door.example/v1/libraries/door' },
    { door: { home: true, account: ACCOUNT, base: 'https://door.example/v1/libraries/door' } }));
  test('an operator slot configured for another account', () => refuses(/serves account/, {},
    { operator: { home: true, account: ACCOUNT, base: `${PREFIX}operator` } }));
  test('an operator slot that is a 0.3 slot', () => refuses(/is a 0\.3 slot/, {}, { operator: { token: TOKEN } }));
  test('a slot named provision-replay', () => refuses(/provisioning replay table/, {}, { 'provision-replay': { token: TOKEN } }));
  test('a provision-replay directory that is a slot\'s', () => refuses(/not a slot/, {}, {}, async (dir) => {
    await mkdir(path.join(dir, 'provision-replay', 'records'), { recursive: true });
  }));
  test('an operator slot provisioned for another account', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-grant-'));
    try {
      const r = await startRelay({ port: 0, dataDir: dir, libraries: {}, clock, tickMs: 0, home: { wasm, key: key.jwk },
        provision: { enabled: true, prefix: PREFIX, slotPattern: '^[a-z]{4,64}$' }, limits: { requestsPerMinute: 0 } });
      assert.equal((await ask(r.port, 'operator')).status, 200);
      await r.close();
      await assert.rejects(start(dir, { slotPattern: '^[a-z]{4,64}$' }), /serves account/);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
  test('a named operator slot that is not set up is not a start-up failure', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-grant-'));
    try {
      const r = await start(dir, {}, { operator: { home: true, account: OPERATOR, base: `${PREFIX}operator` } });
      r.close();
      const s = await start(dir, { operator: { account: OPERATOR, slot: 'notyet' } });
      s.close();
      assert.ok(existsSync(path.join(dir, 'provision-replay')), 'the replay table is made');
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});

describe('the door with gate grant and no operator account set up', { skip: ready ? false : 'module not built' }, () => {
  let dir; let key; let running; let now;
  const clock = () => now;
  before(async () => { key = await homeKey(); });
  const fresh = async (provision = {}) => {
    if (running) await running.close();
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-grant-'));
    now = T0;
    running = await startRelay({ port: 0, dataDir: dir, libraries: {}, clock, tickMs: 0, home: { wasm, key: key.jwk },
      provision: { enabled: true, prefix: PREFIX, ...GRANT, ...provision }, limits: { requestsPerMinute: 0 } });
    return running.port;
  };
  after(async () => { if (running) await running.close(); if (dir) await rm(dir, { recursive: true, force: true }); });

  test('gate ["grant", "open"]: a call\'s refusal is final; no Authorization is the open path, bounded per address', async () => {
    const port = await fresh({ gate: ['grant', 'open'], perAddressPerHour: 3 });
    // A call that does not parse, a well-signed call for another audience, a well-signed call
    // the operator account cannot judge yet: each refused, nothing made, never the open path.
    const garbage = await ask(port, 'tslot000001', { authorization: 'Colophon e30' });
    assert.equal(garbage.status, 403);
    assert.deepEqual(json(garbage), { result: 'malformed' });
    const elsewhere = await ask(port, 'tslot000001', { authorization: await strangerCall({ audience: 'https://other.example/v1/provision', args: argsFor('tslot000001'), now }) });
    assert.equal(elsewhere.status, 403);
    assert.deepEqual(json(elsewhere), { result: 'refused:audience' });
    const unjudged = await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000001'), now }) });
    assert.equal(unjudged.status, 503);
    assert.deepEqual(json(unjudged), { result: 'unavailable' });
    assert.equal(await table(dir), null, 'nothing made');
    assert.equal(existsSync(path.join(dir, 'tslot000001')), false);
    // No Authorization (or a bearer, token not being listed): the open path, with its own share
    // (the two grant refusals above are not in it).
    const open = await ask(port, 'tslot000001');
    assert.equal(open.status, 200);
    assert.deepEqual((await table(dir)).tslot000001.by, { gate: 'open' });
    assert.equal((await ask(port, 'tslot000002', { authorization: `Bearer ${TOKEN}` })).status, 200);
    assert.equal((await ask(port, 'tslot000003')).status, 200);
    const over = await ask(port, 'tslot000004');
    assert.equal(over.status, 429, 'the open path is bounded by perAddressPerHour');
    assert.deepEqual(json(over), { result: 'refused:overQuota' });
    // Nor are the open path's slots in the grant path's share: one refusal is left there.
    const again = await ask(port, 'tslot000004', { authorization: 'Colophon e30' });
    assert.equal(again.status, 403, 'the grant path keeps its own bounds');
    assert.equal((await ask(port, 'tslot000004', { authorization: 'Colophon e30' })).status, 429);
  });

  test('gate ["grant", "token"]: a call\'s refusal is final; a bearer is the token path; nothing else is admitted', async () => {
    const port = await fresh({ gate: ['grant', 'token'], tokenSha256: sha(TOKEN), perAddressPerHour: 5 });
    const bad = await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000002'), now }) });
    assert.equal(bad.status, 403, 'args differ from the body');
    assert.deepEqual(json(bad), { result: 'refused:outOfScope' });
    const purpose = await ask(port, 'tslot000001', { authorization: await strangerCall({ purpose: 'colophon.home.write', args: argsFor('tslot000001'), now }) });
    assert.deepEqual(json(purpose), { result: 'refused:outOfScope' });
    const account = await ask(port, 'tslot000001', { authorization: await strangerCall({ account: ACCOUNT, args: argsFor('tslot000001'), now }) });
    assert.deepEqual(json(account), { result: 'refused:outOfScope' }, 'a call for another account is refused before any history');
    assert.equal(await table(dir), null);
    const none = await ask(port, 'tslot000001');
    assert.equal(none.status, 403);
    assert.deepEqual(json(none), { result: 'refused:noEntitlement' });
    const wrong = await ask(port, 'tslot000001', { authorization: `Bearer ${TOKEN}x` });
    assert.deepEqual(json(wrong), { result: 'refused:noEntitlement' });
    const right = await ask(port, 'tslot000001', { authorization: `Bearer ${TOKEN}` });
    assert.equal(right.status, 200);
    assert.deepEqual((await table(dir)).tslot000001.by, { gate: 'token' });
  });

  test('gate "grant" alone: no call is refused:noEntitlement; a well-signed call before the operator account is set up is 503', async () => {
    const port = await fresh({});
    const none = await ask(port, 'tslot000001');
    assert.equal(none.status, 403);
    assert.deepEqual(json(none), { result: 'refused:noEntitlement' });
    const bearer = await ask(port, 'tslot000001', { authorization: `Bearer ${TOKEN}` });
    assert.deepEqual(json(bearer), { result: 'refused:noEntitlement' });
    const r = await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000001'), now }) });
    assert.equal(r.status, 503);
    assert.deepEqual(json(r), { result: 'unavailable' });
    // A tampered signature: possession is checked first.
    const good = await strangerCall({ args: argsFor('tslot000001'), now });
    const env = JSON.parse(Buffer.from(good.slice('Colophon '.length), 'base64url').toString());
    const sig = Buffer.from(env.signature, 'base64'); sig[5] ^= 1; env.signature = sig.toString('base64');
    const tampered = await ask(port, 'tslot000001', { authorization: `Colophon ${Buffer.from(canonical(env)).toString('base64url')}` });
    assert.deepEqual(json(tampered), { result: 'badSignature' });
    assert.equal(await table(dir), null);
  });

  test('refused grant requests count against the address; past its share they are refused before the module runs', async () => {
    const port = await fresh({ perAddressPerHour: 2 });
    const call = () => strangerCall({ audience: 'https://other.example/v1/provision', args: argsFor('tslot000001'), now });
    for (let i = 0; i < 2; i += 1) assert.equal((await ask(port, 'tslot000001', { authorization: await call() })).status, 403);
    const over = await ask(port, 'tslot000001', { authorization: await call() });
    assert.equal(over.status, 429);
    assert.deepEqual(json(over), { result: 'refused:overQuota' });
    assert.equal(over.headers['retry-after'], '3600');
    // A body the door cannot use counts too, and a 503 (not the caller's fault) does not.
    now = T0 + HOUR;
    assert.equal((await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000001'), now }) })).status, 503);
    assert.equal((await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000001'), now }) })).status, 503);
    assert.equal((await ask(port, 'Bad_Slot', { authorization: await call() })).status, 400);
    assert.equal((await ask(port, 'tslot000001', { authorization: await call() })).status, 403);
    assert.equal((await ask(port, 'tslot000001', { authorization: await call() })).status, 429);
  });

  test('every grant request is charged against the attempt limit first', async () => {
    const port = await fresh({ grantAttemptsPerAddressPerHour: 3, perAddressPerHour: 100 });
    for (let i = 0; i < 3; i += 1) assert.equal((await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000001'), now }) })).status, 503);
    const over = await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000001'), now }) });
    assert.equal(over.status, 429);
    assert.deepEqual(json(over), { result: 'refused:overQuota' });
    assert.equal(over.headers['retry-after'], '3600');
    now += HOUR;
    assert.equal((await ask(port, 'tslot000001', { authorization: await strangerCall({ args: argsFor('tslot000001'), now }) })).status, 503);
  });
});

describe('the table\'s by', { skip: ready ? false : 'module not built' }, () => {
  test('a row whose by is not one of the three shapes refuses start-up; a grant row loads', async () => {
    const key = await homeKey();
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-grant-'));
    const clock = () => T0;
    const start = () => startRelay({ port: 0, dataDir: dir, libraries: {}, clock, tickMs: 0, home: { wasm, key: key.jwk },
      provision: { enabled: true, prefix: PREFIX }, limits: { requestsPerMinute: 0 } });
    try {
      const r = await start();
      assert.equal((await ask(r.port, 'tslot000001')).status, 200);
      await r.close();
      const file = path.join(dir, 'provisioned.json');
      const rows = JSON.parse(await readFile(file, 'utf8'));
      assert.deepEqual(rows.tslot000001.by, { gate: 'open' });
      const write = (by) => writeFile(file, JSON.stringify({ tslot000001: { ...rows.tslot000001, by } }) + '\n');
      for (const by of [{ gate: 'subscription' }, { gate: 'open', member: 'ab'.repeat(16) }, { gate: 'grant', member: 'ab'.repeat(16), key: 'ab'.repeat(16) },
        { gate: 'grant', member: 'ab'.repeat(32), key: 'ab'.repeat(16), call: 'cd'.repeat(32) }]) {
        await write(by);
        await assert.rejects(start(), /by is not/, JSON.stringify(by));
      }
      await write({ gate: 'grant', member: 'ab'.repeat(16), key: 'ef'.repeat(16), call: 'cd'.repeat(32) });
      const ok = await start();
      await ok.close();
      // A row without by (written before it existed) reads as unknown and loads.
      await writeFile(file, JSON.stringify({ tslot000001: { account: rows.tslot000001.account, base: rows.tslot000001.base, at: rows.tslot000001.at, request: rows.tslot000001.request } }) + '\n');
      await (await start()).close();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});
