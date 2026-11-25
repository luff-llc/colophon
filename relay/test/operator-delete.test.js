// The operator's delete of a home slot (operator behaviour of the reference relay, not protocol):
// `DELETE /v1/operator/slots/<slot>?generation=` removes a provisioned, suspended slot's data and
// its row through the release path. These use synthetic accounts; an appointed slot whose
// account revoked the home is deleted in crates/colophon-home-wasm/tests/v05_relay_delete.rs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startRelay } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready && process.env.CI) throw new Error(`CI: the home module is missing (${wasm}); run scripts/test-home.sh, which builds it`);

const PREFIX = 'https://home.example/v1/libraries/';
const T0 = Date.parse('2026-11-25T00:00:00Z');
const TOKEN = 'operator-token-0123456789abcdef';
const ACCOUNT = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const SLOT = 'tslot00000a';
const sha = (b) => createHash('sha256').update(b).digest('hex');
const BEARER = { authorization: `Bearer ${TOKEN}` };
const JSON_TYPE = { 'content-type': 'application/json' };

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
const ask = (port, slot, account = ACCOUNT) =>
  raw(port, '/v1/provision', { method: 'POST', headers: { ...JSON_TYPE, ...BEARER }, body: JSON.stringify({ slot, base: PREFIX + slot, account }) });
const stateOf = async (port, slot) => raw(port, `/v1/operator/slots/${slot}`, { headers: BEARER });
const generationOf = async (port, slot) => json(await stateOf(port, slot)).generation;
const del = (port, slot, generation, headers = BEARER) => raw(port, `/v1/operator/slots/${slot}?generation=${generation}`, { method: 'DELETE', headers });
const suspend = async (port, slot) => raw(port, `/v1/operator/slots/${slot}/suspend?generation=${await generationOf(port, slot)}`, { method: 'POST', headers: BEARER });

async function homeKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) };
}

describe('the operator delete', { skip: ready ? false : `build the module first (${wasm})` }, () => {
  let dir; let key; let running; let now;
  const clock = () => now;
  before(async () => { key = await homeKey(); });
  const start = (rest = {}) => startRelay({
    port: 0, dataDir: dir, tickMs: 0, clock, home: { wasm, key: key.jwk },
    provision: { enabled: true, prefix: PREFIX, gate: 'token', tokenSha256: sha(TOKEN) },
    limits: { requestsPerMinute: 0 },
    ...rest,
  });
  /** A relay with a private listener (the door and the operator API): its private port. */
  const fresh = async (rest = {}) => {
    if (running) await running.close();
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-del-'));
    now = T0;
    running = await start({ privateListen: { host: '127.0.0.1', port: 0 }, ...rest });
    return running.privatePort;
  };
  after(async () => { if (running) await running.close(); if (dir) await rm(dir, { recursive: true, force: true }); });

  test('a suspended provisioned slot is deleted: its data and row go, the name answers notProvisioned, and a new provision has a new generation', async () => {
    const port = await fresh();
    assert.equal((await ask(port, SLOT)).status, 200);
    const first = await generationOf(port, SLOT);
    assert.equal((await suspend(port, SLOT)).status, 204);
    assert.ok(existsSync(path.join(dir, SLOT)));
    const r = await del(port, SLOT, first);
    assert.equal(r.status, 204, r.body.toString());
    assert.equal(existsSync(path.join(dir, SLOT)), false, 'the slot directory is gone');
    assert.equal((await readdir(dir)).some((n) => n.startsWith('.released-')), false, 'nothing is left aside');
    const table = JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8'));
    assert.equal(table[SLOT], undefined, 'the row is gone');
    const after = await stateOf(port, SLOT);
    assert.equal(after.status, 404);
    assert.deepEqual(json(after), { result: 'refused:notProvisioned' });
    assert.equal((await raw(running.port, `/v1/libraries/${SLOT}/head`)).status, 404, 'the public route has nothing');
    // A second delete is a delete already done.
    assert.deepEqual(json(await del(port, SLOT, first)), { result: 'refused:notProvisioned' });
    // The name can be provisioned again, for another account too, with a new generation.
    assert.equal((await ask(port, SLOT, OTHER)).status, 200);
    const second = await generationOf(port, SLOT);
    assert.notEqual(second, first);
    assert.equal(json(await stateOf(port, SLOT)).suspended, false, 'the new slot is writable');
    // The old generation never reaches the new library.
    assert.equal((await suspend(port, SLOT)).status, 204);
    assert.deepEqual(json(await del(port, SLOT, first)), { result: 'refused:staleGeneration' });
    assert.ok(existsSync(path.join(dir, SLOT)));
  });

  test('refusals: not suspended, stale generation, configured slot, no token, and a bad query change nothing', async () => {
    const port = await fresh({ libraries: { configured0: { home: true, base: `${PREFIX}configured0`, account: OTHER } } });
    assert.equal((await ask(port, SLOT)).status, 200);
    const g = await generationOf(port, SLOT);
    assert.deepEqual(json(await del(port, SLOT, g)), { result: 'refused:notSuspended' });
    assert.equal((await suspend(port, SLOT)).status, 204);
    assert.deepEqual(json(await del(port, SLOT, 'f'.repeat(32))), { result: 'refused:staleGeneration' });
    const c = await generationOf(port, 'configured0');
    assert.equal((await suspend(port, 'configured0')).status, 204);
    assert.deepEqual(json(await del(port, 'configured0', c)), { result: 'refused:configured' });
    const noToken = await del(port, SLOT, g, {});
    assert.equal(noToken.status, 403);
    assert.deepEqual(json(noToken), { result: 'refused:noEntitlement' });
    assert.equal((await raw(port, `/v1/operator/slots/${SLOT}`, { method: 'DELETE', headers: BEARER })).status, 400, 'a delete names its generation');
    assert.equal((await raw(port, `/v1/operator/slots/${SLOT}?generation=${g}&x=1`, { method: 'DELETE', headers: BEARER })).status, 400);
    assert.equal((await del(port, SLOT, g, { ...BEARER, origin: 'https://page.example' })).status, 403, 'never from a page');
    assert.equal((await raw(port, `/v1/operator/slots/${SLOT}?generation=${g}`, { method: 'PUT', headers: BEARER })).status, 405);
    assert.ok(existsSync(path.join(dir, SLOT)), 'the slot is still there');
    assert.ok(existsSync(path.join(dir, 'configured0')));
    assert.equal((await stateOf(port, SLOT)).status, 200);
  });

  test('the delete is served on the private listener only: never on the public one, nor on a single listener', async () => {
    const port = await fresh();
    assert.equal((await ask(port, SLOT)).status, 200);
    const g = await generationOf(port, SLOT);
    assert.equal((await suspend(port, SLOT)).status, 204);
    assert.equal((await del(running.port, SLOT, g)).status, 404, 'the public listener');
    await running.close(); running = null;
    running = await start();
    assert.equal((await del(running.port, SLOT, g)).status, 404, 'one listener for everything');
    assert.ok(existsSync(path.join(dir, SLOT)), 'nothing was deleted');
  });

  test('a delete interrupted after the slot left dispatch is finished by a retry at the same generation', async () => {
    let fail = null;
    const hook = (point) => { if (point === fail) { fail = null; throw new Error('simulated failure'); } return undefined; };
    const port = await fresh({ tracing: true, hook });
    assert.equal((await ask(port, SLOT)).status, 200);
    const g = await generationOf(port, SLOT);
    assert.equal((await suspend(port, SLOT)).status, 204);
    fail = `release drained ${SLOT}`;
    assert.equal((await del(port, SLOT, g)).status, 500);
    assert.ok(existsSync(path.join(dir, SLOT)), 'the directory is still there');
    assert.equal((await stateOf(port, SLOT)).status, 404, 'out of dispatch');
    assert.deepEqual(json(await del(port, SLOT, 'f'.repeat(32))), { result: 'refused:staleGeneration' });
    assert.equal((await del(port, SLOT, g)).status, 204, 'the retry finishes it');
    assert.equal(existsSync(path.join(dir, SLOT)), false);
    const table = JSON.parse(await readFile(path.join(dir, 'provisioned.json'), 'utf8'));
    assert.equal(table[SLOT], undefined);
    assert.deepEqual(json(await del(port, SLOT, g)), { result: 'refused:notProvisioned' });
    // Another name is provisioned as usual meanwhile and after.
    assert.equal((await ask(port, 'tslot00000b')).status, 200);
    assert.equal((await ask(port, SLOT)).status, 200, 'the name again');
  });
});
