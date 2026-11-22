import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, symlink, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createECDH, hkdfSync, randomBytes } from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { after, before, describe, test } from 'node:test';
import { sha256, startRelay } from '../relay.js';
import fixture from './fixtures/home-batch.json';

const token = 'batch-fetch-test-token-0123456789';
const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
describe('batch record fetch', () => {
  let dir, running, base;
  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-batch-'));
    running = await startRelay({ port: 0, dataDir: dir, libraries: { batch: { token } }, cors: { origins: ['https://client.example'] } });
    base = `http://127.0.0.1:${running.port}/v1/libraries/batch`;
  });
  after(async () => { await running.close(); await rm(dir, { recursive: true, force: true }); });
  const batch = (paths, extra = {}) => fetch(`${base}/records/batch`, {
    method: 'POST', headers, body: JSON.stringify({ paths }), ...extra,
  });
  const put = async (p, bytes) => {
    const r = await fetch(`${base}/records/${p}`, { method: 'PUT', headers: { ...headers, 'if-none-match': '*' }, body: bytes });
    assert.equal(r.status, 201);
  };
  test('ordered ops, blobs and missing records with integrity and CORS headers', async () => {
    const op = Buffer.from('{"opaque":"record"}'), blob = Buffer.from([0, 255, 128, 42]);
    const paths = ['ops/member/one.json', `blobs/${sha256(blob)}`, 'ops/member/missing.json'];
    await put(paths[0], op); await put(paths[1], blob);
    const r = await batch(paths, { headers: { ...headers, origin: 'https://client.example' } });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('cache-control'), 'no-store, no-transform');
    assert.equal(r.headers.get('access-control-allow-origin'), 'https://client.example');
    assert.deepEqual(await r.json(), { records: [
      { path: paths[0], status: 200, etag: `"${sha256(op)}"`, bytes: op.toString('base64') },
      { path: paths[1], status: 200, etag: `"${sha256(blob)}"`, bytes: blob.toString('base64') },
      { path: paths[2], status: 404 },
    ], truncated: false });
  });
  test('single-record bearer gate', async () => {
    for (const authorization of [undefined, 'Bearer wrong']) {
      const r = await batch(['ops/member/one.json'], { headers: { 'content-type': 'application/json', ...(authorization ? { authorization } : {}) } });
      assert.equal(r.status, 401); assert.equal(r.headers.get('www-authenticate'), 'Bearer');
    }
  });
  test('invalid JSON, shapes, paths, duplicates, oversized batches and bodies', async () => {
    for (const body of ['{', 'null', '[]', '{}', '{"paths":null}', '{"paths":"ops/a/b.json"}',
      ...[[], [null], ['../secret'], ['ops/a/../secret.json'], ['ops/a/%2e.json'],
        ['ops/a/b.json', 'ops/a/b.json'], Array.from({ length: 257 }, (_, i) => `ops/a/${i}.json`)]
        .map(paths => JSON.stringify({ paths }))]) {
      assert.equal((await batch([], { body })).status, 400, body);
    }
    assert.equal((await batch(['ops/a/b.json'], { headers: { ...headers, 'content-type': 'text/plain' } })).status, 415);
    assert.equal((await batch([], { body: ' '.repeat(64 * 1024 + 1) })).status, 413);
    assert.equal((await fetch(`${base}/records/batch`, { headers })).status, 405);
  });
  test('4 MiB encoded response budget and pagination', async () => {
    const bytes = Buffer.alloc(1024 * 1024, 42);
    const paths = ['ops/large/one.json', 'ops/large/two.json', 'ops/large/three.json'];
    for (const p of paths) await put(p, bytes);
    const response = await (await batch(paths)).text();
    assert.ok(Buffer.byteLength(response) <= 4 * 1024 * 1024);
    const first = JSON.parse(response);
    assert.equal(first.truncated, true); assert.equal(first.records.length, 2);
    const next = await (await batch(paths.slice(first.records.length))).json();
    assert.equal(next.truncated, false); assert.equal(next.records.length, 1);
    assert.equal(Buffer.from(next.records[0].bytes, 'base64').length, bytes.length);
  });
  test('oversized records return 413 without reading or encoding, and make progress', async () => {
    const p = 'ops/large/single.json', bytes = Buffer.alloc(16 * 1024 * 1024);
    await put(p, bytes);
    const slot = await running.relay.slot('batch');
    const readFile = slot.readFile;
    slot.readFile = function (recordPath) {
      assert.notEqual(recordPath, p, 'oversized batch record must never be read');
      return readFile.call(this, recordPath);
    };
    try {
      const response = await (await batch([p, 'ops/member/one.json'])).text();
      assert.ok(Buffer.byteLength(response) < 1024);
      const first = JSON.parse(response);
      assert.equal(first.truncated, false); assert.equal(first.records.length, 2);
      assert.deepEqual(first.records[0], { path: p, status: 413, etag: `"${sha256(bytes)}"`, size: bytes.length });
      assert.equal(first.records[1].status, 200);
    } finally { slot.readFile = readFile; }
  });
  test('changed bytes, wrong sizes and symlinks never leak stored bytes', async () => {
    for (const [name, changed] of [['digest', 'evil'], ['size', 'longer']]) {
      const p = `ops/corrupt/${name}.json`; await put(p, Buffer.from('good'));
      await writeFile(path.join(dir, 'batch/records', p), changed);
      const r = await batch([p]); assert.equal(r.status, 500);
      assert.equal((await r.text()).includes(changed), false);
    }
    const p = 'ops/corrupt/symlink.json'; await put(p, Buffer.from('good'));
    const file = path.join(dir, 'batch/records', p);
    await unlink(file); await symlink(path.join(dir, 'batch/records/ops/member/one.json'), file);
    assert.equal((await batch([p])).status, 500);
  });
});

const wasm = process.env.COLOPHON_HOME_WASM ?? new URL('../../target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm', import.meta.url).pathname;
describe('home batch record fetch', { skip: existsSync(wasm) ? false : 'build colophon-home-wasm first' }, () => {
  let dir, running, base, slot, member, revoked;
  const route = '/records/batch';
  const history = 'authority/00000001.json';
  const waitingBase = new URL('../waiting', fixture.base + '/').href;

  // The fixture's signed history grants the device from seed 31 read access to
  // listening.podcasts and revokes the device from seed 32. Both keys are test keys.
  const identity = async (seed) => {
    const d = Buffer.from(hkdfSync('sha256', Buffer.alloc(32, seed), 'colophon/entropy/3', Buffer.alloc(8), 32));
    const ecdh = createECDH('prime256v1');
    ecdh.setPrivateKey(d);
    const point = ecdh.getPublicKey();
    const key = await crypto.subtle.importKey('jwk', {
      kty: 'EC', crv: 'P-256', d: d.toString('base64url'),
      x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url'),
    }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    return { id: sha256(point).slice(0, 32), point, key };
  };

  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-home-batch-'));
    running = await startRelay({
      port: 0, dataDir: dir, clock: () => fixture.now,
      libraries: {
        home: { home: true, base: fixture.base, account: fixture.account },
        waiting: { home: true, base: waitingBase, account: fixture.account },
      },
      home: { wasm, key: fixture.key }, limits: { requestsPerMinute: 0 },
      cors: { origins: ['https://client.example'] },
    });
    base = `http://127.0.0.1:${running.port}/v1/libraries/home`;
    slot = await running.relay.slot('home');
    const res = await fetch(`${base}/authority`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ from: 1, entries: fixture.entries, receipts: [] }),
    });
    assert.equal(res.status, 200, await res.text());
    [member, revoked] = await Promise.all([identity(31), identity(32)]);
  });
  after(async () => {
    await running?.close();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  async function sign(body, { who = member, method = 'POST', path = route,
    purpose = 'colophon.home.read', audience = fixture.base, now = fixture.now } = {}) {
    // The signed body uses canonical JSON (keys in lexical order).
    const call = Buffer.from(JSON.stringify({
      account: fixture.account,
      args: { body: sha256(body), method, path },
      asOf: { digest: fixture.asOf.digest, seq: fixture.asOf.seq },
      audience,
      created: new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      key: who.point.toString('base64'),
      protocol: 'colophon/call/5', purpose,
      requestId: randomBytes(32).toString('base64url'),
      signer: { member: who.id },
    }));
    const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, who.key, call));
    const envelope = JSON.stringify({ body: call.toString('base64'), signature: signature.toString('base64') });
    return `Colophon ${Buffer.from(envelope).toString('base64url')}`;
  }

  const post = (body, authorization, options = {}) => fetch(base + route, {
    method: 'POST', body, ...options,
    headers: { 'content-type': 'application/json', ...(authorization ? { authorization } : {}), ...options.headers },
  });
  const batchBody = (paths) => JSON.stringify({ paths });
  const batch = async (paths) => {
    const body = batchBody(paths);
    return post(body, await sign(body));
  };
  const record = (name, ns = 'listening.podcasts') => `state/${member.id}/${ns}/${name}.json`;
  const okRecord = (path, bytes) => ({ path, status: 200, etag: `"${sha256(bytes)}"`, bytes: bytes.toString('base64') });

  test('an unappointed home returns 404 before checking the call or parsing the body', async () => {
    const body = batchBody([history]);
    const url = new URL('../waiting/records/batch', base + '/');
    const signedMalformed = await sign('{', { audience: waitingBase });
    for (const [payload, authorization] of [[body, undefined], ['{', undefined], ['{', signedMalformed]]) {
      const res = await fetch(url, {
        method: 'POST', body: payload,
        headers: { 'content-type': 'application/json', ...(authorization ? { authorization } : {}) },
      });
      assert.equal(res.status, 404);
      assert.equal(res.headers.get('www-authenticate'), null);
    }
  });

  test('a public head still requires a call in a batch', async () => {
    const head = `heads/${slot.home.key.memberId}.json`;
    assert.equal((await fetch(`${base}/records/${head}`)).status, 200);
    const res = await post(batchBody([head]));
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('www-authenticate'), 'Colophon');
  });

  test('returns ordered records across namespaces like single-record GET and HEAD', async () => {
    const op = `ops/${member.id}/listening.podcasts/000000000001-${'ab'.repeat(16)}.json`;
    const opBytes = Buffer.from('opaque record');
    const blobBytes = Buffer.from([0, 255, 128, 42]);
    const blob = `blobs/${sha256(blobBytes)}`;
    const otherNamespace = record('present', 'notes');
    const otherMissing = record('missing', 'notes');
    const otherBytes = Buffer.from('opaque notes record');
    const missing = record('missing');
    const head = `heads/${slot.home.key.memberId}.json`;
    await slot.putImmutable(op, opBytes);
    await slot.putImmutable(blob, blobBytes);
    await slot.putImmutable(otherNamespace, otherBytes);

    const body = JSON.stringify({ paths: [op, missing, otherNamespace, history, otherMissing, blob, head] }, null, 2);
    const res = await post(body, await sign(body), { headers: { origin: 'https://client.example' } });
    assert.equal(res.status, 200, res.status === 200 ? undefined : await res.text());
    assert.equal(res.headers.get('cache-control'), 'no-store, no-transform');
    assert.equal(res.headers.get('access-control-allow-origin'), 'https://client.example');
    assert.deepEqual(await res.json(), { records: [
      okRecord(op, opBytes), { path: missing, status: 404 }, okRecord(otherNamespace, otherBytes),
      okRecord(history, await slot.readFile(history)), { path: otherMissing, status: 404 },
      okRecord(blob, blobBytes), okRecord(head, await slot.readFile(head)),
    ], truncated: false });
    const path = `/records/${otherNamespace}`;
    for (const method of ['GET', 'HEAD']) {
      const single = await fetch(base + path, { method, headers: { authorization: await sign('', { method, path }) } });
      assert.equal(single.status, 200);
      assert.equal(single.headers.get('etag'), `"${sha256(otherBytes)}"`);
      assert.deepEqual(Buffer.from(await single.arrayBuffer()), method === 'GET' ? otherBytes : Buffer.alloc(0));
    }
  });

  test('rejects missing, invalid, revoked, stale, mismatched and replayed calls before returning records', async () => {
    const body = batchBody([history]);
    for (const authorization of [undefined, 'Bearer wrong']) {
      const res = await post(body, authorization);
      assert.equal(res.status, 401);
      assert.equal(res.headers.get('www-authenticate'), 'Colophon');
    }

    const valid = await sign(body);
    const mismatched = await post(body + '\n', valid);
    assert.equal(mismatched.status, 403);
    assert.deepEqual(await mismatched.json(), { result: 'refused:outOfScope' });
    assert.equal((await post(body, valid)).status, 200, 'a wrong body hash does not spend the call');

    const forged = JSON.parse(Buffer.from(valid.slice('Colophon '.length), 'base64url'));
    const signature = Buffer.from(forged.signature, 'base64');
    signature[0] ^= 1;
    forged.signature = signature.toString('base64');
    const failures = [
      ['Colophon e30', 'malformed'],
      [`Colophon ${Buffer.from(JSON.stringify(forged)).toString('base64url')}`, 'badSignature'],
      [await sign(body, { who: revoked }), 'refused:revoked'],
      [await sign(body, { now: fixture.now - 3_600_000 }), 'refused:window'],
      [await sign(body, { purpose: 'colophon.history.read' }), 'refused:outOfScope'],
      [await sign(body, { purpose: 'colophon.home.write' }), 'refused:outOfScope'],
      [await sign(body, { audience: 'https://elsewhere.example' }), 'refused:audience'],
      [await sign(body, { method: 'GET', path: `/records/${history}` }), 'refused:outOfScope'],
      [valid, 'refused:replay'],
    ];
    const readFile = slot.readFile;
    slot.readFile = () => { throw new Error('a refused batch call must never read a record'); };
    try {
      for (const [authorization, result] of failures) {
        const res = await post(body, authorization);
        assert.equal(res.status, 403, result);
        assert.deepEqual(await res.json(), { result });
      }
    } finally { slot.readFile = readFile; }
  });

  test('rejects missing credentials and malformed batches before taking the slot lock', async () => {
    const get = await fetch(base + route);
    assert.equal(get.status, 405);
    assert.equal(get.headers.get('allow'), 'POST');
    const body = batchBody([history]);
    const authorization = await sign(body);
    assert.equal((await post(body, authorization, { headers: { 'content-type': 'text/plain' } })).status, 415);
    assert.equal((await post(' '.repeat(64 * 1024 + 1), authorization)).status, 413);
    const chunked = await new Promise((resolve, reject) => {
      const req = http.request(base + route, {
        method: 'POST', headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked', authorization },
      }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject);
      req.end(body);
    });
    assert.equal(chunked, 411);
    const lock = slot.home.lock;
    slot.home.lock = () => { throw new Error('a malformed batch must never take the slot lock'); };
    try {
      assert.equal((await post(body, undefined)).status, 401);
      for (const bad of ['{', batchBody([]), batchBody([history, history]), batchBody(['requests/old.json']),
        batchBody(Array.from({ length: 257 }, (_, i) => `authority/${String(i + 1).padStart(8, '0')}.json`))]) {
        assert.equal((await post(bad, await sign(bad))).status, 400, bad);
      }
    } finally { slot.home.lock = lock; }
    const maxBody = body.padEnd(64 * 1024);
    assert.equal((await post(maxBody, await sign(maxBody))).status, 200);
    const maxPaths = Array.from({ length: 256 }, (_, i) => `authority/${String(i + 1).padStart(8, '0')}.json`);
    const full = await batch(maxPaths);
    assert.equal(full.status, 200);
    assert.equal((await full.json()).records.length, 256);
  });

  test('truncates at 4 MiB and resumes with a call for the remaining paths', async () => {
    const paths = [record('oversized'), record('one'), record('two'), record('missing')];
    const oversized = Buffer.alloc(4 * 1024 * 1024, 0x71);
    const bytes = Buffer.alloc(1600 * 1024, 0x72);
    await slot.putImmutable(paths[0], oversized);
    for (const p of paths.slice(1, 3)) await slot.putImmutable(p, bytes);
    const readFile = slot.readFile;
    slot.readFile = function (p) {
      assert.notEqual(p, paths[0], 'an individually oversized record must never be read');
      return readFile.call(this, p);
    };
    try {
      const res = await batch(paths);
      assert.equal(res.status, 200);
      const text = await res.text();
      assert.ok(Buffer.byteLength(text) <= 4 * 1024 * 1024);
      const first = JSON.parse(text);
      assert.equal(first.truncated, true);
      assert.deepEqual(first.records, [
        { path: paths[0], status: 413, etag: `"${sha256(oversized)}"`, size: oversized.length },
        okRecord(paths[1], bytes),
      ]);
      const next = await batch(paths.slice(first.records.length));
      assert.equal(next.status, 200);
      assert.deepEqual(await next.json(), { records: [okRecord(paths[2], bytes), { path: paths[3], status: 404 }], truncated: false });
    } finally { slot.readFile = readFile; }
  });

  test('an unavailable own head returns a 503 item without serving the stored head', async () => {
    const head = `heads/${slot.home.key.memberId}.json`;
    assert.ok(slot.current.has(head));
    const settleForRead = slot.home.settleForRead;
    slot.home.settleForRead = async () => 'due';
    try {
      const res = await batch([head, history]);
      assert.equal(res.status, 200);
      assert.deepEqual(await res.json(), {
        records: [{ path: head, status: 503 }, okRecord(history, await slot.readFile(history))],
        truncated: false,
      });
    } finally { slot.home.settleForRead = settleForRead; }
  });

  test('one corrupt home record fails the entire batch without returning record bytes', async () => {
    const corrupt = record('corrupt');
    await slot.putImmutable(corrupt, Buffer.from('good'));
    await writeFile(path.join(slot.root, 'records', corrupt), 'evil');
    const body = batchBody([history, corrupt]);
    const authorization = await sign(body);
    const res = await post(body, authorization);
    assert.equal(res.status, 500);
    const error = await res.text();
    assert.equal(error.includes('evil'), false);
    assert.equal(error.includes((await slot.readFile(history)).toString('base64')), false);
    assert.equal(JSON.parse(error).records, undefined);
    const replay = await post(body, authorization);
    assert.equal(replay.status, 403);
    assert.deepEqual(await replay.json(), { result: 'refused:replay' });
  });

  test('rate limits batch requests before reading or authenticating their bodies', async () => {
    slot.home.rate.perMinute = 1;
    try {
      assert.equal((await batch([history])).status, 200);
      const denied = await post(' '.repeat(64 * 1024 + 1), undefined);
      assert.equal(denied.status, 429);
      assert.equal(denied.headers.get('retry-after'), '60');
    } finally {
      slot.home.rate.perMinute = 0;
      slot.home.rate.rows.clear();
    }
  });
});
