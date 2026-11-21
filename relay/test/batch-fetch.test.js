import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, symlink, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { after, before, describe, test } from 'node:test';
import { sha256, startRelay } from '../relay.js';

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
test('home batch requests pass the rate gate without parsing or classifying the body', { skip: existsSync(wasm) ? false : 'build colophon-home-wasm first' }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'colophon-home-batch-'));
  let running;
  try {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const key = await crypto.subtle.exportKey('jwk', pair.privateKey);
    running = await startRelay({ port: 0, dataDir: dir,
      libraries: { home: { home: true, base: 'https://home.example', account: 'ab'.repeat(32) } },
      home: { wasm, key }, limits: { requestsPerMinute: 2 },
    });
    const slot = await running.relay.slot('home');
    let classifications = 0, reads = 0, rateChecks = 0;
    slot.classify = () => { classifications++; throw new Error('batch paths must not be classified'); };
    slot.home.deps.readBody = () => { reads++; throw new Error('batch body must not be read'); };
    const take = slot.home.rate.take.bind(slot.home.rate);
    slot.home.rate.take = (...args) => { rateChecks++; return take(...args); };
    const bodies = ['{', JSON.stringify({ paths: Array.from({ length: 256 }, (_, i) => `ops/member/${i}.json`) }),
      JSON.stringify({ paths: Array.from({ length: 256 }, (_, i) => `../invalid/${i}`) })];
    const answers = [];
    for (const body of bodies) {
      const r = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/home/records/batch`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body,
      });
      answers.push({ status: r.status, body: await r.text() });
      if (r.status === 429) assert.equal(r.headers.get('retry-after'), '60');
    }
    assert.ok([404, 405].includes(answers[0].status));
    assert.deepEqual(answers[1], answers[0], 'body shape must not change the home refusal');
    assert.equal(answers[2].status, 429);
    assert.equal(rateChecks, 3);
    assert.equal(reads, 0);
    assert.equal(classifications, 0);
  } finally { await running?.close(); await rm(dir, { recursive: true, force: true }); }
});
