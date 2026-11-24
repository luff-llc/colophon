// Work done once where it was done several times: a stream frame is serialised once for all its
// receivers (and the text is what a per-receiver serialisation gives); a stored record's digest
// is the one its writer computed; an appointed slot is never examined for release.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, test } from 'node:test';
import { startRelay } from '../relay.js';
import { HomeStream, frameText } from '../stream.js';

const sha = (b) => createHash('sha256').update(b).digest('hex');

describe('a stream frame', () => {
  const frames = [
    { type: 'head', home: 'a'.repeat(32), seq: 7, digest: 'b'.repeat(64) },
    { type: 'pong' },
    { type: 'notice', notice: 3, object: 'o', kind: 'transition', deadline: null, extra: undefined },
    { type: 'session', retained: true, frame: { z: 1, a: ['x', { 'é': ' ' }], nested: { deep: true } } },
    { type: 'route', id: 'r', change: 'put', 10: 'integer-like key', kind: 'web' },
    { type: 'odd', n: 99, value: 1 },
    { type: 'error', code: 'badFrame', ref: '"quoted"\\' },
  ];
  test('is the same text as serialising it with each receiver\'s number', () => {
    for (const frame of frames) {
      for (const n of [1, 42, 2 ** 53 - 1]) {
        const { type, ...rest } = frame;
        assert.equal(frameText(frame)(n), JSON.stringify({ type, n, ...rest }), JSON.stringify(frame));
      }
    }
  });

  test('is still exactly the whole serialisation outside the frames the stream makes', () => {
    const odd = [{}, { type: undefined, x: 1 }, { type: 7 }, { type: 'x', toJSON() { return { y: 1 }; } }];
    for (const frame of odd) {
      for (const n of [1, Number.NaN, Infinity]) {
        const { type, ...rest } = frame;
        assert.equal(frameText(frame)(n), JSON.stringify({ type, n, ...rest }), `${JSON.stringify(frame)} at ${n}`);
      }
    }
  });

  test('a dropped connection is not live and takes no more messages', () => {
    const s = Object.create(HomeStream.prototype);
    s.conns = new Set();
    s.stopTimers = () => {};
    const conn = { live: true, timer: null, frames: { take: () => assert.fail('a message was taken') } };
    s.conns.add(conn);
    s.drop(conn);
    assert.equal(conn.live, false);
    s.receive(conn, Buffer.from('{"type":"ping"}'), false);
  });

  test('is serialised once for every receiver of a broadcast', () => {
    const s = Object.create(HomeStream.prototype);
    s.o = { bufferedBytes: 1 << 20 };
    s.home = { clock: () => 0 };
    s.counters = { slow: 0 };
    const sent = [];
    s.conns = new Set([1, 2, 3].map((i) => ({
      live: true, n: i * 10, expiresAt: null,
      ws: { OPEN: 1, readyState: 1, bufferedAmount: 0, send: (text) => sent.push(text) },
    })));
    let serialised = 0;
    const payload = { toJSON() { serialised += 1; return { big: 'x' }; } };
    s.broadcast({ type: 'session', frame: payload });
    assert.equal(serialised, 1, 'the frame body is serialised once');
    assert.deepEqual(sent, [11, 21, 31].map((n) => JSON.stringify({ type: 'session', n, frame: { big: 'x' } })));
  });
});

describe('a stored record', () => {
  test('is indexed under the digest its writer computed (no second hash)', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-digest-'));
    const running = await startRelay({ port: 0, dataDir: dir, libraries: { test: { open: true } } });
    try {
      const s = await running.relay.slot('test');
      const body = Buffer.from('a record');
      const given = 'f'.repeat(64); // not the body's digest: shows which one is used
      assert.equal(await s.putImmutable('ops/a/1.json', body, given), 201);
      assert.equal(s.current.get('ops/a/1.json').sha256, given);
      assert.equal(await s.replaceRequest('requests/r.json', body, undefined, given), 201);
      assert.equal(s.current.get('requests/r.json').sha256, given);
      // Without one, the body's own digest.
      assert.equal(await s.putImmutable('ops/a/2.json', body), 201);
      assert.equal(s.current.get('ops/a/2.json').sha256, sha(body));
      // A read still checks the stored bytes against the index.
      const res = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/test/records/ops/a/1.json`);
      assert.equal(res.status, 500);
    } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
  });
});

const target = process.env.CARGO_TARGET_DIR ?? path.join(import.meta.dir, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const PREFIX = 'https://home.example/v1/libraries/';
const ask = (port, slot, now) => new Promise((resolve, reject) => {
  const body = JSON.stringify({ slot, base: PREFIX + slot, account: 'ab'.repeat(32) });
  const req = http.request({ host: '127.0.0.1', port, path: '/v1/provision', method: 'POST',
    headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', reject);
  req.end(body);
});

describe('releasing unclaimed slots', { skip: existsSync(wasm) ? false : 'build colophon-home-wasm first' }, () => {
  test('an appointed slot is not examined: no lock, no module call', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-release-'));
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    let now = 1_794_384_000_000;
    const running = await startRelay({
      port: 0, dataDir: dir, tickMs: 0, clock: () => now,
      home: { wasm, key: await crypto.subtle.exportKey('jwk', pair.privateKey) },
      provision: { enabled: true, prefix: PREFIX, gate: 'open', unclaimedHours: 1 }, limits: { requestsPerMinute: 0 },
    });
    try {
      assert.equal(await ask(running.port, 'tslot00000a'), 200);
      const a = await running.relay.slot('tslot00000a');
      // As after a committed upload appointed this home (permanent for the slot).
      a.home.appointed = true;
      let examined = 0;
      const lock = a.home.lock; const status = a.home.status;
      a.home.lock = (fn) => { examined += 1; return lock(fn); };
      a.home.status = (...args) => { examined += 1; return status.apply(a.home, args); };
      now += 2 * 3_600_000;
      assert.equal(await ask(running.port, 'tslot00000b'), 200);
      assert.equal(examined, 0, 'the appointed slot was examined for release');
      assert.ok(existsSync(path.join(dir, 'tslot00000a')));
    } finally { await running.close(); await rm(dir, { recursive: true, force: true }); }
  });
});
