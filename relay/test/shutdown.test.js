// Shutdown of a relay with home slots: closing waits for each home's own work that no request
// carries (forwarding passes to other homes, their forward.json writes, work queued on the
// slot's locks), cuts a pass's waits on other homes short, and answers a long poll it ends with
// 503 (retry), not 404 (a slot this relay does not hold).
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { HomeSlot } from '../home.js';
import { startRelay } from '../relay.js';
import fixture from './fixtures/home-batch.json';

const PEER = 'b'.repeat(32);
const HEAD = { body: 'e30=', signature: 'AA==' };
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function until(fn) {
  for (let i = 0; i < 400; i++) { if (fn()) return; await tick(); }
  throw new Error('Timed out waiting for condition');
}

/** A home slot with every dependency stubbed, one peer, and its head to forward. */
function peered() {
  const h = Object.create(HomeSlot.prototype);
  h.state = 's1';
  h.key = { memberId: 'a'.repeat(32) };
  h.slot = { name: 'home', current: new Map() };
  h.forward = { peers: {} };
  h.lock = async (f) => f();
  h.note = () => {};
  h.trace = () => {};
  h.saved = [];
  h.writeJson = async (name) => { h.saved.push(name); };
  h.clock = () => 1_000_000;
  h.headIfFresh = async () => HEAD;
  h.stopping = new AbortController(); // as the constructor makes it
  const peers = [{ id: PEER, endpoints: ['https://peer.example/'] }];
  const answers = {
    status: () => ({ appointed: true, peers }),
    pending_page: () => ({ objects: [], more: false }),
    forward_entries: () => ({ from: 0, entries: [], exchange: false }),
  };
  h.wasm = { call: (req) => answers[req.op](req) };
  return h;
}

describe('a home at shutdown (host side)', () => {
  let realFetch; let started;
  beforeEach(() => {
    realFetch = globalThis.fetch; started = 0;
    // A peer that never answers: only an abort ends the request.
    globalThis.fetch = (url, init) => new Promise((resolve, reject) => {
      started += 1;
      init.signal.addEventListener('abort', () => reject(init.signal.reason));
    });
  });
  afterEach(() => { globalThis.fetch = realFetch; });

  test('quiesce cuts a forwarding pass short, waits for it, and starts no other', async () => {
    const h = peered();
    await h.forwardAll();
    await until(() => started === 1);
    assert.equal(h.passes.size, 1);
    const pass = [...h.passes.values()][0];
    let passEnded = false;
    pass.then(() => { passEnded = true; });
    await h.quiesce();
    assert.equal(passEnded, true, 'the pass ended before quiesce returned');
    assert.equal(h.passes.size, 0);
    await h.forwardAll();
    assert.equal(h.passes.size, 0, 'no pass after quiesce');
    assert.equal(started, 1);
  });

  test('a forwarding start that fails is noted, and never an unhandled rejection', async () => {
    const h = peered();
    const notes = [];
    h.note = (topic, message) => { if (message) notes.push([topic, message]); };
    h.lock = async (f) => f();
    h.settle = async () => 'fresh';
    h.keepLease = async () => {};
    h.resolve = () => ({ 'https://peer.example': 5 }); // not a URL: the start throws
    await h.tickOnce();
    await h.forwarding; // resolves: the failure is the note's
    assert.ok(notes.some(([topic]) => topic === 'forward'), JSON.stringify(notes));
    await h.quiesce();
  });

  test('quiesce waits for a forward.json write and the work queued on the locks', async () => {
    const h = peered();
    let release; let order = [];
    h.saving = new Promise((resolve) => { release = resolve; }).then(() => order.push('saved'));
    let chainTail = Promise.resolve();
    h.lock = (fn) => { const run = chainTail.then(fn, fn); chainTail = run.catch(() => {}); return run; };
    h.replayLock = h.lock;
    let unlock;
    h.lock(() => new Promise((resolve) => { unlock = resolve; })).then(() => order.push('locked work'));
    let done = false;
    const quiet = h.quiesce().then(() => { done = true; });
    await tick(); await tick();
    assert.equal(done, false);
    release(); unlock();
    await quiet;
    assert.deepEqual(order.sort(), ['locked work', 'saved']);
  });
});

const wasm = process.env.COLOPHON_HOME_WASM ?? new URL('../../target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm', import.meta.url).pathname;
describe('relay shutdown with a home slot', { skip: existsSync(wasm) ? false : 'build colophon-home-wasm first' }, () => {
  let dir;
  beforeEach(async () => { dir = await mkdtemp(path.join(tmpdir(), 'colophon-shutdown-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  test('close waits for a home\'s forwarding save that no request carries', async () => {
    const running = await startRelay({
      port: 0, dataDir: dir, clock: () => fixture.now,
      libraries: { home: { home: true, base: fixture.base, account: fixture.account } },
      home: { wasm, key: fixture.key }, limits: { requestsPerMinute: 0 },
    });
    const s = await running.relay.slot('home');
    let awaited = false; let released = false; const waiting = [];
    // A save in flight, as forwardTo leaves one: a thenable that records being awaited.
    s.home.saving = { then(resolve) { awaited = true; if (released) resolve(); else waiting.push(resolve); } };
    const release = () => { released = true; for (const resolve of waiting) resolve(); };
    let closed = false;
    const closing = running.close().then(() => { closed = true; });
    await until(() => awaited);
    assert.equal(closed, false, 'closed while a forward.json write was in flight');
    release();
    await closing;
    assert.equal(closed, true);
  });
});
