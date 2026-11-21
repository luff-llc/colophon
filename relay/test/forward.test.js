// Forwarding to a peer (§13.1), the host side alone: the module and the network are stubbed, so
// what is checked is what home.js does with the module's answers. The time an entries suffix was
// last offered is kept with the forwarding state (it survives a restart) and a clock that moved
// back offers the suffix again at once instead of holding it back.
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { HomeSlot } from '../home.js';

const PEER = 'b'.repeat(32);
const ENTRY = Buffer.from(JSON.stringify({ body: 'e30=', signature: 'AA==' })).toString('base64');

/** A home slot with every dependency stubbed; `posts` counts entries offered to the peer. */
function slot() {
  const h = Object.create(HomeSlot.prototype);
  h.writes = [];
  h.state = null;
  h.key = { memberId: 'a'.repeat(32) };
  h.forward = { peers: {} };
  h.lock = async (f) => f();
  h.note = () => {};
  h.clock = () => 0;
  h.headIfFresh = () => null;
  h.writeJson = async (name, value) => { h.writes.push({ name, value: JSON.parse(JSON.stringify(value)) }); };
  h.wasm = {
    call: (req) => {
      if (req.op === 'pending_page') return { objects: [], more: false };
      if (req.op === 'forward_objects') return { objects: [] };
      if (req.op === 'forward_entries') return { from: 5, entries: [ENTRY], exchange: false };
      throw new Error(`unexpected op ${req.op}`);
    },
  };
  return h;
}

describe('offering entries to a peer', () => {
  let now; let realNow; let realFetch; let posts;
  beforeEach(() => {
    realNow = Date.now; realFetch = globalThis.fetch; posts = 0;
    Date.now = () => now;
    globalThis.fetch = async (url, init) => {
      if (String(url).endsWith('/authority') && init.method === 'POST') posts += 1;
      return { status: 200, text: async () => '', arrayBuffer: async () => new ArrayBuffer(0) };
    };
  });
  afterEach(() => { Date.now = realNow; globalThis.fetch = realFetch; });

  test('the time of the last offer is saved with the forwarding state', async () => {
    const h = slot();
    const row = (h.forward.peers[PEER] = { after: 0, retry: [], head: '' });
    now = 1_000_000;
    await h.forwardTo('http://peer.test', row, PEER);
    assert.equal(posts, 1);
    const saved = h.writes.filter((w) => w.name === 'forward.json').at(-1);
    assert.equal(saved?.value.peers[PEER].entriesAt, 1_000_000, 'saved after the offer');
    // Restarted from what was saved: within 2 s the same suffix is not offered again.
    const back = slot();
    back.forward = saved.value;
    now = 1_001_000;
    await back.forwardTo('http://peer.test', back.forward.peers[PEER], PEER);
    assert.equal(posts, 1);
    now = 1_002_500;
    await back.forwardTo('http://peer.test', back.forward.peers[PEER], PEER);
    assert.equal(posts, 2, 'offered again 2 s later');
  });

  test('an append during the entries request cannot advance the forwarded head', async () => {
    const h = slot();
    const row = { after: 0, retry: [], head: '' };
    now = 1_000;
    let head = { seq: 5 };
    h.headIfFresh = async () => head;
    const sent = [];
    globalThis.fetch = async (url, init) => {
      if (String(url).endsWith('/authority')) head = { seq: 6 };
      else sent.push(JSON.parse(init.body));
      return { status: 200, text: async () => '' };
    };
    await h.forwardTo('http://peer.test', row, PEER);
    assert.deepEqual(sent, [{ seq: 5 }]);
  });

  for (const status of [409, 422, 500]) {
    test(`an entry upload rejected with ${status} does not forward its head`, async () => {
      const h = slot();
      now = 1_000;
      h.headIfFresh = async () => ({ seq: 5 });
      const requests = [];
      globalThis.fetch = async (url, init) => {
        requests.push(init.method);
        return { status, text: async () => 'rejected' };
      };
      const row = { after: 0, retry: [], head: '' };
      await h.forwardTo('http://peer.test', row, PEER);
      now += 1_000;
      await h.forwardTo('http://peer.test', row, PEER);
      assert.deepEqual(requests, ['POST'], 'a throttled retry cannot send the rejected head either');
    });
  }

  for (const name of ['network failure', 'timeout']) {
    test(`an entry upload ending in ${name} does not forward its head`, async () => {
      const h = slot();
      now = 1_000;
      h.headIfFresh = async () => ({ seq: 5 });
      const requests = [];
      globalThis.fetch = async (url, init) => {
        requests.push(init.method);
        throw new Error(name);
      };
      await assert.rejects(h.forwardTo('http://peer.test', { after: 0, retry: [], head: '' }, PEER), { message: name });
      assert.deepEqual(requests, ['POST']);
    });
  }

  for (const status of [200, 204, 421]) {
    test(`an entry upload returning ${status} allows its head`, async () => {
      const h = slot();
      now = 1_000;
      h.headIfFresh = async () => ({ seq: 5 });
      const requests = [];
      globalThis.fetch = async (url, init) => {
        requests.push(init.method);
        return { status: requests.length === 1 ? status : 200, text: async () => '' };
      };
      await h.forwardTo('http://peer.test', { after: 0, retry: [], head: '' }, PEER);
      assert.deepEqual(requests, status === 421 ? ['POST', 'PUT', 'POST'] : ['POST', 'PUT']);
    });
  }

  test('a fork exchange sends its covering head before the expected 409', async () => {
    const h = slot();
    now = 1_000;
    h.headIfFresh = async () => ({ seq: 5 });
    const call = h.wasm.call;
    h.wasm.call = (req) => req.op === 'forward_entries' ? { ...call(req), exchange: true } : call(req);
    const requests = [];
    globalThis.fetch = async (url, init) => {
      requests.push(init.method);
      return { status: init.method === 'POST' ? 409 : 200, text: async () => '' };
    };
    await h.forwardTo('http://peer.test', { after: 0, retry: [], head: '' }, PEER);
    assert.deepEqual(requests, ['PUT', 'POST']);
  });

  test('a head can be sent when there are no entries to upload', async () => {
    const h = slot();
    now = 1_000;
    h.headIfFresh = async () => ({ seq: 5 });
    const call = h.wasm.call;
    h.wasm.call = (req) => req.op === 'forward_entries' ? { ...call(req), entries: [] } : call(req);
    const requests = [];
    globalThis.fetch = async (url, init) => {
      requests.push(init.method);
      return { status: 200, text: async () => '' };
    };
    await h.forwardTo('http://peer.test', { after: 0, retry: [], head: '' }, PEER);
    assert.deepEqual(requests, ['PUT']);
  });

  test('an exhausted pass never starts the entries snapshot lock', async () => {
    const h = slot();
    now = 1_000;
    h.lock = async () => { throw new Error('snapshot lock entered'); };
    await h.forwardEntries('http://peer.test', {}, PEER, now);
  });

  test('entries, head and forced retry share the remaining pass deadline', async () => {
    const h = slot();
    const row = { after: 0, retry: [], head: '' };
    h.headIfFresh = async () => ({ seq: 5 });
    now = 0;
    const realTimeout = AbortSignal.timeout;
    const limits = [];
    AbortSignal.timeout = (ms) => { limits.push(ms); return realTimeout(ms); };
    // Simulate work before forwarding entries, then the 421 and head responses.
    h.saveForward = async () => { if (now === 0) now = 11_000; };
    const requests = [];
    globalThis.fetch = async (url) => {
      requests.push(String(url));
      now += requests.length === 1 ? 3_000 : 1_000;
      return { status: requests.length === 1 ? 421 : 200, text: async () => '' };
    };
    try {
      await h.forwardTo('http://peer.test', row, PEER);
      assert.deepEqual(limits, [4_000, 1_000]);
      assert.equal(requests.length, 2, 'no forced retry after the deadline');
      assert.equal(now, 15_000);
    } finally { AbortSignal.timeout = realTimeout; }
  });

  test('new object offers cannot leave entries or a head outside the pass budget', async () => {
    const h = slot();
    h.forwardEntries = async () => { throw new Error('entries forwarding started after deadline'); };
    const row = { after: 0, retry: [], head: '' };
    now = 0;
    h.headIfFresh = async () => ({ seq: 5 });
    h.wasm.call = (req) => {
      if (req.op === 'pending_page') return { objects: [1, 2, 3, 4].map((seq) => ({ seq, kind: 'transition' })) };
      if (req.op === 'forward_objects') return { objects: [ENTRY] };
      if (req.op === 'peer_answer') return { delivered: false, why: 'timeout' };
      throw new Error(`unexpected op after deadline: ${req.op}`);
    };
    let requests = 0;
    globalThis.fetch = async (url) => {
      assert.ok(String(url).endsWith('/pending'));
      requests += 1;
      now += 5_000;
      return { status: 503, arrayBuffer: async () => new ArrayBuffer(0) };
    };
    await h.forwardTo('http://peer.test', row, PEER);
    assert.equal(requests, 3);
    assert.equal(now, 15_000);
    assert.deepEqual(row.retry, [1, 2, 3, 4]);
  });

  test('a clock that moved back offers the suffix again at once', async () => {
    const h = slot();
    const row = (h.forward.peers[PEER] = { after: 0, retry: [], head: '' });
    now = 5_000_000;
    await h.forwardTo('http://peer.test', row, PEER);
    assert.equal(posts, 1);
    now = 4_000_000; // an hour back
    await h.forwardTo('http://peer.test', row, PEER);
    assert.equal(posts, 2, 'not held back until the clock catches up');
  });
});

describe('the forwarding state saved while a pass is offering', () => {
  let realFetch;
  beforeEach(() => { realFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = realFetch; });

  test('a save made by another pass never has the cursor past an object without its retry', async () => {
    const h = slot();
    const listed = { seq: 7, digest: 'd'.repeat(64), kind: 'transition', envelope: ENTRY };
    h.wasm.call = (req) => {
      if (req.op === 'pending_page') return { objects: req.after < 7 ? [listed] : [], more: false };
      if (req.op === 'forward_objects') return { objects: [ENTRY] };
      if (req.op === 'forward_entries') return { from: 0, entries: [], exchange: false };
      if (req.op === 'peer_answer') return { delivered: false, why: 'status 503' };
      throw new Error(`unexpected op ${req.op}`);
    };
    let release; let offered;
    const asked = new Promise((r) => { offered = r; });
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      if (calls === 1) { offered(); await new Promise((r) => { release = r; }); }
      return { status: 503, text: async () => '', arrayBuffer: async () => new ArrayBuffer(0) };
    };
    const row = (h.forward.peers[PEER] = { after: 0, retry: [], head: '' });
    const pass = h.forwardTo('http://peer.test', row, PEER);
    await asked; // the pass is offering seq 7, and has not heard back
    await h.saveForward(); // another peer's pass saves now; then the process dies
    const saved = h.writes.filter((w) => w.name === 'forward.json').at(-1).value.peers[PEER];
    assert.ok(saved.after < 7 || saved.retry.includes(7), `cursor ${saved.after} without retry ${JSON.stringify(saved.retry)}`);
    release();
    await pass;
    const last = h.writes.filter((w) => w.name === 'forward.json').at(-1).value.peers[PEER];
    assert.deepEqual([last.after, last.retry], [7, [7]], 'after the pass: past it, and to be offered again');
  });
});
