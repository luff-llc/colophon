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
