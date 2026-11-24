// The scheduler's quiet, the host side alone (relay/README.md "Idle passes are skipped"): the
// module and the network are stubbed, so what is checked is what home.js does with the module's
// answers. One clock reading per pass; no quiet after a pass that could not settle; a peer pass
// skipped only when the last one had nothing to send, never for a peer that fails.
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { HomeSlot, ModuleError } from '../home.js';

const PEER = 'b'.repeat(32);
const HEAD = { body: 'e30=', signature: 'AA==' };

/** A home slot with every dependency stubbed. `answers[op]` gives the module's answer (a
 * function of the request); `asked` lists every call as `[op, now]`. */
function slot(answers) {
  const h = Object.create(HomeSlot.prototype);
  h.state = 's1';
  h.key = { memberId: 'a'.repeat(32) };
  h.slot = { name: 'home', current: new Map() };
  h.forward = { peers: {} };
  h.lock = async (f) => f();
  h.note = () => {};
  h.trace = () => {};
  h.stream = { notice() {}, revalidate() {}, head() {} };
  h.routes = new Map();
  h.writeJson = async () => {};
  let t = 1_000_000;
  h.clock = () => (t += 1); // every reading is later than the last
  h.asked = [];
  h.wasm = {
    call: (req) => {
      h.asked.push([req.op, req.now]);
      const a = answers[req.op];
      if (!a) throw new Error(`unexpected op ${req.op}`);
      return a(req, h);
    },
  };
  return h;
}

const quietAnswers = (record = {}, head = {}) => ({
  status: () => ({ appointed: true, peers: [] }),
  record_due: (req) => ({ state: req.state, store: [], sign: [], notify: [], result: 'ok', settled: true, wakeAt: req.now + 60_000, ...record }),
  head_request: (req) => ({ state: req.state, sign: null, due: false, wakeAt: req.now + 30_000, ...head }),
});

describe('settling a pass', () => {
  test('one clock reading for the whole pass, and the quiet is of that reading', async () => {
    const h = slot(quietAnswers());
    assert.equal(await h.settle(), 'fresh');
    const nows = new Set(h.asked.map(([, now]) => now));
    assert.equal(nows.size, 1, `every call at one reading: ${JSON.stringify(h.asked)}`);
    const [now] = nows;
    assert.equal(h.quiet.now, now);
    assert.equal(h.quiet.until, now + 30_000, 'the earlier of the two wake times');
    h.asked = [];
    assert.equal(await h.settle(), 'fresh');
    assert.deepEqual(h.asked, [], 'a quiet pass asks nothing');
  });

  for (const [name, record, head] of [
    ['settled: false', { settled: false }, {}],
    ['no record wake time', { wakeAt: null }, {}],
    ['a record wake time that is NaN', { wakeAt: NaN }, {}],
    ['a record wake time not after the clock', { wakeAt: 0 }, {}],
    ['a guarded head (due, nothing to sign)', {}, { due: true, why: 'guard', wakeAt: undefined }],
    ['a head wake time not after the clock', {}, { wakeAt: 1 }],
  ]) {
    test(`${name} leaves no quiet: the next pass asks again`, async () => {
      const h = slot(quietAnswers(record, head));
      await h.settle();
      assert.equal(h.quiet, null);
      h.asked = [];
      await h.settle();
      assert.ok(h.asked.some(([op]) => op === 'record_due' || op === 'head_request'), JSON.stringify(h.asked));
    });
  }

  test('a module error leaves no quiet', async () => {
    const h = slot({ ...quietAnswers(), record_due: () => { throw new ModuleError('history: unavailable'); } });
    await assert.rejects(h.settle(), ModuleError);
    assert.equal(h.quiet, null);
  });

  test('a recorded entry leaves no quiet (something may be due at once over it)', async () => {
    const h = slot(quietAnswers({ state: 's2', wakeAt: null }));
    h.commit = async (state) => { if (state) h.state = state; };
    await h.settle();
    assert.equal(h.quiet, null);
  });

  test('an unappointed slot is quiet until its state changes', async () => {
    const h = slot({ status: () => ({ appointed: false, held: 0 }) });
    await h.settle();
    assert.equal(h.quiet.until, Infinity);
    h.asked = [];
    await h.settle();
    assert.deepEqual(h.asked, []);
    h.state = 's2'; // the first upload
    await h.settle();
    assert.deepEqual(h.asked.map(([op]) => op), ['status']);
  });
});

describe('forwarding while quiet', () => {
  let realFetch; let heads; let status;
  beforeEach(() => {
    realFetch = globalThis.fetch; heads = 0; status = 200;
    globalThis.fetch = async (url, init) => {
      if (String(url).includes('/records/heads/') && init.method === 'PUT') heads += 1;
      return { status, text: async () => '', arrayBuffer: async () => new ArrayBuffer(0) };
    };
  });
  afterEach(() => { globalThis.fetch = realFetch; });

  /** A quiet slot with one peer, nothing pending, no entries the peer lacks, and `head()` as its head. */
  function peered(head = () => HEAD) {
    const peers = [{ id: PEER, endpoints: ['https://peer.example/'] }];
    const h = slot({
      status: () => ({ appointed: true, peers }),
      pending_page: () => ({ objects: [], more: false }),
      forward_entries: () => ({ from: 0, entries: [], exchange: false }),
    });
    h.headIfFresh = async () => head();
    h.quiet = { state: h.state, now: 0, until: Infinity, status: { appointed: true, peers } };
    return h;
  }
  const pass = async (h) => { await h.forwardAll(); await Promise.all([...(h.passes?.values() ?? [])]); };
  const passes = (h) => h.asked.filter(([op]) => op === 'pending_page').length;

  test('a peer that took everything gets no pass until the state changes, then gets it', async () => {
    let head = HEAD;
    const h = peered(() => head);
    await pass(h); // sends the head
    await pass(h); // nothing to send: idle from here
    assert.equal(heads, 1);
    const before = passes(h);
    for (let i = 0; i < 5; i++) await pass(h);
    assert.equal(passes(h), before, 'no pass while quiet over the same state');
    assert.ok(!h.asked.some(([op]) => op === 'status'), 'the quiet status is reused');
    // The state changes (a new head was signed): the next pass runs and delivers it.
    head = { ...HEAD, signature: 'AQ==' };
    h.state = 's2';
    await pass(h);
    assert.equal(passes(h), before + 1);
    assert.equal(heads, 2, 'the new head reaches the peer on the first pass after the change');
  });

  for (const [name, setup] of [
    ['refuses the head', () => { status = 503; }],
    ['cannot be reached', () => { globalThis.fetch = async () => { throw new Error('connection refused'); }; }],
  ]) {
    test(`a peer that ${name} is tried again every pass while quiet`, async () => {
      setup();
      const h = peered();
      for (let i = 0; i < 4; i++) await pass(h);
      assert.equal(passes(h), 4, 'every pass runs');
      assert.equal(h.forwardIdle.has(PEER), false);
    });
  }

  test('a backlog keeps the peer in every pass', async () => {
    const h = peered();
    h.forward.peers[PEER] = { after: 0, retry: [7], head: '' };
    h.wasm.call = ((call) => (req) => (req.op === 'forward_objects' ? (h.asked.push([req.op]), { objects: [] }) : call(req)))(h.wasm.call);
    await pass(h);
    await pass(h);
    // The backlog object is no longer listed, so it drops out; only then may the peer go idle.
    assert.equal(passes(h), 2);
  });

  test('a peer marked idle gets a pass again after the clock steps back', async () => {
    const h = peered();
    await pass(h); // sends the head
    await pass(h); // nothing to send: idle
    const before = passes(h);
    await pass(h);
    assert.equal(passes(h), before, 'idle while quiet');
    // The clock steps back before the quiet's reading: settle asks again and makes a new quiet
    // over the same state; what the peer was sent was judged at the later reading.
    const back = h.quiet.now - 60_000;
    let t = back;
    h.clock = () => (t += 1);
    h.wasm.call = ((call) => (req) => (req.op === 'status' || req.op === 'record_due' || req.op === 'head_request'
      ? ({ status: { appointed: true, peers: [{ id: PEER, endpoints: ['https://peer.example/'] }] },
        record_due: { state: req.state, store: [], sign: [], notify: [], result: 'ok', settled: true, wakeAt: req.now + 60_000 },
        head_request: { state: req.state, sign: null, due: false, wakeAt: req.now + 30_000 } })[req.op]
      : call(req)))(h.wasm.call);
    await h.settle();
    assert.ok(h.isQuiet(), 'quiet again, over the same state');
    await pass(h);
    assert.equal(passes(h), before + 1, 'the peer gets a pass at the earlier reading');
  });
});
