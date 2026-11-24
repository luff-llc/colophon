// The scheduler's quiet (relay/README.md "Scheduler"): a home whose state has not changed is not
// asked anything before the time the module said something could come due (`wakeAt` from
// `record_due` and `head_request`), and is asked again at that time, after a state change, or
// when the clock goes back. Synthetic account (fixtures/home-batch.json); test keys only.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, test } from 'node:test';
import { startRelay } from '../relay.js';
import { HomeModule } from '../home.js';
import fixture from './fixtures/home-batch.json';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasmFile = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasmFile);
if (!ready && (process.env.CI || process.env.COLOPHON_REQUIRE_RELAY)) throw new Error(`Home module missing: ${wasmFile}`);

describe('scheduler quiet', { skip: ready ? false : 'module not built' }, () => {
  let dir, running, slot, wasm;
  let now = fixture.now;
  const calls = new Map();
  const asked = (op) => calls.get(op) ?? 0;
  const tick = async (at) => { now = at; await running.relay.tickAll(); };
  const headIssued = async () => {
    const file = path.join(dir, 'home/records/heads', `${slot.home.key.memberId}.json`);
    const envelope = JSON.parse(await readFile(file, 'utf8'));
    return Date.parse(JSON.parse(Buffer.from(envelope.body, 'base64')).issued);
  };

  before(async () => {
    wasm = await HomeModule.load(wasmFile);
    const call = wasm.call.bind(wasm);
    wasm.call = (request) => { calls.set(request.op, asked(request.op) + 1); return call(request); };
    dir = await mkdtemp(path.join(tmpdir(), 'colophon-scheduler-'));
    running = await startRelay({
      port: 0, dataDir: dir, clock: () => now, tickMs: 0,
      libraries: { home: { home: true, base: fixture.base, account: fixture.account } },
      home: { wasm, key: fixture.key }, limits: { requestsPerMinute: 0 },
    });
    slot = await running.relay.slot('home');
    // Unappointed: quiet until its state changes, which the first upload does.
    await tick(fixture.now);
    assert.equal(slot.home.quiet?.until, Infinity, 'an unappointed slot is quiet');
    calls.clear();
    await tick(fixture.now + 500);
    assert.deepEqual([...calls.keys()].filter((op) => op !== 'lease'), [], 'and asks nothing');
    const res = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/home/authority`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ from: 1, entries: fixture.entries, receipts: [] }),
    });
    assert.equal(res.status, 200, await res.text());
    calls.clear();
    await tick(fixture.now + 900);
    assert.ok(asked('record_due') >= 1, 'the first upload ends the quiet');
    // Settle: the first passes sign the head over the uploaded history.
    for (let i = 1; i <= 3; i++) await tick(fixture.now + i * 1_000);
  });
  after(async () => {
    await running?.close();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  test('an idle home is asked nothing until its wake time, and its head is signed again then', async () => {
    const quiet = slot.home.quiet;
    assert.ok(quiet && Number.isFinite(quiet.until) && quiet.until > now, `a quiet with a time: ${JSON.stringify(quiet && { now: quiet.now, until: quiet.until })}`);
    const issued = await headIssued();
    const { headMaxAge } = slot.home.status();
    assert.equal(quiet.until, issued + headMaxAge * 500, 'the wake time is the next head time (nothing else waits)');
    calls.clear();
    for (let t = now + 2_000; t < quiet.until; t += Math.max(2_000, Math.floor((quiet.until - now) / 20))) await tick(t);
    await tick(quiet.until - 1);
    assert.deepEqual([...calls.keys()].filter((op) => op !== 'lease'), [], `no module call while quiet: ${JSON.stringify([...calls])}`);
    assert.equal(await headIssued(), issued, 'no new head before its time');
    await tick(quiet.until);
    assert.ok(asked('record_due') >= 1 && asked('head_request') >= 1, `asked again at the wake time: ${JSON.stringify([...calls])}`);
    assert.equal(await headIssued(), issued + headMaxAge * 500, 'the head is signed at exactly its time');
  });

  test('a head read while quiet asks nothing of the scheduler; a large clock jump wakes it', async () => {
    for (let i = 1; i <= 3; i++) await tick(now + 1_000);
    assert.ok(slot.home.isQuiet());
    calls.clear();
    const r = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/home/head`);
    assert.equal(r.status, 200);
    assert.equal(asked('record_due') + asked('head_request'), 0, `a read settles through the quiet: ${JSON.stringify([...calls])}`);
    const jump = now + 30 * 24 * 3_600_000;
    await tick(jump);
    assert.ok(asked('record_due') >= 1, 'a jump past the wake time asks again');
    assert.equal(await headIssued(), jump, 'and the head is signed at once');
  });

  test('a state change, or a clock that went back, ends the quiet', async () => {
    for (let i = 1; i <= 3; i++) await tick(now + 1_000);
    assert.ok(slot.home.isQuiet(), 'quiet again after the new head');
    calls.clear();
    await tick(now + 1_000);
    assert.equal(asked('record_due'), 0);
    // A clock that went back is asked again.
    await tick(slot.home.quiet.now - 1);
    assert.equal(asked('record_due'), 1, 'a clock before the quiet began asks again');
    for (let i = 1; i <= 3; i++) await tick(slot.home.quiet.now + i * 1_000);
    calls.clear();
    // A committed state change (a serving interval closed, as at a restart) asks again.
    const r = wasm.call({ op: 'resume', state: slot.home.state, now, alive: now - 60_000 });
    assert.equal(r.changed, true);
    await slot.home.lock(() => slot.home.commit(r.state));
    calls.clear();
    await tick(now + 1_000);
    assert.equal(asked('record_due'), 1, 'a new state asks again');
    calls.clear();
    await tick(now + 1_000);
    assert.equal(asked('record_due'), 0, 'and is quiet again after');
  });
});
