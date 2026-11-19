// Checkpoint loss is an operator recovery, never permission to initialize a retained slot.
// Real appointed and stopped histories are covered by v05_relay_stopped.rs.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startRelay } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready && (process.env.CI || process.env.COLOPHON_REQUIRE_RELAY)) throw new Error(`Home module missing: ${wasm}`);
const ACCOUNT = 'ab'.repeat(32);
const PREFIX = 'https://home.example/v1/libraries/';
const NOW = Date.parse('2026-11-16T00:00:00Z');

async function snapshot(dir) {
  const out = {};
  async function walk(at, prefix) {
    for (const entry of (await readdir(at, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const name = prefix + entry.name;
      if (entry.isDirectory()) { out[name + '/'] = null; await walk(path.join(at, entry.name), name + '/'); }
      else out[name] = (await readFile(path.join(at, entry.name))).toString('base64');
    }
  }
  await walk(dir, '');
  return out;
}

describe('home checkpoint recovery', { skip: ready ? false : 'module not built' }, () => {
  let key;
  before(async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    key = await crypto.subtle.exportKey('jwk', pair.privateKey);
  });
  const start = (dir, extra = {}) => startRelay({
    port: 0, dataDir: dir, tickMs: 0, clock: () => NOW,
    home: { wasm, key }, libraries: { home: { home: true, base: PREFIX + 'home', account: ACCOUNT } },
    ...extra,
  });

  test('a genuinely empty slot opens without a checkpoint', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-state-'));
    let running;
    try {
      await mkdir(path.join(dir, 'home/records/empty'), { recursive: true });
      await writeFile(path.join(dir, 'home/log.jsonl'), '');
      running = await start(dir);
      const r = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/home`);
      assert.equal(r.status, 200);
      assert.deepEqual((await r.json()).layouts, [2]);
      assert.ok(await readFile(path.join(dir, 'home/home-state.json')));
    } finally { await running?.close(); await rm(dir, { recursive: true, force: true }); }
  });

  for (const [name, bytes] of [
    ['records/unrecognized-file', 'held'],
    ['log.jsonl', '{"path":"authority/00000001.json","deleted":true}\n'],
    ['replay.log', ''], ['alive.json', '{}'], ['forward.json', '{}'],
  ]) test(`a missing checkpoint with only ${name} refuses startup without writes`, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-state-'));
    try {
      await mkdir(path.join(dir, 'home/records'), { recursive: true });
      await mkdir(path.join(dir, 'home/tmp'), { recursive: true });
      await writeFile(path.join(dir, 'home/tmp/keep-me'), 'untouched');
      await writeFile(path.join(dir, 'home', name), bytes);
      const before = await snapshot(dir);
      await assert.rejects(start(dir), /Home slot home: cannot open .*home-state\.json/);
      assert.deepEqual(await snapshot(dir), before);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  for (const bytes of ['', '{', '{}', 'null', '""', '"bad state"']) {
    test(`an existing invalid checkpoint ${JSON.stringify(bytes)} refuses even an otherwise empty slot`, async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'colophon-state-'));
      try {
        await mkdir(path.join(dir, 'home'), { recursive: true });
        await writeFile(path.join(dir, 'home/home-state.json'), bytes);
        const before = await snapshot(dir);
        await assert.rejects(start(dir), /Home slot home: cannot open .*home-state\.json/);
        assert.deepEqual(await snapshot(dir), before);
      } finally { await rm(dir, { recursive: true, force: true }); }
    });
  }

  test('a bad provisioned slot returns 503, leaves other slots serving, and retries after restore', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-state-'));
    let running;
    const errors = [];
    const log = console.error;
    console.error = (...args) => errors.push(args.join(' '));
    try {
      // Crash-like boundary: a durable provision row, but the checkpoint is damaged before
      // the first open. The valid backup belongs to the same key and synthetic account.
      running = await start(dir, {
        tracing: true,
        provision: { enabled: true, prefix: PREFIX, slotPattern: '^[a-z]{4,64}$' },
        hook: async (point) => {
          if (point !== 'provision written') return;
          await mkdir(path.join(dir, 'broken'), { recursive: true });
          await writeFile(path.join(dir, 'broken/home-state.json'), '{}');
        },
      });
      const base = `http://127.0.0.1:${running.port}`;
      const r = await fetch(base + '/v1/provision', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ slot: 'broken', base: PREFIX + 'broken', account: ACCOUNT }),
      });
      assert.equal(r.status, 503);
      assert.deepEqual(await r.json(), { result: 'unavailable' });
      const before = await snapshot(dir);
      for (const [method, suffix, body] of [['GET', '', undefined], ['POST', '/authority', '{"from":1,"entries":[],"receipts":[]}']]) {
        const answer = await fetch(base + '/v1/libraries/broken' + suffix, {
          method, headers: { 'content-type': 'application/json' }, body,
        });
        assert.equal(answer.status, 503);
        assert.deepEqual(await answer.json(), { result: 'unavailable' });
      }
      assert.deepEqual(await snapshot(dir), before);
      assert.equal((await fetch(base + '/v1/libraries/home')).status, 200);
      assert.ok(errors.length >= 3);
      assert.ok(errors.every((line) => line.includes('broken') && line.includes('home-state.json')));
      const backup = await readFile(path.join(dir, 'home/home-state.json'));
      await writeFile(path.join(dir, 'broken/home-state.json'), backup);
      assert.equal((await fetch(base + '/v1/libraries/broken')).status, 200, 'retry uses the restored checkpoint');

      // A later restart also isolates a provisioned failure, even when release is due.
      await running.close(); running = null;
      await writeFile(path.join(dir, 'broken/home-state.json'), '{}');
      running = await start(dir, {
        provision: { enabled: true, prefix: PREFIX, slotPattern: '^[a-z]{4,64}$', unclaimedHours: 1 },
        clock: () => NOW + 3_600_000,
      });
      const restarted = `http://127.0.0.1:${running.port}/v1/libraries/`;
      assert.equal((await fetch(restarted + 'home')).status, 200);
      const unavailable = await fetch(restarted + 'broken');
      assert.equal(unavailable.status, 503);
      assert.deepEqual(await unavailable.json(), { result: 'unavailable' });
    } finally { console.error = log; await running?.close(); await rm(dir, { recursive: true, force: true }); }
  });
});
