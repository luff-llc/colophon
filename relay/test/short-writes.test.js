// A write to a file may take fewer bytes than it was given (a full disk, a signal). Every durable
// file the relay writes, written by a file system that takes at most a few bytes per call, is
// still written whole: replay logs and their compactions, a stored record, the change log, and
// the provisioning table.
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { HomeSlot } from '../home.js';
import { ProvisionReplay, ProvisionTable } from '../provision.js';
import { startRelay } from '../relay.js';
import { writeAllSync } from '../container-entry.js';

/** Every file handle opened from now on writes at most 5 bytes per call. */
function shortWrites() {
  const open = fsp.open;
  fsp.open = async (...args) => {
    const handle = await open.apply(fsp, args);
    const write = handle.write.bind(handle);
    handle.write = (data, ...rest) => {
      if (typeof data === 'string') return write(Buffer.from(data, rest[1] ?? 'utf8').subarray(0, 5), 0, Math.min(5, Buffer.byteLength(data)), rest[0] ?? null);
      const [offset = 0, length = data.length - offset, position = null] = rest;
      return write(data, offset, Math.min(5, length), position);
    };
    return handle;
  };
  return () => { fsp.open = open; };
}

const wasm = {
  call: (req) => {
    if (req.op === 'limits') return { retentionMs: 7_260_000 };
    if (req.op === 'replay_keep') return { keep: req.rows.map((r) => r.key) };
    if (req.op === 'replay_recover') return { states: [] };
    throw new Error(`unexpected op ${req.op}`);
  },
};
const row = (key) => ({ key, digest: 'd'.repeat(64), at: 1_000_000, signer: 'member:m' });
const lines = async (file) => (await readFile(file, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l));

describe('short writes', () => {
  let root; let restore;
  beforeEach(async () => { root = await mkdtemp(path.join(tmpdir(), 'colophon-short-')); restore = shortWrites(); });
  afterEach(async () => { restore(); await rm(root, { recursive: true, force: true }); });

  test('a home slot\'s replay log: appends and compaction', async () => {
    await fsp.mkdir(path.join(root, 'tmp'));
    const h = Object.create(HomeSlot.prototype);
    Object.assign(h, { slot: { root, current: new Map() }, rows: new Map(), bySigner: new Map(), logLines: 0, clock: () => 1_000_000, wasm });
    await h.reserve(row('a'), null);
    await h.reserve(row('b'), { path: 'ops/x.json', prior: null });
    assert.deepEqual((await lines(path.join(root, 'replay.log'))).map((l) => l.r), ['a', 'b']);
    await h.compactReplay();
    assert.deepEqual((await lines(path.join(root, 'replay.log'))).map((l) => l.r), ['a', 'b']);
  });

  test('the provisioning replay log and table', async () => {
    const r = await ProvisionReplay.open(root, { wasm, clock: () => 1_000_000, table: { get: () => undefined } });
    await r.reserve(row('p'), { slot: 'tslot00000a' });
    await r.complete('p', 'completed');
    assert.deepEqual((await lines(path.join(root, 'provision-replay', 'replay.log'))).map((l) => l.r ?? l.c), ['p', 'p']);
    await r.compact();
    assert.deepEqual((await lines(path.join(root, 'provision-replay', 'replay.log'))).map((l) => l.r), ['p']);
    const table = ProvisionTable.empty(root);
    const entry = { account: 'ab'.repeat(32), base: 'https://h.example/v1/libraries/tslot00000a', at: 1, request: 'AAAA' };
    await table.write('tslot00000a', entry);
    assert.deepEqual(JSON.parse(await readFile(path.join(root, 'provisioned.json'), 'utf8')), { tslot00000a: entry });
  });

  test('a stored record and the change log', async () => {
    const running = await startRelay({ port: 0, dataDir: root, libraries: { test: { open: true } } });
    try {
      const body = Buffer.from('a record a good deal longer than five bytes');
      const res = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/test/records/ops/a/1.json`, { method: 'PUT', body, headers: { 'if-none-match': '*' } });
      assert.equal(res.status, 201);
      assert.deepEqual(await readFile(path.join(root, 'test', 'records', 'ops', 'a', '1.json')), body);
      const logged = await lines(path.join(root, 'test', 'log.jsonl'));
      assert.deepEqual(logged.map((e) => e.path), ['ops/a/1.json']);
      const read = await fetch(`http://127.0.0.1:${running.port}/v1/libraries/test/records/ops/a/1.json`);
      assert.equal(read.status, 200);
    } finally { await running.close(); }
  });

  test('an append that fails part way is cut back to the last whole line', async () => {
    restore();
    await fsp.mkdir(path.join(root, 'tmp'));
    const h = Object.create(HomeSlot.prototype);
    Object.assign(h, { slot: { root, current: new Map() }, rows: new Map(), bySigner: new Map(), logLines: 0, clock: () => 1_000_000, wasm });
    await h.reserve(row('a'), null);
    const before = await readFile(path.join(root, 'replay.log'), 'utf8');
    const open = fsp.open;
    fsp.open = async (...args) => {
      const handle = await open.apply(fsp, args);
      const write = handle.write.bind(handle);
      let calls = 0;
      handle.write = async (data, offset = 0, length = data.length, position = null) => {
        calls += 1;
        if (calls > 1) throw Object.assign(new Error('no space left on device'), { code: 'ENOSPC' });
        return write(data, offset, Math.min(5, length), position);
      };
      return handle;
    };
    try { await assert.rejects(h.reserve(row('b'), null), /no space/); } finally { fsp.open = open; }
    assert.equal(await readFile(path.join(root, 'replay.log'), 'utf8'), before, 'no part of a line is left');
    await h.reserve(row('c'), null);
    assert.deepEqual((await lines(path.join(root, 'replay.log'))).map((l) => l.r), ['a', 'c']);
  });
});

describe('the change log after an append it could not cut back', () => {
  test('takes no further row: no row ever follows a part of a line', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'colophon-log-'));
    const running = await startRelay({ port: 0, dataDir: root, libraries: { test: { open: true } } });
    const put = (p) => fetch(`http://127.0.0.1:${running.port}/v1/libraries/test/records/${p}`, { method: 'PUT', body: 'x', headers: { 'if-none-match': '*' } });
    const open = fsp.open;
    try {
      assert.equal((await put('ops/a/1.json')).status, 201);
      // The next append writes part of its line, fails, and cannot be cut back.
      fsp.open = async (file, ...rest) => {
        const handle = await open.call(fsp, file, ...rest);
        if (!String(file).endsWith('log.jsonl')) return handle;
        const write = handle.write.bind(handle);
        handle.write = async (data, offset = 0, length = data.length, position = null) => {
          await write(data, offset, Math.min(5, length), position);
          throw Object.assign(new Error('i/o error'), { code: 'EIO' });
        };
        handle.truncate = async () => { throw Object.assign(new Error('i/o error'), { code: 'EIO' }); };
        return handle;
      };
      assert.equal((await put('ops/a/2.json')).status, 500);
      fsp.open = open;
      assert.equal((await put('ops/a/3.json')).status, 500, 'the log takes nothing after the fragment');
      const text = await readFile(path.join(root, 'test', 'log.jsonl'), 'utf8');
      assert.ok(!/\n[^\n]*\{[^\n]*\n.+/.test(text.slice(text.indexOf('\n') + 1)), JSON.stringify(text));
      assert.equal(text.split('\n').filter(Boolean).length, 2, 'one whole line and the fragment');
    } finally { fsp.open = open; await running.close(); await rm(root, { recursive: true, force: true }); }
  });
});

describe('synchronous writes in the entry point', () => {
  test('write every byte however few each call takes', () => {
    const out = [];
    const short = (fd, buf, offset, length) => { const n = Math.min(3, length); out.push(...buf.subarray(offset, offset + n)); return n; };
    writeAllSync(7, 'a token hash, in full\n', short);
    assert.equal(Buffer.from(out).toString(), 'a token hash, in full\n');
    assert.throws(() => writeAllSync(7, 'x', () => 0), /no progress/);
  });
});
