import { test, expect } from 'bun:test';
import { promises as fs, constants as flags } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRelay, startRelay, sha256 } from '../relay.js';

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn) {
  for (let i = 0; i < 200; i++) { if (fn()) return; await delay(5); }
  throw new Error('Timed out waiting for condition');
}
async function fixture(fn, limits = {}) {
  const dataDir = await fs.mkdtemp(path.join(tmpdir(), 'relay-hardening-'));
  let running;
  try {
    running = await startRelay({ port: 0, dataDir, libraries: { test: { open: true } }, limits });
    await fn(running, `http://127.0.0.1:${running.port}/v1/libraries/test`, dataDir);
  } finally { await running?.close(); await fs.rm(dataDir, { recursive: true, force: true }); }
}
const put = (base, p, body, headers = { 'if-none-match': '*' }) => fetch(`${base}/records/${p}`, { method: 'PUT', body, headers });

test('disconnect immediately cleans long-poll waiters and timers', () => fixture(async (r, base) => {
  const slot = await r.relay.slot('test');
  const req = request(`${base}/changes?wait=30`);
  req.on('error', () => {});
  req.end();
  await until(() => slot.waiters.size === 1);
  req.destroy();
  await until(() => slot.waiters.size === 0);
}));

test('filtered long poll waits through unrelated writes and expires at its deadline', () => fixture(async (r, base) => {
  const slot = await r.relay.slot('test');
  let done = false;
  const poll = fetch(`${base}/changes?namespace=notes&wait=2`).then((res) => { done = true; return res.json(); });
  await until(() => slot.waiters.size === 1);
  const waiter = [...slot.waiters][0];
  const wake = waiter.wake;
  let wakes = 0;
  waiter.wake = () => { wakes++; wake(); };
  const changes = slot.changes;
  let repolls = 0;
  slot.changes = function (...args) { repolls++; return changes.apply(this, args); };
  await put(base, 'ops/a/other/1.json', 'other');
  await delay(50);
  expect(done).toBe(false);
  expect(slot.waiters.size).toBe(1);
  expect([...slot.waiters][0]).toBe(waiter);
  expect(wakes).toBe(0);
  expect(repolls).toBe(0);
  await put(base, 'ops/a/notes/1.json', 'notes');
  expect((await poll).entries.map((e) => e.path)).toEqual(['ops/a/notes/1.json']);
  expect(wakes).toBe(1);
  expect(repolls).toBe(1);
  slot.changes = changes;
  const cursor = slot.changes('', 100).cursor;
  const started = Date.now();
  const timeout = fetch(`${base}/changes?namespace=absent&wait=1&after=${cursor}`);
  await until(() => slot.waiters.size === 1);
  await put(base, 'ops/a/other/2.json', 'other');
  expect((await (await timeout).json()).entries).toEqual([]);
  expect(Date.now() - started).toBeGreaterThanOrEqual(900);
  expect(slot.waiters.size).toBe(0);
}));

test('long-poll cap refuses excess polls and frees capacity after disconnect', () => fixture(async (r, base) => {
  const slot = await r.relay.slot('test');
  const req = request(`${base}/changes?namespace=notes&wait=30`);
  req.on('error', () => {}); req.end();
  try {
    await until(() => slot.waiters.size === 1);
    const excess = await fetch(`${base}/changes?namespace=other&wait=30`);
    expect(excess.status).toBe(503);
    expect(excess.headers.get('retry-after')).toBe('1');
    expect(slot.waiters.size).toBe(1);
    // Immediate listings still work while the long-poll capacity is full.
    expect((await fetch(`${base}/changes`)).status).toBe(200);
    req.destroy();
    await until(() => slot.waiters.size === 0);
    const poll = fetch(`${base}/changes?namespace=notes&wait=30`);
    await until(() => slot.waiters.size === 1);
    await put(base, 'ops/a/notes/1.json', 'notes');
    expect((await poll).status).toBe(200);
  } finally { req.destroy(); }
}, { maxWaiters: 1 }));

test('shutdown wakes every filtered long poll', () => fixture(async (r, base) => {
  const slot = await r.relay.slot('test');
  const polls = ['notes', 'other', ''].map((ns) => fetch(`${base}/changes?namespace=${ns}&wait=30`));
  await until(() => slot.waiters.size === 3);
  await r.relay.close();
  // Retryable: the relay is going away, not the slot.
  for (const poll of polls) {
    const res = await poll;
    expect(res.status).toBe(503);
    expect(res.headers.get('retry-after')).toBe('1');
  }
  expect(slot.waiters.size).toBe(0);
}));

test('HEAD and conditional GET use index without body reads; GET checks size and digest', () => fixture(async (r, base, dir) => {
  const p = 'authority/1.json', body = 'hello', etag = `"${sha256(Buffer.from(body))}"`;
  await put(base, p, body);
  const slot = await r.relay.slot('test');
  const read = slot.readFile;
  slot.readFile = () => { throw new Error('Unexpected body read'); };
  try {
    const head = await fetch(`${base}/records/${p}`, { method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(head.headers.get('content-length')).toBe('5');
    expect(head.headers.get('etag')).toBe(etag);
    for (const method of ['GET', 'HEAD']) for (const value of [etag, '*']) {
      const res = await fetch(`${base}/records/${p}`, { method, headers: { 'if-none-match': value } });
      expect(res.status).toBe(304);
      expect(res.headers.get('etag')).toBe(etag);
      expect(res.headers.get('cache-control')).toContain('no-store');
    }
  } finally { slot.readFile = read; }
  const got = await fetch(`${base}/records/${p}`, { headers: { 'if-none-match': '"stale"' } });
  expect(got.headers.get('etag')).toBe(etag);
  expect(await got.text()).toBe(body);
  await fs.writeFile(path.join(dir, 'test/records', p), 'jello');
  const tampered = await fetch(`${base}/records/${p}`);
  expect(tampered.status).toBe(500);
  expect(tampered.headers.get('etag')).toBeNull();
  expect(await tampered.text()).not.toContain('jello');
  await fs.writeFile(path.join(dir, 'test/records', p), 'shorter?');
  expect((await fetch(`${base}/records/${p}`)).status).toBe(500);
  await fs.unlink(path.join(dir, 'test/records', p));
  expect((await fetch(`${base}/records/${p}`, { method: 'HEAD' })).status).toBe(404);
}));

test('stale If-Match fails even for identical current bytes', () => fixture(async (_, base) => {
  const p = 'state/a/notes/slot.json';
  await put(base, p, 'current');
  expect((await put(base, p, 'current', { 'if-match': `"${'0'.repeat(64)}"` })).status).toBe(412);
}));

test('EEXIST recovery logs once and an already indexed race returns 200', () => fixture(async (r, base, dir) => {
  const slot = await r.relay.slot('test'), p = 'authority/recovered.json', body = Buffer.from('record');
  const file = await slot.target(p, true);
  await fs.writeFile(file, body);
  expect(await slot.putImmutable(p, body)).toBe(201);
  expect(await slot.putImmutable(p, body)).toBe(200);
  expect(slot.entries.filter((e) => e.path === p).length).toBe(1);
  const stage = slot.stage;
  const race = 'authority/race.json';
  slot.stage = async function (bytes) {
    const staged = await stage.call(this, bytes);
    await fs.writeFile(await this.target(race, true), bytes);
    await this.log({ path: race, size: bytes.length, sha256: sha256(bytes) });
    return staged;
  };
  try { expect(await slot.putImmutable(race, body)).toBe(200); } finally { slot.stage = stage; }
  expect(slot.entries.filter((e) => e.path === race).length).toBe(1);
  expect((await fs.readFile(path.join(dir, 'test/log.jsonl'), 'utf8')).trim().split('\n').length).toBe(2);
}));

test('log refuses symlinks and durable metadata staging uses exclusive no-follow flags and cleans failed rename', () => fixture(async (r, _, dir) => {
  const slot = await r.relay.slot('test');
  const outside = path.join(dir, 'outside');
  await fs.writeFile(outside, 'untouched');
  await fs.unlink(path.join(slot.root, 'log.jsonl'));
  await fs.symlink(outside, path.join(slot.root, 'log.jsonl'));
  await expect(slot.log({ path: 'authority/1.json', size: 1, sha256: 'a'.repeat(64) })).rejects.toThrow('regular file');
  expect(await fs.readFile(outside, 'utf8')).toBe('untouched');
  const rename = fs.rename, open = fs.open;
  let checked = false;
  fs.open = async (file, mode, ...rest) => {
    if (String(file).includes('/tmp/')) {
      expect(mode & (flags.O_WRONLY | flags.O_CREAT | flags.O_EXCL | flags.O_NOFOLLOW)).toBe(flags.O_WRONLY | flags.O_CREAT | flags.O_EXCL | flags.O_NOFOLLOW);
      checked = true;
    }
    return open(file, mode, ...rest);
  };
  fs.rename = async () => { throw new Error('rename failure'); };
  try {
    // A new configured slot initializes log.jsonl using writeDurable.
    const other = await createRelay({ dataDir: path.join(dir, 'other'), libraries: { test: { open: true } } });
    try { await expect(other.slot('test')).rejects.toThrow('rename failure');
      expect(await fs.readdir(path.join(dir, 'other/test/tmp'))).toEqual([]);
    } finally { await other.close(); }
  } finally { fs.rename = rename; fs.open = open; }
  expect(checked).toBe(true);
}));

test('dataDir is exclusive across processes and reusable after close; shutdown drains writes', () => fixture(async (r, base, dir) => {
  const options = { dataDir: dir, libraries: { test: { open: true } } };
  await expect(createRelay(options)).rejects.toThrow('locked');
  const child = Bun.spawn([process.execPath, '--eval', `import {createRelay} from ${JSON.stringify(path.resolve(import.meta.dir, '../relay.js'))}; try { await createRelay(${JSON.stringify(options)}); process.exit(2); } catch(e) { console.error(e.message); process.exit(e.message.includes('locked') ? 0 : 3); }`], { stdout: 'pipe', stderr: 'pipe' });
  expect(await child.exited).toBe(0);
  const slot = await r.relay.slot('test');
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const write = slot.exclusive(async () => { await blocked; await fs.writeFile(path.join(dir, 'drained'), 'yes'); });
  await delay(0); // The already running mutation must drain; queued work must refuse.
  let closed = false;
  const closing = r.close().then(() => { closed = true; });
  await delay(30);
  expect(closed).toBe(false);
  await expect(createRelay(options)).rejects.toThrow('locked');
  release(); await write; await closing;
  expect(await fs.readFile(path.join(dir, 'drained'), 'utf8')).toBe('yes');
  const next = await createRelay(options);
  await next.close();
}));

test('dead process lock is recovered and failed initialization releases its lock', async () => {
  const dataDir = await fs.mkdtemp(path.join(tmpdir(), 'relay-lock-recovery-'));
  const module = JSON.stringify(path.resolve(import.meta.dir, '../relay.js'));
  const options = { dataDir, libraries: { test: { open: true } } };
  try {
    const child = Bun.spawn([process.execPath, '--eval', `import {createRelay} from ${module}; await createRelay(${JSON.stringify(options)}); process.exit(0);`], { stdout: 'pipe', stderr: 'pipe' });
    expect(await child.exited).toBe(0);
    const previous = await fs.readFile(path.join(dataDir, '.relay.lock'), 'utf8');
    await expect(createRelay({ dataDir, libraries: { INVALID: { open: true } } })).rejects.toThrow('Invalid library');
    expect(await fs.readFile(path.join(dataDir, '.relay.lock'), 'utf8')).toBe(previous);
    const recovered = await createRelay(options);
    await recovered.close();
    await expect(createRelay({ dataDir, libraries: { INVALID: { open: true } } })).rejects.toThrow('Invalid library');
    const next = await createRelay(options);
    await next.close();
  } finally { await fs.rm(dataDir, { recursive: true, force: true }); }
});

test('shutdown deadline retains ownership until a blocked write settles', async () => {
  const dataDir = await fs.mkdtemp(path.join(tmpdir(), 'relay-drain-timeout-'));
  const options = { dataDir, libraries: { test: { open: true } } };
  const relay = await createRelay(options);
  let release;
  try {
    const slot = await relay.slot('test');
    const blocked = new Promise((resolve) => { release = resolve; });
    const write = slot.exclusive(() => blocked);
    await delay(0);
    await expect(relay.close()).rejects.toThrow('timed out draining writes');
    await expect(createRelay(options)).rejects.toThrow('locked');
    release(); await write;
    for (let i = 0; i < 200; i++) {
      if (!(await fs.lstat(path.join(dataDir, '.relay.lock')).catch(() => null))) break;
      await delay(5);
    }
    const next = await createRelay(options);
    await next.close();
  } finally { release?.(); await fs.rm(dataDir, { recursive: true, force: true }); }
}, 10000);

test('closing rejects queued and new mutations on retained slots after restart', () => fixture(async (r, base, dir) => {
  const p = 'requests/a.json';
  await put(base, p, 'original');
  const slot = await r.relay.slot('test');
  const log = await fs.readFile(path.join(slot.root, 'log.jsonl'), 'utf8');
  let release;
  const running = slot.exclusive(() => new Promise((resolve) => { release = resolve; }));
  await until(() => release);
  const mutations = () => [slot.putImmutable('authority/late.json', Buffer.from('late')),
    slot.replaceRequest(p, Buffer.from('changed')), slot.deleteRequest(p)].map((p) => p.then(() => null, (error) => error));
  const queued = Promise.all(mutations());
  const closing = r.relay.close();
  try { for (const error of await Promise.all(mutations())) expect(error).toMatchObject({ status: 503 }); }
  finally { release(); }
  await running;
  for (const error of await queued) expect(error).toMatchObject({ status: 503, message: 'Relay is closing' });
  await closing;
  const next = await createRelay({ dataDir: dir, libraries: { test: { open: true } } });
  try {
    for (const error of await Promise.all(mutations())) expect(error).toMatchObject({ status: 503 });
    expect(await fs.readFile(path.join(slot.root, 'log.jsonl'), 'utf8')).toBe(log);
    expect(await fs.readFile(path.join(slot.recordsDir(), p), 'utf8')).toBe('original');
    expect(await fs.readdir(path.join(slot.root, 'tmp'))).toEqual([]);
    expect(await fs.lstat(path.join(slot.recordsDir(), 'authority/late.json')).catch(() => null)).toBeNull();
  } finally { await next.close(); }
}));

test('mutable GET rejects same-size tampering and concurrent replacement with a stale index', () => fixture(async (r, base, dir) => {
  const slot = await r.relay.slot('test');
  for (const p of ['state/a/notes/slot.json', 'requests/a.json']) {
    await put(base, p, 'original');
    await fs.writeFile(path.join(dir, 'test/records', p), 'tampered');
    const res = await fetch(`${base}/records/${p}`);
    expect(res.status).toBe(500);
    expect(res.headers.get('etag')).toBeNull();
    expect(await res.text()).not.toContain('tampered');
    const read = slot.readFile;
    slot.readFile = async function (recordPath) {
      await this.replaceRequest(recordPath, Buffer.from('replaced'));
      return read.call(this, recordPath);
    };
    try {
      const raced = await fetch(`${base}/records/${p}`);
      expect(raced.status).toBe(500);
      expect(raced.headers.get('etag')).toBeNull();
    } finally { slot.readFile = read; }
  }
}));

test('locks publish synced complete files and recover dead reclaim owners', async () => {
  const dataDir = await fs.mkdtemp(path.join(tmpdir(), 'relay-atomic-lock-'));
  const options = { dataDir, libraries: { test: { open: true } } };
  const child = Bun.spawn([process.execPath, '--eval', 'process.exit(0)'], { stdout: 'pipe', stderr: 'pipe' });
  expect(await child.exited).toBe(0);
  const deadOwner = JSON.stringify({ pid: child.pid, at: new Date().toISOString() }) + '\n';
  const file = path.join(dataDir, '.relay.lock'), marker = `${file}.reclaim`;
  const open = fs.open, link = fs.link;
  const synced = new Set(), published = [];
  let relay;
  try {
    await fs.writeFile(file, deadOwner);
    await fs.writeFile(marker, deadOwner);
    fs.open = async (name, mode, ...rest) => {
      const handle = await open(name, mode, ...rest);
      if (String(name).startsWith(`${file}.`) && String(name) !== marker) {
        expect(mode & (flags.O_WRONLY | flags.O_CREAT | flags.O_EXCL | flags.O_NOFOLLOW)).toBe(flags.O_WRONLY | flags.O_CREAT | flags.O_EXCL | flags.O_NOFOLLOW);
        const sync = handle.sync.bind(handle);
        handle.sync = async () => { await sync(); synced.add(String(name)); };
      }
      return handle;
    };
    fs.link = async (source, target) => {
      if (target === file || target === marker) {
        expect(synced.has(String(source))).toBe(true);
        const owner = JSON.parse(await fs.readFile(source, 'utf8'));
        expect(owner.pid).toBe(process.pid);
        expect(typeof owner.at).toBe('string');
        published.push(target);
      }
      return link(source, target);
    };
    relay = await createRelay(options);
    expect(JSON.parse(await fs.readFile(file, 'utf8')).pid).toBe(process.pid);
    expect(published).toContain(marker);
    expect(await fs.readdir(dataDir)).toEqual(['.relay.lock']);
    await relay.close(); relay = null;
    expect(await fs.readdir(dataDir)).toEqual([]);
  } finally {
    fs.open = open; fs.link = link;
    await relay?.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test('legacy torn locks require a grace period and stale torn reclaim markers recover', async () => {
  const dataDir = await fs.mkdtemp(path.join(tmpdir(), 'relay-torn-lock-'));
  const options = { dataDir, libraries: { test: { open: true } } };
  const file = path.join(dataDir, '.relay.lock'), marker = `${file}.reclaim`;
  try {
    for (const bytes of ['', '{"pid":']) {
      await fs.writeFile(file, bytes);
      await expect(createRelay(options)).rejects.toThrow('locked');
      expect(await fs.readFile(file, 'utf8')).toBe(bytes);
      const old = new Date(Date.now() - 20_000);
      await fs.utimes(file, old, old);
      await fs.writeFile(marker, bytes);
      await expect(createRelay(options)).rejects.toThrow('stale-lock recovery');
      await fs.utimes(marker, old, old);
      const relay = await createRelay(options);
      await relay.close();
      expect(await fs.readdir(dataDir)).toEqual([]);
    }
  } finally { await fs.rm(dataDir, { recursive: true, force: true }); }
});

test('a slot that finishes opening during shutdown also refuses retained mutations', async () => {
  const dataDir = await fs.mkdtemp(path.join(tmpdir(), 'relay-opening-close-'));
  const relay = await createRelay({ dataDir, libraries: { test: { open: true } } });
  const readdir = fs.readdir;
  let release;
  fs.readdir = async (dir, ...args) => {
    if (dir === path.join(dataDir, 'test/records')) await new Promise((resolve) => { release = resolve; });
    return readdir(dir, ...args);
  };
  try {
    const opening = relay.slot('test');
    await until(() => release);
    const closing = relay.close();
    release();
    const slot = await opening;
    await closing;
    await expect(slot.putImmutable('authority/late.json', Buffer.from('late'))).rejects.toThrow('Relay is closing');
    expect(await readdir(path.join(dataDir, 'test/records'))).toEqual([]);
  } finally {
    fs.readdir = readdir;
    release?.();
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
