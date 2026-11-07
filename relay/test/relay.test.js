import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile, mkdir, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, test } from 'node:test';
import { classifyPath, pathInNamespace, startRelay } from '../relay.js';

const TOKEN = 'test-token-0123456789abcdef';
const sha = (b) => createHash('sha256').update(b).digest('hex');
const auth = { authorization: `Bearer ${TOKEN}` };

async function relayAt(dataDir, extra = {}) {
  const running = await startRelay({ port: 0, dataDir, libraries: { home: { token: TOKEN }, open: { open: true } }, ...extra });
  const base = `http://127.0.0.1:${running.port}/v1/libraries`;
  return { running, base, home: `${base}/home` };
}

function put(url, body, headers = { ...auth, 'if-none-match': '*' }) {
  return fetch(url, { method: 'PUT', body, headers });
}

async function listAll(home, after = '') {
  const out = [];
  let cursor = after;
  for (;;) {
    const r = await fetch(`${home}/changes?after=${encodeURIComponent(cursor)}&limit=2`, { headers: auth });
    assert.equal(r.status, 200);
    const page = await r.json();
    out.push(...page.entries);
    cursor = page.cursor;
    if (!page.more) return { entries: out, cursor };
  }
}

describe('reference relay', () => {
  let dir, relay;
  before(async () => { dir = await mkdtemp(path.join(tmpdir(), 'colophon-relay-')); relay = await relayAt(dir); });
  after(async () => { await relay.running.close(); await rm(dir, { recursive: true, force: true }); });

  test('path grammar matches the SDK adapters', () => {
    assert.equal(classifyPath('authority/00000001.json'), 'record');
    assert.equal(classifyPath('requests/abc.json'), 'request');
    assert.equal(classifyPath('ops/a/000000000001-x.json'), 'record');
    assert.equal(classifyPath('ops/a/notes/000000000001-x.json'), 'record');
    assert.equal(classifyPath('state/a/listening.podcasts/slot.json'), 'state');
    assert.equal(classifyPath('history/a/listening.podcasts/000000000001-x.json'), 'record');
    assert.equal(classifyPath(`blobs/${'a'.repeat(64)}`), 'blob');
    assert.equal(pathInNamespace('ops/a/notes/000000000001-x.json', 'notes'), true);
    assert.equal(pathInNamespace('ops/a/notes/000000000001-x.json', 'listening.podcasts'), false);
    assert.equal(pathInNamespace('authority/00000001.json', 'notes'), true);
    assert.equal(pathInNamespace('ops/a/000000000001-x.json', 'notes'), true);
    for (const bad of ['../x.json', 'authority/../x.json', 'ops/a.json', 'authority/.x.json', 'authority/x.txt',
      'ops/a/b/c/d.json', 'other/x.json', 'authority//x.json', `blobs/${'A'.repeat(64)}`, 'authority/a%2f.json', 'authority/a\\b.json']) {
      assert.equal(classifyPath(bad), null, bad);
    }
  });

  test('bearer token grants storage only to its slot', async () => {
    assert.equal((await fetch(relay.home)).status, 401);
    assert.equal((await fetch(relay.home, { headers: { authorization: 'Bearer wrong-token-000000000' } })).status, 401);
    const unknown = await fetch(`${relay.base}/nobody`, { headers: auth });
    assert.equal(unknown.status, 401, 'unknown slots look like wrong tokens');
    assert.equal(unknown.headers.get('www-authenticate'), 'Bearer');
    const info = await (await fetch(relay.home, { headers: auth })).json();
    assert.equal(info.protocol, 'colophon/relay/3');
    assert.equal(info.limits.recordBytes, 16 * 1024 * 1024);
    assert.equal((await fetch(`${relay.base}/open`)).status, 200, 'open slots need no token');
  });

  test('put-if-absent, idempotent re-put, 412 on different bytes, exact bytes back', async () => {
    const bytes = Buffer.from('{"body":"AA==","signature":"BB=="}');
    const url = `${relay.home}/records/authority/00000001.json`;
    assert.equal((await put(url, bytes)).status, 201);
    assert.equal((await put(url, bytes)).status, 200);
    assert.equal((await put(url, Buffer.from('{"different":true}'))).status, 412);
    const got = await fetch(url, { headers: auth });
    assert.equal(got.status, 200);
    assert.equal(got.headers.get('etag'), `"${sha(bytes)}"`);
    assert.deepEqual(Buffer.from(await got.arrayBuffer()), bytes);
    assert.equal((await fetch(`${relay.home}/records/authority/00000002.json`, { headers: auth })).status, 404);
    assert.equal((await put(url, bytes, auth)).status, 428, 'immutable paths need If-None-Match');
    assert.equal((await put(`${relay.home}/records/ops/a.json`, bytes)).status, 400);
    assert.equal((await put(`${relay.home}/records/..%2Fescape.json`, bytes)).status, 400);
  });

  test('changes feed pages with a cursor and only returns later entries', async () => {
    for (let i = 1; i <= 5; i++) {
      assert.equal((await put(`${relay.home}/records/ops/m/00000000000${i}-op${i}.json`, Buffer.from(`op${i}`))).status, 201);
    }
    const all = await listAll(relay.home);
    const paths = all.entries.map((e) => e.path);
    assert.ok(paths.includes('authority/00000001.json'));
    assert.equal(paths.filter((p) => p.startsWith('ops/m/')).length, 5);
    for (const e of all.entries) assert.match(e.sha256, /^[0-9a-f]{64}$/);
    assert.equal((await put(`${relay.home}/records/ops/m/000000000006-op6.json`, Buffer.from('op6'))).status, 201);
    const later = await listAll(relay.home, all.cursor);
    assert.deepEqual(later.entries.map((e) => e.path), ['ops/m/000000000006-op6.json']);
    const none = await listAll(relay.home, later.cursor);
    assert.equal(none.entries.length, 0);
    assert.equal(none.cursor, later.cursor);
    assert.equal((await fetch(`${relay.home}/changes?after=bogus.3`, { headers: auth })).status, 410);
    assert.equal((await fetch(`${relay.home}/changes?after=${later.cursor.split('.')[0]}.99999`, { headers: auth })).status, 410);
  });

  test('long-poll wakes on a new record', async () => {
    const { cursor } = await listAll(relay.home);
    const started = Date.now();
    const waiting = fetch(`${relay.home}/changes?after=${cursor}&wait=10`, { headers: auth }).then((r) => r.json());
    await new Promise((r) => setTimeout(r, 100));
    await put(`${relay.home}/records/ops/m/000000000007-op7.json`, Buffer.from('op7'));
    const page = await waiting;
    assert.deepEqual(page.entries.map((e) => e.path), ['ops/m/000000000007-op7.json']);
    assert.ok(Date.now() - started < 5000);
    const idle = await (await fetch(`${relay.home}/changes?after=${page.cursor}&wait=1`, { headers: auth })).json();
    assert.deepEqual(idle, { entries: [], cursor: page.cursor, more: false }, 'an elapsed wait returns an empty page');
  });

  test('namespaced ops, live state replacement and namespace-filtered changes', async () => {
    const notes = `${relay.home}/records/ops/a/notes/000000000001-n1.json`;
    const listen = `${relay.home}/records/ops/a/listening.podcasts/000000000001-l1.json`;
    const slot = `${relay.home}/records/state/a/listening.podcasts/${'b'.repeat(64)}.json`;
    const hist = `${relay.home}/records/history/a/listening.podcasts/000000000002-h1.json`;
    assert.equal((await put(notes, Buffer.from('notes-op'))).status, 201);
    assert.equal((await put(listen, Buffer.from('listen-op'))).status, 201);
    assert.equal((await put(hist, Buffer.from('history-op'))).status, 201);
    assert.equal((await put(slot, Buffer.from('live-1'), auth)).status, 201, 'state creates without If-None-Match');
    assert.equal((await put(slot, Buffer.from('live-2'), auth)).status, 200, 'state replaces');
    const got = await fetch(slot, { headers: auth });
    assert.equal(Buffer.from(await got.arrayBuffer()).toString(), 'live-2');
    const filtered = await (await fetch(`${relay.home}/changes?namespace=notes&limit=1000`, { headers: auth })).json();
    const paths = filtered.entries.map((e) => e.path);
    assert.ok(paths.includes('ops/a/notes/000000000001-n1.json'));
    assert.ok(!paths.includes('ops/a/listening.podcasts/000000000001-l1.json'));
    assert.ok(!paths.includes(`state/a/listening.podcasts/${'b'.repeat(64)}.json`));
    assert.ok(paths.some((p) => p.startsWith('authority/')));
  });

  test('requests/ is the only mutable area', async () => {
    const url = `${relay.home}/records/requests/member.json`;
    assert.equal((await put(url, Buffer.from('one'), auth)).status, 201);
    assert.equal((await put(url, Buffer.from('two'), auth)).status, 200);
    assert.equal(Buffer.from(await (await fetch(url, { headers: auth })).arrayBuffer()).toString(), 'two');
    assert.equal((await put(url, Buffer.from('three'))).status, 412, 'conditional PUT never replaces');
    assert.equal((await fetch(url, { method: 'DELETE', headers: auth })).status, 204);
    assert.equal((await fetch(url, { headers: auth })).status, 404);
    assert.equal((await fetch(`${relay.home}/records/authority/00000001.json`, { method: 'DELETE', headers: auth })).status, 405);
    const { entries } = await listAll(relay.home);
    const history = entries.filter((e) => e.path === 'requests/member.json');
    assert.equal(history.length, 3);
    assert.equal(history[2].deleted, true);
  });

  test('blob names are verified content addresses', async () => {
    const chunk = Buffer.from('ciphertext chunk');
    assert.equal((await put(`${relay.home}/records/blobs/${sha(chunk)}`, chunk)).status, 201);
    assert.equal((await put(`${relay.home}/records/blobs/${'0'.repeat(64)}`, chunk)).status, 400);
    assert.equal((await put(`${relay.home}/records/blobs/${sha(Buffer.alloc(70000))}`, Buffer.alloc(70000))).status, 413);
  });

  test('size limits reject oversized bodies without storing a prefix', async () => {
    const small = await relayAt(path.join(dir, 'small'), { limits: { recordBytes: 1024 } });
    try {
      const url = `${small.home}/records/ops/m/000000000001-big.json`;
      assert.equal((await put(url, Buffer.alloc(2048))).status, 413);
      assert.equal((await fetch(url, { headers: auth })).status, 404);
    } finally { await small.running.close(); }
  });
});

describe('relay durability', () => {
  test('restart keeps records and cursors; a lost record resets cursors', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-relay-'));
    try {
      let r = await relayAt(dir);
      await put(`${r.home}/records/authority/00000001.json`, Buffer.from('genesis'));
      await put(`${r.home}/records/ops/m/000000000001-a.json`, Buffer.from('a'));
      const first = await listAll(r.home);
      await r.running.close();

      // A crash after linking a record but before logging it is recovered on open.
      await mkdir(path.join(dir, 'home/records/ops/m'), { recursive: true });
      await writeFile(path.join(dir, 'home/records/ops/m/000000000002-b.json'), 'b');
      await appendFile(path.join(dir, 'home/log.jsonl'), '{"path":"torn');
      r = await relayAt(dir);
      const resumed = await listAll(r.home, first.cursor);
      assert.deepEqual(resumed.entries.map((e) => e.path), ['ops/m/000000000002-b.json']);
      assert.equal(Buffer.from(await (await fetch(`${r.home}/records/authority/00000001.json`, { headers: auth })).arrayBuffer()).toString(), 'genesis');
      await r.running.close();

      await rm(path.join(dir, 'home/records/ops/m/000000000001-a.json'));
      r = await relayAt(dir);
      assert.equal((await fetch(`${r.home}/changes?after=${resumed.cursor}`, { headers: auth })).status, 410);
      const relisted = await listAll(r.home);
      assert.deepEqual(relisted.entries.map((e) => e.path).sort(), ['authority/00000001.json', 'ops/m/000000000002-b.json']);
      await r.running.close();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  test('symlinks in storage are refused', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-relay-'));
    const outside = await mkdtemp(path.join(tmpdir(), 'colophon-outside-'));
    try {
      let r = await relayAt(dir);
      await put(`${r.home}/records/authority/00000001.json`, Buffer.from('genesis'));
      await r.running.close();
      await symlink(outside, path.join(dir, 'home/records/ops'));
      r = await relayAt(dir);
      const res = await fetch(r.home, { headers: auth });
      assert.equal(res.status, 500);
      await r.running.close();
    } finally { await rm(dir, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
  });

  test('server.js reports its port and serves env-configured tokens', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-relay-'));
    const script = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.js');
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, COLOPHON_RELAY_PORT: '0', COLOPHON_RELAY_DATA: dir, COLOPHON_RELAY_TOKENS: `home=${TOKEN}` },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    try {
      const line = await new Promise((resolve) => child.stdout.once('data', (d) => resolve(d.toString())));
      const { listening } = JSON.parse(line.split('\n')[0]);
      const res = await fetch(`http://127.0.0.1:${listening.port}/v1/libraries/home`, { headers: auth });
      assert.equal(res.status, 200);
      const meta = JSON.parse(await readFile(path.join(dir, 'home/meta.json'), 'utf8'));
      assert.match(meta.instance, /^[0-9a-f]{16}$/);
    } finally { child.kill(); await rm(dir, { recursive: true, force: true }); }
  });
});
