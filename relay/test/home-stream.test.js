import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startRelay } from '../relay.js';
// Synthetic account generated with v05_engine_support and support_relay. All keys are test keys.
import fixture from './home-stream.fixture.json' with { type: 'json' };

const target = process.env.CARGO_TARGET_DIR ?? fileURLToPath(new URL('../../target', import.meta.url));
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready) {
  if (process.env.CI || process.env.COLOPHON_REQUIRE_RELAY === '1') throw new Error(`Build the home WASM first (${wasm})`);
  console.error(`SKIPPED: Home stream and notice tests need the module (${wasm})`);
}

const prefix = '/v1/libraries/home';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const stamp = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
const route = '{"address":"private-device-token","kind":"push","reaches":"Phone"}';
const routeId = sha('push\0private-device-token');
const routePath = `/routes/${routeId}`;
const rawBody = (envelope) => Buffer.from(envelope.body, 'base64');

function canonical(value) {
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

function testHome(name, run) {
  test(name, { skip: ready ? false : 'module not built' }, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-w2-'));
    let now = fixture.now;
    let running;
    const files = (name) => path.join(dir, 'home', name);
    const clock = () => now;
    const advance = () => { now += 1000; };
    const restart = async () => {
      await running?.close();
      running = await startRelay({
        port: 0, clock, tickMs: 0, dataDir: dir,
        libraries: { home: { home: true, account: fixture.account, base: fixture.base } },
        home: { key: fixture.homeKey, wasm },
      });
    };

    const call = async (method, relative, body = '', { signer = 'controller', kind = signer === 'member' ? 'member' : 'controller',
      audience = fixture.base, purpose = method === 'GET' ? 'colophon.home.read' : 'colophon.home.write',
      asOf = fixture.asOf } = {}) => {
      const { id, key } = fixture[signer];
      const point = Buffer.concat([Buffer.from([4]), Buffer.from(key.x, 'base64url'), Buffer.from(key.y, 'base64url')]);
      const signingKey = await crypto.subtle.importKey('jwk', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      const bytes = Buffer.from(canonical({
        protocol: 'colophon/call/5', account: fixture.account, asOf, audience, purpose,
        signer: { [kind]: id }, key: point.toString('base64'),
        args: { method, path: relative, body: sha(body) },
        requestId: randomBytes(32).toString('base64url'), created: stamp(now),
      }));
      const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, bytes));
      return `Colophon ${Buffer.from(JSON.stringify({ body: bytes.toString('base64'), signature: signature.toString('base64') })).toString('base64url')}`;
    };
    const host = () => `127.0.0.1:${running.port}`;
    const request = (relative, method = 'GET', body, authorization, extra) => fetch(`http://${host()}${prefix}${relative}`, {
      method, body,
      headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(authorization ? { authorization } : {}), ...extra },
    });
    const signed = async (relative, method = 'GET', body, options, extra) =>
      request(relative, method, body, await call(method, relative, body, options), extra);
    try {
      await restart();
      const upload = await request('/authority', 'POST', JSON.stringify({ from: 1, entries: fixture.entries, receipts: [] }));
      assert.equal(upload.status, 200, await upload.text());
      await run({ request, call, signed, host, files, restart, advance, slot: () => running.relay.slot('home') });
    } finally {
      await running?.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
}

function rejectedUpgrade(host, authorization) {
  return new Promise((resolve, reject) => {
    const request = http.get(`http://${host}${prefix}/stream`, { headers: {
      connection: 'Upgrade', upgrade: 'websocket', 'sec-websocket-version': '13',
      'sec-websocket-key': randomBytes(16).toString('base64'), ...(authorization ? { authorization } : {}),
    } }, (response) => {
      response.resume();
      resolve({ status: response.statusCode, headers: response.headers });
    });
    request.on('error', reject);
    request.on('upgrade', (_, socket) => {
      socket.destroy();
      reject(new Error('The relay upgraded a refused request'));
    });
  });
}

async function connect(host, authorization) {
  const { WebSocket } = await import('ws');
  const ws = new WebSocket(`ws://${host}${prefix}/stream`, { headers: { authorization } });
  await once(ws, 'open');
  return ws;
}

function nextFrame(ws, type) {
  return new Promise((resolve) => {
    const receive = (data) => {
      const frame = JSON.parse(data);
      if (frame.type !== type) return;
      ws.off('message', receive);
      resolve(frame);
    };
    ws.on('message', receive);
  });
}

testHome('notice route CRUD verifies calls, redacts addresses and persists across restart', async ({ request, signed, restart }) => {
  assert.equal((await request('/routes')).status, 401);
  const wrong = await signed(`/routes/${'0'.repeat(64)}`, 'PUT', route);
  assert.equal(wrong.status, 400);
  const created = await request(routePath, 'PUT', route, `Colophon ${fixture.recoverCall}`);
  assert.equal(created.status, 201, await created.text());
  const listing = await signed('/routes', 'GET', undefined, { signer: 'member' });
  assert.equal(listing.status, 200);
  const recoveryList = await listing.json();
  const recovered = JSON.parse(rawBody(JSON.parse(Buffer.from(fixture.recoverCall, 'base64url'))));
  assert.deepEqual(recoveryList, { routes: [{ id: routeId, kind: 'push', reaches: 'Phone', by: `controller:${recovered.signer.controller}` }] });

  const update = await signed(routePath, 'PUT', route.replace('Phone', 'Tablet'), { signer: 'member' });
  assert.equal(update.status, 200, await update.text());
  await restart();
  const listed = await (await signed('/routes')).text();
  assert.ok(!listed.includes('private-device-token'));
  assert.deepEqual(JSON.parse(listed), { routes: [{ id: routeId, kind: 'push', reaches: 'Tablet', by: `member:${fixture.member.id}` }] });
  assert.equal((await signed(routePath, 'DELETE')).status, 204);
  assert.equal((await signed(routePath, 'DELETE')).status, 404);
  assert.deepEqual(await (await signed('/routes')).json(), { routes: [] });
});

testHome('stream rejects missing, invalid, misbound and replayed calls, then pushes record changes', async ({ call, signed, host, slot }) => {
  const missing = await rejectedUpgrade(host());
  assert.equal(missing.status, 401);
  assert.equal(missing.headers['www-authenticate'], 'Colophon');
  assert.equal((await rejectedUpgrade(host(), 'Colophon bad')).status, 403);
  assert.equal((await rejectedUpgrade(host(), await call('GET', '/changes'))).status, 403);
  assert.equal((await rejectedUpgrade(host(), await call('GET', '/stream', 'a body'))).status, 403);
  assert.equal((await rejectedUpgrade(host(), await call('GET', '/stream', '', { audience: 'https://wrong.example' }))).status, 403);

  const authorization = await call('GET', '/stream', '', { signer: 'member' });
  const ws = await connect(host(), authorization);
  try {
    assert.equal((await rejectedUpgrade(host(), authorization)).status, 403);
    const record = 'encrypted chunk';
    const recordPath = `/records/blobs/${sha(record)}`;
    const cursor = (await slot()).entries.length + 1;
    const pushed = nextFrame(ws, 'change');
    const write = await signed(recordPath, 'PUT', record, undefined, { 'if-none-match': '*' });
    assert.equal(write.status, 201, await write.text());
    assert.deepEqual(await pushed, { type: 'change', cursor });

    const repeated = signed(recordPath, 'PUT', record, undefined, { 'if-none-match': '*' });
    const nextRecord = 'a different encrypted chunk';
    const next = nextFrame(ws, 'change');
    assert.equal((await repeated).status, 200);
    assert.equal((await signed(`/records/blobs/${sha(nextRecord)}`, 'PUT', nextRecord, undefined, { 'if-none-match': '*' })).status, 201);
    assert.deepEqual(await next, { type: 'change', cursor: cursor + 1 });
  } finally {
    const { sockets } = (await slot()).home;
    const detached = once([...sockets][0], 'close');
    const closed = once(ws, 'close');
    ws.close();
    await Promise.all([closed, detached]);
    assert.equal(sockets.size, 0);
  }
});

testHome('admitted transitions, suspends and vetoes queue public metadata and push live notices', async ({
  call, request, signed, host, files, advance, restart,
}) => {
  assert.equal((await signed(routePath, 'PUT', route)).status, 201);
  const email = { kind: 'email', address: 'private@example.test', reaches: 'Mail' };
  assert.equal((await signed(`/routes/${sha(`${email.kind}\0${email.address}`)}`, 'PUT', JSON.stringify(email))).status, 201);
  const ws = await connect(host(), await call('GET', '/stream'));
  const pending = (envelope) => request('/pending', 'POST', JSON.stringify({ objects: [envelope] }));
  const expected = [];
  const deadline = stamp(fixture.now + 3_600_000);
  async function assertNotice(kind, envelope, submit) {
    const bytes = rawBody(envelope);
    const object = sha(bytes);
    const issued = JSON.parse(bytes).issued;
    const frame = nextFrame(ws, 'notice');
    const response = await submit();
    assert.equal(response.status, 200, await response.text());
    assert.deepEqual(await frame, { type: 'notice', object, kind, deadline });
    const line = { account: fixture.account, object, kind, issued, deadline };
    expected.push(line, line);
  }
  try {
    await assertNotice('transition', fixture.transition, () => pending(fixture.transition));
    assert.equal((await pending(fixture.transition)).status, 200);

    advance();
    const head = nextFrame(ws, 'head');
    const seq = fixture.asOf.seq + 1;
    await assertNotice('suspend', fixture.suspend, () =>
      request('/authority', 'POST', JSON.stringify({ from: seq, entries: [fixture.suspend], receipts: [] })));
    const digest = sha(rawBody(fixture.suspend));
    assert.deepEqual(await head, { type: 'head', seq, digest });
    // A suspended controller may still maintain its route.
    assert.equal((await signed(routePath, 'PUT', route, { signer: 'secondController', asOf: { seq, digest } })).status, 200);
    await assertNotice('veto', fixture.veto, () => pending(fixture.veto));

    const queue = await readFile(files('notices.jsonl'), 'utf8');
    assert.deepEqual(queue.trimEnd().split('\n').map(JSON.parse), expected);
    // Simulate a torn append after the corresponding checkpoint was committed.
    const last = queue.trimEnd().split('\n').slice(-2).join('\n') + '\n';
    const offset = Buffer.byteLength(queue) - Buffer.byteLength(last);
    const state = JSON.parse(await readFile(files('home-state.json'), 'utf8'));
    await writeFile(files('notice-commit.json'), JSON.stringify({ state: sha(state), offset, lines: last }));
    await writeFile(files('notices.jsonl'), Buffer.from(queue).subarray(0, offset + 3));
    await restart();
    assert.equal(await readFile(files('notices.jsonl'), 'utf8'), queue);
  } finally { ws.terminate(); }
});
