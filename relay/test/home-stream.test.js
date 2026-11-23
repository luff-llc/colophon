// Notice routes and the home stream's tickets, pushes, resume, limits and hygiene
// (docs/colophon-0.6-stream.md), on the W2 synthetic account (controllers, one member).
// Session forwarding is in home-stream-v2.test.js.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFile, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
// Synthetic account generated with v05_engine_support and support_relay. All keys are test keys.
import fixture from './home-stream.fixture.json' with { type: 'json' };
import { Client, prefix, rawBody, ready, rejectedUpgrade, sha, signBody, stamp, testHome as testHomeOn, wasm } from './stream-support.js';
import { test } from 'node:test';

const testHome = (name, run, options) => testHomeOn(fixture, name, run, options);
const route = '{"address":"private-device-token","kind":"push","reaches":"Phone"}';
/** Register a route; its keyed ID from the answer. */
async function register(signed, body, options) {
  const response = await signed('/routes', 'POST', typeof body === 'string' ? body : JSON.stringify(body), options);
  const text = await response.text();
  return { status: response.status, id: text ? JSON.parse(text).id : undefined, body: text };
}

// ---------------------------------------------------------------------------------------------
// Notice routes.

testHome('notice routes: verified calls, keyed IDs, owner-only changes, redacted listing, persistence', async ({ request, signed, restart, files }) => {
  assert.equal((await request('/routes')).status, 401);
  // `reaches` may not repeat the address (the core's rule): the list would leak it.
  assert.equal((await register(signed, route.replace('Phone', ' my PRIVATE-DEVICE-TOKEN '))).status, 400);
  // A webhook must be an https URL to a public name.
  assert.equal((await register(signed, { kind: 'webhook', address: 'https://127.0.0.1/hook', reaches: 'Server' })).status, 400);
  // Routes are registered by POST; there is no client-chosen ID to PUT.
  assert.equal((await signed(`/routes/${'0'.repeat(64)}`, 'PUT', route)).status, 405);

  const sms = { kind: 'sms', address: '+15551234567', reaches: 'Phone' };
  const created = await register(signed, sms);
  assert.equal(created.status, 201, created.body);
  // The listed ID is keyed by the home's secret: it is not the digest of the address, so a
  // reader of the list cannot test guessed numbers against it.
  assert.notEqual(created.id, sha(`sms\0${sms.address}`));
  assert.match(created.id, /^[0-9a-f]{64}$/);
  const by = `controller:${fixture.controller.id}`;
  assert.deepEqual(await (await signed('/routes', 'GET', undefined, { signer: 'member' })).json(),
    { routes: [{ id: created.id, kind: 'sms', reaches: 'Phone', by }] });
  // The same address again replaces the principal's own route.
  const again = await register(signed, { ...sms, reaches: 'New phone' });
  assert.deepEqual([again.status, again.id], [200, created.id]);

  // Another principal registering the same address gets its own route, not an oracle.
  const member = await register(signed, sms, { signer: 'member' });
  assert.equal(member.status, 201);
  assert.notEqual(member.id, created.id);
  // Nobody else may delete a route: one stolen key cannot silence another device.
  const refused = await signed(`/routes/${created.id}`, 'DELETE', undefined, { signer: 'member' });
  assert.equal(refused.status, 403);
  assert.deepEqual(await refused.json(), { result: 'refused:notGranted' });

  await restart();
  const listed = await (await signed('/routes')).text();
  assert.ok(!listed.includes(sms.address));
  assert.deepEqual(JSON.parse(listed).routes.map((r) => [r.id, r.reaches, r.by]).sort(), [
    [created.id, 'New phone', by], [member.id, 'Phone', `member:${fixture.member.id}`],
  ].sort());
  // The key survived the restart: the same address still names the same route.
  assert.deepEqual((await register(signed, sms)).id, created.id);
  assert.equal((await signed(`/routes/${member.id}`, 'DELETE', undefined, { signer: 'member' })).status, 204);
  assert.equal((await signed(`/routes/${member.id}`, 'DELETE', undefined, { signer: 'member' })).status, 404);
  // The key is never served; it is only in the route file.
  const stored = JSON.parse(await readFile(files('routes.json'), 'utf8'));
  assert.match(stored.key, /^[0-9a-f]{64}$/);
  assert.ok(!listed.includes(stored.key));
});

testHome('notice routes: a principal holds at most 8; others keep their share', async ({ signed }) => {
  const put = (i, signer = 'controller', reaches = 'Phone') => register(signed, { kind: 'push', address: `device-${i}`, reaches }, { signer });
  const ids = [];
  for (let i = 0; i < 8; i++) {
    const r = await put(i);
    assert.equal(r.status, 201);
    ids.push(r.id);
  }
  const refused = await put(8);
  assert.equal(refused.status, 507);
  assert.deepEqual(JSON.parse(refused.body), { result: 'refused:overQuota' });
  assert.equal((await put(0, 'controller', 'Tablet')).status, 200); // a replacement is not new
  assert.equal((await put(9, 'member')).status, 201); // another principal's share is its own
  assert.equal((await signed(`/routes/${ids[1]}`, 'DELETE')).status, 204);
  assert.equal((await put(8)).status, 201);
  const { routes } = await (await signed('/routes')).json();
  assert.equal(routes.length, 9);
});

testHome('routes of the unshipped W2 layout are re-keyed on load', async ({ signed, files, restart }) => {
  const legacy = [[sha('push\0legacy-token'), { kind: 'push', address: 'legacy-token', reaches: 'Old', by: `controller:${fixture.controller.id}` }]];
  await writeFile(files('routes.json'), JSON.stringify(legacy));
  await restart();
  const { routes } = await (await signed('/routes')).json();
  assert.equal(routes.length, 1);
  assert.notEqual(routes[0].id, legacy[0][0]);
  assert.deepEqual((await register(signed, { kind: 'push', address: 'legacy-token', reaches: 'Old' })).id, routes[0].id);
});

// ---------------------------------------------------------------------------------------------
// Tickets.

testHome('stream tickets: minted by a stream call, single use, short-lived, never logged', async ({ request, call, signed, host, ticket, advance }) => {
  const logged = [];
  const saved = { error: console.error, log: console.log, warn: console.warn };
  for (const k of Object.keys(saved)) console[k] = (...args) => { logged.push(args.map(String).join(' ')); saved[k](...args); };
  try {
    assert.equal((await request('/stream/ticket', 'POST')).status, 401);
    // Only the reserved purpose, only for this request.
    assert.equal((await signed('/stream/ticket', 'POST', undefined, { purpose: 'colophon.home.read' })).status, 403);
    assert.equal((await request('/stream/ticket', 'POST', undefined, await call('POST', '/stream/ticket', '', { audience: 'https://wrong.example' }))).status, 403);
    assert.equal((await request('/stream/ticket', 'POST', 'x', await call('POST', '/stream/ticket', 'x'))).status, 400);
    assert.equal((await signed('/stream/ticket', 'GET')).status, 405);
    assert.equal((await request('/stream')).status, 426);
    const replayed = await call('POST', '/stream/ticket');
    assert.equal((await request('/stream/ticket', 'POST', undefined, replayed)).status, 200);
    assert.equal((await request('/stream/ticket', 'POST', undefined, replayed)).status, 403);

    const missing = await rejectedUpgrade(host());
    assert.deepEqual([missing.status, missing.body], [401, { result: 'refused:ticket' }]);
    assert.deepEqual((await rejectedUpgrade(host(), `?ticket=${randomBytes(32).toString('base64url')}`)).body, { result: 'refused:ticket' });
    // A W2-style call on the upgrade is not a ticket.
    assert.equal((await rejectedUpgrade(host(), '', { authorization: await call('GET', '/stream') })).status, 401);

    const t = await ticket('member');
    const client = await Client.connect(host(), t);
    const hello = await client.next('hello');
    assert.equal(hello.principal, `member:${fixture.member.id}`);
    assert.equal(hello.n, 1);
    assert.deepEqual(hello.namespaces, ['notes']);
    // Single use, whatever happened the first time.
    assert.equal((await rejectedUpgrade(host(), `?ticket=${t}`)).status, 403);
    client.ws.terminate();

    const late = await ticket();
    advance(30_001);
    assert.equal((await rejectedUpgrade(host(), `?ticket=${late}`)).status, 403);
    // A ticket presented with anything wrong around it is burnt all the same: a URL that was
    // refused (and perhaps logged) never yields a usable ticket.
    const logged1 = await ticket();
    assert.equal((await rejectedUpgrade(host(), `?ticket=${logged1}&extra=1`)).status, 400);
    assert.equal((await rejectedUpgrade(host(), `?ticket=${logged1}`)).status, 403);
    const logged2 = await ticket();
    assert.equal((await rejectedUpgrade(host(), `?ticket=${logged2}&ticket=${logged2}`)).status, 400);
    assert.equal((await rejectedUpgrade(host(), `?ticket=${logged2}`)).status, 403);
    assert.ok(logged.every((line) => !line.includes(t) && !line.includes(late)), 'a ticket was logged');
  } finally { Object.assign(console, saved); }
});

testHome('a ticket whose member lost access before redeeming it is refused', async ({ request, host, ticket, advance }) => {
  const t = await ticket('member');
  advance();
  const entry = await endSessions(stamp(fixture.now + 1000));
  const response = await request('/authority', 'POST', JSON.stringify({ from: fixture.asOf.seq + 1, entries: [entry], receipts: [] }));
  assert.equal(response.status, 200, await response.text());
  const refused = await rejectedUpgrade(host(), `?ticket=${t}`);
  assert.deepEqual([refused.status, refused.body], [403, { result: 'refused:revoked' }]);
});

testHome('outstanding tickets are capped per principal', async ({ signed, ticket }) => {
  for (let i = 0; i < 8; i++) await ticket('member');
  const refused = await signed('/stream/ticket', 'POST', undefined, { signer: 'member' });
  assert.equal(refused.status, 429);
  await ticket('controller');
});

// ---------------------------------------------------------------------------------------------
// Pushes and resume.

testHome('change frames carry the /changes entry and cursor, and resume from either', async ({ signed, open, writeBlob, slot }) => {
  const changes = async (after) => (await signed(`/changes${after ? `?after=${after}` : ''}`)).json();
  const start = (await changes()).cursor;
  const ws = await open('member');
  const first = ws.next('change');
  await writeBlob('encrypted chunk');
  const frame = await first;
  const page = await changes(start);
  assert.equal(page.entries.length, 1);
  assert.deepEqual(frame.entry, page.entries[0]);
  assert.equal(frame.cursor, page.cursor);
  assert.match(frame.cursor, new RegExp(`^${(await slot()).instance}\\.\\d+$`));
  ws.ws.terminate();

  // Missed while away: replayed in order after hello, then live.
  await writeBlob('second chunk');
  await writeBlob('third chunk');
  const missed = await changes(frame.cursor);
  const back = await open('member', { after: frame.cursor });
  const replay = [await back.next('change'), await back.next('change')];
  assert.deepEqual(replay.map((f) => f.entry), missed.entries);
  assert.equal(replay[1].cursor, missed.cursor);
  assert.equal(back.all('hello')[0].cursor, missed.cursor);
  // The stream's last cursor continues /changes exactly.
  await writeBlob('fourth chunk');
  const live = await back.next('change');
  assert.deepEqual((await changes(replay[1].cursor)).entries, [live.entry]);
  // A cursor of another instance cannot be continued: resync from the start, like 410.
  const gone = await open('member', { after: 'ffffffffffffffff.1' });
  assert.deepEqual(await gone.next('resync'), { type: 'resync', n: 2, reason: 'gone', after: 'ffffffffffffffff.1' });
  assert.equal((await signed('/changes?after=ffffffffffffffff.1')).status, 410);
});

testHome('more missed changes than the stream replays answer resync tooFar', async ({ signed, open, writeBlob }) => {
  const start = (await (await signed('/changes')).json()).cursor;
  await writeBlob('one');
  await writeBlob('two');
  const ws = await open('member', { after: start });
  assert.equal((await ws.next('resync')).reason, 'tooFar');
  await ws.settle();
  assert.equal(ws.all('change').length, 0);
}, { stream: { resumeEntries: 1 } });

async function endSessions(issued) {
  return signBody({
    protocol: 'colophon/authority/5', kind: 'endSessions', seq: fixture.asOf.seq + 1,
    previous: fixture.asOf.digest, issued, by: fixture.member.id, member: fixture.member.id,
  }, fixture.member.key);
}

async function revoke(issued) {
  return signBody({
    protocol: 'colophon/authority/5', kind: 'revoke', seq: fixture.asOf.seq + 1,
    previous: fixture.asOf.digest, issued, by: fixture.controller.id, member: fixture.member.id,
    kept: [], heads: [], epochs: [{ namespace: 'notes', epoch: 2, seals: {} }],
  }, fixture.controller.key);
}

for (const makeEntry of [endSessions, revoke]) {
  testHome(`${makeEntry.name} closes an open member stream (1008) before pushing the new head`, async ({ request, open, advance, slot }) => {
    const ws = await open('member');
    const controller = await open('controller');
    advance();
    const entry = await makeEntry(stamp(fixture.now + 1000));
    const seq = fixture.asOf.seq + 1;
    const response = await request('/authority', 'POST', JSON.stringify({ from: seq, entries: [entry], receipts: [] }));
    assert.equal(response.status, 200, await response.text());
    const head = await controller.next('head');
    assert.deepEqual([head.seq, head.digest, head.home], [seq, sha(rawBody(entry)), JSON.parse(rawBody(await (await request('/head')).json())).by]);
    assert.equal((await ws.closed).code, 1008);
    assert.deepEqual(ws.all('head'), []);
    assert.equal((await slot()).home.stream.conns.size, 1);
  });
}

testHome('an expired member stream closes instead of receiving further pushes', async ({ request, open, writeBlob, advance }) => {
  const grant = JSON.parse(rawBody(fixture.entries[3]));
  advance(Date.parse(grant.terms.expires) - fixture.now - 1000);
  assert.equal((await request('/head')).status, 200);
  const ws = await open('member');
  const controller = await open('controller');
  advance(1001);
  const pushed = controller.next('change');
  await writeBlob('another encrypted chunk');
  await pushed;
  assert.equal((await ws.closed).code, 1008);
  assert.deepEqual(ws.all('change'), []);
});

testHome('a suspend committed on a replacement branch queues and pushes its numbered notice', async ({
  request, open, files, advance, slot,
}) => {
  const ws = await open('controller');
  const seq = fixture.asOf.seq + 1;
  const postEntry = (entry) => request('/authority', 'POST', JSON.stringify({ from: seq, entries: [entry], receipts: [] }));
  const ownHead = await (await request('/head')).json();
  const { by } = JSON.parse(rawBody(ownHead));
  const first = await postEntry(await endSessions(stamp(fixture.now)));
  assert.equal(first.status, 200, await first.text());
  advance();
  const object = sha(rawBody(fixture.suspend));
  const covering = await signBody({
    protocol: 'colophon/head/5', account: fixture.account, by,
    authority: { seq, digest: object }, issued: stamp(fixture.now + 1000),
  }, fixture.homeKey);
  const { home } = await slot();
  await home.lock(async () => {
    const bytes = Buffer.from(JSON.stringify(covering)).toString('base64');
    const head = home.wasm.call({ op: 'admit_one', state: home.state, now: fixture.now + 1000, bytes });
    assert.equal(head.outcome, 'ok', JSON.stringify(head));
    await home.commit(head.state);
    await home.materialize(head.store);
  });
  const notice = ws.next('notice');
  const replacement = await postEntry(fixture.suspend);
  assert.equal(replacement.status, 200, await replacement.text());
  const deadline = stamp(fixture.now + 3_600_000);
  const { n, ...frame } = await notice;
  assert.deepEqual(frame, { type: 'notice', notice: 1, object, kind: 'suspend', deadline });
  assert.deepEqual(JSON.parse(await readFile(files('notices.jsonl'), 'utf8')), {
    seq: 1, account: fixture.account, object, kind: 'suspend', issued: stamp(fixture.now), deadline, routes: [],
  });
});

testHome('admitted transitions, suspends and vetoes queue one numbered line each, naming the routes', async ({
  request, signed, open, files, advance, restart, host, ticket,
}) => {
  const pushRoute = await register(signed, route);
  assert.equal(pushRoute.status, 201);
  const routeId = pushRoute.id;
  const email = { kind: 'email', address: 'private@example.test', reaches: 'Mail' };
  const emailRoute = await register(signed, email);
  assert.equal(emailRoute.status, 201);
  const emailId = emailRoute.id;
  const ws = await open('controller');
  const suspended = await open('secondController');
  const pending = (envelope) => request('/pending', 'POST', JSON.stringify({ objects: [envelope] }));
  const expected = [];
  const deadline = stamp(fixture.now + 3_600_000);
  async function assertNotice(kind, envelope, submit) {
    const bytes = rawBody(envelope);
    const object = sha(bytes);
    const issued = JSON.parse(bytes).issued;
    const frame = ws.next('notice');
    const response = await submit();
    assert.equal(response.status, 200, await response.text());
    const seq = expected.length + 1;
    const { n, ...got } = await frame;
    assert.deepEqual(got, { type: 'notice', notice: seq, object, kind, deadline });
    expected.push({ seq, account: fixture.account, object, kind, issued, deadline, routes: [routeId, emailId] });
  }
  await assertNotice('transition', fixture.transition, () => pending(fixture.transition));
  assert.equal((await pending(fixture.transition)).status, 200);

  advance();
  const seq = fixture.asOf.seq + 1;
  await assertNotice('suspend', fixture.suspend, () =>
    request('/authority', 'POST', JSON.stringify({ from: seq, entries: [fixture.suspend], receipts: [] })));
  const digest = sha(rawBody(fixture.suspend));
  const head = await ws.next('head');
  assert.deepEqual([head.seq, head.digest], [seq, digest]);
  assert.equal((await suspended.closed).code, 1008);
  // A suspended controller keeps its route upkeep: it may list routes and change its own.
  const listing = await signed('/routes', 'GET', undefined, { signer: 'secondController', asOf: { seq, digest } });
  assert.equal(listing.status, 200, await listing.text());
  const own = { kind: 'sms', address: '+15551234567', reaches: 'Old phone' };
  const ownRoute = await register(signed, own, { signer: 'secondController', asOf: { seq, digest } });
  assert.equal(ownRoute.status, 201, ownRoute.body);
  // ...but not another principal's.
  assert.equal((await signed(`/routes/${routeId}`, 'DELETE', undefined, { signer: 'secondController', asOf: { seq, digest } })).status, 403);
  // Nor a stream: a suspended controller polls /pending with colophon.history.read.
  assert.equal((await signed('/stream/ticket', 'POST', undefined, { signer: 'secondController', asOf: { seq, digest } })).status, 403);
  const routesNow = [routeId, emailId, ownRoute.id];
  const before = expected.length;
  await assertNotice('veto', fixture.veto, () => pending(fixture.veto));
  expected[before].routes = routesNow;

  const queue = await readFile(files('notices.jsonl'), 'utf8');
  assert.deepEqual(queue.trimEnd().split('\n').map(JSON.parse), expected);
  // A torn append after the corresponding checkpoint committed is finished on restart.
  const last = queue.trimEnd().split('\n').slice(-1).join('\n') + '\n';
  const offset = Buffer.byteLength(queue) - Buffer.byteLength(last);
  const state = JSON.parse(await readFile(files('home-state.json'), 'utf8'));
  await writeFile(files('notice-commit.json'), JSON.stringify({ state: sha(state), offset, lines: last }));
  await writeFile(files('notices.jsonl'), Buffer.from(queue).subarray(0, offset + 3));
  await restart();
  assert.equal(await readFile(files('notices.jsonl'), 'utf8'), queue);
  // The numbering continues after a restart, and the hello says where it is.
  const again = await Client.connect(host(), await ticket());
  assert.equal((await again.next('hello')).notice, 3);
  again.ws.terminate();
});

testHome('route changes are pushed, and routes of a principal that lost access are dropped', async ({ request, signed, open, advance }) => {
  const ws = await open('controller');
  const { id: routeId } = await register(signed, route, { signer: 'member' });
  const put = await ws.next('route');
  assert.deepEqual(put, { type: 'route', n: put.n, id: routeId, change: 'put', kind: 'push', reaches: 'Phone', by: `member:${fixture.member.id}` });
  advance();
  const entry = await revoke(stamp(fixture.now + 1000));
  const response = await request('/authority', 'POST', JSON.stringify({ from: fixture.asOf.seq + 1, entries: [entry], receipts: [] }));
  assert.equal(response.status, 200, await response.text());
  const dropped = await ws.next('route');
  assert.deepEqual([dropped.id, dropped.change], [routeId, 'delete']);
  assert.deepEqual((await (await signed('/routes', 'GET', undefined, { asOf: { seq: fixture.asOf.seq + 1, digest: sha(rawBody(entry)) } })).json()).routes, []);
});

// ---------------------------------------------------------------------------------------------
// Frames from clients, limits and hygiene.

testHome('unknown, binary and malformed client frames are refused without closing', async ({ open }) => {
  const ws = await open('member');
  ws.send({ type: 'teleport', id: 'x1' });
  assert.deepEqual(await ws.next('error'), { type: 'error', n: 2, code: 'unknownType', ref: 'x1' });
  ws.send('not json');
  assert.equal((await ws.next('error')).code, 'badFrame');
  ws.ws.send(Buffer.from([1, 2, 3]), { binary: true });
  assert.equal((await ws.next('error')).code, 'binary');
  ws.send({ type: 'session', frame: { protocol: 'colophon/session/6' } });
  assert.equal((await ws.next('error')).code, 'badFrame');
  await ws.settle();
  assert.equal(ws.ws.readyState, ws.ws.OPEN);
  const frames = ws.frames.map((f) => f.n);
  assert.deepEqual(frames, frames.map((_, i) => i + 1), 'n counts every frame without a gap');
});

testHome('a controller stream takes pushes but neither subscribes to nor sends session frames', async ({ open }) => {
  const ws = await open('controller');
  ws.send({ type: 'subscribe', namespace: 'notes', cell: 'now-playing', id: 'c1' });
  assert.equal((await ws.next('error')).code, 'notEntitled');
  ws.send({ type: 'session', id: 'c2', frame: { protocol: 'colophon/session/6' } });
  assert.deepEqual([(await ws.next('error')).code, ws.all('subscribed').length], ['notEntitled', 0]);
});

testHome('an oversize session frame is refused; an oversize message closes 1009', async ({ open, slot }) => {
  const ws = await open('member');
  ws.send({ type: 'session', frame: { ciphertext: 'A'.repeat(17_000), protocol: 'colophon/session/6' } });
  assert.equal((await ws.next('error')).code, 'tooLarge');
  ws.send({ type: 'ping', pad: 'x'.repeat(21_000) });
  assert.equal((await ws.closed).code, 1009);
  assert.equal((await slot()).home.stream.conns.size, 0);
});

testHome('inbound frames over the rate are dropped and counted, not queued', async ({ open, slot }) => {
  const ws = await open('member');
  for (let i = 0; i < 6; i++) ws.send({ type: 'ping', t: i });
  const warned = await ws.next('error');
  assert.equal(warned.code, 'rateLimited');
  assert.ok(warned.dropped >= 1);
  assert.ok(ws.all('pong').length <= 2);
  assert.ok((await slot()).home.stream.counters.dropped >= 4);
}, { stream: { framesPerSecond: 1, frameBurst: 2 } });

testHome('connections are capped per principal and per account', async ({ open, host, ticket }) => {
  await open('member');
  await open('member');
  const third = await rejectedUpgrade(host(), `?ticket=${await ticket('member')}`);
  assert.equal(third.status, 429);
  await open('controller');
  const fourth = await rejectedUpgrade(host(), `?ticket=${await ticket('secondController')}`);
  assert.equal(fourth.status, 429);
}, { stream: { streamsPerPrincipal: 2, streamsPerAccount: 3 } });

/** A WebSocket handshake by hand, with a socket that never answers a ping or reads. */
async function rawStream(host, ticket) {
  const [hostname, port] = host.split(':');
  const socket = net.connect(Number(port), hostname);
  await once(socket, 'connect');
  socket.write(`GET ${prefix}/stream?ticket=${ticket} HTTP/1.1\r\nHost: ${host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n`
    + `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n\r\n`);
  const [first] = await once(socket, 'data');
  assert.match(first.toString('latin1'), /^HTTP\/1.1 101/);
  const closed = new Promise((resolve) => socket.on('close', resolve));
  return { socket, closed, first };
}

testHome('a client that answers no ping is closed after the idle timeout; one that does stays', async ({ host, ticket, open, slot }) => {
  const alive = await open('controller');
  const { closed, socket } = await rawStream(host(), await ticket('member'));
  const chunks = [];
  socket.on('data', (d) => chunks.push(d));
  await closed;
  // The close frame: opcode 8, code 4008.
  const all = Buffer.concat(chunks);
  const at = all.indexOf(Buffer.from([0x88]));
  assert.ok(at >= 0, 'no close frame');
  assert.equal(all.readUInt16BE(at + 2), 4008);
  assert.equal((await slot()).home.stream.counters.idle, 1);
  assert.equal(alive.ws.readyState, alive.ws.OPEN);
}, { stream: { pingMs: 50, idleMs: 300 } });

testHome('shutdown tells clients to resume (bye, 1012)', async ({ open, relay }) => {
  const ws = await open('member');
  const closing = relay().close();
  const bye = await ws.next('bye');
  assert.deepEqual([bye.reason, bye.resume, bye.retryMs], ['restart', true, 1000]);
  assert.equal((await ws.closed).code, 1012);
  await closing;
});

testHome('stream settings are checked', async ({ dir }) => {
  const { startRelay } = await import('../relay.js');
  await assert.rejects(startRelay({ port: 0, dataDir: `${dir}-x`, tickMs: 0, stream: { nope: 1 },
    libraries: { home: { home: true, account: fixture.account, base: fixture.base } } }), /stream\.nope/);
});

// Node is not a supported runtime for a home: start-up fails loudly instead of serving no stream.
const node = spawnSync('node', ['--version']).status === 0;
test('a relay with home slots refuses to start on Node', { skip: ready && node ? false : 'needs the module and node' }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'colophon-stream-node-'));
  try {
    const relay = fileURLToPath(new URL('../relay.js', import.meta.url));
    const script = `import { startRelay } from ${JSON.stringify(relay)};
      await startRelay({ port: 0, tickMs: 0, dataDir: ${JSON.stringify(dir)},
        libraries: { home: { home: true, account: ${JSON.stringify(fixture.account)}, base: ${JSON.stringify(fixture.base)} } },
        home: { key: ${JSON.stringify(fixture.homeKey)}, wasm: ${JSON.stringify(wasm)} } });`;
    const r = spawnSync('node', ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 30_000 });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /needs Bun/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
