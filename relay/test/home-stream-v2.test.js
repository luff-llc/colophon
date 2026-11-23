// The home as a session carrier (0.6 sessions §S9, docs/colophon-0.6-stream.md): sealed frames
// forwarded between the connected, entitled, subscribed members of one account; retained frames
// in memory only; refusals for spoofed and unentitled senders; slow consumers cut off.
// Synthetic account from crates/colophon-home-wasm/tests/v06_stream_fixture.rs: members a
// (notes read), b (notes write), c (books only), d (notes read). All keys are test keys.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readdir, readFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import fixture from './home-stream-v2.fixture.json' with { type: 'json' };
import { Client, prefix, sha, signBody, stamp, testHome as testHomeOn, tryUpgrade } from './stream-support.js';

const testHome = (name, run, options) => testHomeOn(fixture, name, run, options);
const CELL = 'now-playing';

/** A session frame as a member's core would send it: a raw envelope over the frame body. The
 * home never opens `ciphertext` or checks the signature; these are placeholders. */
function frame(from, { namespace = 'notes', cell = CELL, to, retain, n = 1, marker = 'sealed', size = 0 } = {}) {
  const body = {
    protocol: 'colophon/session/6', account: fixture.account, namespace, cell, from: fixture[from].id,
    key: 'session-key-1', ...(to ? { to: fixture[to].id } : {}), n, epoch: 1,
    ...(retain ? { retain: true } : {}),
    nonce: randomBytes(12).toString('base64'),
    ciphertext: Buffer.from(`${marker}${'.'.repeat(size)}`).toString('base64'),
  };
  return { body: Buffer.from(JSON.stringify(body)).toString('base64'), signature: randomBytes(64).toString('base64') };
}

async function subscribe(client, namespace = 'notes', cell = CELL) {
  client.send({ type: 'subscribe', namespace, cell, id: `${namespace}/${cell}` });
  const ack = await Promise.race([client.next('subscribed', (f) => f.ref === `${namespace}/${cell}`), client.next('error', (f) => f.ref === `${namespace}/${cell}`)]);
  return ack;
}

/** Everything sent before now has been handled and answered, on every client. */
async function settle(...clients) {
  for (const c of clients) await c.settle();
}

testHome('frames reach every other subscribed, entitled member, addressed or not; no echo', async ({ open }) => {
  const [a, b, d, c] = [await open('a'), await open('b'), await open('d'), await open('c')];
  for (const m of [a, b, d]) assert.equal((await subscribe(m)).type, 'subscribed');
  assert.equal((await subscribe(c)).code, 'notEntitled');
  assert.deepEqual(c.all('subscribed'), []);

  const f1 = frame('a', { n: 1 });
  a.send({ type: 'session', frame: f1 });
  assert.deepEqual((await b.next('session')).frame, f1);
  assert.deepEqual((await d.next('session')).frame, f1);

  // `to` is advice to receivers, not a route (§S3): d, which it does not name, gets it too.
  const f2 = frame('a', { n: 2, to: 'b' });
  a.send({ type: 'session', frame: f2 });
  assert.deepEqual((await b.next('session')).frame, f2);
  assert.deepEqual((await d.next('session')).frame, f2);

  // Another cell nobody subscribed to, then after d leaves the cell.
  a.send({ type: 'session', frame: frame('a', { n: 3, cell: 'queue' }) });
  d.send({ type: 'unsubscribe', namespace: 'notes', cell: CELL });
  await d.next('unsubscribed');
  const f4 = frame('a', { n: 4 });
  a.send({ type: 'session', frame: f4 });
  assert.deepEqual((await b.next('session')).frame, f4);
  await settle(a, b, c, d);
  assert.deepEqual(a.all('session'), [], 'echoed to the sender');
  assert.deepEqual(d.all('session').map((f) => f.frame), [f1, f2]);
  assert.deepEqual(b.all('session').map((f) => f.frame), [f1, f2, f4]);
  assert.deepEqual(c.all('session'), []);

  // The reverse direction, by a writer: nothing while a is out of the cell.
  a.send({ type: 'unsubscribe', namespace: 'notes', cell: CELL });
  await a.next('unsubscribed');
  const back = frame('b', { n: 1, to: 'a' });
  b.send({ type: 'session', frame: back });
  await settle(b, a);
  assert.equal(a.all('session').length, 0, 'a is not subscribed');
  await subscribe(a);
  b.send({ type: 'session', frame: back });
  assert.deepEqual((await a.next('session')).frame, back);
}, { stream: { framesPerSecond: 1000, frameBurst: 1000 } });

testHome('an addressed frame reaches every other subscriber but not the unentitled or unsubscribed', async ({ open }) => {
  const [a, b, c, d] = [await open('a'), await open('b'), await open('c'), await open('d')];
  for (const m of [a, b]) assert.equal((await subscribe(m)).type, 'subscribed');
  assert.equal((await subscribe(c)).code, 'notEntitled');
  // d is connected and entitled but not subscribed.
  const toD = frame('a', { n: 1, to: 'd' });
  a.send({ type: 'session', id: 'to-d', frame: toD });
  assert.deepEqual((await b.next('session')).frame, toD, 'a subscriber the frame does not name');
  await settle(a, b, c, d);
  assert.deepEqual(a.all('session'), [], 'echoed to the sender');
  assert.deepEqual(c.all('session'), [], 'not entitled to the namespace');
  assert.deepEqual(d.all('session'), [], 'not subscribed, though named');
}, { stream: { framesPerSecond: 1000, frameBurst: 1000 } });

testHome('the sender hears the same whether or not `to` names a connected member', async ({ open }) => {
  const [a, b] = [await open('a'), await open('b')];
  await subscribe(b);
  /** Everything a receives in answer to one addressed frame, without its sequence numbers. */
  const answer = async (to, n) => {
    const before = a.frames.length;
    a.send({ type: 'session', id: `to-${to}`, frame: frame('a', { n, to }) });
    await b.next('session', (f) => JSON.parse(Buffer.from(f.frame.body, 'base64')).n === n);
    await settle(a);
    return a.frames.slice(before).map(({ n: _n, t: _t, taken: _taken, ...rest }) => rest);
  };
  const connected = await answer('b', 1); // b is connected and subscribed
  const absent = await answer('e', 2); // e has no connection
  assert.deepEqual(connected, absent);
  assert.deepEqual(connected.map((f) => f.type), ['pong'], 'no acknowledgement and no error');
}, { stream: { framesPerSecond: 1000, frameBurst: 1000 } });

testHome('spoofed senders and unentitled members cannot send', async ({ open }) => {
  const [a, b, c] = [await open('a'), await open('b'), await open('c')];
  await subscribe(b);
  a.send({ type: 'session', id: 's1', frame: frame('b') });
  assert.deepEqual(await a.next('error'), { type: 'error', n: a.frames.at(-1).n, code: 'from', ref: 's1' });
  c.send({ type: 'session', id: 's2', frame: frame('c') });
  assert.equal((await c.next('error')).code, 'notEntitled');
  const foreign = frame('a');
  const body = JSON.parse(Buffer.from(foreign.body, 'base64'));
  foreign.body = Buffer.from(JSON.stringify({ ...body, account: '0'.repeat(64) })).toString('base64');
  a.send({ type: 'session', id: 's4', frame: foreign });
  assert.equal((await a.next('error')).code, 'account');
  // c's own namespace is its to use.
  c.send({ type: 'session', frame: frame('c', { namespace: 'books' }) });
  await settle(a, b, c);
  assert.equal(c.all('error').length, 1);
  assert.deepEqual(b.all('session'), []);
});

testHome('the latest retained frame per (cell, from) is given on subscribe, and lapses', async ({ open }) => {
  const [a, b, d] = [await open('a'), await open('b'), await open('d')];
  a.send({ type: 'session', frame: frame('a', { n: 1, retain: true }) });
  const latest = frame('a', { n: 2, retain: true });
  a.send({ type: 'session', frame: latest });
  const toB = frame('b', { n: 1, retain: true, to: 'a' });
  b.send({ type: 'session', frame: toB });
  await settle(a, b);
  await subscribe(d);
  const given = await d.next('session');
  assert.equal(given.retained, true);
  await settle(d);
  // Retained frames are given whatever their `to` says: d is given b's frame to a as well.
  const givenAll = d.all('session').map((f) => f.frame);
  const expected = [latest, toB];
  assert.equal(givenAll.length, 2, 'only the latest per sender');
  assert.deepEqual(new Set(givenAll.map((f) => f.body)), new Set(expected.map((f) => f.body)));
  // A member is not given its own retained frame; the addressee is given b's.
  await subscribe(a);
  assert.deepEqual((await a.next('session')).frame, toB);
  await settle(a);
  assert.equal(a.all('session').length, 1);
  // After retainMs, nothing is given.
  await new Promise((resolve) => setTimeout(resolve, 450));
  d.send({ type: 'unsubscribe', namespace: 'notes', cell: CELL });
  await subscribe(d);
  await settle(d);
  assert.equal(d.all('session').length, 2);
}, { stream: { retainMs: 300 } });

async function endSessions(member, seq, previous, issued) {
  return signBody({
    protocol: 'colophon/authority/5', kind: 'endSessions', seq, previous, issued,
    by: fixture[member].id, member: fixture[member].id,
  }, fixture[member].key);
}

testHome('access ending mid-connection closes the socket and drops its retained frames', async ({ request, open, advance, slot }) => {
  const [a, b] = [await open('a'), await open('b')];
  await subscribe(a);
  a.send({ type: 'session', frame: frame('a', { retain: true }) });
  await settle(a);
  advance();
  const entry = await endSessions('a', fixture.asOf.seq + 1, fixture.asOf.digest, stamp(fixture.now + 1000));
  const response = await request('/authority', 'POST', JSON.stringify({ from: fixture.asOf.seq + 1, entries: [entry], receipts: [] }));
  assert.equal(response.status, 200, await response.text());
  assert.equal((await a.closed).code, 1008);
  await subscribe(b);
  await settle(b);
  assert.deepEqual(b.all('session'), []);
  assert.equal((await slot()).home.stream.retained.size, 0);
});

/** A client WebSocket frame by hand (masked text). */
function clientFrame(text) {
  const payload = Buffer.from(text);
  const mask = randomBytes(4);
  const header = payload.length < 126 ? Buffer.from([0x81, 0x80 | payload.length])
    : Buffer.from([0x81, 0x80 | 126, payload.length >> 8, payload.length & 0xff]);
  const masked = Buffer.from(payload.map((byte, i) => byte ^ mask[i % 4]));
  return Buffer.concat([header, mask, masked]);
}

testHome('a member that cannot keep up is cut off (4013) instead of buffered', async ({ host, ticket, open, slot }) => {
  const [hostname, port] = host().split(':');
  const socket = net.connect(Number(port), hostname);
  await once(socket, 'connect');
  socket.write(`GET ${prefix}/stream?ticket=${await ticket('b')} HTTP/1.1\r\nHost: ${host()}\r\nConnection: Upgrade\r\n`
    + `Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n\r\n`);
  await once(socket, 'data');
  socket.write(clientFrame(JSON.stringify({ type: 'subscribe', namespace: 'notes', cell: CELL })));
  const closed = new Promise((resolve) => socket.on('close', resolve));
  const { stream } = (await slot()).home;
  // Wait until the subscription is in (the stream answers it before anything else).
  for (let i = 0; i < 200 && ![...stream.conns].some((c) => c.subs.size); i++) await new Promise((r) => setTimeout(r, 10));
  socket.pause();
  const a = await open('a');
  for (let i = 0; i < 400 && stream.counters.slow === 0; i++) {
    a.send({ type: 'session', frame: frame('a', { n: i + 1, size: 8_000 }) });
    if (i % 16 === 15) await a.settle();
  }
  await a.settle();
  assert.equal(stream.counters.slow, 1);
  assert.equal([...stream.conns].filter((c) => c.member === fixture.b.id).length, 0);
  assert.equal(a.ws.readyState, a.ws.OPEN, 'the sender is unaffected');
  socket.destroy();
  await closed;
}, { stream: { bufferedBytes: 65_536, framesPerSecond: 10_000, frameBurst: 10_000, bytesPerSecond: 1 << 30, byteBurst: 1 << 30 } });

testHome('nothing of a session frame is written under the data directory', async ({ open, dir, restart }) => {
  const [a, b] = [await open('a'), await open('b')];
  await subscribe(b);
  const marker = `MARKER-${randomBytes(8).toString('hex')}`;
  const sent = [frame('a', { marker, retain: true }), frame('a', { marker, to: 'b' })];
  for (const f of sent) a.send({ type: 'session', frame: f });
  await b.next('session');
  await b.next('session');
  await settle(a, b);
  await restart(); // a shutdown keeps nothing either
  const needles = [marker, Buffer.from(marker).toString('base64').slice(0, 12), ...sent.map((f) => f.body.slice(0, 40)), ...sent.map((f) => f.signature)];
  const walk = async (d) => {
    for (const e of await readdir(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else {
        const text = (await readFile(p)).toString('latin1');
        for (const n of needles) assert.ok(!text.includes(n), `${p} holds part of a session frame`);
      }
    }
  };
  await walk(dir);
  // And the restarted home holds no retained frame.
  const d = await open('d');
  await subscribe(d);
  await settle(d);
  assert.deepEqual(d.all('session'), []);
});

// ---------------------------------------------------------------------------------------------
// Tickets: redemption races, link keys, caps; eviction of a stopped home; the retained cap.

testHome('two simultaneous redemptions of one ticket: exactly one connects', async ({ host, ticket }) => {
  const t = await ticket('a');
  const results = await Promise.all([tryUpgrade(host(), `?ticket=${t}`), tryUpgrade(host(), `?ticket=${t}`)]);
  assert.deepEqual(results.map((r) => r.status).sort(), [101, 403]);
});

testHome('the per-account ticket cap refuses further minting', async ({ signed, ticket }) => {
  await ticket('a');
  await ticket('b');
  const refused = await signed('/stream/ticket', 'POST', undefined, { signer: 'c' });
  assert.equal(refused.status, 429);
}, { stream: { ticketsPerSlot: 2 } });

testHome('a full retained table forwards a frame without keeping it', async ({ open }) => {
  const [a, b] = [await open('a'), await open('b')];
  a.send({ type: 'session', frame: frame('a', { cell: 'first', retain: true }) });
  a.send({ type: 'session', frame: frame('a', { cell: 'second', retain: true }) });
  await settle(a);
  await subscribe(b, 'notes', 'first');
  await subscribe(b, 'notes', 'second');
  await settle(b);
  const cells = b.all('session').map((f) => JSON.parse(Buffer.from(f.frame.body, 'base64')).cell);
  assert.deepEqual(cells, ['first']);
}, { stream: { retainedPerSlot: 1 } });

/** A link from member `e` to a fresh in-memory key, and a ticket call signed by that key. */
async function linkKey(now, { session = 0, lifeMs = 600_000 } = {}) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64');
  const link = await signBody({
    protocol: 'colophon/link/5', account: fixture.account, from: fixture.e.id, to: { signing: point }, session,
    terms: { services: [{ audience: fixture.base, purposes: ['colophon.home.stream'] }] },
    notBefore: stamp(now), expires: stamp(now + lifeMs), created: stamp(now),
  }, fixture.e.key);
  const encodedLink = Buffer.from(JSON.stringify(link)).toString('base64');
  return {
    expires: now + lifeMs,
    call: async (at, asOf = fixture.asOf) => {
      const envelope = await signBody({
        protocol: 'colophon/call/5', account: fixture.account, asOf, audience: fixture.base,
        purpose: 'colophon.home.stream', signer: { member: fixture.e.id }, key: point, links: [encodedLink],
        args: { method: 'POST', path: '/stream/ticket', body: sha('') },
        requestId: randomBytes(32).toString('base64url'), created: stamp(at),
      }, jwk);
      return `Colophon ${Buffer.from(JSON.stringify(envelope)).toString('base64url')}`;
    },
  };
}

testHome('a link key mints tickets; its stream ends with the link', async ({ request, host, now, advance }) => {
  const link = await linkKey(now(), { lifeMs: 600_000 });
  const minted = await request('/stream/ticket', 'POST', undefined, await link.call(now()));
  assert.equal(minted.status, 200, await minted.clone().text());
  const ws = await Client.connect(host(), (await minted.json()).ticket);
  const hello = await ws.next('hello');
  assert.deepEqual([hello.principal, hello.expiresAt], [`member:${fixture.e.id}`, Math.floor(link.expires / 1000) * 1000]);
  advance(600_001);
  // The sweep (at most every sweepMs) re-judges the stream at the clock and closes it.
  assert.equal((await ws.closed).code, 1008);
}, { stream: { sweepMs: 50 } });

testHome('ending the member\'s sessions closes its link-key stream and refuses the old link', async ({ request, host, now, advance }) => {
  const link = await linkKey(now());
  const minted = await request('/stream/ticket', 'POST', undefined, await link.call(now()));
  assert.equal(minted.status, 200, await minted.clone().text());
  const ws = await Client.connect(host(), (await minted.json()).ticket);
  await ws.next('hello');
  advance();
  const entry = await endSessions('e', fixture.asOf.seq + 1, fixture.asOf.digest, stamp(now()));
  const response = await request('/authority', 'POST', JSON.stringify({ from: fixture.asOf.seq + 1, entries: [entry], receipts: [] }));
  assert.equal(response.status, 200, await response.text());
  assert.equal((await ws.closed).code, 1008);
  advance();
  const asOf = { seq: fixture.asOf.seq + 1, digest: sha(Buffer.from(entry.body, 'base64')) };
  const again = await request('/stream/ticket', 'POST', undefined, await link.call(now(), asOf));
  assert.equal(again.status, 403);
  assert.deepEqual(await again.json(), { result: 'refused:ended' });
});

testHome('a home that stops closes every stream', async ({ request, open, advance, now }) => {
  const [a, b] = [await open('a'), await open('b')];
  advance();
  // An entry the verifier finds of a newer format stops a 0.5 home (relay README "A stopped home").
  const entry = await signBody({
    protocol: 'colophon/authority/5', kind: 'endSessions', seq: fixture.asOf.seq + 1,
    previous: fixture.asOf.digest, issued: stamp(now()), by: fixture.a.id, member: fixture.a.id, future: true,
  }, fixture.a.key);
  const response = await request('/authority', 'POST', JSON.stringify({ from: fixture.asOf.seq + 1, entries: [entry], receipts: [] }));
  assert.equal(response.status, 422, await response.clone().text());
  assert.deepEqual(await response.json(), { result: 'newerFormat' });
  assert.deepEqual([(await a.closed).code, (await b.closed).code], [1008, 1008]);
});
