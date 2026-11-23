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
import { prefix, signBody, stamp, testHome as testHomeOn } from './stream-support.js';

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

testHome('frames reach every other subscribed, entitled member; `to` reaches one; no echo', async ({ open }) => {
  const [a, b, d, c] = [await open('a'), await open('b'), await open('d'), await open('c')];
  for (const m of [a, b, d]) assert.equal((await subscribe(m)).type, 'subscribed');
  assert.equal((await subscribe(c)).code, 'notEntitled');
  assert.deepEqual(c.all('subscribed'), []);

  const f1 = frame('a', { n: 1 });
  a.send({ type: 'session', frame: f1 });
  assert.deepEqual((await b.next('session')).frame, f1);
  assert.deepEqual((await d.next('session')).frame, f1);

  const f2 = frame('a', { n: 2, to: 'b' });
  a.send({ type: 'session', frame: f2 });
  assert.deepEqual((await b.next('session')).frame, f2);

  // Another cell nobody subscribed to, then after d leaves the cell.
  a.send({ type: 'session', frame: frame('a', { n: 3, cell: 'queue' }) });
  d.send({ type: 'unsubscribe', namespace: 'notes', cell: CELL });
  await d.next('unsubscribed');
  const f4 = frame('a', { n: 4 });
  a.send({ type: 'session', frame: f4 });
  assert.deepEqual((await b.next('session')).frame, f4);
  await settle(a, b, c, d);
  assert.deepEqual(a.all('session'), [], 'echoed to the sender');
  assert.deepEqual(d.all('session').map((f) => f.frame), [f1]);
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
}, { stream: { sweepMs: 0, framesPerSecond: 1000, frameBurst: 1000 } });

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
  assert.deepEqual(given, { type: 'session', n: given.n, retained: true, frame: latest });
  await settle(d);
  assert.equal(d.all('session').length, 1, 'only the latest, and not a frame addressed to another');
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
  assert.equal(d.all('session').length, 1);
}, { stream: { sweepMs: 0, retainMs: 300 } });

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
}, { stream: { sweepMs: 0, bufferedBytes: 65_536, framesPerSecond: 10_000, frameBurst: 10_000, bytesPerSecond: 1 << 30, byteBurst: 1 << 30 } });

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
