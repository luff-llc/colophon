// Shared helpers for the home stream tests: a relay on a synthetic account with the test clock,
// signed calls, stream tickets, and a WebSocket client that queues the frames it receives.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startRelay } from '../relay.js';

const target = process.env.CARGO_TARGET_DIR ?? fileURLToPath(new URL('../../target', import.meta.url));
export const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
export const ready = existsSync(wasm);
if (!ready) {
  if (process.env.CI || process.env.COLOPHON_REQUIRE_RELAY === '1') throw new Error(`Build the home WASM first (${wasm})`);
  console.error(`SKIPPED: Home stream tests need the module (${wasm})`);
}

export const prefix = '/v1/libraries/home';
export const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const stamp = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
export const rawBody = (envelope) => Buffer.from(envelope.body, 'base64');

export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export async function signBody(value, key) {
  const signingKey = await crypto.subtle.importKey('jwk', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const bytes = Buffer.from(canonical(value));
  const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, bytes));
  return { body: bytes.toString('base64'), signature: signature.toString('base64') };
}

/** A test with a fresh relay holding `fixture`'s account (its history uploaded). `stream` and
 * `limits` go to the relay. `run` gets helpers. */
export function testHome(fixture, name, run, { stream = {}, limits } = {}) {
  test(name, { skip: ready ? false : 'module not built' }, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'colophon-stream-'));
    let now = fixture.now;
    let running;
    const clients = [];
    const files = (name) => path.join(dir, 'home', name);
    const clock = () => now;
    const advance = (ms = 1000) => { now += ms; };
    const restart = async () => {
      await running?.close();
      running = await startRelay({
        port: 0, clock, tickMs: 0, dataDir: dir, stream, ...(limits ? { limits } : {}),
        libraries: { home: { home: true, account: fixture.account, base: fixture.base } },
        home: { key: fixture.homeKey, wasm },
      });
    };
    const call = async (method, relative, body = '', { signer = 'controller', kind,
      audience = fixture.base, purpose, asOf = fixture.asOf } = {}) => {
      const who = fixture[signer];
      kind ??= signer === 'controller' || signer === 'secondController' ? 'controller' : 'member';
      purpose ??= relative === '/stream/ticket' ? 'colophon.home.stream'
        : (method === 'GET' ? 'colophon.home.read' : 'colophon.home.write');
      const { id, key } = who;
      const point = Buffer.concat([Buffer.from([4]), Buffer.from(key.x, 'base64url'), Buffer.from(key.y, 'base64url')]);
      const envelope = await signBody({
        protocol: 'colophon/call/5', account: fixture.account, asOf, audience, purpose,
        signer: { [kind]: id }, key: point.toString('base64'),
        args: { method, path: relative, body: sha(body) },
        requestId: randomBytes(32).toString('base64url'), created: stamp(now),
      }, key);
      return `Colophon ${Buffer.from(JSON.stringify(envelope)).toString('base64url')}`;
    };
    const host = () => `127.0.0.1:${running.port}`;
    const request = (relative, method = 'GET', body, authorization, extra) => fetch(`http://${host()}${prefix}${relative}`, {
      method, body,
      headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(authorization ? { authorization } : {}), ...extra },
    });
    const signed = async (relative, method = 'GET', body, options, extra) =>
      request(relative, method, body, await call(method, relative, body, options), extra);
    /** A fresh stream ticket for `signer`. */
    const ticket = async (signer = 'controller', options = {}) => {
      const response = await signed('/stream/ticket', 'POST', undefined, { signer, ...options });
      assert.equal(response.status, 200, await response.clone().text());
      return (await response.json()).ticket;
    };
    /** An open stream client for `signer` (or for a given ticket), past its hello. */
    const open = async (signer = 'controller', { after, ticket: given } = {}) => {
      const t = given ?? await ticket(signer);
      const client = await Client.connect(host(), t, after);
      clients.push(client);
      await client.next('hello');
      return client;
    };
    const writeBlob = async (text, signer = 'controller') => {
      const response = await signed(`/records/blobs/${sha(text)}`, 'PUT', text, { signer }, { 'if-none-match': '*' });
      assert.equal(response.status, 201, await response.clone().text());
    };
    try {
      await restart();
      const upload = await request('/authority', 'POST', JSON.stringify({ from: 1, entries: fixture.entries, receipts: [] }));
      assert.equal(upload.status, 200, await upload.text());
      await run({ request, call, signed, host, files, restart, advance, ticket, open, writeBlob, dir,
        relay: () => running, slot: () => running.relay.slot('home'), now: () => now });
    } finally {
      for (const c of clients) c.ws.terminate();
      await running?.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
}

/** Ask for an upgrade by hand and report the HTTP answer of a refused one. */
export function rejectedUpgrade(host, query = '', headers = {}) {
  return new Promise((resolve, reject) => {
    const request = http.get(`http://${host}${prefix}/stream${query}`, { headers: {
      connection: 'Upgrade', upgrade: 'websocket', 'sec-websocket-version': '13',
      'sec-websocket-key': randomBytes(16).toString('base64'), ...headers,
    } }, (response) => {
      let text = '';
      response.on('data', (d) => { text += d; });
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: text ? JSON.parse(text) : null }));
    });
    request.on('error', reject);
    request.on('upgrade', (_, socket) => {
      socket.destroy();
      reject(new Error('The relay upgraded a refused request'));
    });
  });
}

/** Ask for an upgrade by hand: `{status: 101}` when it upgraded (the socket is closed), else the
 * refusal's status. */
export function tryUpgrade(host, query) {
  return new Promise((resolve, reject) => {
    const request = http.get(`http://${host}${prefix}/stream${query}`, { headers: {
      connection: 'Upgrade', upgrade: 'websocket', 'sec-websocket-version': '13',
      'sec-websocket-key': randomBytes(16).toString('base64'),
    } }, (response) => { response.resume(); resolve({ status: response.statusCode }); });
    request.on('error', reject);
    request.on('upgrade', (_, socket) => { socket.destroy(); resolve({ status: 101 }); });
  });
}

/** A stream client: every text frame is parsed and queued; `next` takes the next one of a type. */
export class Client {
  constructor(ws) {
    this.ws = ws;
    this.frames = [];
    this.waiters = [];
    this.closed = new Promise((resolve) => ws.on('close', (code, reason) => resolve({ code, reason: String(reason) })));
    ws.on('message', (data) => {
      const frame = JSON.parse(String(data));
      this.frames.push(frame);
      this.waiters = this.waiters.filter((w) => !w(frame));
    });
  }

  static async connect(host, ticket, after) {
    const { WebSocket } = await import('ws');
    const query = new URLSearchParams({ ticket, ...(after ? { after } : {}) });
    const ws = new WebSocket(`ws://${host}${prefix}/stream?${query}`);
    const client = new Client(ws);
    await once(ws, 'open');
    return client;
  }

  /** The next frame of `type` (matching `pred`) not taken before, waiting up to `ms`. */
  next(type, pred = () => true, ms = 3000) {
    const found = this.frames.findIndex((f) => !f.taken && f.type === type && pred(f));
    if (found >= 0) { this.frames[found].taken = true; return Promise.resolve(strip(this.frames[found])); }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no ${type} frame within ${ms} ms; got ${JSON.stringify(this.frames.map(strip))}`)), ms);
      this.waiters.push((frame) => {
        if (frame.taken || frame.type !== type || !pred(frame)) return false;
        frame.taken = true;
        clearTimeout(timer);
        resolve(strip(frame));
        return true;
      });
    });
  }

  /** Frames of `type` received so far (taken or not). */
  all(type) { return this.frames.filter((f) => f.type === type).map(strip); }

  send(value) { this.ws.send(typeof value === 'string' ? value : JSON.stringify(value)); }

  /** A ping round trip: everything the server sent before its pong has arrived. */
  async settle() {
    const t = Math.random();
    this.send({ type: 'ping', t });
    await this.next('pong', (f) => f.t === t);
  }
}

function strip(frame) {
  const { taken, ...rest } = frame;
  return rest;
}
