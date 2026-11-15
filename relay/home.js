// Colophon 0.5 home (spec §13, §14) for the relay. I/O only.
//
// Every decision (admit or refuse an object, what to receipt, which recording entry to append
// and its bytes, whether a head may be signed, whether a call is authorized) is made by the Rust
// home module (`crates/colophon-home-wasm`, a plain C-ABI WebAssembly module). This file does
// what a host does: sockets, files, a clock, the home's signing key, timers, and calls to other
// homes. It holds no verifier rule. It signs only what the module asks it to sign.
import { createHash, timingSafeEqual } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import path from 'node:path';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const unb64 = (text) => Buffer.from(text, 'base64');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** A loaded home module. The module is pure: an instance that traps is dropped and replaced. */
export class HomeModule {
  constructor(module) { this.module = module; this.instance = null; }

  static async load(file) {
    return new HomeModule(await WebAssembly.compile(await fsp.readFile(file)));
  }

  /** One request, one response, both JSON. A response with `ok: false` throws. */
  call(request) {
    this.instance ??= new WebAssembly.Instance(this.module, {});
    const { colophon_alloc: alloc, colophon_free: free, colophon_home: home, memory } = this.instance.exports;
    const input = Buffer.from(JSON.stringify(request));
    try {
      const inPtr = alloc(input.length);
      new Uint8Array(memory.buffer, inPtr, input.length).set(input);
      let outPtr;
      try { outPtr = home(inPtr, input.length); } finally { free(inPtr, input.length); }
      const length = new DataView(memory.buffer).getUint32(outPtr, true);
      const text = Buffer.from(new Uint8Array(memory.buffer, outPtr + 4, length)).toString('utf8');
      free(outPtr, length + 4);
      // A page of memory that grew for one big request is not kept for ever.
      if (memory.buffer.byteLength > 512 * 1024 * 1024) this.instance = null;
      const out = JSON.parse(text);
      if (!out.ok) throw new Error(`home module: ${out.error}`);
      return out;
    } catch (error) {
      if (error instanceof WebAssembly.RuntimeError) this.instance = null;
      throw error;
    }
  }
}

/** The home's signing key: a P-256 private JWK, imported non-extractable. Never logged. */
export class HomeKey {
  constructor(key, memberId, point) { this.key = key; this.memberId = memberId; this.point = point; }

  static async fromJwk(jwk, module) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d || !jwk.x || !jwk.y) {
      throw new Error('The home key must be a private P-256 JWK');
    }
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    const { id } = module.call({ op: 'identity', signing: b64(point) });
    return new HomeKey(key, id, point);
  }

  /** `raw` signature (§4.2): 64 bytes r ‖ s over exactly these bytes. */
  async sign(bytes) {
    return Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.key, bytes));
  }
}

/** The path grammar of a home slot: what kind of file a path names, or null. */
export function classifyHomePath(p) {
  if (typeof p !== 'string' || Buffer.byteLength(p) >= 512) return null;
  const parts = p.split('/');
  const ok = parts.every((c) => c.length > 0 && c !== '.' && c !== '..' && !c.startsWith('.') &&
    !c.includes('\\') && !c.includes('\0') && !c.includes('%'));
  if (!ok) return null;
  const json = (s) => s.endsWith('.json');
  const [a, b, c, d] = parts;
  if (parts.length === 2 && a === 'authority') return /^\d{8}\.json$/.test(b) ? 'authority' : null;
  if (parts.length === 2 && (a === 'transitions' || a === 'vetoes')) return HEX64.test(b.replace(/\.json$/, '')) && json(b) ? 'pending' : null;
  if (parts.length === 3 && a === 'receipts') return HEX64.test(b) && HEX32.test(c.replace(/\.receipt\.json$/, '')) && c.endsWith('.receipt.json') ? 'pending' : null;
  if (parts.length === 2 && a === 'heads') return json(b) && HEX32.test(b.slice(0, -5)) ? 'head' : null;
  if (parts.length === 3 && a === 'predecessor' && b === 'authority') return /^\d{8}\.json$/.test(c) ? 'predecessor' : null;
  if (parts.length === 2 && a === 'blobs') return HEX64.test(b) ? 'blob' : null;
  if (parts.length === 4 && json(d) && HEX32.test(b)) {
    if (a === 'ops' || a === 'history') return 'record';
    if (a === 'state') return 'state';
  }
  return null;
}

/** Per-address request counting for the rate limit (§12.4 allows `refused:window`; §14 is silent). */
class RateLimit {
  constructor(perMinute) { this.perMinute = perMinute; this.rows = new Map(); }
  take(address, now) {
    if (!this.perMinute) return true;
    if (this.rows.size > 10_000) this.rows.clear();
    const row = this.rows.get(address);
    if (!row || now - row.start >= 60_000) { this.rows.set(address, { start: now, count: 1 }); return true; }
    row.count += 1;
    return row.count <= this.perMinute;
  }
}

/** One account's home, on one library slot. */
export class HomeSlot {
  /**
   * @param {object} o `slot` (the relay's Slot), `wasm` (HomeModule), `key` (HomeKey), `base` (the
   * URL accounts name as this home's endpoint, also the call audience), `clock`, `resolve` (maps
   * another home's endpoint to the URL to reach it), `deps` (the relay's HttpError, send, readBody,
   * clampInt), `auth` (bearer check), `limits`.
   */
  constructor(o) {
    Object.assign(this, o);
    this.chain = Promise.resolve();
    this.state = null;
    this.replay = new Map();
    this.forward = { peers: {} };
    this.rate = new RateLimit(o.limits.requestsPerMinute);
    this.limit = this.wasm.call({ op: 'limits' });
  }

  file(name) { return path.join(this.slot.root, name); }

  lock(fn) {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run;
  }

  async open() {
    this.state = await this.readJson('home-state.json', null);
    if (!this.state) {
      this.state = this.wasm.call({ op: 'init', home: this.key.memberId }).state;
      await this.writeJson('home-state.json', this.state);
    }
    const replay = await this.readJson('replay.json', []);
    this.replay = new Map(replay);
    this.forward = await this.readJson('forward.json', { peers: {} });
    // The state is the commit point; the files are derived from it. A crash between the two
    // leaves a state whose files are missing: write them again (idempotent).
    const { files, heads } = this.wasm.call({ op: 'objects', state: this.state });
    await this.materialize([...files, ...heads]);
  }

  async readJson(name, fallback) {
    try { return JSON.parse(await fsp.readFile(this.file(name), 'utf8')); } catch { return fallback; }
  }
  async writeJson(name, value) {
    const staged = path.join(this.slot.root, 'tmp', `${name}.${process.pid}.${Date.now()}`);
    const handle = await fsp.open(staged, 'w', 0o600);
    try { await handle.write(JSON.stringify(value)); await handle.sync(); } finally { await handle.close(); }
    await fsp.rename(staged, this.file(name));
  }

  async commit(state) {
    if (state === this.state) return;
    await this.writeJson('home-state.json', state);
    this.state = state;
  }

  /** Store files the module said to store. A stored immutable file is never replaced (§14: the
   * home keeps the envelope it stored); a head file is replaced only by the home that signed it, in `ensureHead`. */
  async materialize(files) {
    for (const { path: p, bytes } of files) {
      const body = unb64(bytes);
      const have = this.slot.current.get(p);
      if (have && have.sha256 === sha(body)) continue;
      if (!have) {
        if (p.startsWith('heads/')) await this.slot.replaceRequest(p, body);
        else await this.slot.putImmutable(p, body);
      }
    }
  }

  /** Sign what the module asked for, give each signature back, commit, and store the results. */
  async signReceipts(list) {
    const envelopes = [];
    for (const item of list) {
      const body = unb64(item.body);
      const signature = b64(await this.key.sign(body));
      try {
        const r = this.wasm.call({ op: 'finish_receipt', state: this.state, object: item.object, body: item.body, signature, now: this.clock() });
        await this.commit(r.state);
        await this.materialize(r.store);
        envelopes.push(JSON.parse(unb64(r.envelope).toString('utf8')));
      } catch { /* the window ended or it was signed already: nothing is returned for it */ }
    }
    return envelopes;
  }

  /** A fresh head when the module says one is due (§13.3): guard, sign, verify, store. */
  async ensureHead() {
    const now = this.clock();
    const r = this.wasm.call({ op: 'head_request', state: this.state, now });
    await this.commit(r.state);
    if (!r.sign) return false;
    const signature = b64(await this.key.sign(unb64(r.sign.body)));
    const f = this.wasm.call({ op: 'finish_head', state: this.state, now, seq: r.sign.seq, digest: r.sign.digest, issued: r.sign.issued, signature });
    await this.commit(f.state);
    await this.slot.replaceRequest(f.path, unb64(f.envelope));
    return true;
  }

  async headEnvelope() {
    if (!this.slot.current.has(`heads/${this.key.memberId}.json`)) return null;
    return JSON.parse((await this.slot.readFile(`heads/${this.key.memberId}.json`)).toString('utf8'));
  }

  status() { return this.wasm.call({ op: 'status', state: this.state, now: this.clock() }); }

  // -------------------------------------------------------------------------------------------
  // Who may do what (§13.4, §14). A bearer token is storage access only: it never reads history.

  async access(req, cls) {
    const { HttpError } = this.deps;
    if (cls !== 'history' && this.auth(req)) return;
    const header = req.headers.authorization ?? '';
    const m = /^Colophon ([A-Za-z0-9_-]+)$/.exec(header);
    const st = this.status();
    if (!st.appointed) {
      if (cls === 'history') return; // nothing is held to be read
      throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Colophon, Bearer' });
    }
    let call; let existing = null; let key = null;
    if (m) {
      call = b64(Buffer.from(m[1], 'base64url'));
      const k = this.wasm.call({ op: 'call_key', call });
      if (k.parsed) {
        key = k.key;
        const row = this.replay.get(key);
        existing = row ? { at: row.at, digest: row.digest } : null;
      }
    }
    const now = this.clock();
    const r = this.wasm.call({ op: 'authorize', state: this.state, now, class: cls, base: this.base, call, existing });
    if (r.allowed) {
      if (r.reserve) await this.reserve(r.reserve);
      return;
    }
    if (!m) throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Colophon, Bearer' });
    throw new HttpError(403, JSON.stringify({ result: r.code }));
  }

  /** The replay reservation (§12.4), durable before any effect. The table is bounded: a full
   * one refuses new calls (`refused:window`, which §12.4 allows a store to answer). */
  async reserve({ key, at, digest }) {
    const { HttpError } = this.deps;
    for (const [k, row] of this.replay) if (at - row.at > this.limit.retentionMs) this.replay.delete(k);
    if (this.replay.size >= this.limits.replayRows) throw new HttpError(429, JSON.stringify({ result: 'refused:window' }), { 'retry-after': '60' });
    this.replay.set(key, { at, digest });
    await this.writeJson('replay.json', [...this.replay]);
  }

  // -------------------------------------------------------------------------------------------
  // HTTP. Returns true when it answered; false to let the relay's generic record code go on.

  async handle(req, res, url, section, rest) {
    const { HttpError, send, readBody, clampInt } = this.deps;
    if (!this.rate.take(req.socket.remoteAddress ?? '', this.clock())) {
      throw new HttpError(429, 'Too many requests', { 'retry-after': '60' });
    }
    const method = req.method;
    if (!section) {
      if (method !== 'GET') throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      return false;
    }
    if (section === 'head') {
      if (method !== 'GET' || rest !== undefined) throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      const head = await this.headEnvelope();
      if (!head) throw new HttpError(404, 'No head');
      send(res, 200, head);
      return true;
    }
    if (section === 'authority') {
      if (rest !== undefined) throw new HttpError(404, 'Not found');
      if (method === 'GET') { await this.getAuthority(req, res, url); return true; }
      if (method !== 'POST') throw new HttpError(405, 'Method not allowed', { allow: 'GET, POST' });
      const body = await readBody(req, this.limits.authorityBodyBytes);
      await this.lock(() => this.postAuthority(res, body));
      return true;
    }
    if (section === 'pending') {
      if (rest === undefined) {
        if (method === 'GET') { await this.getPending(req, res, url); return true; }
        if (method !== 'POST') throw new HttpError(405, 'Method not allowed', { allow: 'GET, POST' });
        const body = await readBody(req, this.limits.pendingBodyBytes);
        await this.lock(() => this.postPending(res, body));
        return true;
      }
      if (method !== 'GET') throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      if (!HEX64.test(rest)) throw new HttpError(404, 'Not found');
      await this.access(req, 'history');
      if (!this.status().appointed) throw new HttpError(404, 'Not found');
      const r = this.wasm.call({ op: 'pending_object', state: this.state, now: this.clock(), digest: rest });
      if (!r.found) throw new HttpError(404, 'Not found');
      send(res, 200, { envelope: JSON.parse(unb64(r.envelope)), receipts: r.receipts.map((x) => JSON.parse(unb64(x))) });
      return true;
    }
    if (section === 'predecessor') throw new HttpError(404, 'This home serves no predecessor');
    if (section === 'changes') {
      if (method !== 'GET') throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      await this.access(req, 'records_read');
      return false;
    }
    if (section === 'records') return this.records(req, res, url, rest);
    return false;
  }

  async getAuthority(req, res, url) {
    const { send, clampInt } = this.deps;
    await this.access(req, 'history');
    const after = clampInt(url.searchParams.get('after'), 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = clampInt(url.searchParams.get('limit'), 64, 1, 64);
    const st = this.status();
    const seq = st.appointed && !st.error ? st.seq : 0;
    const entries = [];
    for (let s = after + 1; s <= seq && entries.length < limit; s += 1) {
      entries.push(JSON.parse((await this.slot.readFile(`authority/${String(s).padStart(8, '0')}.json`)).toString('utf8')));
    }
    send(res, 200, { entries, receipts: [], more: after + entries.length < seq });
  }

  async getPending(req, res, url) {
    const { send, clampInt, HttpError } = this.deps;
    await this.access(req, 'history');
    const after = clampInt(url.searchParams.get('after'), 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = clampInt(url.searchParams.get('limit'), 64, 1, 64);
    if (!this.status().appointed) return send(res, 200, { objects: [], more: false });
    let page;
    try { page = this.wasm.call({ op: 'pending_page', state: this.state, now: this.clock(), after, limit }); }
    catch { throw new HttpError(503, 'The home cannot list its pending objects now'); }
    send(res, 200, {
      objects: page.objects.map((o) => ({ seq: o.seq, digest: o.digest, kind: o.kind, envelope: JSON.parse(unb64(o.envelope)) })),
      more: page.more,
    });
  }

  async answerOutcome(res, r) {
    const { send } = this.deps;
    if (r.outcome === 'conflict') return send(res, 409, (await this.headEnvelope()) ?? {});
    if (r.outcome === 'primary') return send(res, 421, { endpoints: r.endpoints });
    return send(res, 422, { result: r.result });
  }

  async postAuthority(res, body) {
    const { send } = this.deps;
    const now = this.clock();
    const r = this.wasm.call({ op: 'post_authority', state: this.state, now, body: b64(body) });
    await this.commit(r.state); // even a refusal changes state (§13.1)
    await this.materialize(r.store);
    const receipts = await this.signReceipts(r.sign);
    if (r.appointed) await this.ensureHead();
    if (r.outcome !== 'ok') return this.answerOutcome(res, r);
    return send(res, 200, { head: await this.headEnvelope(), receipts });
  }

  async postPending(res, body) {
    const { send } = this.deps;
    const r = this.wasm.call({ op: 'post_pending', state: this.state, now: this.clock(), body: b64(body) });
    await this.commit(r.state);
    await this.materialize(r.store);
    const receipts = await this.signReceipts(r.sign);
    if (r.outcome !== 'ok') return send(res, 422, r.results?.length ? r.results : { result: r.result });
    return send(res, 200, { receipts });
  }

  /** `records/…` of a home: history files, heads, and the record store behind the module's check. */
  async records(req, res, url, recordPath) {
    const { HttpError, send, readBody } = this.deps;
    const kind = classifyHomePath(recordPath ?? '');
    if (!kind) throw new HttpError(400, 'Invalid record path');
    if (url.search) throw new HttpError(400, 'Record URLs take no query');
    const method = req.method;
    if (method === 'GET' || method === 'HEAD') {
      await this.access(req, ['authority', 'pending', 'head', 'predecessor'].includes(kind) ? 'history' : 'records_read');
      return false;
    }
    if (method !== 'PUT') throw new HttpError(405, 'Method not allowed', { allow: 'GET, PUT' });
    if (kind === 'head') {
      // A head forwarded by another current home (§13.1). Anyone may send one: it is checked.
      const body = await readBody(req, 8192);
      let parsed; let by; let issued;
      try {
        parsed = JSON.parse(body.toString('utf8'));
        const head = JSON.parse(Buffer.from(parsed.body, 'base64').toString('utf8'));
        by = head.by; issued = Date.parse(head.issued);
      } catch { throw new HttpError(400, 'Not a head'); }
      if (`heads/${by}.json` !== recordPath || by === this.key.memberId) throw new HttpError(400, 'A head is stored under its home');
      await this.lock(async () => {
        const r = this.wasm.call({ op: 'admit_one', state: this.state, now: this.clock(), bytes: b64(body) });
        await this.commit(r.state);
        if (r.outcome !== 'ok') { await this.answerOutcome(res, r); return; }
        // Serve the newest head each home has sent.
        let newer = true;
        if (this.slot.current.has(recordPath)) {
          const old = JSON.parse(Buffer.from(JSON.parse((await this.slot.readFile(recordPath)).toString('utf8')).body, 'base64').toString('utf8'));
          newer = issued > Date.parse(old.issued);
        }
        if (newer) await this.slot.replaceRequest(recordPath, Buffer.from(JSON.stringify(parsed)));
        res.writeHead(200, { 'content-length': 0 });
        res.end();
      });
      return true;
    }
    if (kind === 'authority' || kind === 'pending' || kind === 'predecessor') {
      throw new HttpError(405, 'Use POST /authority or POST /pending', { allow: 'GET' });
    }
    await this.access(req, 'records_write');
    const max = kind === 'blob' ? this.limits.blobBytes : this.limits.recordBytes;
    const body = await readBody(req, max);
    return this.lock(async () => {
      const check = this.wasm.call({ op: 'check_record', state: this.state, now: this.clock(), path: recordPath, bytes: b64(body) });
      if (!check.allowed) return send(res, 422, { result: check.code }), true;
      const conditional = req.headers['if-none-match'];
      let status;
      if (conditional === '*') status = await this.slot.putImmutable(recordPath, body);
      else if (conditional !== undefined) throw new HttpError(400, 'Only If-None-Match: * is supported');
      else if (kind === 'state') {
        const expected = req.headers['if-match'];
        if (!expected || !/^"[0-9a-f]{64}"$/.test(expected)) throw new HttpError(428, 'Live replacement requires If-Match');
        status = await this.slot.replaceRequest(recordPath, body, expected);
      } else throw new HttpError(428, 'Immutable records require If-None-Match: *');
      res.writeHead(status, { etag: `"${sha(body)}"`, 'content-length': 0 });
      res.end();
      return true;
    });
  }

  // -------------------------------------------------------------------------------------------
  // The scheduler: recording entries when due (§8.7), heads (§13.3), and forwarding to the
  // account's other homes (§13.1). Driven by the relay's clock; the module decides, this runs it.

  async tick() {
    if (this.ticking) return; // one scheduler pass at a time
    this.ticking = true;
    try { await this.tickOnce(); } finally { this.ticking = false; }
  }

  async tickOnce() {
    await this.lock(async () => {
      if (!this.status().appointed) return;
      const r = this.wasm.call({ op: 'record_due', state: this.state, now: this.clock() });
      const said = r.result === 'ok' && !r.note ? '' : `${r.result} ${r.note ?? ''}`;
      if (said && said !== this.lastSaid) console.error(`recording entries for slot ${this.slot.name}: ${said}`);
      this.lastSaid = said;
      await this.commit(r.state);
      await this.materialize(r.store);
      await this.signReceipts(r.sign);
      await this.ensureHead();
    });
    // Calls to other homes happen outside the lock: two homes forwarding to each other would
    // otherwise wait on one another.
    await this.forwardAll();
  }

  async forwardAll() {
    const st = await this.lock(async () => this.status());
    for (const peer of st.peers ?? []) {
      const endpoint = (peer.endpoints ?? [])[0];
      if (!endpoint) continue;
      const base = (this.resolve?.[endpoint.replace(/\/$/, '')] ?? endpoint).replace(/\/$/, '');
      const row = (this.forward.peers[peer.id] ??= { after: 0, head: '' });
      try { await this.forwardTo(base, row); row.said = ''; } catch (error) {
        const said = `forwarding to home ${peer.id} failed (it will be retried): ${error.message}`;
        if (said !== row.said) console.error(said); // once per distinct failure, not once per tick
        row.said = said;
      }
    }
  }

  async forwardTo(base, row) {
    const init = (extra) => ({ signal: AbortSignal.timeout(5000), ...extra });
    // Pending objects, in the order this home first stored them, from this peer's cursor.
    for (;;) {
      const page = await this.lock(async () => this.wasm.call({ op: 'pending_page', state: this.state, now: this.clock(), after: row.after, limit: 16 }));
      if (page.objects.length === 0) break;
      const objects = page.objects.map((o) => JSON.parse(unb64(o.envelope)));
      const r = await fetch(`${base}/pending`, init({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ objects }) }));
      if (r.status !== 200 && r.status !== 422) throw new Error(`peer answered ${r.status}`);
      if (r.status === 200) {
        // Its receipts of what we sent come back; we take them like any forwarded receipt.
        const { receipts } = await r.json();
        if (Array.isArray(receipts) && receipts.length) {
          await this.lock(async () => {
            const back = this.wasm.call({ op: 'post_pending', state: this.state, now: this.clock(), body: b64(Buffer.from(JSON.stringify({ objects: receipts.slice(0, 16) }))) });
            await this.commit(back.state);
            await this.materialize(back.store);
          });
        }
      }
      row.after = page.objects[page.objects.length - 1].seq;
      await this.writeJson('forward.json', this.forward);
      if (!page.more) break;
    }
    const head = await this.headEnvelope();
    if (head) {
      const text = JSON.stringify(head);
      if (sha(text) !== row.head) {
        const r = await fetch(`${base}/records/heads/${this.key.memberId}.json`, init({ method: 'PUT', headers: { 'content-type': 'application/json' }, body: text }));
        if (r.status === 200) { row.head = sha(text); await this.writeJson('forward.json', this.forward); }
        else console.error(`peer refused our head: ${r.status} ${(await r.text()).slice(0, 200)}`);
      }
    }
  }
}

export { timingSafeEqual };
