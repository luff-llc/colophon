// Colophon 0.5 home (spec §13, §14) for the relay. I/O only.
//
// Every decision (admit or refuse an object, what to receipt, which recording entry to append
// and its bytes, whether a head may be signed and which head to serve, which class a path is,
// whether a request is authorized, whether a caller is over its share of the replay table,
// whether a peer's answer delivered a forwarded object) is made by the Rust home module
// (`crates/colophon-home-wasm`, a plain C-ABI WebAssembly module). This file does what a host
// does: sockets, files, a clock, the home's signing key, timers, and calls to other homes. It
// holds no verifier rule. It signs only what the module asks it to sign.
//
// Storage follows state: every mutation commits the module's new state, then stores the files the
// module lists, under one lock; at start-up the files are reconciled with the state before
// anything is served.
import { createHash } from 'node:crypto';
import { promises as fsp, writeSync } from 'node:fs';
import path from 'node:path';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const unb64 = (text) => Buffer.from(text, 'base64');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** A loaded home module. The module is pure: an instance that traps is dropped and replaced. */
export class HomeModule {
  constructor(module) { this.module = module; this.instance = null; }

  static async load(file) {
    return new HomeModule(await WebAssembly.compile(await fsp.readFile(file)));
  }

  /** One request, one response, both JSON. A response with `ok: false` throws a ModuleError. */
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
      if (!out.ok) throw new ModuleError(out.error);
      return out;
    } catch (error) {
      if (error instanceof WebAssembly.RuntimeError) this.instance = null;
      throw error;
    }
  }
}

/** The module refused or could not answer a request (not an I/O failure of the host). */
export class ModuleError extends Error {
  constructor(message) { super(`home module: ${message}`); }
}

/** The home's signing key: a P-256 private JWK, imported non-extractable. Never logged. */
export class HomeKey {
  constructor(key, memberId, point) { this.key = key; this.memberId = memberId; this.point = point; }

  static async fromJwk(jwk, module) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d || !jwk.x || !jwk.y) {
      throw new Error('The home key must be a private P-256 JWK');
    }
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    // The public half must be the private key's: sign once and verify under x, y. A mismatch
    // would make every receipt and head fail the module's check.
    const pub = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const probe = Buffer.from('colophon home key check');
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, probe);
    if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, probe)) {
      throw new Error('The home key\'s x and y are not the public half of its d');
    }
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    const { id } = module.call({ op: 'identity', signing: b64(point) });
    return new HomeKey(key, id, point);
  }

  /** `raw` signature (§4.2): 64 bytes r ‖ s over exactly these bytes. */
  async sign(bytes) {
    return Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.key, bytes));
  }
}

/** Per-address request counting (a host's defence against floods; §12.4 replay shares are the
 * module's). Rows whose minute has passed are dropped, never the whole table. */
class RateLimit {
  constructor(perMinute) { this.perMinute = perMinute; this.rows = new Map(); }
  take(address, now) {
    if (!this.perMinute) return true;
    if (this.rows.size > 10_000) {
      for (const [a, row] of this.rows) if (now - row.start >= 60_000) this.rows.delete(a);
    }
    const row = this.rows.get(address);
    if (!row || now - row.start >= 60_000) {
      if (this.rows.size > 10_000) return false; // too many live addresses: refuse new ones
      this.rows.set(address, { start: now, count: 1 });
      return true;
    }
    row.count += 1;
    return row.count <= this.perMinute;
  }
}

/** A promise-chain lock. */
function chain() {
  let tail = Promise.resolve();
  return (fn) => {
    const run = tail.then(fn, fn);
    tail = run.catch(() => {});
    return run;
  };
}

/** One account's home, on one library slot provisioned for that account. */
export class HomeSlot {
  /**
   * @param {object} o `slot` (the relay's Slot), `wasm` (HomeModule), `key` (HomeKey), `base` (the
   * URL accounts name as this home's endpoint, also the call audience), `account` (the account ID
   * the operator provisioned the slot for), `clock`, `resolve` (maps another home's endpoint to
   * the URL to reach it), `deps` (the relay's HttpError, send, readBody, clampInt), `limits`.
   */
  constructor(o) {
    Object.assign(this, o);
    this.lock = chain();
    this.replayLock = chain();
    this.state = null;
    this.rows = new Map(); // replay key -> { digest, at, signer }
    this.bySigner = new Map(); // principal -> Set of keys
    this.logLines = 0;
    this.forward = { peers: {} };
    this.rate = new RateLimit(o.limits.requestsPerMinute);
    this.said = new Map();
  }

  file(name) { return path.join(this.slot.root, name); }

  /** Say something once per distinct message per topic, not once per tick. */
  note(topic, message) {
    if (this.said.get(topic) === message) return;
    this.said.set(topic, message);
    if (message) console.error(message);
  }

  async open() {
    this.state = await this.readJson('home-state.json', null);
    if (!this.state) {
      this.state = this.wasm.call({ op: 'init', home: this.key.memberId, account: this.account }).state;
      await this.writeJson('home-state.json', this.state);
    }
    const st = this.status();
    if (st.home !== this.key.memberId) throw new Error(`Home slot ${this.slot.name} holds the state of another home key`);
    if (st.account !== this.account) throw new Error(`Home slot ${this.slot.name} was provisioned for account ${st.account}, not ${this.account}`);
    // Reconcile storage with the state before serving: a crash between a commit and its files
    // (a missing entry, a head file older than the committed head) heals here, not later.
    await this.materialize(this.wasm.call({ op: 'objects', state: this.state, now: this.clock() }).files);
    await this.openReplay();
    this.forward = await this.readJson('forward.json', { peers: {} });
  }

  async readJson(name, fallback) {
    try { return JSON.parse(await fsp.readFile(this.file(name), 'utf8')); } catch { return fallback; }
  }
  async writeJson(name, value) {
    const staged = path.join(this.slot.root, 'tmp', `${name}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`);
    const handle = await fsp.open(staged, 'w', 0o600);
    try { await handle.write(JSON.stringify(value)); await handle.sync(); } finally { await handle.close(); }
    await fsp.rename(staged, this.file(name));
  }

  async commit(state) {
    if (!state || state === this.state) return;
    await this.writeJson('home-state.json', state);
    this.state = state;
  }

  /** Store the files the module listed. A path the module marks `replace` (a head; an entry
   * whose seq another candidate now stands at, §8.6) is replaced; any other path is written once
   * (§14: the home keeps the envelope it stored), and a different file already there is
   * corruption, not something to overwrite. */
  async materialize(files) {
    for (const { path: p, bytes, replace } of files ?? []) {
      const body = unb64(bytes);
      const have = this.slot.current.get(p);
      if (have && have.sha256 === sha(body)) continue;
      if (replace) await this.slot.replaceRequest(p, body);
      else if (!have) await this.slot.putImmutable(p, body);
      else throw new Error(`Home slot ${this.slot.name}: ${p} on disk differs from the state`);
    }
  }

  /** Sign what the module asked for, give each signature back, commit, and store the results.
   * A request the module no longer accepts (its window ended, or it was signed already) yields
   * nothing; an I/O failure is not swallowed. */
  async signReceipts(list) {
    const envelopes = [];
    for (const item of list ?? []) {
      const signature = b64(await this.key.sign(unb64(item.body)));
      let r;
      try {
        r = this.wasm.call({ op: 'finish_receipt', state: this.state, object: item.object, body: item.body, signature, now: this.clock() });
      } catch (error) {
        if (error instanceof ModuleError) continue;
        throw error;
      }
      await this.commit(r.state);
      await this.materialize(r.store);
      envelopes.push(JSON.parse(unb64(r.envelope).toString('utf8')));
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
    await this.materialize(f.store);
    return true;
  }

  async headEnvelope() {
    const p = `heads/${this.key.memberId}.json`;
    if (!this.slot.current.has(p)) return null;
    return JSON.parse((await this.slot.readFile(p)).toString('utf8'));
  }

  status() { return this.wasm.call({ op: 'status', state: this.state, now: this.clock() }); }

  // -------------------------------------------------------------------------------------------
  // The replay table (§12.4). The module decides; this keeps the rows durable: an append-only
  // log, a reservation line (fsynced) before any effect, a completion line after it, and
  // recovery at start-up from the effect's own record.

  async openReplay() {
    const file = this.file('replay.log');
    let text = '';
    try { text = await fsp.readFile(file, 'utf8'); } catch { text = ''; }
    const end = text.lastIndexOf('\n');
    if (end !== text.length - 1) text = text.slice(0, end + 1); // a torn last line
    const pending = new Map();
    for (const line of text.split('\n')) {
      if (!line) continue;
      let e; try { e = JSON.parse(line); } catch { continue; }
      this.logLines += 1;
      if (e.r) {
        this.addRow(e.r, { digest: e.d, at: e.at, signer: e.s });
        if (e.e && !e.t) pending.set(e.r, e.e); else pending.delete(e.r);
      } else if (e.c) pending.delete(e.c);
    }
    // A reservation left pending by a crash: completed if its effect is there, else abandoned.
    // Either way the row stays and the call is a replay.
    const rows = [...pending].map(([key, effect]) => {
      const now = this.slot.current.get(effect.path)?.sha256 ?? null;
      return { key, present: now !== null && now !== (effect.prior ?? null) };
    });
    const lines = rows.length ? this.wasm.call({ op: 'replay_recover', rows }).states.map((s) => ({ c: s.key, t: s.state })) : [];
    await this.compactReplay(lines);
  }

  addRow(key, row) {
    this.rows.set(key, row);
    let set = this.bySigner.get(row.signer);
    if (!set) this.bySigner.set(row.signer, (set = new Set()));
    set.add(key);
  }
  dropRows(keys) {
    for (const key of keys ?? []) {
      const row = this.rows.get(key);
      if (!row) continue;
      this.rows.delete(key);
      const set = this.bySigner.get(row.signer);
      set?.delete(key);
      if (set && set.size === 0) this.bySigner.delete(row.signer);
    }
  }

  /** Rewrite the log with the rows the module keeps (§12.4 retention), plus `extra` lines. */
  async compactReplay(extra = []) {
    const all = [...this.rows].map(([key, r]) => ({ key, at: r.at }));
    const keep = new Set(this.wasm.call({ op: 'replay_keep', now: this.clock(), rows: all }).keep);
    this.dropRows(all.map((r) => r.key).filter((k) => !keep.has(k)));
    const lines = [...this.rows].map(([key, r]) => JSON.stringify({ r: key, d: r.digest, s: r.signer, at: r.at, t: 'completed' }));
    for (const e of extra) lines.push(JSON.stringify(e));
    const staged = path.join(this.slot.root, 'tmp', `replay.${process.pid}.${Date.now()}`);
    const handle = await fsp.open(staged, 'w', 0o600);
    try { await handle.write(lines.map((l) => l + '\n').join('')); await handle.sync(); } finally { await handle.close(); }
    await fsp.rename(staged, this.file('replay.log'));
    this.logLines = lines.length;
  }

  async appendReplay(entry, durable) {
    const handle = await fsp.open(this.file('replay.log'), 'a', 0o600);
    try { await handle.write(JSON.stringify(entry) + '\n'); if (durable) await handle.sync(); } finally { await handle.close(); }
    this.logLines += 1;
  }

  /** The reservation, durable before any effect. A read's effect is not durable, so its
   * reservation is written completed (`completed(result, none)`); a write's names its effect
   * (the path and what was there before), so recovery can tell whether it happened. */
  async reserve(row, effect) {
    const line = { r: row.key, d: row.digest, s: row.signer, at: row.at, ...(effect ? { e: effect } : { t: 'completed' }) };
    await this.appendReplay(line, true);
    this.addRow(row.key, { digest: row.digest, at: row.at, signer: row.signer });
    if (this.logLines > 2 * this.rows.size + 1024) await this.compactReplay();
  }
  async complete(key, t) { await this.appendReplay({ c: key, t }, false); }

  // -------------------------------------------------------------------------------------------
  // Who may do what (§13.4, §14): the module's `access` decision, all of it.

  async access(req, section, rest, effect, body) {
    const { HttpError } = this.deps;
    const header = req.headers.authorization ?? '';
    const m = /^Colophon ([A-Za-z0-9_-]+)$/.exec(header);
    const call = m ? b64(Buffer.from(m[1], 'base64url')) : null;
    return this.replayLock(async () => {
      let existing = null; let signerRows = [];
      if (call) {
        const k = this.wasm.call({ op: 'call_key', call });
        if (k.parsed) {
          const row = this.rows.get(k.key);
          existing = row ? { at: row.at, digest: row.digest } : null;
          signerRows = [...(this.bySigner.get(k.signer) ?? [])].map((key) => ({ key, at: this.rows.get(key).at }));
        }
      }
      const r = this.wasm.call({
        op: 'access', state: this.state, now: this.clock(), method: req.method, section, rest,
        call, existing, signerRows, replayRows: this.limits.replayRows, base: this.base,
        path: this.relativePath(req), bodySha256: sha(body ?? Buffer.alloc(0)),
      });
      this.dropRows(r.drop);
      if (r.allowed) {
        if (r.reserve) await this.reserve(r.reserve, effect);
        return r;
      }
      switch (r.status) {
        case 401: throw new HttpError(401, 'A Colophon call is required', { 'www-authenticate': 'Colophon' });
        case 403: throw new HttpError(403, 'Forbidden', {}, { result: r.result });
        case 429: throw new HttpError(429, 'Too many requests', { 'retry-after': String(r.retryAfter ?? 60) }, { result: r.result });
        case 405: throw new HttpError(405, 'Method not allowed', { allow: r.allow });
        case 400: throw new HttpError(400, r.error ?? 'Bad request');
        default: throw new HttpError(r.status ?? 404, 'Not found');
      }
    });
  }

  /** The request's path and query relative to the slot's base, exactly as sent: what a call's
   * `args.path` names. */
  relativePath(req) {
    const prefix = `/v1/libraries/${this.slot.name}`;
    const raw = req.url ?? '';
    return raw.startsWith(prefix) ? raw.slice(prefix.length) : raw;
  }

  // -------------------------------------------------------------------------------------------
  // HTTP. Returns true when it answered; false to let the relay's generic code serve the file,
  // the change feed or `GET {base}` (after the module allowed it).

  async handle(req, res, url, section, rest) {
    const { HttpError, send, readBody, clampInt } = this.deps;
    if (!this.rate.take(req.socket.remoteAddress ?? '', this.clock())) {
      throw new HttpError(429, 'Too many requests', { 'retry-after': '60' });
    }
    const method = req.method;
    const writing = section === 'records' && method === 'PUT';
    const effect = writing ? { path: rest, prior: this.slot.current.get(rest)?.sha256 ?? null } : null;
    // A write's body is read (bounded) before its call is judged: the call is bound to its digest.
    const recordWrite = writing && typeof rest === 'string' && !rest.startsWith('heads/');
    const body = recordWrite ? await readBody(req, rest.startsWith('blobs/') ? this.limits.blobBytes : this.limits.recordBytes) : null;
    const allowed = await this.access(req, section ?? '', rest ?? null, effect, body);
    const key = allowed.reserve?.key;
    if (!section || section === 'changes') return false;
    if (section === 'head') {
      // A head due a refresh (§13.3: at least every headMaxAge / 2, the module decides) is signed
      // before it is served, so a caller never waits a scheduler tick for a fresh head.
      try { await this.lock(async () => { if (this.status().appointed) await this.ensureHead(); }); }
      catch (error) { if (!(error instanceof ModuleError)) throw error; }
      const head = await this.headEnvelope();
      if (!head) throw new HttpError(404, 'No head');
      send(res, 200, head);
      return true;
    }
    if (section === 'authority') {
      if (method === 'GET') {
        const after = clampInt(url.searchParams.get('after'), 0, 0, Number.MAX_SAFE_INTEGER);
        const limit = clampInt(url.searchParams.get('limit'), 64, 1, 64);
        let page;
        // Under the lock: a reader never sees a committed entry before its file is stored.
        try { page = await this.lock(async () => this.wasm.call({ op: 'authority_page', state: this.state, now: this.clock(), after, limit })); }
        catch (error) { if (error instanceof ModuleError) throw new HttpError(503, 'The home cannot serve its history now'); throw error; }
        send(res, 200, { entries: page.entries.map((e) => JSON.parse(unb64(e))), receipts: [], more: page.more });
        return true;
      }
      const body = await readBody(req, this.limits.authorityBodyBytes);
      await this.lock(() => this.postAuthority(res, body));
      return true;
    }
    if (section === 'pending') {
      if (method === 'POST') {
        const body = await readBody(req, this.limits.pendingBodyBytes);
        await this.lock(() => this.postPending(res, body));
        return true;
      }
      if (rest === undefined || rest === null) {
        const after = clampInt(url.searchParams.get('after'), 0, 0, Number.MAX_SAFE_INTEGER);
        const limit = clampInt(url.searchParams.get('limit'), 64, 1, 64);
        let page;
        try { page = await this.lock(async () => this.wasm.call({ op: 'pending_page', state: this.state, now: this.clock(), after, limit })); }
        catch (error) { if (error instanceof ModuleError) throw new HttpError(503, 'The home cannot list its pending objects now'); throw error; }
        send(res, 200, {
          objects: page.objects.map((o) => ({ seq: o.seq, digest: o.digest, kind: o.kind, envelope: JSON.parse(unb64(o.envelope)) })),
          more: page.more,
        });
        return true;
      }
      const r = this.wasm.call({ op: 'pending_object', state: this.state, now: this.clock(), digest: rest });
      if (!r.found) throw new HttpError(404, 'Not found');
      send(res, 200, { envelope: JSON.parse(unb64(r.envelope)), receipts: r.receipts.map((x) => JSON.parse(unb64(x))) });
      return true;
    }
    if (section === 'records') {
      if (!writing) return false; // a read the module allowed: the relay serves the file
      if (url.search) throw new HttpError(400, 'Record URLs take no query');
      if (rest.startsWith('heads/')) { await this.putHead(req, res, rest); return true; }
      try { await this.putRecord(req, res, rest, body); } finally { if (key) await this.complete(key, 'completed'); }
      return true;
    }
    throw new HttpError(404, 'Not found');
  }

  /** A head forwarded by another current home (§13.1). Anyone may send one: the module checks
   * it, and says which head to serve for that home. */
  async putHead(req, res, recordPath) {
    const { readBody } = this.deps;
    const body = await readBody(req, 8192);
    await this.lock(async () => {
      const r = this.wasm.call({ op: 'admit_one', state: this.state, now: this.clock(), bytes: b64(body), path: recordPath });
      await this.commit(r.state);
      await this.materialize(r.store);
      if (r.outcome !== 'ok') { await this.answerOutcome(res, r); return; }
      res.writeHead(200, { 'content-length': 0 });
      res.end();
    });
  }

  async putRecord(req, res, recordPath, body) {
    const { HttpError, send } = this.deps;
    await this.lock(async () => {
      const check = this.wasm.call({ op: 'check_record', state: this.state, now: this.clock(), path: recordPath, bytes: b64(body) });
      if (!check.allowed) { send(res, 422, { result: check.code }); return; }
      const conditional = req.headers['if-none-match'];
      let status;
      if (conditional === '*') status = await this.slot.putImmutable(recordPath, body);
      else if (conditional !== undefined) throw new HttpError(400, 'Only If-None-Match: * is supported');
      else if (recordPath.startsWith('state/')) {
        const expected = req.headers['if-match'];
        if (!expected || !/^"[0-9a-f]{64}"$/.test(expected)) throw new HttpError(428, 'Live replacement requires If-Match');
        status = await this.slot.replaceRequest(recordPath, body, expected);
      } else throw new HttpError(428, 'Immutable records require If-None-Match: *');
      res.writeHead(status, { etag: `"${sha(body)}"`, 'content-length': 0 });
      res.end();
    });
  }

  async answerOutcome(res, r) {
    const { send } = this.deps;
    if (r.outcome === 'conflict') return send(res, 409, (await this.headEnvelope()) ?? null);
    if (r.outcome === 'primary') return send(res, 421, { endpoints: r.endpoints });
    return send(res, 422, { result: r.result });
  }

  async postAuthority(res, body) {
    const { send } = this.deps;
    const r = this.wasm.call({ op: 'post_authority', state: this.state, now: this.clock(), body: b64(body) });
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
    if (r.outcome !== 'ok') return send(res, 422, r.results);
    return send(res, 200, { receipts });
  }

  // -------------------------------------------------------------------------------------------
  // The scheduler: recording entries when due (§8.7), heads (§13.3), and forwarding to the
  // account's other homes (§13.1). Driven by the relay's clock; the module decides, this runs it.

  async tick() {
    if (this.ticking) return; // one scheduler pass at a time
    this.ticking = true;
    try { await this.tickOnce(); } finally { this.ticking = false; }
  }

  /** Test builds only (`--test-clock` with COLOPHON_RELAY_TRACE=1): a synchronous marker on
   * stderr, so a test that kills the process can tell where it was. */
  trace(what) { if (this.tracing) writeSync(2, `trace ${what}\n`); }

  async tickOnce() {
    await this.lock(async () => {
      const now = this.clock();
      // record_due is a pure function of (state, now): an unchanged pair would give the same
      // answer, so it is not asked again (it verifies the whole history each time).
      if (this.lastDue && this.lastDue.state === this.state && this.lastDue.now === now) { await this.ensureHead(); return; }
      if (!this.status().appointed) return;
      this.trace('record_due start');
      const r = this.wasm.call({ op: 'record_due', state: this.state, now });
      const said = r.result === 'ok' && !r.note ? '' : `recording entries for slot ${this.slot.name}: ${r.result} ${r.note ?? ''}`;
      this.note('record', said);
      await this.commit(r.state);
      await this.materialize(r.store);
      await this.signReceipts(r.sign);
      this.trace('record_due end');
      this.lastDue = { state: this.state, now };
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
      const row = (this.forward.peers[peer.id] ??= { after: 0, retry: [], head: '' });
      row.retry ??= [];
      try { await this.forwardTo(base, row, peer.id); this.note(`forward ${peer.id}`, ''); } catch (error) {
        this.note(`forward ${peer.id}`, `forwarding to home ${peer.id} failed (it will be retried): ${error.message}`);
      }
    }
  }

  /** Offer one pending object to a peer. Returns whether it was delivered (the module reads the
   * peer's answer); receipts the peer returns are admitted like any forwarded receipt. */
  async offer(base, object, peerId) {
    const r = await fetch(`${base}/pending`, { signal: AbortSignal.timeout(5000), method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ objects: [object] }) });
    const body = Buffer.from(await r.arrayBuffer());
    const a = this.wasm.call({ op: 'peer_answer', status: r.status, body: b64(body) });
    if (a.receipts?.length) {
      await this.lock(async () => {
        const back = this.wasm.call({ op: 'post_pending', state: this.state, now: this.clock(), body: b64(Buffer.from(JSON.stringify({ objects: a.receipts.slice(0, 16) }))) });
        await this.commit(back.state);
        await this.materialize(back.store);
      });
    }
    if (!a.delivered) this.note(`offer ${peerId}`, `home ${peerId} did not take a forwarded object yet (${a.why}); it will be offered again`);
    return a.delivered;
  }

  /** The object this home still lists at exactly `seq`, or null. */
  async listed(seq) {
    const page = await this.lock(async () => this.wasm.call({ op: 'pending_page', state: this.state, now: this.clock(), after: seq - 1, limit: 1 }));
    const o = page.objects[0];
    return o && o.seq === seq ? JSON.parse(unb64(o.envelope)) : null;
  }

  /** Forward to one peer (§13.1: a home MUST forward). The cursor moves past an object once it
   * was offered; an object the peer did not take (not delivered, by the module's reading of the
   * answer) is kept in `retry` and offered again every pass while this home still lists it. */
  async forwardTo(base, row, peerId) {
    const save = () => this.writeJson('forward.json', this.forward);
    const retry = [];
    for (const seq of row.retry) {
      const object = await this.listed(seq);
      if (!object) continue; // recorded or expired: no longer listed, nothing left to forward
      if (!await this.offer(base, object, peerId)) retry.push(seq);
    }
    row.retry = retry;
    await save();
    for (;;) {
      const page = await this.lock(async () => this.wasm.call({ op: 'pending_page', state: this.state, now: this.clock(), after: row.after, limit: 16 }));
      if (page.objects.length === 0) break;
      for (const o of page.objects) {
        if (!await this.offer(base, JSON.parse(unb64(o.envelope)), peerId)) row.retry.push(o.seq);
        row.after = o.seq;
        await save();
      }
      if (!page.more) break;
    }
    const head = await this.headEnvelope();
    if (head) {
      const text = JSON.stringify(head);
      if (sha(text) !== row.head) {
        const r = await fetch(`${base}/records/heads/${this.key.memberId}.json`, { signal: AbortSignal.timeout(5000), method: 'PUT', headers: { 'content-type': 'application/json' }, body: text });
        if (r.status === 200) { row.head = sha(text); await save(); this.note(`head ${peerId}`, ''); }
        else this.note(`head ${peerId}`, `home ${peerId} refused this home's head: ${r.status} ${(await r.text()).slice(0, 200)}`);
      }
    }
  }
}
