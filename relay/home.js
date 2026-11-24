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
import { createHash, randomBytes } from 'node:crypto';
import { constants as fsc, promises as fsp, writeSync } from 'node:fs';
import path from 'node:path';
import { HomeStream } from './stream.js';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const unb64 = (text) => Buffer.from(text, 'base64');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

function colophonCall(req) {
  const match = /^Colophon ([A-Za-z0-9_-]+)$/.exec(req.headers.authorization ?? '');
  return match ? b64(Buffer.from(match[1], 'base64url')) : null;
}

/** The module's replay retention rule, `retained(at, now)`: kept while `now - at <= retentionMs`
 * (inclusive; a row from a clock that later stepped back is kept). `at` is read as the module
 * reads it from JSON: anything but an integer in the 64-bit signed range is never retained. */
export function retainedAt(at, now, retentionMs) {
  return Number.isInteger(at) && at >= -(2 ** 63) && at < 2 ** 63 && now - at <= retentionMs;
}

const ROUTE_BODY_BYTES = 4096;
const NOTICE_COMMIT = 'notice-commit.json';

// Forwarding (§13.1), per peer: each request's own time limit, a pass's wall-time budget, how many
// newly listed objects and how many backlog objects one pass offers, and how soon the same
// entries are offered again while the peer's head lags. PASS_MS bounds all network request
// wait times in a pass; local lock/state commits always finish atomically to avoid torn state.
const PEER_TIMEOUT_MS = 5000;
const PASS_MS = 15000;
const NEW_PER_PASS = 64;
const RETRY_PER_PASS = 16;
const ENTRIES_RESEND_MS = 2000;

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
   * the URL to reach it), `deps` (the relay's HttpError, send, readBody, clampInt), `limits`,
   * `stream` (HomeStream options) and `scheduled` (whether the relay's scheduler ticks).
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
    this.routes = new Map();
    this.noticeSeq = 0;
    this.lastHead = null;
    this.stream = new HomeStream(this, o.stream ?? {});
  }

  file(name) { return path.join(this.slot.root, name); }

  /** Say something once per distinct message per topic, not once per tick. */
  note(topic, message) {
    if (this.said.get(topic) === message) return;
    this.said.set(topic, message);
    // Each line names the home that says it (several homes may share one log).
    if (message) console.error(`[home ${this.key.memberId.slice(0, 8)} @${this.clock()}] ${message}`);
  }

  async open() {
    // Validate before Slot.open: even its log repair and tmp cleanup must not touch a slot
    // whose checkpoint is lost or damaged. Retained files are never a fresh home.
    let fresh = false;
    let files;
    try {
      let stat;
      try { stat = await fsp.lstat(this.file('home-state.json')); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (stat) {
        if (!stat.isFile()) throw new Error('not a regular file');
        this.state = JSON.parse(await fsp.readFile(this.file('home-state.json'), 'utf8'));
      } else {
        if (await this.hasPriorStorage()) throw new Error('missing while the slot retains storage');
        this.state = this.wasm.call({ op: 'init', home: this.key.memberId, account: this.account }).state;
        fresh = true;
      }
      const st = this.status();
      if (st.error) throw new Error(st.error);
      if (st.home !== this.key.memberId) throw new Error('state belongs to another home key');
      if (st.account !== this.account) throw new Error(`state belongs to account ${st.account}, not ${this.account}`);
      this.appointed = st.appointed;
      files = this.wasm.call({ op: 'objects', state: this.state, now: this.clock() }).files;
    } catch (error) {
      throw new Error(`Home slot ${this.slot.name}: cannot open ${this.file('home-state.json')}: ${error.message}; restore the state file from a backup`);
    }
    await this.slot.open();
    if (fresh) await this.writeJson('home-state.json', this.state);
    await this.loadRoutes();
    this.noticeCommit = await this.readOptionalJson(NOTICE_COMMIT);
    await this.flushNotices();
    this.noticeSeq = await this.lastNoticeSeq();
    // Reconcile storage with the state before serving: a crash between a commit and its files
    // (a missing entry, a head file older than the committed head) heals here, not later.
    await this.materialize(files);
    this.lastHead = await this.ownHeadMark();
    // Every change-log entry is pushed to the stream with the cursor `/changes` gives it.
    this.slot.onEntry = (index) => this.stream.change(index);
    await this.openReplay();
    this.forward = await this.readJson('forward.json', { peers: {} });
    // Serving intervals (§13.1). The module decides from the last lease recorded (the home may
    // have served until its end, never after) whether the interval it had open closes. Then a
    // new lease is written durably before the reopened interval is committed and before the
    // relay listens: a kill at any later instant leaves a lease that covers all real uptime.
    const alive = await this.readJson('alive.json', null);
    const until = alive && typeof alive.until === 'number' ? alive.until : null;
    const now = this.clock();
    const r = this.wasm.call({ op: 'resume', state: this.state, now, alive: until });
    await this.renewLease(now);
    if (r.changed) await this.commit(r.state);
  }

  /** A missing checkpoint is safe only when nothing that could outlive it remains. Check the
   * raw directory and log, not Slot's reconstructed index (which omits deleted records). */
  async hasPriorStorage() {
    const stat = async (name) => {
      try { return await fsp.lstat(this.file(name)); }
      catch (error) { if (error.code !== 'ENOENT') throw error; return null; }
    };
    for (const name of ['replay.log', 'alive.json', 'forward.json', 'routes.json', 'notices.jsonl', NOTICE_COMMIT]) if (await stat(name)) return true;
    const log = await stat('log.jsonl');
    if (log && (!log.isFile() || log.size > 0)) return true;
    const records = await stat('records');
    if (!records) return false;
    if (!records.isDirectory()) return true;
    const holdsFile = async (dir) => {
      for (const entry of await fsp.readdir(dir, { withFileTypes: true })) {
        if (!entry.isDirectory() || await holdsFile(path.join(dir, entry.name))) return true;
      }
      return false;
    };
    return holdsFile(this.file('records'));
  }

  /** Record that this home may serve until the module's lease end, durably, before serving
   * past the previous one. */
  async renewLease(now) {
    const l = this.wasm.call({ op: 'lease', now });
    await this.writeJson('alive.json', { until: l.until });
    this.lease = l;
  }

  /** Before any work at a clock reading: renew the lease when the module says it is due. */
  async keepLease() {
    const now = this.clock();
    if (this.lease && now < this.lease.renewAt) return;
    await (this.leaseLock ??= chain())(async () => {
      if (!this.lease || this.clock() >= this.lease.renewAt) await this.renewLease(this.clock());
    });
  }

  async readJson(name, fallback) {
    try { return JSON.parse(await fsp.readFile(this.file(name), 'utf8')); } catch { return fallback; }
  }
  async readOptionalJson(name) {
    let handle;
    try { handle = await fsp.open(this.file(name), fsc.O_RDONLY | fsc.O_NOFOLLOW); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    try {
      if (!(await handle.stat()).isFile()) throw new Error(`${name} must be a regular file`);
      return JSON.parse(await handle.readFile('utf8'));
    } finally { await handle.close(); }
  }

  async writeJson(name, value) {
    const staged = path.join(this.slot.root, 'tmp', `${name}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`);
    const handle = await fsp.open(staged, 'wx', 0o600);
    try { await handle.writeFile(JSON.stringify(value)); await handle.sync(); } finally { await handle.close(); }
    await fsp.rename(staged, this.file(name));
    // The rename must be durable too: in particular, a refused unknown-format entry's
    // stop has no stored entry to replay if a crash were to lose the checkpoint update.
    const directory = await fsp.open(this.slot.root, 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  }

  async commit(state, notices = []) {
    await this.flushNotices();
    if (!state || state === this.state) return;
    if (notices.length) {
      const file = this.file('notices.jsonl');
      const stat = await fsp.lstat(file).catch((error) => { if (error.code !== 'ENOENT') throw error; });
      if (stat && !stat.isFile()) throw new Error('notices.jsonl must be a regular file');
      const offset = stat?.size ?? 0;
      // One line per notice, numbered (increasing, never reused; a failed commit may skip a
      // number), naming the routes registered when it was queued. A sender keeps its own
      // cursor per route; the stream's `notice` frames carry the same number.
      const routes = [...this.routes.keys()];
      const lines = notices.map((notice) => {
        notice.seq = ++this.noticeSeq;
        return JSON.stringify({ seq: notice.seq, account: this.account, ...notice, routes }) + '\n';
      }).join('');
      // A restart finishes the append only if the corresponding checkpoint committed.
      // The offset makes replay safe after a torn or already completed append.
      const journal = { state: sha(state), offset, lines };
      await this.writeJson(NOTICE_COMMIT, journal);
      this.noticeCommit = journal;
    }
    await this.writeJson('home-state.json', state);
    this.state = state;
    await this.flushNotices();
    // Every authority commit re-checks every open stream (§S9: only current, entitled members)
    // and the owners of notice routes.
    this.stream.revalidate();
    await this.pruneRoutes();
  }

  /** The number of the last notice queued (0 for none). */
  async lastNoticeSeq() {
    let text;
    try { text = await fsp.readFile(this.file('notices.jsonl'), 'utf8'); } catch (error) { if (error.code === 'ENOENT') return 0; throw error; }
    const lines = text.split('\n').filter(Boolean);
    if (!lines.length) return 0;
    try {
      const seq = JSON.parse(lines[lines.length - 1]).seq;
      if (Number.isSafeInteger(seq) && seq > 0) return seq;
    } catch { /* an older line without a number */ }
    return lines.length;
  }

  /** `{seq, digest}` of the head this home last stored, for the stream's hello. */
  async ownHeadMark() {
    const head = await this.headEnvelope().catch(() => null);
    if (!head) return null;
    try {
      const { seq, digest } = JSON.parse(unb64(head.body)).authority;
      return { seq, digest };
    } catch { return null; }
  }

  /** Routes and the slot's secret route key (route IDs are keyed by it, so a listed ID reveals
   * no address). `routes.json` is `{"key","routes":[[id, route]…]}`. A file of the unshipped W2
   * layout (a bare list, IDs an unkeyed digest of the address) is re-keyed on load. */
  async loadRoutes() {
    const held = await this.readOptionalJson('routes.json');
    if (held && !Array.isArray(held)) {
      if (typeof held.key !== 'string' || !/^[0-9a-f]{64}$/.test(held.key) || !Array.isArray(held.routes)) {
        throw new Error('routes.json is damaged');
      }
      this.routeKey = held.key;
      this.routes = new Map(held.routes);
      return;
    }
    this.routeKey = randomBytes(32).toString('hex');
    this.routes = new Map();
    if (!held) return;
    for (const [, r] of held) {
      const { id } = this.wasm.call({ op: 'route_id', key: this.routeKey, principal: r.by, kind: r.kind, address: r.address });
      this.routes.set(id, r);
    }
    await this.saveRoutes(this.routes);
  }

  async saveRoutes(routes) {
    await this.writeJson('routes.json', { key: this.routeKey, routes: [...routes] });
  }

  /** Drop the routes of principals that are no longer principals of the account (the module
   * decides), so a revoked device's routes neither linger nor hold the slot's capacity. */
  async pruneRoutes() {
    if (!this.routes.size) return;
    const owners = [...new Set([...this.routes.values()].map((r) => r.by))];
    let current;
    try { ({ current } = this.wasm.call({ op: 'principals_current', state: this.state, now: this.clock(), principals: owners })); }
    catch (error) { this.note('routes', `route owners could not be checked: ${error.message}`); return; }
    const gone = new Set(owners.filter((_, i) => !current[i]));
    if (!gone.size) return;
    const routes = new Map([...this.routes].filter(([, r]) => !gone.has(r.by)));
    await this.saveRoutes(routes);
    const dropped = [...this.routes.keys()].filter((id) => !routes.has(id));
    this.routes = routes;
    for (const id of dropped) this.stream.route(id, 'delete');
  }

  async flushNotices() {
    if (!this.noticeCommit) return;
    const { state, offset, lines } = this.noticeCommit;
    if (state === sha(this.state)) {
      const handle = await fsp.open(this.file('notices.jsonl'), fsc.O_WRONLY | fsc.O_APPEND | fsc.O_CREAT | fsc.O_NOFOLLOW, 0o600);
      try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.size < offset) throw new Error('Invalid notices.jsonl at the committed offset');
        await handle.truncate(offset);
        await handle.writeFile(lines);
        await handle.sync();
      } finally { await handle.close(); }
      const directory = await fsp.open(this.slot.root, 'r');
      try { await directory.sync(); } finally { await directory.close(); }
    }
    await fsp.unlink(this.file(NOTICE_COMMIT));
    this.noticeCommit = null;
  }

  publishNotices(notices) {
    for (const notice of notices ?? []) this.stream.notice(notice);
  }

  /** A WebSocket upgrade of `GET {base}/stream?ticket=…[&after=<cursor>]` (0.6 draft). */
  async upgrade(req, url, connect) {
    // The ticket is burnt first: no later refusal (a body, the rate, a bad parameter) leaves a
    // presented ticket usable.
    const taken = this.stream.take(url);
    const { HttpError } = this.deps;
    if (req.headers['transfer-encoding'] || (req.headers['content-length'] ?? '0') !== '0') {
      throw new HttpError(400, 'A stream request takes no body');
    }
    await this.rateGate(req);
    await this.stream.connect(url, taken, connect);
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
      if (p === `heads/${this.key.memberId}.json`) {
        const signed = JSON.parse(body);
        const { seq, digest } = JSON.parse(unb64(signed.body)).authority;
        this.lastHead = { seq, digest };
        this.stream.head(seq, digest);
      }
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

  /** A fresh head when the module says one is due (§13.3): guard, sign, verify, store. Returns
   * `signed`, `fresh` (nothing was due), or `due` (a head is due and the module could not
   * produce one now: the guard refused, the clock has not passed the latest head's `issued`, or
   * the history stops at a fork). */
  async ensureHead(now = this.clock()) {
    const r = this.wasm.call({ op: 'head_request', state: this.state, now });
    await this.commit(r.state);
    this.note('head', r.sign || !r.due ? '' : `home ${this.key.memberId}: a head is due and cannot be signed now: ${r.why}`);
    // When no head is due, the module says from when one could be over this same state.
    this.headWake = !r.sign && !r.due && Number.isFinite(r.wakeAt) && r.wakeAt > now ? r.wakeAt : null;
    if (!r.sign) return r.due ? 'due' : 'fresh';
    const signature = b64(await this.key.sign(unb64(r.sign.body)));
    const f = this.wasm.call({ op: 'finish_head', state: this.state, now, seq: r.sign.seq, digest: r.sign.digest, issued: r.sign.issued, signature });
    await this.commit(f.state);
    await this.materialize(f.store);
    return 'signed';
  }

  /** Bring the home's history up to its clock, then its head (under the lock): the determined
   * recording entries due now are appended first (`record_due`), and only then is a due head
   * signed. A head signed at clock T is therefore over everything due at T: never a head at T
   * over the history before an entry that is due at T, which would leave the head over that entry
   * unsignable until the clock passes T (heads have strictly increasing `issued`, §13.3). */
  async settle() {
    const now = this.clock();
    // Quiet: the module said nothing can come due over this state before `until` (no recording
    // entry, no head), so nothing is asked of it. A changed state or a clock that went back
    // asks again; so does reaching `until`.
    if (this.isQuiet(now)) return 'fresh';
    this.quiet = null;
    const asked = this.state;
    // One clock reading for the whole pass: the quiet it may leave certifies exactly the reading
    // every module call of the pass was asked at.
    const st = this.status(now);
    if (!st.appointed) {
      // An unappointed slot's answers change only with its state.
      this.quiet = { state: asked, now, until: Infinity, status: st };
      return 'fresh';
    }
    let recordWake = null;
    // record_due is a pure function of (state, now): an unchanged pair would give the same
    // answer, so it is not asked again (it verifies the whole history each time).
    if (!(this.lastDue && this.lastDue.state === this.state && this.lastDue.now === now)) {
      this.trace('record_due start');
      const r = this.wasm.call({ op: 'record_due', state: this.state, now });
      const said = r.result === 'ok' && !r.note ? '' : `recording entries for slot ${this.slot.name}: ${r.result} ${r.note ?? ''}`;
      this.note('record', said);
      await this.commit(r.state, r.notify);
      await this.materialize(r.store);
      this.publishNotices(r.notify);
      await this.signReceipts(r.sign);
      this.trace('record_due end');
      // When what is due now could not be determined, no head is produced now (it stays due:
      // a GET is answered 503, a peer is sent none) and the next pass asks again.
      if (r.settled === false) return 'due';
      this.lastDue = { state: this.state, now };
      if (Number.isFinite(r.wakeAt) && r.wakeAt > now && this.state === asked) recordWake = r.wakeAt;
    }
    const outcome = await this.ensureHead(now);
    // Quiet only when this pass changed nothing and both answers gave a time: an entry recorded,
    // a receipt or a head signed may make something else due at once (a `final` over the new
    // head), so the next pass asks again.
    if (outcome === 'fresh' && this.state === asked && recordWake !== null && this.headWake !== null) {
      this.quiet = { state: asked, now, until: Math.min(recordWake, this.headWake), status: st };
    }
    return outcome;
  }

  /** Whether the last settle's quiet still holds at clock `now`: same state, and `now` in
   * [the reading it was given at, the earliest time anything can come due). */
  isQuiet(now = this.clock()) {
    const q = this.quiet;
    return Boolean(q && q.state === this.state && now >= q.now && now < q.until);
  }

  /** Serve this home's own head (`GET {base}/head`, `records/heads/<this home>.json`). §13.3:
   * the due head is produced and stored first; a due head that cannot be produced fails the
   * request (503, retryable) and the older head is never served. */
  async serveOwnHead(res) {
    const { HttpError, send } = this.deps;
    const outcome = await this.lock(() => this.settleForRead());
    if (outcome === 'due') throw new HttpError(503, 'The head is due and cannot be signed yet', { 'retry-after': '1' }, { result: 'unavailable' });
    const head = await this.headEnvelope();
    if (!head) throw new HttpError(404, 'No head');
    send(res, 200, head);
  }

  /** The stored head, only when no other head is due (§13.3); null otherwise. Under the lock. */
  async headIfFresh() {
    const outcome = await this.settleForRead();
    return outcome === 'due' ? null : this.headEnvelope();
  }

  async settleForRead() {
    try { return await this.settle(); }
    catch (error) { if (!(error instanceof ModuleError)) throw error; return 'due'; }
  }

  async headEnvelope() {
    const p = `heads/${this.key.memberId}.json`;
    if (!this.slot.current.has(p)) return null;
    return JSON.parse((await this.slot.readFile(p)).toString('utf8'));
  }

  status(now = this.clock()) { return this.wasm.call({ op: 'status', state: this.state, now }); }

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

  async access(req, section, rest, effect, body, call = colophonCall(req)) {
    const { HttpError } = this.deps;
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
      // One clock reading, after the call's key and rows are looked up, for the count and the call.
      const now = this.clock();
      const share = this.signerShare(signerRows, now);
      const r = this.wasm.call({
        op: 'access', state: this.state, now, method: req.method, section, rest,
        call, existing, ...(share ? { signerLive: share.live, signerOldest: share.oldest } : { signerRows }),
        replayRows: this.limits.replayRows, base: this.base,
        path: this.relativePath(req),
        ...(section === 'records' && rest === 'batch'
          ? { batchBody: b64(body) }
          : { bodySha256: sha(body ?? Buffer.alloc(0)) }),
      });
      // With counts, the module answers `drop` where it would have listed the expired rows.
      if (r.drop) this.dropRows(share ? [...r.drop, ...share.expired] : r.drop);
      if (r.allowed) {
        if (r.reserve) await this.reserve(r.reserve, effect);
        return r;
      }
      switch (r.status) {
        case 401: throw new HttpError(401, 'A Colophon call is required', { 'www-authenticate': 'Colophon' });
        case 403: throw new HttpError(403, 'Forbidden', {}, { result: r.result });
        case 503: throw new HttpError(503, 'The home is unavailable', {}, { result: r.result });
        case 429: throw new HttpError(429, 'Too many requests', { 'retry-after': String(r.retryAfter ?? 60) }, { result: r.result });
        case 405: throw new HttpError(405, 'Method not allowed', { allow: r.allow });
        case 400: throw new HttpError(400, r.error ?? 'Bad request');
        default: throw new HttpError(r.status ?? 404, 'Not found');
      }
    });
  }

  /** A principal's replay rows (`{key, at}`) as the module counts them at `now` (§12.4): how many
   * are retained, the oldest `at` among those, and the keys of the rest. Null when the rows must
   * be sent as they are: the loaded module does not say it takes counts (`limits.replayCounts`),
   * or the clock or a row's time is an integer JavaScript cannot subtract exactly. */
  signerShare(rows, now) {
    this.replayLimits ??= this.wasm.call({ op: 'limits' });
    const { retentionMs, replayCounts } = this.replayLimits;
    if (replayCounts !== true || !Number.isSafeInteger(now)) return null;
    let live = 0; let oldest = null; const expired = [];
    for (const { key, at } of rows) {
      if (Number.isInteger(at) && !Number.isSafeInteger(at)) return null;
      if (retainedAt(at, now, retentionMs)) { live += 1; if (oldest === null || at < oldest) oldest = at; } else expired.push(key);
    }
    return { live, oldest, expired };
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

  async rateGate(req, section, rest) {
    const { HttpError } = this.deps;
    await this.keepLease();
    if (section === 'records' && rest === 'batch' && !this.appointed) {
      req.resume();
      throw new HttpError(404, 'Not found');
    }
    if (!this.rate.take(this.deps.clientAddress(req), this.clock())) {
      throw new HttpError(429, 'Too many requests', { 'retry-after': '60' });
    }
  }

  /** `work` is the relay's record of this request: an allowed read of a record gets its `kind`. */
  async handle(req, res, url, section, rest, work) {
    const { HttpError, send, readBody, clampInt } = this.deps;
    await this.rateGate(req, section, rest);
    if (section === 'routes') {
      if (this.relativePath(req) !== (rest === undefined ? '/routes' : `/routes/${rest}`)) {
        throw new HttpError(400, 'Invalid notice route URL');
      }
      await this.handleRoutes(req, res, rest);
      return true;
    }
    if (section === 'records' && rest === 'batch') {
      const call = colophonCall(req);
      if (req.method === 'POST' && !call) {
        req.resume();
        throw new HttpError(401, 'A Colophon call is required', { 'www-authenticate': 'Colophon' });
      }
      const body = await this.deps.readBatchBody(req, url);
      const validation = this.wasm.call({ op: 'validate_batch', batchBody: b64(body) });
      if (!validation.allowed) throw new HttpError(validation.status, validation.error ?? 'Record exceeds the relay limit');
      await this.lock(async () => {
        const { records } = await this.access(req, section, rest, null, body, call);
        const ownHead = records.find((r) => r.status === 200 && r.path === `heads/${this.key.memberId}.json`);
        if (ownHead && await this.settleForRead() === 'due') ownHead.status = 503;
        await this.deps.serveBatch(res, this.slot, records);
      });
      return true;
    }
    if (section === 'stream') {
      if (rest === undefined) throw new HttpError(426, 'WebSocket upgrade required', { upgrade: 'websocket' });
      if (rest !== 'ticket' || this.relativePath(req) !== '/stream/ticket') throw new HttpError(404, 'Not found');
      if (req.method !== 'POST') throw new HttpError(405, 'Method not allowed', { allow: 'POST' });
      if (req.headers['transfer-encoding'] || (req.headers['content-length'] ?? '0') !== '0') {
        req.resume();
        throw new HttpError(400, 'A ticket request takes no body');
      }
      // Mint under the lock: the standing the module judged is the committed state's.
      await this.lock(async () => {
        const allowed = await this.access(req, section, rest, null, Buffer.alloc(0));
        try {
          if (this.slot.closing) throw new HttpError(503, 'Home unavailable');
          send(res, 200, this.stream.mint(allowed), { 'cache-control': 'no-store' });
        } finally { await this.complete(allowed.reserve.key, 'completed'); }
      });
      return true;
    }
    const method = req.method;
    const writing = section === 'records' && method === 'PUT';
    const effectPath = writing ? rest : (section === 'predecessor' && method === 'PUT' ? `predecessor/${rest}` : null);
    const effect = effectPath ? { path: effectPath, prior: this.slot.current.get(effectPath)?.sha256 ?? null } : null;
    // A write's body is read (bounded) before its call is judged: the call is bound to its digest.
    const recordWrite = writing && typeof rest === 'string' && !rest.startsWith('heads/');
    const predecessorPut = section === 'predecessor' && method === 'PUT';
    const body = recordWrite || predecessorPut
      ? await readBody(req, rest?.startsWith('blobs/') ? this.limits.blobBytes : this.limits.recordBytes)
      : null;
    const allowed = await this.access(req, section ?? '', rest ?? null, effect, body);
    await this.deps.reach?.(`access ${section ?? ''}`); // a test hook (traced builds only)
    const key = allowed.reserve?.key;
    if (!section || section === 'changes') return false;
    if (section === 'head') { await this.serveOwnHead(res); return true; }
    if (section === 'authority') {
      if (method === 'GET') {
        const after = clampInt(url.searchParams.get('after'), 0, 0, Number.MAX_SAFE_INTEGER);
        const limit = clampInt(url.searchParams.get('limit'), 64, 1, 64);
        let page;
        // Under the lock: a reader never sees a committed entry before its file is stored.
        try { page = await this.lock(async () => this.wasm.call({ op: 'authority_page', state: this.state, now: this.clock(), after, limit })); }
        catch (error) { if (error instanceof ModuleError) throw new HttpError(503, 'The home cannot serve its history now'); throw error; }
        send(res, 200, { entries: page.entries.map((e) => JSON.parse(unb64(e))), receipts: (page.receipts ?? []).map((r) => JSON.parse(unb64(r))), more: page.more });
        return true;
      }
      const body = await readBody(req, this.limits.authorityBodyBytes);
      // A test marker (traced builds only): the upload holds the slot's lock. The provisioning
      // door holds the operator slot's lock from a grant's verification to its durable write,
      // so an upload (a revocation) to that slot is ordered before or after it, never between.
      // A test may pause the upload here, holding the lock.
      await this.lock(async () => {
        if (this.deps.reach) await this.deps.reach('authority locked'); else this.trace('authority locked');
        return this.postAuthority(res, body);
      });
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
      // Under the lock, like every history read: never an object before its file is stored.
      const r = await this.lock(async () => this.wasm.call({ op: 'pending_object', state: this.state, now: this.clock(), digest: rest }));
      if (!r.found) throw new HttpError(404, 'Not found');
      send(res, 200, { envelope: JSON.parse(unb64(r.envelope)), receipts: r.receipts.map((x) => JSON.parse(unb64(x))) });
      return true;
    }
    if (section === 'predecessor') {
      const file = `predecessor/${rest}`;
      if (method === 'PUT') {
        await this.lock(async () => {
          const r = this.wasm.call({ op: 'put_predecessor', state: this.state, now: this.clock(), path: rest, bytes: b64(body) });
          await this.commit(r.state);
          await this.materialize(r.store);
          if (r.outcome !== 'ok') {
            if (r.outcome === 'conflict') { send(res, 412, { result: 'conflict' }); return; }
            await this.answerOutcome(res, r);
            return;
          }
          res.writeHead(r.created ? 201 : 200, { etag: `"${sha(body)}"`, 'content-length': 0 });
          res.end();
        });
        if (key) await this.complete(key, 'completed');
        return true;
      }
      const entry = this.slot.current.get(file);
      if (!entry) throw new HttpError(404, 'Not found');
      const bytes = await this.slot.readFile(file);
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.length, etag: `"${entry.sha256}"`, 'cache-control': 'no-store' });
      res.end(method === 'HEAD' ? undefined : bytes);
      return true;
    }
    if (section === 'records') {
      if (!writing && rest === `heads/${this.key.memberId}.json` && (method === 'GET' || method === 'HEAD')) { await this.serveOwnHead(res); return true; }
      if (!writing) { if (work) work.kind = allowed.kind; return false; } // a read the module allowed: the relay serves the file
      if (url.search) throw new HttpError(400, 'Record URLs take no query');
      if (rest.startsWith('heads/')) { await this.putHead(req, res, rest); return true; }
      try { await this.putRecord(req, res, rest, body); } finally { if (key) await this.complete(key, 'completed'); }
      return true;
    }
    throw new HttpError(404, 'Not found');
  }

  async handleRoutes(req, res, id) {
    const { HttpError, send, readBody, isJsonType } = this.deps;
    const posting = req.method === 'POST' && id === undefined;
    let body;
    if ((req.method === 'GET' || req.method === 'DELETE')
        && (req.headers['transfer-encoding'] || (req.headers['content-length'] ?? '0') !== '0')) {
      throw new HttpError(400, 'This request takes no body');
    }
    if (posting) {
      if (!isJsonType(req.headers['content-type'])) throw new HttpError(415, 'Content-Type must be application/json');
      body = await readBody(req, ROUTE_BODY_BYTES);
    }
    await this.lock(async () => {
      const allowed = await this.access(req, 'routes', id ?? null, null, body);
      const key = allowed.reserve.key;
      try {
        if (req.method === 'GET') {
          const routes = Array.from(this.routes, ([id, { kind, reaches, by }]) => ({ id, kind, reaches, by }));
          send(res, 200, { routes });
          return;
        }
        // The keyed ID, ownership, caps and the route's form are the module's.
        const principal = allowed.signer;
        const r = this.wasm.call({
          op: 'route_change', method: req.method, key: this.routeKey, principal,
          routes: Array.from(this.routes, ([id, { by }]) => ({ id, by })),
          ...(posting ? { body: b64(body) } : { id }),
        });
        if (!r.allowed) {
          if (r.status === 400) throw new HttpError(400, r.error ?? 'Invalid notice route');
          if (r.status === 404) throw new HttpError(404, 'Route not found');
          throw new HttpError(r.status, 'Refused', {}, { result: r.result });
        }
        const routes = new Map(this.routes);
        if (posting) routes.set(r.id, { ...r.route, by: principal });
        else routes.delete(r.id);
        await this.saveRoutes(routes);
        this.routes = routes;
        this.stream.route(r.id, posting ? 'put' : 'delete', posting ? routes.get(r.id) : null);
        if (posting) send(res, r.created ? 201 : 200, { id: r.id });
        else { res.writeHead(204); res.end(); }
      } finally { await this.complete(key, 'completed'); }
    });
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
    if (r.outcome === 'conflict') return send(res, 409, (await this.headIfFresh()) ?? null);
    if (r.outcome === 'primary') return send(res, 421, { endpoints: r.endpoints });
    return send(res, 422, { result: r.result });
  }

  async postAuthority(res, body) {
    const { send } = this.deps;
    const r = this.wasm.call({ op: 'post_authority', state: this.state, now: this.clock(), body: b64(body) });
    await this.commit(r.state, r.notify); // even a refusal changes state (§13.1)
    // The first successful appointment in a committed upload is permanent for this slot.
    if (r.appointed) this.appointed = true;
    await this.materialize(r.store);
    this.publishNotices(r.notify);
    const receipts = await this.signReceipts(r.sign);
    const head = r.appointed ? await this.settle() : 'fresh';
    if (r.outcome !== 'ok') return this.answerOutcome(res, r);
    // A due head that could not be produced yet is not answered with the older one (§13.3).
    return send(res, 200, { head: head === 'due' ? null : await this.headEnvelope(), receipts });
  }

  async postPending(res, body) {
    const { send } = this.deps;
    const r = this.wasm.call({ op: 'post_pending', state: this.state, now: this.clock(), body: b64(body) });
    await this.commit(r.state, r.notify);
    await this.materialize(r.store);
    this.publishNotices(r.notify);
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
      await this.keepLease();
      await this.settle();
    });
    // Calls to other homes happen outside the lock (two homes forwarding to each other would
    // otherwise wait on one another), and each peer has its own pass: the tick starts them and
    // does not wait, so one slow or silent peer delays neither this home's settling nor its
    // forwarding to any other peer.
    this.forwardAll();
  }

  /** Start a forwarding pass to every peer that has none running (§13.1). */
  async forwardAll() {
    // One start at a time: a tick that comes while the last start still waits for the lock adds
    // nothing to the lock's queue (a queue growing every tick would delay every request).
    if (this.startingPasses) return;
    this.startingPasses = true;
    let st;
    // While quiet, the status settle read for this same state is still the module's answer.
    try { st = await this.lock(async () => (this.isQuiet() ? this.quiet.status : this.status())); } catch (error) {
      this.note('forward', `forwarding could not start: ${error.message}`);
      return;
    } finally { this.startingPasses = false; }
    const resolve = typeof this.resolve === 'function' ? this.resolve() : this.resolve;
    this.passes ??= new Map();
    for (const peer of st.peers ?? []) {
      const endpoint = (peer.endpoints ?? [])[0];
      if (!endpoint || this.passes.has(peer.id)) continue; // its last pass is still running
      // The last pass to this peer found nothing to send (no new or backlogged object, no entry,
      // its head already taken) and the state has not changed since, nor can anything come
      // due before the quiet ends: another pass would send nothing and save the same rows.
      if (this.forwardIdle?.get(peer.id) === this.state && this.isQuiet()) continue;
      const base = (resolve?.[endpoint.replace(/\/$/, '')] ?? endpoint).replace(/\/$/, '');
      const row = (this.forward.peers[peer.id] ??= { after: 0, retry: [], head: '' });
      row.retry ??= [];
      const pass = this.forwardTo(base, row, peer.id)
        .then(() => this.note(`forward ${peer.id}`, ''))
        .catch((error) => this.note(`forward ${peer.id}`, `forwarding to home ${peer.id} failed (it will be retried): ${error.message}`))
        .finally(() => this.passes.delete(peer.id));
      this.passes.set(peer.id, pass);
    }
  }

  /** Persist the forwarding rows, one write at a time (passes to several peers run at once). */
  saveForward() {
    // A snapshot taken under the lock when the save is asked for, not the live rows at write time.
    const snapshot = this.lock(async () => JSON.parse(JSON.stringify(this.forward)));
    this.saving = (this.saving ?? Promise.resolve()).then(async () => this.writeJson('forward.json', await snapshot)).catch((error) => {
      this.note('forward.json', `the forwarding state could not be saved: ${error.message}`);
    });
    return this.saving;
  }

  /** Offer one listed object to a peer, with what the module sends with it (its receipts).
   * Returns whether it was delivered (the module reads the peer's answer); receipts the peer
   * returns are admitted like any forwarded receipt. */
  async offer(base, objects, peerId, deadline) {
    const timeout = Math.min(PEER_TIMEOUT_MS, deadline - Date.now());
    if (timeout <= 0) return false;
    const r = await fetch(`${base}/pending`, { signal: AbortSignal.timeout(timeout), method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ objects }) });
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

  /** An offer that counts a failed request as not delivered. */
  async tryOffer(base, objects, peerId, deadline) {
    try { return await this.offer(base, objects, peerId, deadline); } catch (error) {
      this.note(`offer ${peerId}`, `home ${peerId} could not be reached (${error.message}); the object will be offered again`);
      return false;
    }
  }

  /** What to forward for the object this home still lists at exactly `seq` (the module says:
   * the object and its receipts), or null when it lists nothing there. */
  async listed(seq) {
    const r = await this.lock(async () => this.wasm.call({ op: 'forward_objects', state: this.state, now: this.clock(), seq }));
    return r.objects.length ? r.objects.map((o) => JSON.parse(unb64(o))) : null;
  }

  /** One forwarding pass to one peer (§13.1: a home MUST forward), bounded in requests and
   * network wait time (local lock/state commits finish atomically), in this order: (1) objects
   * newly listed since the last pass, transitions and vetoes before receipts, so an in-window
   * transition or veto never waits behind a backlog; (2) this
   * home's entries the peer lacks and its head; (3) the backlog of objects the peer has not taken
   * (`retry`), the oldest first, a bounded number per pass, those still not taken going to the
   * back. Requests time out on their own, so a peer that never answers holds only its own pass. */
  async forwardTo(base, row, peerId) {
    const save = () => this.saveForward();
    const deadline = Date.now() + PASS_MS;
    (this.forwardIdle ??= new Map()).delete(peerId);
    let seen;
    // (1) New objects, at most a page per pass.
    const page = await this.lock(async () => {
      seen = this.state;
      return this.wasm.call({ op: 'pending_page', state: this.state, now: this.clock(), after: row.after, limit: NEW_PER_PASS });
    });
    const urgent = (o) => (o.kind === 'transition' || o.kind === 'veto' ? 0 : 1);
    const fresh = [...page.objects].sort((x, y) => urgent(x) - urgent(y) || x.seq - y.seq);
    // The cursor moves past the page only together with the page's misses, so no saved state
    // has the one without the other.
    const missed = [];
    for (const o of fresh) {
      const objects = Date.now() < deadline ? await this.listed(o.seq) : null;
      if (Date.now() >= deadline) { missed.push(o.seq); continue; }
      if (objects && !await this.tryOffer(base, objects, peerId, deadline)) missed.push(o.seq);
    }
    if (page.objects.length) { row.after = page.objects[page.objects.length - 1].seq; row.retry.push(...missed); }
    await save();
    // (2) Entries and the head.
    const sent = Date.now() < deadline ? await this.forwardEntries(base, row, peerId, deadline) : true;
    // (3) The backlog.
    const todo = [...new Set(row.retry)];
    const now = todo.slice(0, RETRY_PER_PASS);
    const rest = todo.slice(RETRY_PER_PASS);
    const again = [];
    for (const seq of now) {
      if (Date.now() >= deadline) { again.push(seq); continue; }
      const object = await this.listed(seq);
      if (!object) continue; // recorded or expired: no longer listed, nothing left to forward
      if (!await this.tryOffer(base, object, peerId, deadline)) again.push(seq);
    }
    row.retry = [...rest, ...again];
    await save();
    // Nothing was there to send, over a state nothing changed during the pass.
    if (!page.objects.length && !missed.length && !todo.length && !row.retry.length && sent === false && this.state === seen) {
      this.forwardIdle.set(peerId, seen);
    }
  }

  /** §13.1: the entries of this home's history after the peer's latest head (a recording entry
   * the peer has not appended, above all), ahead of the head, so the peer can sign a head over
   * them; when the homes are on different branches (the module says `exchange`), this home's
   * branch from the last shared entry, after its head, so the peer holds the head that covers
   * them and keeps them as evidence. The same suffix is offered again at most every 2 s while the
   * peer's head lags (the time is kept with the forwarding state; a clock that moved back offers
   * it again at once); an immediate entry a non-primary peer refused (421) for want of this
   * home's head is offered again right after the head. */
  async forwardEntries(base, row, peerId, deadline) {
    if (Date.now() >= deadline) return true;
    const { fwd, head } = await this.lock(async () => {
      // Settling can append entries. Capture the head first, then the entries from that
      // same state, so an append during the network request cannot advance this head.
      const head = await this.headIfFresh();
      const fwd = this.wasm.call({ op: 'forward_entries', state: this.state, now: this.clock(), peer: peerId });
      return { fwd, head };
    });
    const sendEntries = async (force) => {
      if (!fwd.entries.length) return 0;
      const mark = `${fwd.from}:${fwd.entries.length}:${sha(fwd.entries[fwd.entries.length - 1])}`;
      const now = Date.now();
      const at = row.entriesAt ?? 0;
      if (!force && mark === row.entries && now >= at && now - at < ENTRIES_RESEND_MS) return 0;
      if (now >= deadline) return 0;
      row.entries = mark; row.entriesAt = now;
      await this.saveForward();
      const body = JSON.stringify({ from: fwd.from, entries: fwd.entries.map((e) => JSON.parse(unb64(e))), receipts: [] });
      const timeout = Math.min(PEER_TIMEOUT_MS, deadline - Date.now());
      if (timeout <= 0) return 0;
      const r = await fetch(`${base}/authority`, { signal: AbortSignal.timeout(timeout), method: 'POST', headers: { 'content-type': 'application/json' }, body });
      this.note(`entries ${peerId}`, r.status === 200 ? '' : `home ${peerId} did not take this home's entries from ${fwd.from}: ${r.status} ${(await r.text()).slice(0, 200)}`);
      return r.status;
    };
    const putHead = async () => {
      if (Date.now() >= deadline) return;
      // §13.3: a head the home is due to replace never leaves it, to a peer either.
      if (!head) return;
      const text = JSON.stringify(head);
      if (sha(text) === row.head) return;
      const timeout = Math.min(PEER_TIMEOUT_MS, deadline - Date.now());
      if (timeout <= 0) return;
      const r = await fetch(`${base}/records/heads/${this.key.memberId}.json`, { signal: AbortSignal.timeout(timeout), method: 'PUT', headers: { 'content-type': 'application/json' }, body: text });
      if (r.status === 200) { row.head = sha(text); await this.saveForward(); this.note(`head ${peerId}`, ''); }
      else this.note(`head ${peerId}`, `home ${peerId} refused this home's head: ${r.status} ${(await r.text()).slice(0, 200)}`);
    };
    // Nothing to send at all: no entry the peer lacks, and the peer took this very head.
    if (!fwd.entries.length && head && sha(JSON.stringify(head)) === row.head) return false;
    if (fwd.exchange) {
      await putHead();
      await sendEntries(false);
      return true;
    }
    const status = await sendEntries(false);
    // A rejected or throttled upload cannot be followed by a head covering missing entries.
    // 421 deliberately needs the covering head first; exchange mode already sent it above.
    if (!fwd.entries.length || (status >= 200 && status < 300) || status === 421) {
      await putHead();
      if (status === 421) await sendEntries(true);
    }
    return true;
  }
}
