// Colophon 0.3 reference relay (spec §8). Stores opaque records per library slot.
// Uses built-in Node APIs; a home's stream uses Bun's built-in `ws` module, so a relay with home
// slots runs on Bun only (startRelay refuses another runtime rather than serving no stream).
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants as fsc, promises as fsp, writeSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { appendLines, writeAll } from './files.js';
import { failingChecks, healthChecks } from './health.js';
import { HomeKey, HomeModule, HomeSlot, ModuleError, SUSPENSION_FILE, moduleMemoryBytes } from './home.js';
import { streamOptions } from './stream.js';
import {
  ProvisionReplay, ProvisionTable, REPLAY_DIR, TABLE_FILE, clientAddressConfig, tableKind, clientAddressResolver, isJsonType, memberRequest,
  checkPrivateListen, grantLimits, operatorGate, parseProvisionBody, provisionConfig, provisionGate, provisionRoute,
} from './provision.js';
import path from 'node:path';

export const PROTOCOL = 'colophon/relay/3';
export const DEFAULT_LIMITS = Object.freeze({
  recordBytes: 16 * 1024 * 1024,
  blobBytes: 65536 + 16,
  pageEntries: 1000,
  waitSeconds: 30,
  maxWaiters: 256, // concurrent long polls per slot
  slotBytes: 0, // 0 = no per-slot quota (at a home slot: its data only)
  historyBytes: 64 * 1024 * 1024, // a home slot's history and the module's files; 0 = none
  // Home slots only (not published at GET {base}):
  authorityBodyBytes: 16 * 1024 * 1024,
  pendingBodyBytes: 12 * 1024 * 1024,
  replayRows: 65536, // replay rows per slot, shared out per principal by the home module
  requestsPerMinute: 1200, // per address; 0 = unlimited
  // Forwarding to the account's other homes (§13.1), bounded in memory and in concurrency:
  peerAnswerBytes: 1024 * 1024, // the most decoded bytes read of one peer's answer
  forwardPeersPerSlot: 8, // passes running at once for one slot
  forwardPasses: 64, // passes running at once for the whole home
});
/** Limits that are the home's own business, not published at `GET {base}`. */
const UNPUBLISHED = ['slotBytes', 'historyBytes', 'authorityBodyBytes', 'pendingBodyBytes', 'replayRows', 'requestsPerMinute', 'peerAnswerBytes', 'forwardPeersPerSlot', 'forwardPasses'];

const SLOT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
/** A released slot's directory, renamed aside before it is removed (never a slot name: slots
 * start with a letter or digit). Left by a crash, it is removed at the next start-up. */
const RELEASED_PREFIX = '.released-';
const HEX64 = /^[0-9a-f]{64}$/;
const STREAM_PATH = /^\/v1\/libraries\/([a-z0-9][a-z0-9._-]{0,63})\/stream$/;
/** The largest WebSocket message a stream takes (a 16,384-byte session frame and its wrapper). */
const STREAM_MESSAGE_BYTES = 20_480;
const BATCH_BYTES = 4 * 1024 * 1024; // Encoded JSON/base64 response budget.

export function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

// Cross-origin answers (operator behaviour, not protocol). CORS is not access control: no
// decision about a request reads `Origin`; it only chooses which headers decorate the answer.
const CORS_EXPOSE = 'ETag, Retry-After, WWW-Authenticate';
const CORS_METHODS = 'GET, POST, PUT, OPTIONS';
const CORS_HEADERS = 'Authorization, Content-Type, If-Match, If-None-Match';
const CORS_MAX_AGE = '600';
const OPTIONS_ALLOW = 'GET, HEAD, POST, PUT, DELETE, OPTIONS';
const CACHE_CONTROL = 'no-store, no-transform';
// scheme://host[:port], lower case: a DNS name of letter-digit-hyphen labels, an IPv4 literal,
// or a bracketed IPv6 literal. No path, no trailing slash, no wildcard, no user info.
const ORIGIN = /^https?:\/\/(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*|\[[0-9a-f:.]+\])(?::[1-9][0-9]{0,4})?$/;

/** Checks the configured CORS origins and returns them as a Set. Throws on any entry that is
 * not exactly `scheme://host[:port]` as a browser serializes an origin (so `*`, `null`, an
 * upper-case letter, a path, a trailing slash or dot, or an explicit default port are refused:
 * a browser never sends them, and a wildcard is never wanted). */
export function corsOrigins(list) {
  if (list === undefined || list === null) return new Set();
  if (!Array.isArray(list)) throw new Error('cors.origins must be an array of origins (scheme://host[:port])');
  const out = new Set();
  for (const entry of list) {
    let canonical = null;
    if (typeof entry === 'string' && ORIGIN.test(entry)) {
      try { canonical = new URL(entry).origin; } catch { canonical = null; }
    }
    if (typeof entry !== 'string' || canonical !== entry) throw new Error(`Invalid CORS origin ${JSON.stringify(entry)}: each entry must be exactly scheme://host[:port], lower case, http or https, no path, no wildcard, no default port`);
    out.add(entry);
  }
  return out;
}

/** The single enforcement point for headers every answer carries. It is applied before any
 * handler runs, and `res.writeHead` (which every answer passes through, an implicit one from a
 * bare `res.end()` included) is wrapped so that the headers a call site passes are merged first
 * and these are set last: no later call site can drop or override them. */
function enforceAnswerHeaders(req, res, origins) {
  const origin = req.headers.origin;
  const listed = typeof origin === 'string' && origins.has(origin);
  const apply = () => {
    res.setHeader('cache-control', CACHE_CONTROL);
    res.removeHeader('content-encoding');
    res.removeHeader('access-control-allow-credentials');
    if (origins.size > 0) {
      const vary = res.getHeader('vary');
      const parts = (vary === undefined ? [] : String(vary).split(',')).map((v) => v.trim()).filter(Boolean);
      if (!parts.some((v) => v.toLowerCase() === 'origin')) parts.push('Origin');
      res.setHeader('vary', parts.join(', '));
    }
    if (listed) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('access-control-expose-headers', CORS_EXPOSE);
    } else {
      for (const name of res.getHeaderNames()) if (name.startsWith('access-control-')) res.removeHeader(name);
    }
  };
  const writeHead = res.writeHead;
  res.writeHead = function (status, ...rest) {
    const last = rest[rest.length - 1];
    const headers = last !== null && typeof last === 'object' ? rest.pop() : undefined;
    if (Array.isArray(headers)) {
      const pairs = Array.isArray(headers[0]) ? headers : headers.flatMap((v, i) => (i % 2 ? [] : [[v, headers[i + 1]]]));
      for (const [name, value] of pairs) this.setHeader(name, value);
    } else if (headers) {
      for (const [name, value] of Object.entries(headers)) this.setHeader(name, value);
    }
    apply();
    return writeHead.call(this, status, ...rest);
  };
  apply();
  return listed;
}

/** `OPTIONS` on any path: answered before slot lookup, authorization, call checks and rate
 * counting. It opens no slot and touches no disk. */
function answerOptions(req, res, listed) {
  req.resume();
  const preflight = typeof req.headers.origin === 'string' && req.headers['access-control-request-method'] !== undefined;
  const headers = {}; // a 204 carries no Content-Length (RFC 9110 §8.6)
  if (preflight) {
    if (listed) {
      headers['access-control-allow-methods'] = /^\/v1\/libraries\/[^/]+\/routes\/[0-9a-f]{64}$/.test(req.url)
        ? 'DELETE, OPTIONS' : CORS_METHODS;
      headers['access-control-allow-headers'] = CORS_HEADERS;
      headers['access-control-max-age'] = CORS_MAX_AGE;
    }
  } else headers.allow = OPTIONS_ALLOW;
  res.writeHead(204, headers);
  res.end();
}

/** Path grammar shared with the SDK adapters (RecordPath/BlobPath). Returns the kind or null. */
export function classifyPath(p) {
  if (typeof p !== 'string' || Buffer.byteLength(p) >= 512) return null;
  const parts = p.split('/');
  const ok = parts.every((c) => c.length > 0 && c !== '.' && c !== '..' && !c.startsWith('.') &&
    !c.includes('\\') && !c.includes('\0') && !c.includes('%'));
  if (!ok) return null;
  if (parts.length === 2 && parts[0] === 'blobs') return HEX64.test(parts[1]) ? 'blob' : null;
  if (!p.endsWith('.json')) return null;
  if (parts.length === 2 && parts[0] === 'authority') return 'record';
  if (parts.length === 2 && parts[0] === 'requests') return 'request';
  if (parts.length === 3 && parts[0] === 'ops') return 'record';
  if (parts.length === 4 && parts[0] === 'ops') return 'record';
  if (parts.length === 4 && parts[0] === 'history') return 'record';
  if (parts.length === 4 && parts[0] === 'state') return 'state';
  return null;
}

/** Authority, requests and legacy three-part ops always match; namespaced paths match `ns`. */
export function pathInNamespace(p, ns) {
  const parts = p.split('/');
  if (parts[0] === 'authority' || parts[0] === 'requests') return true;
  if (parts.length === 3 && parts[0] === 'ops') return true;
  if (parts.length === 4 && (parts[0] === 'ops' || parts[0] === 'state' || parts[0] === 'history')) {
    return parts[2] === ns;
  }
  return false;
}

export function newToken() {
  const token = randomBytes(32).toString('base64url');
  return { token, tokenSha256: sha256(Buffer.from(token)) };
}

class HttpError extends Error {
  /** `body`, when given, is the JSON answer as it is (a home's `{"result":…}`), else `{"error"}`. */
  constructor(status, message, headers = {}, body = undefined) { super(message); this.status = status; this.headers = headers; this.body = body; }
}

/** One library slot on disk: records/<path>, an append-only log.jsonl and meta.json. */
class Slot {
  constructor(root, name, limits, classify = classifyPath) {
    this.root = root; this.name = name; this.limits = limits; this.classify = classify; this.home = null;
    this.entries = []; this.current = new Map(); this.bytes = 0;
    // A home slot counts only its data (records, live values, blob chunks) against `slotBytes`:
    // `isData` says which paths those are. Null (a 0.3 slot): every path counts, as always.
    this.isData = null; this.dataBytes = 0;
    this.waiters = new Set(); this.chain = Promise.resolve(); this.instance = null;
  }
  recordsDir() { return path.join(this.root, 'records'); }

  async open() {
    await ensureRealDir(this.root);
    await ensureRealDir(this.recordsDir());
    await ensureRealDir(path.join(this.root, 'tmp'));
    for (const stale of await fsp.readdir(path.join(this.root, 'tmp'))) {
      await fsp.rm(path.join(this.root, 'tmp', stale), { force: true });
    }
    let meta = null;
    try { meta = JSON.parse(await fsp.readFile(path.join(this.root, 'meta.json'), 'utf8')); } catch { meta = null; }
    const logged = meta && typeof meta.instance === 'string' ? await this.readLog() : null;
    const onDisk = await this.scan();
    let consistent = logged !== null;
    if (consistent) {
      const latest = new Map();
      for (const e of logged) { if (e.deleted) latest.delete(e.path); else latest.set(e.path, e); }
      // A logged record missing or changed on disk means the log cannot be continued: start a new
      // instance so every old cursor answers 410 and clients relist (spec §8.2).
      for (const [p, e] of latest) {
        const d = onDisk.get(p);
        if (!d || d.size !== e.size || await this.digestOf(p) !== e.sha256) { consistent = false; break; }
      }
    }
    if (!consistent) {
      this.instance = randomBytes(8).toString('hex');
      this.entries = [];
      await writeDurable(path.join(this.root, 'log.jsonl'), Buffer.alloc(0), path.join(this.root, 'tmp'));
      await writeDurable(path.join(this.root, 'meta.json'), Buffer.from(JSON.stringify({ instance: this.instance }) + '\n'), path.join(this.root, 'tmp'));
      for (const p of [...onDisk.keys()].sort()) await this.log({ path: p, size: onDisk.get(p).size, sha256: await this.digestOf(p) });
    } else {
      this.instance = meta.instance;
      for (const e of logged) this.indexEntry(e);
      // Crash recovery: a record linked into place before its log line was written.
      for (const p of [...onDisk.keys()].sort()) {
        if (!this.current.has(p)) await this.log({ path: p, size: onDisk.get(p).size, sha256: await this.digestOf(p) });
      }
    }
  }

  async readLog() {
    const file = path.join(this.root, 'log.jsonl');
    let text;
    try { text = await fsp.readFile(file, 'utf8'); } catch { return null; }
    const end = text.lastIndexOf('\n');
    if (end !== text.length - 1) {
      // Drop a torn final line from an interrupted append.
      text = text.slice(0, end + 1);
      await fsp.truncate(file, Buffer.byteLength(text));
    }
    const out = [];
    for (const line of text.split('\n')) {
      if (!line) continue;
      try {
        const e = JSON.parse(line);
        if (!this.classify(e.path)) return null;
        out.push(e.deleted ? { path: e.path, deleted: true } : { path: e.path, size: e.size, sha256: e.sha256 });
      } catch { return null; }
    }
    return out;
  }

  async scan() {
    const found = new Map();
    const walk = async (dir, rel) => {
      for (const ent of await fsp.readdir(dir, { withFileTypes: true })) {
        if (ent.name.startsWith('.')) continue;
        const relPath = rel ? `${rel}/${ent.name}` : ent.name;
        const full = path.join(dir, ent.name);
        if (ent.isSymbolicLink()) throw new Error(`Refusing symlink in relay storage: ${full}`);
        if (ent.isDirectory()) await walk(full, relPath);
        else if (ent.isFile() && this.classify(relPath)) found.set(relPath, { size: (await fsp.lstat(full)).size });
      }
    };
    await walk(this.recordsDir(), '');
    return found;
  }

  async digestOf(p) { return sha256(await this.readFile(p)); }

  indexEntry(e) {
    this.entries.push(e);
    const old = this.current.get(e.path);
    const data = this.isData?.(e.path) ?? false;
    if (old) { this.bytes -= old.size; if (data) this.dataBytes -= old.size; }
    if (e.deleted) this.current.delete(e.path);
    else { this.current.set(e.path, { size: e.size, sha256: e.sha256 }); this.bytes += e.size; if (data) this.dataBytes += e.size; }
  }

  async log(e) {
    const file = path.join(this.root, 'log.jsonl');
    const st = await fsp.lstat(file).catch((e) => { if (e.code !== 'ENOENT') throw e; });
    if (st && !st.isFile()) throw new Error('Relay log must be a regular file');
    // A part of a line that could not be cut back: no row may follow it (the next open finds the
    // log damaged at that line, and starts a new instance, as for any inconsistent log).
    if (this.logBroken) throw this.logBroken;
    const handle = await fsp.open(file, fsc.O_WRONLY | fsc.O_APPEND | fsc.O_CREAT | fsc.O_NOFOLLOW, 0o600);
    try { await appendLines(handle, JSON.stringify(e) + '\n', true); }
    catch (error) { if (error.unrepaired) this.logBroken = error; throw error; }
    finally { await handle.close(); }
    this.indexEntry(e);
    this.onEntry?.(this.entries.length - 1); // a home's stream pushes the same entry and cursor
    for (const waiter of [...this.waiters]) {
      if (!waiter.namespaces.length || waiter.namespaces.some((ns) => pathInNamespace(e.path, ns))) waiter.wake();
    }
  }

  /** Serializes mutations within the slot; reads use the in-memory index. */
  async exclusive(fn) {
    // At shutdown no new request is admitted, and the work already admitted on the slot (a
    // request, a scheduler pass) finishes its file work: a checkpoint already committed is not
    // left without its files, nor answered 503. Anything else is refused once the slot closes,
    // and everything once it is being released after its work drained.
    const refused = () => this.released || (this.closing && (this.releasing || !this.active));
    if (refused()) throw new HttpError(503, 'Relay is closing');
    const execute = () => {
      if (refused()) throw new HttpError(503, 'Relay is closing');
      return fn();
    };
    const run = this.chain.then(execute, execute);
    this.chain = run.catch(() => {});
    return run;
  }

  async target(p, create) {
    // Every component under records/ must be a real directory; never follow a symlink.
    const parts = p.split('/');
    let dir = this.recordsDir();
    for (const part of parts.slice(0, -1)) {
      dir = path.join(dir, part);
      if (create) await ensureRealDir(dir); else {
        const st = await fsp.lstat(dir).catch(() => null);
        if (!st) return null;
        if (!st.isDirectory() || st.isSymbolicLink()) throw new HttpError(500, 'Relay storage is not a plain directory');
      }
    }
    return path.join(dir, parts[parts.length - 1]);
  }

  async readFile(p) {
    const file = await this.target(p, false);
    if (!file) throw new HttpError(404, 'Not found');
    let handle;
    try { handle = await fsp.open(file, fsc.O_RDONLY | fsc.O_NOFOLLOW); }
    catch (error) { if (error.code === 'ENOENT') throw new HttpError(404, 'Not found'); throw error; }
    try {
      const st = await handle.stat();
      if (!st.isFile()) throw new HttpError(500, 'Relay storage is not a regular file');
      return await handle.readFile();
    } finally { await handle.close(); }
  }

  changes(after, limit, namespaces = []) {
    let start = 0;
    if (after) {
      const dot = after.lastIndexOf('.');
      const instance = after.slice(0, dot);
      const seq = Number(after.slice(dot + 1));
      if (dot < 1 || instance !== this.instance || !Number.isSafeInteger(seq) || seq < 0 || seq > this.entries.length) {
        throw new HttpError(410, 'Cursor cannot be continued; list from the beginning');
      }
      start = seq;
    }
    const page = [];
    let i = start;
    while (i < this.entries.length && page.length < limit) {
      const e = this.entries[i];
      i += 1;
      if (namespaces.length && !namespaces.some((ns) => pathInNamespace(e.path, ns))) continue;
      page.push(e);
    }
    return { entries: page, cursor: `${this.instance}.${i}`, more: i < this.entries.length };
  }

  waitForEntry(ms, res, namespaces = []) {
    if (this.waiters.size >= this.limits.maxWaiters) throw new HttpError(503, 'Too many long polls', { 'retry-after': '1' });
    return new Promise((resolve) => {
      const waiter = { wake: null, namespaces };
      const wake = () => { clearTimeout(timer); this.waiters.delete(waiter); res?.off('close', wake); resolve(); };
      waiter.wake = wake;
      const timer = setTimeout(wake, ms);
      this.waiters.add(waiter);
      res?.once('close', wake);
      if (res?.destroyed) wake();
    });
  }

  /** `digest`: the body's SHA-256 when the caller has it already. */
  async putImmutable(p, body, digest = sha256(body)) {
    return this.exclusive(async () => {
      const existing = this.current.get(p);
      if (existing) {
        if (existing.sha256 === digest && existing.size === body.length) return 200;
        throw new HttpError(412, 'A different record already exists at this path');
      }
      this.checkQuota(body.length, p);
      const file = await this.target(p, true);
      const staged = await this.stage(body);
      try {
        await fsp.link(staged, file);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const old = await this.readFile(p);
        if (!old.equals(body)) throw new HttpError(412, 'A different record already exists at this path');
        if (this.current.has(p)) return 200;
      } finally { await fsp.rm(staged, { force: true }); }
      await syncDir(path.dirname(file));
      await this.log({ path: p, size: body.length, sha256: digest });
      return 201;
    });
  }

  async replaceRequest(p, body, expected, digest = sha256(body)) {
    return this.exclusive(async () => {
      const existing = this.current.get(p);
      if (expected !== undefined && (!existing || `"${existing.sha256}"` !== expected)) throw new HttpError(412, 'Live slot changed');
      if (existing && existing.sha256 === digest) return 200;
      this.checkQuota(body.length - (existing ? existing.size : 0), p);
      const file = await this.target(p, true);
      const staged = await this.stage(body);
      try { await fsp.rename(staged, file); } finally { await fsp.rm(staged, { force: true }); }
      await syncDir(path.dirname(file));
      await this.log({ path: p, size: body.length, sha256: digest });
      return existing ? 200 : 201;
    });
  }

  async deleteRequest(p) {
    return this.exclusive(async () => {
      if (!this.current.has(p)) return 204;
      const file = await this.target(p, false);
      if (file) { await fsp.rm(file, { force: true }); await syncDir(path.dirname(file)); }
      await this.log({ path: p, deleted: true });
      return 204;
    });
  }

  checkQuota(added, p) {
    if (!(this.limits.slotBytes > 0)) return;
    if (this.isData) {
      // A home slot: the account's history and everything the module stores is never refused
      // (an account must always be able to change its keys and homes); data writes are.
      if (!this.isData(p) || added <= 0 || this.dataBytes + added <= this.limits.slotBytes) return;
      throw new HttpError(507, 'Library slot quota exceeded', {}, { result: 'refused:overQuota' });
    }
    if (this.bytes + added > this.limits.slotBytes) throw new HttpError(507, 'Library slot quota exceeded');
  }

  async stage(body) {
    const staged = path.join(this.root, 'tmp', randomBytes(12).toString('hex'));
    const handle = await fsp.open(staged, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
    try { await writeAll(handle, body); await handle.sync(); } finally { await handle.close(); }
    return staged;
  }
}

async function ensureRealDir(dir) {
  const st = await fsp.lstat(dir).catch(() => null);
  if (!st) {
    // A new directory is a new name in its parent: durable only once the parent is synced.
    const made = await fsp.mkdir(dir, { mode: 0o700 }).then(() => true, (e) => { if (e.code !== 'EEXIST') throw e; return false; });
    if (made) await syncDir(path.dirname(dir));
    return ensureRealDir(dir);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`Relay storage must be a plain directory: ${dir}`);
}

async function syncDir(dir) {
  const handle = await fsp.open(dir, fsc.O_RDONLY);
  try { await handle.sync(); } catch (error) { if (error.code !== 'EINVAL' && error.code !== 'EPERM') throw error; }
  finally { await handle.close(); }
}

async function writeDurable(file, bytes, tmpDir) {
  const staged = path.join(tmpDir, randomBytes(12).toString('hex'));
  const handle = await fsp.open(staged, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
  try { await writeAll(handle, bytes); await handle.sync(); } finally { await handle.close(); }
  try { await fsp.rename(staged, file); }
  catch (error) { await fsp.rm(staged, { force: true }); throw error; }
  await syncDir(path.dirname(file));
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const declared = req.headers['content-length'];
    if (declared === undefined) { reject(new HttpError(411, 'Content-Length is required')); req.resume(); return; }
    if (!/^\d+$/.test(declared)) { reject(new HttpError(400, 'Invalid Content-Length')); req.resume(); return; }
    if (Number(declared) > max) { reject(new HttpError(413, 'Record exceeds the relay limit', { connection: 'close' })); req.resume(); return; }
    const chunks = []; let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > max) { reject(new HttpError(413, 'Record exceeds the relay limit', { connection: 'close' })); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (size !== Number(declared)) reject(new HttpError(400, 'Body length does not match Content-Length'));
      else resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

function readBatchBody(req, url) {
  if (req.method !== 'POST') throw new HttpError(405, 'Method not allowed', { allow: 'POST' });
  if (url.search) throw new HttpError(400, 'Record URLs take no query');
  if (!isJsonType(req.headers['content-type'])) throw new HttpError(415, 'Content-Type must be application/json');
  return readBody(req, 64 * 1024);
}

/** A home base as compared for duplicates: scheme and host case and trailing slashes ignored. */
function normalBase(base) {
  try { return new URL(base).href.replace(/\/+$/, ''); } catch { return String(base).replace(/\/+$/, ''); }
}
function basePair(account, base) { return `${account} ${normalBase(base)}`; }

async function serveBatch(res, slot, decisions) {
  const records = [];
  // Include the envelope (false is longer than true), commas, and JSON path escaping.
  const envelopeBytes = Buffer.byteLength(JSON.stringify({ records: [], truncated: false }));
  let total = envelopeBytes;
  for (const { path: p, status, kind } of decisions) {
    const entry = status === 200 ? slot.current.get(p) : undefined;
    const encodedSize = entry ? Math.ceil(entry.size / 3) * 4 + Buffer.byteLength(JSON.stringify(p)) + 128 : 0;
    const refusal = !entry ? { path: p, status: status === 200 ? 404 : status }
      : encodedSize + envelopeBytes > BATCH_BYTES ? { path: p, status: 413, etag: `"${entry.sha256}"`, size: entry.size } : null;
    const cost = (refusal ? Buffer.byteLength(JSON.stringify(refusal)) : encodedSize) + (records.length ? 1 : 0);
    if (total + cost > BATCH_BYTES) break;
    total += cost;
    if (refusal) { records.push(refusal); continue; }
    // A home's decision names the kind (the module's grammar), so it is not asked again.
    const max = (kind ?? slot.classify(p)) === 'blob' ? slot.limits.blobBytes : slot.limits.recordBytes;
    if (entry.size > max) throw new HttpError(500, 'Stored record exceeds its limit');
    // Indexed, so it must be there: a missing or unreadable file is a storage failure (500,
    // naming no path), never a whole-request 404. The call is spent either way.
    let bytes;
    try { bytes = await slot.readFile(p); } catch { throw new HttpError(500, 'Stored record failed integrity check'); }
    if (bytes.length !== entry.size || sha256(bytes) !== entry.sha256) throw new HttpError(500, 'Stored record failed integrity check');
    records.push({ path: p, status: 200, etag: `"${entry.sha256}"`, bytes: bytes.toString('base64') });
  }
  return send(res, 200, { records, truncated: records.length < decisions.length });
}

/**
 * Creates the relay. `libraries` maps slot names to `{ tokenSha256 }`, `{ token }` or
 * `{ open: true }` (no bearer token; local testing only).
 */
export async function createRelay({ dataDir, libraries, limits = {}, home, clock = Date.now, resolve, tickMs = 0, tracing = false, cors, provision, clientAddress: addressConfig, crashAt, hook, stream: streamOptionsIn = {}, drainMs = DRAIN_MS, metrics, privateApi = false }) {
  if (!dataDir) throw new Error('dataDir is required');
  const metricsToken = metricsConfig(metrics);
  if (cors !== undefined && cors !== null && (typeof cors !== 'object' || Array.isArray(cors))) throw new Error('cors must be an object with origins, an array of origins');
  const origins = corsOrigins(cors?.origins);
  const provisioning = provisionConfig(provision);
  streamOptions(streamOptionsIn);
  // The address requests count against, for every per-address limit (never for access).
  const clientAddress = clientAddressResolver(clientAddressConfig(addressConfig));
  // Test builds only (tracing needs --test-clock): a marker on stderr, a SIGKILL of this process
  // at the named point, and `hook` (a test's pause), so a test can stop it exactly there.
  const reach = async (point) => {
    if (!tracing) return;
    writeSync(2, `trace ${point}\n`);
    if (crashAt === point) process.kill(process.pid, 'SIGKILL');
    if (hook) await hook(point);
  };
  const effective = { ...DEFAULT_LIMITS, ...limits };
  for (const k of ['peerAnswerBytes', 'forwardPeersPerSlot', 'forwardPasses']) {
    if (!Number.isSafeInteger(effective[k]) || effective[k] < 1) throw new Error(`limits.${k} must be a positive integer`);
  }
  if (!Number.isSafeInteger(effective.historyBytes) || effective.historyBytes < 0) throw new Error('limits.historyBytes must be a whole number of bytes (0: none)');
  // Forwarding passes running now, across every home slot (bounded by `forwardPasses`).
  const forwarding = { running: 0, max: effective.forwardPasses };
  await fsp.mkdir(dataDir, { recursive: true, mode: 0o700 });
  await ensureRealDir(path.resolve(dataDir));
  const unlock = await lockDataDir(dataDir);
  try {
  // Directories a release renamed aside (`.released-<slot>.<hex>`) are removed; the names they
  // were released from are kept, so a release that stopped between the rename and its row's
  // removal is finished below, once the table is read, instead of reopening the slot empty.
  const releasedNames = new Set();
  for (const name of await fsp.readdir(path.resolve(dataDir))) {
    if (!name.startsWith(RELEASED_PREFIX)) continue;
    const m = /^(.+)\.[0-9a-f]{16}$/.exec(name.slice(RELEASED_PREFIX.length));
    if (m) releasedNames.add(m[1]);
    await fsp.rm(path.join(path.resolve(dataDir), name), { recursive: true, force: true });
  }
  let closing = false;
  const requests = new Set();
  const auth = new Map();
  const homeSlots = new Map();
  // Slots apps provisioned through the door (`POST /v1/provision`), read before anything is served.
  // The table is in use only when provisioning is on or a regular file of that name is there;
  // otherwise nothing of that name is read, scanned or removed (a 0.3 slot may be called so).
  const kind = await tableKind(path.resolve(dataDir));
  if (provisioning.enabled && kind === 'other') {
    throw new Error(`${path.join(path.resolve(dataDir), TABLE_FILE)} is not a regular file (a 0.3 slot of that name?): rename that slot before turning provisioning on`);
  }
  const tableInUse = provisioning.enabled || kind === 'file';
  const table = tableInUse ? await ProvisionTable.load(path.resolve(dataDir), provisioning) : ProvisionTable.empty(path.resolve(dataDir));
  for (const name of releasedNames) {
    const present = await fsp.lstat(path.join(path.resolve(dataDir), name)).then(() => true, (error) => { if (error.code === 'ENOENT') return false; throw error; });
    if (table.get(name) && !present && !Object.hasOwn(libraries ?? {}, name)) await table.write(name, null);
  }
  let homeModule = null; let homeKey = null;
  if (Object.values(libraries ?? {}).some((e) => e && e.home) || provisioning.enabled || table.size > 0) {
    if (!home?.wasm || !home?.key) throw new Error('A home slot, and provisioning, need home.wasm (the module path) and home.key (a private P-256 JWK)');
    homeModule = home.wasm instanceof HomeModule ? home.wasm : await HomeModule.load(home.wasm, { resetBytes: moduleMemoryBytes(home.moduleMemoryMB) });
    homeKey = await HomeKey.fromJwk(home.key, homeModule);
  }
  // Every row against this relay's settings and key, through the module. Nothing is repaired.
  table.validate(provisioning, (slot, e) => homeModule.call({ op: 'member_request', account: e.account,
    signing: homeKey.point.toString('base64'), endpoint: `${e.base}/`, request: e.request }));
  for (const [name, entry] of Object.entries(libraries ?? {})) {
    if (!SLOT.test(name)) throw new Error(`Invalid library slot name: ${name}`);
    if (name === TABLE_FILE && tableInUse) throw new Error(`${TABLE_FILE} is the provisioning table, not a slot name, while provisioning is or has been on`);
    const provisioned = table.get(name);
    if (provisioned && (!entry?.home || entry.account !== provisioned.account)) {
      throw new Error(`Slot ${name} is configured, and provisioned for account ${provisioned.account} in ${TABLE_FILE}: they must agree, or the slot be removed from one`);
    }
    if (entry && entry.home) {
      if (typeof entry.base !== 'string' || !/^https?:\/\//.test(entry.base)) throw new Error(`Home slot ${name} needs base, the URL its account names as its endpoint`);
      // Provisioning: a home slot serves the one account the operator created it for.
      if (typeof entry.account !== 'string' || !HEX64.test(entry.account)) throw new Error(`Home slot ${name} needs account, the 64-hex ID of the account it is provisioned for`);
      homeSlots.set(name, { base: entry.base.replace(/\/+$/, ''), account: entry.account });
      if (entry.token || entry.tokenSha256) console.error(`Home slot ${name}: a bearer token authorizes nothing at a 0.5 home and is ignored`);
      continue;
    }
    if (entry && entry.open === true) auth.set(name, null);
    else if (entry && entry.home && !entry.token && !entry.tokenSha256) auth.set(name, Buffer.alloc(32)); // calls only: no bearer matches
    else if (entry && typeof entry.tokenSha256 === 'string' && HEX64.test(entry.tokenSha256)) auth.set(name, Buffer.from(entry.tokenSha256, 'hex'));
    else if (entry && typeof entry.token === 'string' && entry.token.length >= 16) auth.set(name, createHash('sha256').update(entry.token).digest());
    else throw new Error(`Library slot ${name} needs tokenSha256, a token of at least 16 characters, or open: true`);
  }
  for (const [name, e] of table.rows) if (!homeSlots.has(name)) homeSlots.set(name, { base: e.base, account: e.account });
  // Replay tables are per slot: two slots serving one account at one base would each take the
  // same captured call once. One account, one home slot per base.
  // The door checks the same pair under its lock (`baseHolder`) before it reserves or writes.
  const bases = new Map();
  for (const [name, { base, account }] of homeSlots) {
    const pair = basePair(account, base);
    const other = bases.get(pair);
    if (other !== undefined) throw new Error(`Home slots ${other} and ${name} both serve account ${account} at base ${normalBase(base)}: a base names one home slot per account`);
    bases.set(pair, name);
  }
  /** Another home slot serving `account` at `base`, if any (not `except`). */
  const baseHolder = (account, base, except) => {
    const pair = basePair(account, base);
    for (const [name, e] of homeSlots) if (name !== except && basePair(e.account, e.base) === pair) return name;
    return undefined;
  };
  const configured = new Set(Object.keys(libraries ?? {}));
  // Gate "grant": the operator account is one of this home's own slots, and the door's audience
  // is its own. A slot named but not set up yet is not a start-up failure (every grant request is
  // then 503 unavailable); a slot for another account, or a bad audience, is.
  const granting = provisioning.enabled && provisioning.gates.has('grant');
  let provisionReplay = null;
  if (provisioning.gates.has('grant')) {
    const op = provisioning.operator;
    const held = homeSlots.get(op.slot);
    if (configured.has(op.slot) && !held) throw new Error(`provision.operator.slot ${op.slot} is a 0.3 slot, not a home slot of this home`);
    if (held && held.account !== op.account) throw new Error(`provision.operator.slot ${op.slot} serves account ${held.account}, not provision.operator.account ${op.account}`);
    if (configured.has(REPLAY_DIR) || table.get(REPLAY_DIR)) throw new Error(`${REPLAY_DIR} is the provisioning replay table, not a slot name, while gate "grant" is on`);
    if (homeModule && !homeModule.call({ op: 'provision_access', query: 'audience', audience: provisioning.audience }).valid) {
      throw new Error(`provision.audience ${JSON.stringify(provisioning.audience)} is not an audience (§10.1: an https URL with no port, query or fragment, or a urn:)`);
    }
    for (const [name, h] of homeSlots) if (h.base === provisioning.audience.replace(/\/+$/, '')) throw new Error(`provision.audience is the base of slot ${name}: the door's audience must be its own`);
    if (granting) provisionReplay = await ProvisionReplay.open(path.resolve(dataDir), { wasm: homeModule, clock, table });
  }
  const slots = new Map();
  const opening = new Map();
  const notProvisioned = () => new HttpError(404, 'Not provisioned', {}, { result: 'refused:notProvisioned' });
  // Shutdown, unlike a release, says nothing about the slot: the request may be retried.
  const relayClosing = () => new HttpError(503, 'Relay is closing', { 'retry-after': '1' });
  async function slot(name) {
    if (closing) throw relayClosing();
    if (slots.has(name)) return slots.get(name);
    // Never opened for a name this relay does not hold (a released slot is not reopened).
    if (!homeSlots.has(name) && !auth.has(name)) throw notProvisioned();
    if (!opening.has(name)) {
      opening.set(name, (async () => {
        const isHome = homeSlots.has(name);
        // A home slot's path grammar is the module's (the engine's paths).
        const homeClassify = (p) => homeModule.call({ op: 'classify', path: p }).kind;
        const s = new Slot(path.join(path.resolve(dataDir), name), name, effective, isHome ? homeClassify : classifyPath);
        if (isHome) s.isData = (p) => /^(ops|history|state|blobs)\//.test(p);
        if (isHome) {
          s.home = new HomeSlot({
            slot: s, wasm: homeModule, key: homeKey, base: homeSlots.get(name).base, account: homeSlots.get(name).account,
            clock, resolve, tracing, stream: streamOptions(streamOptionsIn), scheduled: tickMs > 0,
            deps: { HttpError, send, readBody, readBatchBody, serveBatch, clampInt, clientAddress, isJsonType, reach, firstChanges, serveChanges, serveRecord, forwarding },
            limits: { ...effective, requestsPerMinute: effective.requestsPerMinute ?? 0 },
          });
          await s.home.open();
        } else await s.open();
        s.closing = closing; // Opening may have overlapped shutdown's first drain pass.
        slots.set(name, s);
        return s;
      })().catch((error) => {
        opening.delete(name); // a repaired runtime slot is retried on the next request
        if (!homeSlots.has(name) || configured.has(name)) throw error;
        console.error(`Home slot ${name} unavailable: ${error.message}`);
        throw new HttpError(503, 'Home slot unavailable', {}, { result: 'unavailable' });
      }));
    }
    return opening.get(name);
  }

  function authorize(req, name) {
    if (!auth.has(name)) throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Bearer' });
    const expected = auth.get(name);
    if (expected === null) return;
    const header = req.headers.authorization ?? '';
    const match = /^Bearer ([^\s]+)$/.exec(header);
    const given = createHash('sha256').update(match ? match[1] : '').digest();
    if (!match || !timingSafeEqual(given, expected)) throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Bearer' });
  }

  // ---------------------------------------------------------------------------------------------
  // Work in flight on a slot: every request from dispatch until both its response has ended and
  // its handler has settled, and every scheduler pass. A slot being released waits for none.

  function enter(s) { s.active = (s.active ?? 0) + 1; }
  function leave(s) {
    s.active -= 1;
    if (s.active === 0 && s.drained) { const done = s.drained; s.drained = null; done(); }
  }
  const drained = (s) => (s.active ? new Promise((done) => { s.drained = done; }) : Promise.resolve());

  // ---------------------------------------------------------------------------------------------
  // Provisioning: the door, under one lock, and the release of slots nobody claimed.

  const admitProvision = provisionGate(provisioning, clock);
  let provisionTail = Promise.resolve();
  const provisionLock = (fn) => { const run = provisionTail.then(fn, fn); provisionTail = run.catch(() => {}); return run; };
  // A suspended slot counts as claimed, and so does one whose suspension is uncertain or whose
  // marker is on disk whatever the state in memory says (a suspend that failed after the rename).
  const claimed = async (s) => {
    if (s.home.suspended || s.home.suspensionUncertain || await s.home.suspensionOnDisk()) return true;
    const st = s.home.status();
    return Boolean(st.appointed || st.held > 0);
  };

  /**
   * Release one provisioned slot that holds no genesis (never appointed) and is not suspended,
   * in three steps, so the door's lock is never held while work on the slot drains:
   *
   * 1. Under the provisioning lock (`startRelease`), never waiting on the slot's own lock: if the
   *    slot looks unclaimed, it is marked for release and taken out of dispatch (new requests answer refused:notProvisioned, long polls
   *    are woken and end), and the release is listed in `releases`. A provision of the name, and
   *    an operator call on it, wait for the release to end before they decide.
   * 2. Outside the lock: the work in flight on it (requests, scheduler passes, direct Slot
   *    callers) drains.
   * 3. Under the provisioning lock again: the row must be the very row the release started from,
   *    and the slot the same Slot; then "nothing held, not suspended" is checked again under the
   *    slot's lock, and only then are its directory and its row removed. Otherwise the release is
   *    abandoned and the slot returns to service.
   *
   * A late use of the released Slot fails closed (its locks refuse), never on a later slot's
   * directory. A crash between the directory and the row leaves the row: the slot is opened
   * fresh and released at the next start-up.
   *
   * `force` (the operator's delete, `DELETE /v1/operator/slots/<slot>`) releases a slot however
   * claimed it is, appointed or suspended, by the same three steps. `done` resolves to whether
   * the slot was removed.
   */
  const releases = new Map(); // slot name -> the promise of its release's end
  async function startRelease(name, e, { force = false } = {}) {
    if (releases.has(name)) return null;
    let s;
    // A slot that cannot be opened now (503), or whose release was interrupted after it left
    // dispatch (404), is not released here; the door's sweep goes on with the others.
    try { s = await slot(name); } catch (error) { if (error instanceof HttpError && (error.status === 503 || error.status === 404)) return null; throw error; }
    // A first look at the state as it stands, without waiting for the slot's lock (a slow request
    // may hold it): the decision is made again under that lock in step 3, before anything goes.
    if (!force && await claimed(s)) return null;
    s.releasing = true;
    homeSlots.delete(name);
    for (const waiter of [...s.waiters]) waiter.wake();
    const done = (async () => {
      await reach(`release draining ${name}`);
      await drained(s);
      // Admitted requests may still claim the slot while it drains. Once they settle, stop all
      // mutations and drain any direct Slot callers before removing storage.
      s.closing = true;
      await s.chain;
      await reach(`release drained ${name}`);
      const trash = await provisionLock(() => finishRelease(name, e, s, force));
      // The released directory was renamed aside under the lock; it is removed outside it.
      if (trash) await fsp.rm(trash, { recursive: true, force: true });
      return trash !== null;
    })().finally(() => releases.delete(name));
    releases.set(name, done);
    return { done }; // wrapped: an async function returning the promise itself would wait for it
  }
  async function finishRelease(name, e, s, force = false) {
    const same = table.get(name) === e && slots.get(name) === s && !s.released;
    const trash = path.join(path.resolve(dataDir), `${RELEASED_PREFIX}${name}.${randomBytes(8).toString('hex')}`);
    const removed = same && await s.home.lock(async () => {
      if (!force && await claimed(s)) return false;
      const refuse = () => Promise.reject(new Error(`slot ${name} was released`));
      s.released = true;
      await s.home.replayLock(() => s.home.closeReplay());
      s.home.lock = refuse; s.home.replayLock = refuse; s.exclusive = refuse;
      s.home.stream.closeAll('released');
      slots.delete(name); opening.delete(name);
      // One rename takes the directory out of the slot's name at once; its contents are removed
      // after the lock (a crash leaves the renamed directory, removed at the next start-up).
      await fsp.rename(s.root, trash);
      await syncDir(path.resolve(dataDir));
      return true;
    });
    if (!removed) {
      s.releasing = false; s.closing = closing;
      if (table.get(name) === e) homeSlots.set(name, { base: e.base, account: e.account });
      await reach(`release abandoned ${name}`);
      return null;
    }
    await table.write(name, null);
    await reach(`released ${name}`);
    return trash;
  }

  /** A provisioned slot holding no genesis `unclaimedHours` after it was provisioned is
   * released (on the relay's clock), and the sweep waits for those releases to end, outside the
   * provisioning lock. Configured slots never are released. An appointed home is never released:
   * it witnesses and receipts until the account's revocation of it is final. A suspended slot is
   * never released either. */
  async function sweepUnclaimed() {
    const started = await provisionLock(async () => {
      const now = clock();
      const out = [];
      for (const name of [...table.keys()]) {
        const e = table.get(name);
        if (configured.has(name) || now - e.at < provisioning.unclaimedHours * 3_600_000) continue;
        // Appointed is for good (HomeSlot.appointed): no lock, no module call to find it claimed.
        if (slots.get(name)?.home?.appointed === true) continue;
        const started = await startRelease(name, e);
        if (started) out.push(started.done);
      }
      return out;
    });
    await Promise.all(started.map((done) => done.catch((error) => {
      if (!(error instanceof HttpError && error.status === 503)) throw error;
    })));
  }

  /** Run `fn` under the provisioning lock once no release of `name` is under way: a release in
   * progress is waited for outside the lock, and the decision is made after it ended. */
  async function afterRelease(name, fn) {
    for (;;) {
      const r = await provisionLock(async () => {
        const pending = releases.get(name);
        if (pending) return { pending };
        // `fn` may ask to wait outside the lock too (`waitFor`), and is then run again.
        let waitFor = null;
        const value = await fn((promise) => { waitFor = promise; });
        return waitFor ? { pending: waitFor } : { value };
      });
      if (!r.pending) return r.value;
      await r.pending.catch(() => {});
    }
  }

  /** The slot's generation, opaque: it changes whenever the name is released and provisioned
   * again (a provisioned row's time and member request are new each time), and stays the same
   * across restarts. A configured home slot's names its account. Null for a name not held. */
  function generationOf(name) {
    const e = table.get(name);
    if (e) return sha256(Buffer.from(`colophon-slot-generation\nprovisioned\n${name}\n${e.account}\n${e.at}\n${e.request}`)).slice(0, 32);
    const h = homeSlots.get(name);
    if (h && configured.has(name)) return sha256(Buffer.from(`colophon-slot-generation\nconfigured\n${name}\n${h.account}`)).slice(0, 32);
    return null;
  }

  /**
   * A grant request's judgement. `verify()` first asks the module's `provision_access` with no
   * state, outside any lock: a call it refuses there (possession, account, audience, purpose,
   * args, a controller, or a grant over its `perHour`) costs no history work and does not wait
   * for, or hold up, the operator slot. Otherwise it takes the operator slot's mutation lock,
   * settles the slot (its head fresh), and asks `provision_access` again over its state and the
   * call's replay row; the lock is then held until `finish()`, after the gate's remaining checks,
   * the reservation and the durable write. An authority upload to the operator slot (a
   * revocation) waits for it, and it waits for an upload: a revocation the home has accepted is
   * seen by every later verification, and none verified before it commits after it. The gate's
   * cheap checks run before `verify()`, outside the lock. An operator slot that is not held, not
   * set up, or stopped answers 503 unavailable. The replay table changes only under the door's
   * own lock, so both asks see the same rows.
   */
  /** Whether a grant call is by a member of the operator account the home holds now: the module's
   * judgement with no state (possession, account, audience, purpose, args), then with the operator
   * slot's current state (membership, revocation, expiry, the grant's rate), read as it stands,
   * with no lock taken. Only then may the call start work such as a sweep; the call is judged
   * again, under the operator slot's lock, before it has any effect. Pure. */
  function grantPassesEarly(call, body) {
    if (!call || !provisionReplay) return false;
    const operatorSlot = slots.get(provisioning.operator.slot);
    if (!operatorSlot?.home?.state || operatorSlot.releasing || operatorSlot.released) return false;
    try {
      const parsed = homeModule.call({ op: 'call_key', call });
      const rows = parsed.parsed ? provisionReplay.lookup(parsed.key, parsed.signer) : { existing: null, signerRows: [] };
      const member = parsed.parsed && parsed.signer.startsWith('member:') ? parsed.signer.slice('member:'.length) : null;
      const early = homeModule.call({ op: 'provision_access', state: null, call, body: body.toString('base64'),
        operator: provisioning.operator.account, audience: provisioning.audience, now: clock(),
        existing: rows.existing, signerRows: rows.signerRows, replayRows: provisioning.replayRows,
        perHour: grantLimits(provisioning, member).perHour });
      if (early.status !== 503) return false; // refused with no state
      const judged = homeModule.call({ op: 'provision_access', state: operatorSlot.home.state, call, body: body.toString('base64'),
        operator: provisioning.operator.account, audience: provisioning.audience, now: clock(),
        existing: rows.existing, signerRows: rows.signerRows, replayRows: provisioning.replayRows,
        perHour: grantLimits(provisioning, member).perHour });
      return Boolean(judged.allowed);
    } catch (error) { if (error instanceof ModuleError) return false; throw error; }
  }

  function grantSession(call, body) {
    let s = null; let unlock = null;
    const verify = async () => {
      const parsed = call ? homeModule.call({ op: 'call_key', call }) : { parsed: false };
      const rows = parsed.parsed ? provisionReplay.lookup(parsed.key, parsed.signer) : { existing: null, signerRows: [] };
      const member = parsed.parsed && parsed.signer.startsWith('member:') ? parsed.signer.slice('member:'.length) : null;
      const ask = (state) => homeModule.call({ op: 'provision_access', state, call: call ?? '', body: body.toString('base64'),
        operator: provisioning.operator.account, audience: provisioning.audience, now: clock(),
        existing: rows.existing, signerRows: rows.signerRows, replayRows: provisioning.replayRows,
        perHour: grantLimits(provisioning, member).perHour });
      const early = ask(null);
      if (early.status !== 503) { await reach('grant refused'); return early; }
      const name = provisioning.operator.slot;
      let o = null;
      if (homeSlots.has(name)) o = await slot(name).catch((error) => { if (error instanceof HttpError) return null; throw error; });
      if (o && !o.closing && !o.releasing && !o.released && o.home) {
        s = o; enter(s);
        await reach('grant locking');
        await new Promise((locked, failed) => {
          s.home.lock(() => new Promise((release) => { unlock = release; locked(); })).catch(failed);
        });
        await s.home.keepLease();
        try { await s.home.settle(); } catch (error) { if (!(error instanceof ModuleError)) throw error; }
      }
      const r = ask(s ? s.home.state : null);
      provisionReplay.dropRows(r.drop);
      await reach(r.allowed ? 'grant verified' : 'grant refused');
      return r;
    };
    const finish = () => { if (unlock) unlock(); if (s) leave(s); };
    return { verify, finish };
  }

  async function door(req, res) {
    if (req.method !== 'POST') throw new HttpError(405, 'Method not allowed', { allow: 'POST' });
    // Checked before the body is read. A page on an origin not listed is refused here; any page
    // must send application/json, which a browser preflights, and only a listed origin's
    // preflight succeeds.
    if (req.headers.origin !== undefined && !origins.has(req.headers.origin)) { req.resume(); throw new HttpError(403, 'Requests from this origin are refused'); }
    if (!isJsonType(req.headers['content-type'])) { req.resume(); throw new HttpError(415, 'Content-Type must be application/json'); }
    const body = await readBody(req, 4096);
    const asked = parseProvisionBody(body) ?? {};
    const address = clientAddress(req);
    const authorization = req.headers.authorization;
    const route = provisionRoute(provisioning, authorization);
    const m = /^Colophon ([A-Za-z0-9_-]+)$/.exec(authorization ?? '');
    const call = m ? Buffer.from(m[1], 'base64url').toString('base64') : null;
    // A request the open or token path refuses (its address over its share, a missing or wrong
    // token) is refused here, before any work under the door's lock: it can neither start nor
    // wait for the sweep of unclaimed slots.
    const early = admitProvision.preflight({ address, authorization });
    if (early) {
      throw new HttpError(early.status, early.error ?? 'Refused', early.retryAfter ? { 'retry-after': String(early.retryAfter) } : {},
        early.result ? { result: early.result } : undefined);
    }
    // Releases of unclaimed slots drain outside the lock; a release of the asked name is waited
    // for before the request is decided. A grant request sweeps only once its call passes the
    // module's stateless judgement (possession, account, audience, purpose, args): anything else
    // is refused under the lock as before, having started nothing.
    if (route !== 'grant' || grantPassesEarly(call, body)) await sweepUnclaimed();
    const answer = await afterRelease(asked.slot, async (waitFor) => {
      const valid = typeof asked.slot === 'string' && SLOT.test(asked.slot);
      const occupied = valid && (configured.has(asked.slot)
        || (!table.get(asked.slot) && await fsp.lstat(path.join(path.resolve(dataDir), asked.slot)).then(() => true, () => false)));
      // A full home with releases under way: wait for them outside the lock, then decide again,
      // so a slot being reclaimed is not answered 507.
      if (!table.get(asked.slot) && table.size >= provisioning.maxSlots && releases.size > 0) {
        waitFor(Promise.allSettled([...releases.values()]));
        return null;
      }
      const session = route === 'grant' && provisioning.enabled ? grantSession(call, body) : null;
      const decide = async (verify) => {
        const verdict = await admitProvision({ ...asked, address, authorization,
          held: { entry: table.get(asked.slot), occupied, count: table.size },
          grant: route === 'grant' ? { replay: provisionReplay, heldBy: (member) => table.heldBy(member), verify } : undefined });
        if (!verdict.admit) {
          // A verified call refused with no effect (the slot's holder, the room): recorded
          // completed, so it spends its grant's `perHour` like an admitted one.
          if (verdict.reserve) await provisionReplay.reserve(verdict.reserve, null);
          throw new HttpError(verdict.status, verdict.error ?? 'Refused', verdict.retryAfter ? { 'retry-after': String(verdict.retryAfter) } : {},
            verdict.result ? { result: verdict.result } : undefined);
        }
        const reserve = verdict.grant?.reserve;
        if (verdict.existing) {
          // An idempotent answer: the call is recorded (it counts against its grant's rate) and
          // has no effect.
          if (reserve) await provisionReplay.reserve(reserve, null);
          return { request: Buffer.from(verdict.existing.request, 'base64'), generation: generationOf(asked.slot) };
        }
        // One account, one home slot per base: a slot that would repeat another's (account,
        // base) would let one captured call be taken once in each. Refused before any effect.
        if (baseHolder(asked.account, asked.base, asked.slot) !== undefined) {
          throw new HttpError(409, 'Another home slot already serves this account at this base');
        }
        // Verify, reserve, make the slot (the durable write names the call's digest), complete.
        if (reserve) { await provisionReplay.reserve(reserve, { slot: asked.slot }); await reach('grant reserved'); }
        const request = await memberRequest({ wasm: homeModule, key: homeKey, account: asked.account, base: asked.base, now: clock() });
        // Durable before answered: a crash after this write leaves a row the same request completes.
        await table.write(asked.slot, { account: asked.account, base: asked.base, at: clock(), request: request.toString('base64'), by: verdict.by });
        await reach('provision written');
        if (reserve) await provisionReplay.complete(reserve.key, 'completed');
        homeSlots.set(asked.slot, { base: asked.base, account: asked.account });
        // The row is durable: a shutdown that began meanwhile leaves the slot to open at the next
        // start, and the request is answered, not refused after its effect.
        await slot(asked.slot).catch((error) => { if (!closing) throw error; });
        return { request, generation: generationOf(asked.slot) };
      };
      if (!session) return decide(undefined);
      try { return await decide(session.verify); } finally { session.finish(); }
    });
    // The slot's generation, read under the same lock as the answer: the operator API's commands
    // name it, and a later read could see a name released and provisioned again.
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': answer.request.length, 'colophon-slot-generation': answer.generation });
    res.end(answer.request);
  }

  // ---------------------------------------------------------------------------------------------
  // The operator API (operator behaviour, not protocol): suspend and resume a home slot, and read
  // its state. Only with gate "token", by the same token; otherwise it does not exist (404).

  const admitOperator = provisioning.gates.has('token') ? operatorGate(provisioning, clock) : null;

  async function operator(req, res, url) {
    if (admitOperator && url.pathname === '/v1/operator/slots') return operatorList(req, res, url);
    const m = /^\/v1\/operator\/slots\/([^/]+)(?:\/(suspend|resume))?$/.exec(url.pathname);
    if (!admitOperator || !m) { req.resume(); throw new HttpError(404, 'Not found'); }
    const [, name, sub] = m;
    // GET reads the state; DELETE removes the slot; POST .../suspend and .../resume act on it.
    const allow = sub ? 'POST' : 'GET, DELETE';
    if (!allow.split(', ').includes(req.method)) { req.resume(); throw new HttpError(405, 'Method not allowed', { allow }); }
    const action = sub ?? (req.method === 'DELETE' ? 'delete' : undefined);
    // For an operator's own tools, never a page: a page on an origin not listed is refused.
    if (req.headers.origin !== undefined && !origins.has(req.headers.origin)) { req.resume(); throw new HttpError(403, 'Requests from this origin are refused'); }
    req.resume(); // no body is read
    const refused = admitOperator({ address: clientAddress(req), authorization: req.headers.authorization });
    if (refused) {
      throw new HttpError(refused.status, 'Refused', refused.retryAfter ? { 'retry-after': String(refused.retryAfter) } : {}, { result: refused.result });
    }
    // The query: none to read the state; exactly one `generation` to change it.
    const keys = [...url.searchParams.keys()];
    if (!action && keys.length) throw new HttpError(400, 'GET /v1/operator/slots/<slot> takes no query');
    const generation = url.searchParams.get('generation');
    if (action && (keys.length !== 1 || keys[0] !== 'generation' || !generation)) {
      throw new HttpError(400, `${action} needs ?generation=<the slot's generation>, from GET /v1/operator/slots/<slot>`);
    }
    if (action === 'delete') return operatorDelete(res, name, generation);
    // A slot this home holds as a home slot, configured or provisioned; anything else is unknown.
    // Decided once no release of the name is under way (it may yet be abandoned).
    const held = async () => {
      if (!SLOT.test(name) || !homeSlots.has(name)) throw notProvisioned();
      const s = await slot(name);
      if (!s.home || s.releasing || s.released) throw notProvisioned();
      return s;
    };
    if (!action) {
      const state = await afterRelease(name, async () => {
        const s = await held();
        await s.home.reconcileSuspension();
        // This home as the account's verified history names it: "unappointed" before the first
        // upload, then "home", "revocationPending", "revoked" or "notHome" (the module's
        // `status`); "unknown" when the history cannot be read now. An operator may act on an
        // account's own removal of this home, which only its controllers can sign.
        const st = s.home.status();
        const standing = !st.appointed ? 'unappointed' : typeof st.standing === 'string' ? st.standing : 'unknown';
        return { slot: name, provisioned: table.get(name) !== undefined, suspended: s.home.suspended, generation: generationOf(name), standing };
      });
      return send(res, 200, state);
    }
    // Under the provisioning lock, as a release and a provision are: the generation is compared
    // there, so a command meant for a slot that has since been released and provisioned again
    // (the same name, another library) never reaches the new one.
    await afterRelease(name, async () => {
      const s = await held();
      if (generationOf(name) !== generation) throw new HttpError(409, 'The slot has another generation', {}, { result: 'refused:staleGeneration' });
      await s.home.setSuspended(action === 'suspend');
    });
    res.writeHead(204);
    return res.end();
  }

  /**
   * `DELETE /v1/operator/slots/<slot>?generation=<g>`: removes a provisioned slot, its data and its
   * row, by the release path forced (an appointed slot is released too). Only a slot the door
   * provisioned (a configured one is the operator's own: 409 `refused:configured`), at that
   * generation (409 `refused:staleGeneration`), and already suspended, so a delete always follows a
   * suspension the operator decided on (409 `refused:notSuspended`). 204 once the slot is gone; a
   * name the home does not hold is 404 `refused:notProvisioned` (a delete already done). The name
   * may be provisioned again afterwards, with a new generation. Private listener only (404 on a
   * single public listener). A delete interrupted part way (the slot out of dispatch, its row or
   * directory still there) is finished by a retry at the same generation. In-flight requests on
   * the slot drain first; each is bounded by the server's request timeout, and new ones are
   * refused once the release starts.
   */
  async function operatorDelete(res, name, generation) {
    // Destructive: served on the private listener only, never on a single public listener.
    if (!privateApi) throw new HttpError(404, 'Not found');
    const started = await afterRelease(name, async () => {
      if (!SLOT.test(name)) throw notProvisioned();
      const e = table.get(name);
      // A delete interrupted after the slot left dispatch (its directory or row not yet gone):
      // a retry at the row's generation finishes it.
      if (e && !homeSlots.has(name) && !configured.has(name)) {
        if (generationOf(name) !== generation) throw new HttpError(409, 'The slot has another generation', {}, { result: 'refused:staleGeneration' });
        // Under the provisioning lock, as every write of the table is.
        const removed = await finishInterruptedDelete(name, e);
        return { done: Promise.resolve(removed) };
      }
      if (!homeSlots.has(name)) throw notProvisioned();
      if (!e || configured.has(name)) throw new HttpError(409, 'A configured slot is not deleted here', {}, { result: 'refused:configured' });
      const s = await slot(name);
      if (!s.home || s.releasing || s.released) throw notProvisioned();
      if (generationOf(name) !== generation) throw new HttpError(409, 'The slot has another generation', {}, { result: 'refused:staleGeneration' });
      await s.home.reconcileSuspension();
      if (!s.home.suspended) throw new HttpError(409, 'Suspend the slot before deleting it', {}, { result: 'refused:notSuspended' });
      return startRelease(name, e, { force: true });
    });
    const removed = started ? await started.done : false;
    if (!removed) throw new HttpError(503, 'The slot could not be deleted now; try again', { 'retry-after': '60' }, { result: 'unavailable' });
    await reach(`deleted ${name}`);
    res.writeHead(204);
    return res.end();
  }

  /** Finishes a delete that stopped after its slot left dispatch: its directory (if still there)
   * is renamed aside and its row removed, under the provisioning lock (the caller's), then the
   * directory is removed. Resolves true. */
  async function finishInterruptedDelete(name, e) {
    if (table.get(name) !== e) return false;
    slots.delete(name); opening.delete(name);
    const root = path.join(path.resolve(dataDir), name);
    const trash = path.join(path.resolve(dataDir), `${RELEASED_PREFIX}${name}.${randomBytes(8).toString('hex')}`);
    const st = await fsp.lstat(root).catch((error) => { if (error.code === 'ENOENT') return null; throw error; });
    if (st && (!st.isDirectory() || st.isSymbolicLink())) throw new Error(`${root} is not the slot's directory`);
    if (st) { await fsp.rename(root, trash); await syncDir(path.resolve(dataDir)); }
    await table.write(name, null);
    // The directory, renamed aside, is removed after the row (a crash leaves it for start-up).
    if (st) await fsp.rm(trash, { recursive: true, force: true });
    await reach(`released ${name}`);
    return true;
  }

  /** The operator's gate for a request: method, origin, then the token and its share, as for
   * every operator route. Throws the refusal. */
  function operatorAdmit(req, allow) {
    if (req.method !== allow) { req.resume(); throw new HttpError(405, 'Method not allowed', { allow }); }
    if (req.headers.origin !== undefined && !origins.has(req.headers.origin)) { req.resume(); throw new HttpError(403, 'Requests from this origin are refused'); }
    req.resume();
    const refused = admitOperator({ address: clientAddress(req), authorization: req.headers.authorization });
    if (refused) {
      throw new HttpError(refused.status, 'Refused', refused.retryAfter ? { 'retry-after': String(refused.retryAfter) } : {}, { result: refused.result });
    }
  }

  /**
   * `GET /v1/operator/slots?after=<slot>&limit=<n>`: every home slot this home holds, configured
   * or provisioned, in name order, a page at a time (`limit` 1-1000, default 100), each as
   * `{slot, provisioned, suspended, generation}`; `next` is the cursor for the page after (the
   * last name), or null at the end. A slot whose release is under way is left out (it may yet be
   * abandoned: it is listed again once it is). Read under the door's lock, so a page never shows
   * a generation a provision or release is changing.
   */
  async function operatorList(req, res, url) {
    operatorAdmit(req, 'GET');
    for (const k of url.searchParams.keys()) if (k !== 'after' && k !== 'limit') throw new HttpError(400, `GET /v1/operator/slots takes after and limit only, not ${k}`);
    if (url.searchParams.getAll('after').length > 1 || url.searchParams.getAll('limit').length > 1) throw new HttpError(400, 'after and limit are given once');
    const after = url.searchParams.get('after') ?? '';
    const limit = clampInt(url.searchParams.get('limit'), 100, 1, 1000);
    const page = await provisionLock(async () => {
      const names = [...homeSlots.keys()].filter((n) => n > after).sort();
      const out = [];
      for (const name of names.slice(0, limit)) {
        let suspended;
        try {
          const s = await slot(name);
          await s.home.reconcileSuspension();
          suspended = s.home.suspended;
        } catch (error) {
          // A slot that cannot be opened now: its marker on disk says.
          if (!(error instanceof HttpError)) throw error;
          suspended = await fsp.lstat(path.join(path.resolve(dataDir), name, SUSPENSION_FILE)).then(() => true, () => false);
        }
        out.push({ slot: name, provisioned: table.get(name) !== undefined, suspended, generation: generationOf(name) });
      }
      return { slots: out, next: names.length > limit ? out[out.length - 1].slot : null };
    });
    return send(res, 200, page);
  }

  /** Which listener a path belongs to. With a private listener, provisioning and the operator API
   * are served only there, and the public listener answers 404 for them as for any unknown path;
   * the private listener serves nothing else. Without one, the public listener serves everything. */
  const privatePath = (pathname) => pathname === '/v1/provision' || pathname.startsWith('/v1/operator/');

  async function handle(req, res, work, scope) {
    if (closing) throw relayClosing();
    const url = new URL(req.url, 'http://relay.invalid');
    if (url.pathname === '/healthz' && req.method === 'GET') {
      const failing = failingChecks();
      return failing.length ? send(res, 503, { ok: false, failing }) : send(res, 200, { ok: true });
    }
    if (metricsToken && url.pathname === '/metrics') return serveMetrics(req, res);
    if (scope !== 'all' && (scope === 'private') !== privatePath(url.pathname)) { req.resume(); throw new HttpError(404, 'Not found'); }
    if (provisioning.enabled && url.pathname === '/v1/provision') return door(req, res);
    if (url.pathname.startsWith('/v1/operator/')) return operator(req, res, url);
    const route = /^\/v1\/libraries\/([^/]+)(?:\/(changes|records|head|authority|pending|predecessor|routes|stream)(?:\/(.*))?)?$/.exec(url.pathname);
    if (!route) throw new HttpError(404, 'Not found');
    const [, name, section, recordPath] = route;
    // With provisioning on, a slot this home does not hold is named as such (an app asks for its
    // slot at the door); off, it is the 0.3 answer, unchanged.
    if (provisioning.enabled && !homeSlots.has(name) && !auth.has(name)) {
      throw notProvisioned();
    }
    if (!SLOT.test(name)) throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Bearer' });
    if (!homeSlots.has(name)) {
      if (section === 'routes' || section === 'stream') throw new HttpError(404, 'Not found');
      authorize(req, name);
    }
    const s = await slot(name);
    // Counted from here until the response has ended and this handler has settled.
    if (s.releasing || s.released) throw notProvisioned();
    if (closing || s.closing) throw relayClosing();
    enter(s); work.slot = s;
    if (s.home && await s.home.handle(req, res, url, section, recordPath, work)) return undefined;
    if (section === 'records' && recordPath === 'batch') {
      const body = await readBatchBody(req, url);
      let parsed;
      try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); } catch { throw new HttpError(400, 'Invalid JSON'); }
      const paths = parsed?.paths;
      if (!Array.isArray(paths) || paths.length === 0 || paths.length > 256 ||
          new Set(paths).size !== paths.length || paths.some((p) => typeof p !== 'string' || !s.classify(p))) {
        throw new HttpError(400, 'Expected 1–256 unique valid record paths');
      }
      return serveBatch(res, s, paths.map((path) => ({ path, status: 200 })));
    }
    if (!s.home && ['head', 'authority', 'pending', 'predecessor'].includes(section)) throw new HttpError(404, 'Not found');
    if (!section) {
      if (req.method !== 'GET') throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      const published = Object.fromEntries(Object.entries(effective).filter(([k]) => !UNPUBLISHED.includes(k)));
      const { slotBytes } = effective;
      return send(res, 200, { protocol: PROTOCOL, slot: name, limits: published, ...(slotBytes ? { quotaBytes: slotBytes } : {}),
        ...(s.home ? { home: { member: s.home.key.memberId }, layouts: homeModule.call({ op: 'limits' }).layouts } : {}) });
    }
    if (section === 'changes') return serveChanges(req, res, url, s, recordPath);
    // A home's access decision named the record's kind already.
    const kind = work.kind ?? s.classify(recordPath);
    if (!kind) throw new HttpError(400, 'Invalid record path');
    if (url.search) throw new HttpError(400, 'Record URLs take no query');
    if (req.method === 'GET' || req.method === 'HEAD') return serveRecord(req, res, s, recordPath);
    if (req.method === 'PUT') {
      const max = kind === 'blob' ? effective.blobBytes : effective.recordBytes;
      const body = await readBody(req, max);
      const digest = sha256(body); // once, for the check, the index and the ETag
      if (kind === 'blob' && digest !== recordPath.slice(6)) throw new HttpError(400, 'Blob name must be the SHA-256 of its bytes');
      const conditional = req.headers['if-none-match'];
      let status;
      if (conditional === '*') status = await s.putImmutable(recordPath, body, digest);
      else if (conditional !== undefined) throw new HttpError(400, 'Only If-None-Match: * is supported');
      else if (kind === 'state') {
        const expected = req.headers['if-match'];
        if (!expected || !/^"[0-9a-f]{64}"$/.test(expected)) throw new HttpError(428, 'Live replacement requires If-Match');
        status = await s.replaceRequest(recordPath, body, expected, digest);
      }
      else if (kind === 'request') status = await s.replaceRequest(recordPath, body, undefined, digest);
      else throw new HttpError(428, 'Immutable records require If-None-Match: *');
      res.writeHead(status, { etag: `"${digest}"`, 'content-length': 0 });
      return res.end();
    }
    if (req.method === 'DELETE') {
      if (kind !== 'request') throw new HttpError(405, 'Only requests/ records can be deleted', { allow: 'GET, PUT' });
      const status = await s.deleteRequest(recordPath);
      res.writeHead(status); return res.end();
    }
    throw new HttpError(405, 'Method not allowed', { allow: kind === 'request' ? 'GET, PUT, DELETE' : 'GET, PUT' });
  }

  // ---------------------------------------------------------------------------------------------
  // Metrics for the operator (`GET /metrics`, off unless `metrics.tokenSha256` is set): counters
  // read from memory, naming no slot or account. The event loop's lag is sampled once a second.

  const started = Date.now();
  let lag = 0;
  let lagTimer = null;
  if (metricsToken) {
    let expected = Date.now() + 1000;
    lagTimer = setInterval(() => { const at = Date.now(); lag = Math.max(0, at - expected); expected = at + 1000; }, 1000);
    lagTimer.unref?.();
  }
  function serveMetrics(req, res) {
    req.resume();
    const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization ?? '');
    const given = createHash('sha256').update(match ? match[1] : '').digest();
    if (!match || !timingSafeEqual(given, metricsToken)) throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Bearer' });
    if (req.method !== 'GET') throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
    const lock = healthChecks()['container lock'];
    const homes = [...slots.values()].filter((s) => s.home);
    send(res, 200, {
      uptimeSeconds: Math.round((Date.now() - started) / 1000),
      rssBytes: process.memoryUsage.rss(),
      moduleMemoryBytes: homeModule?.memoryBytes() ?? 0,
      moduleResets: homeModule?.resets ?? 0,
      requestsInFlight: requests.size, // others: this one is answered before it is counted
      eventLoopLagMs: lag,
      slots: homeSlots.size + auth.size, // every slot this relay holds, open or not
      // As of each home's last scheduler pass that asked the module.
      stoppedSlots: homes.filter((s) => s.home.lastStatus?.stopped === true).length,
      containerLockAgeSeconds: Number.isFinite(lock?.lastBeatAt) ? Math.max(0, Math.round((Date.now() - lock.lastBeatAt) / 1000)) : null,
    });
  }

  /** `GET`/`HEAD {base}/records/<path>`: the stored file, checked against the index. */
  async function serveRecord(req, res, s, recordPath) {
    const entry = s.current.get(recordPath);
    if (!entry) throw new HttpError(404, 'Not found');
    const etag = `"${entry.sha256}"`;
    const conditional = req.headers['if-none-match'];
    if (conditional === '*' || conditional?.split(',').some((tag) => tag.trim().replace(/^W\//, '') === etag)) {
      res.writeHead(304, { etag, 'cache-control': 'no-store' });
      return res.end();
    }
    if (req.method === 'HEAD') {
      const file = await s.target(recordPath, false);
      const st = file && await fsp.lstat(file).catch((e) => { if (e.code !== 'ENOENT') throw e; });
      if (!st) throw new HttpError(404, 'Not found');
      if (!st.isFile() || st.size !== entry.size) throw new HttpError(500, 'Relay storage does not match index');
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': entry.size, etag });
      return res.end();
    }
    const bytes = await s.readFile(recordPath);
    const actual = sha256(bytes);
    if (bytes.length !== entry.size || actual !== entry.sha256) throw new HttpError(500, 'Relay storage does not match index');
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': bytes.length,
      etag, 'cache-control': 'no-store' });
    return res.end(bytes);
  }

  /** `GET {base}/changes`: its query, checked. */
  function changesQuery(req, url, rest) {
    if (req.method !== 'GET' || rest !== undefined) throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
    return {
      after: url.searchParams.get('after') ?? '',
      limit: clampInt(url.searchParams.get('limit'), 500, 1, effective.pageEntries),
      wait: clampInt(url.searchParams.get('wait'), 0, 0, effective.waitSeconds),
      namespaces: url.searchParams.getAll('namespace').filter((n) => n.length > 0),
    };
  }
  /** A home's first page of the change feed, taken under its lock with the call's judgement. */
  function firstChanges(req, url, rest, s) {
    const q = changesQuery(req, url, rest);
    return s.changes(q.after, q.limit, q.namespaces);
  }
  /**
   * The change feed, and its long poll. A home slot passes `judged`: the first page and its
   * commit count, taken under its lock with the call's judgement. When the home's state changes
   * during the wait (a revocation, among others) the poll ends with the page it has (empty, the
   * same cursor), so the caller is judged again on its next poll.
   */
  async function serveChanges(req, res, url, s, rest, judged) {
    const { limit, wait, namespaces, after } = changesQuery(req, url, rest);
    let page = judged ? judged.page : s.changes(after, limit, namespaces);
    const deadline = Date.now() + wait * 1000;
    const changed = () => Boolean(judged) && s.home.commits !== judged.commits;
    while (page.entries.length === 0 && Date.now() < deadline && !changed()) {
      // Checked right before registering (nothing in between waits): a release or a shutdown
      // that began meanwhile has already woken every waiter, and would not wake this one.
      if (s.releasing || s.released) throw notProvisioned();
      if (s.closing) throw relayClosing();
      const waiting = s.waitForEntry(deadline - Date.now(), res, namespaces);
      await reach('changes waiting'); // a test hook (traced builds only)
      await waiting;
      if (res.destroyed) return undefined;
      if (s.releasing) throw notProvisioned(); // woken by a release
      if (s.closing) throw relayClosing(); // woken by shutdown: retry elsewhere or later
      if (changed()) break;
      page = s.changes(page.cursor, limit, namespaces);
    }
    return send(res, 200, page);
  }

  async function upgrade(req, connect) {
    // The ticket is in the query: never log req.url (or this URL) anywhere.
    const url = new URL(req.url, 'http://relay.invalid');
    const match = STREAM_PATH.exec(url.pathname);
    if (!match || !homeSlots.has(match[1])) throw new HttpError(404, 'Not found');
    if (closing) throw relayClosing();
    const s = await slot(match[1]); // the home burns the ticket before any other refusal
    if (s.releasing || s.released) { s.home.stream.take(url); throw notProvisioned(); }
    if (closing || s.closing) { s.home.stream.take(url); throw relayClosing(); }
    enter(s);
    try { await s.home.upgrade(req, url, connect); } finally { leave(s); }
  }

  const serve = (scope) => function listener(req, res) {
    const listed = enforceAnswerHeaders(req, res, origins);
    if (req.method === 'OPTIONS') { answerOptions(req, res, listed); return; }
    const work = { slot: null };
    const settled = handle(req, res, work, scope).catch((error) => {
      if (res.headersSent || res.destroyed) { res.destroy(); return; }
      if (error instanceof HttpError) send(res, error.status, error.body !== undefined ? error.body : { error: error.message }, error.headers);
      else { console.error(error); send(res, 500, { error: 'Internal relay error' }); }
    });
    requests.add(settled);
    settled.finally(() => requests.delete(settled));
    Promise.all([settled, ended(res)]).then(() => { if (work.slot) leave(work.slot); });
  };
  // With `privateApi`, two listeners: the public one (everything but provisioning and the
  // operator API) and the private one (only those, and /healthz).
  const listener = serve(privateApi ? 'public' : 'all');
  const privateListener = privateApi ? serve('private') : null;

  // The scheduler: recording entries, heads and forwarding for every home slot, on the relay's clock.
  // Slots tick concurrently (each runs one pass at a time), so one slot never waits on another.
  // Each pass starts from the next slot in turn, so the same slots do not always ask first for
  // the home-wide forwarding budget (`forwardPasses`).
  let tickRound = 0;
  const tickAll = async () => {
    const names = [...homeSlots.keys()];
    const start = names.length ? tickRound++ % names.length : 0;
    const order = [...names.slice(start), ...names.slice(0, start)];
    await Promise.all(order.map(async (name) => {
      let s;
      try { s = await slot(name); } catch { return; }
      if (s.closing || s.releasing || s.released) return;
      enter(s);
      try { await s.home.tick(); } catch (error) { console.error(`home tick failed for slot ${name}: ${error.message}`); } finally { leave(s); }
    }));
  };
  let timer = null;
  for (const name of configured) if (homeSlots.has(name)) await slot(name);
  for (const name of table.keys()) if (!configured.has(name)) {
    try { await slot(name); }
    catch (error) { if (!(error instanceof HttpError && error.status === 503)) throw error; }
  }
  if (table.size > 0) await sweepUnclaimed();
  // The timer runs whenever a home slot may exist: provisioning adds slots at run time, and
  // `tickAll` reads the slot table on every pass.
  if ((homeSlots.size > 0 || provisioning.enabled) && tickMs > 0) { timer = setInterval(() => { tickAll(); }, tickMs); timer.unref?.(); }

  let closePromise;
  return { listener, privateListener, upgrade, homes: homeModule !== null, limits: effective, slot, tickAll, close: () => {
    if (closePromise) return closePromise;
    closing = true;
    if (timer) clearInterval(timer);
    if (lagTimer) clearInterval(lagTimer);
    for (const s of slots.values()) {
      s.closing = true;
      s.home?.stream.closeAll('restart');
      s.home?.stop();
      for (const waiter of [...s.waiters]) waiter.wake();
    }
    const drain = async () => {
      await Promise.allSettled([...requests, ...opening.values(), ...releases.values(), provisionTail]);
      // Then each home's own work no request carries (forwarding, its saves, queued lock work).
      await Promise.all([...slots.values()].map(async (s) => { await drained(s); await s.home?.quiesce(); await s.chain; }));
      await provisionReplay?.close();
      await unlock();
    };
    closePromise = boundedDrain(drain(), drainMs);
    return closePromise;
  } };
  } catch (error) { await unlock(true); throw error; }
}

/** How long shutdown waits for work in flight: under the 10 s Docker gives a container to stop
 * by default (docker-compose.yml gives 15 s), with time left to exit. A forwarding pass's waits
 * on other homes are cut at once; what remains is local commits and requests in flight. */
export const DRAIN_MS = 8_000;

// The lock stays held until writes settle, even after the shutdown deadline expires.
function boundedDrain(work, ms = DRAIN_MS) {
  let timer;
  return Promise.race([work, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Relay shutdown timed out draining writes')), ms);
  })]).finally(() => clearTimeout(timer));
}

// Publish only complete, synced owner records. A crash before link leaves an unreferenced
// temp file, never an empty lock or reclaim marker.
async function publishLock(file, bytes, replace = false) {
  const tmp = `${file}.${process.pid}.${randomBytes(12).toString('hex')}`;
  const handle = await fsp.open(tmp, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
  try {
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    if (replace) await fsp.rename(tmp, file);
    else await fsp.link(tmp, file);
  } finally { await fsp.unlink(tmp).catch((e) => { if (e.code !== 'ENOENT') throw e; }); }
}

async function lockSnapshot(file) {
  let handle;
  try { handle = await fsp.open(file, fsc.O_RDONLY | fsc.O_NOFOLLOW); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new Error(`Relay dataDir lock is not a regular file: ${file}`);
    const bytes = await handle.readFile('utf8');
    let owner;
    try { owner = JSON.parse(bytes); } catch { /* Legacy empty/torn lock. */ }
    let stale = false;
    if (Number.isSafeInteger(owner?.pid) && owner.pid > 0) {
      try { process.kill(owner.pid, 0); }
      catch (e) { if (e.code === 'ESRCH') stale = true; else if (e.code !== 'EPERM') throw e; }
    } else stale = Date.now() - st.mtimeMs > 10_000;
    return { st, bytes, stale };
  } finally { await handle.close(); }
}

async function sameLock(file, snapshot) {
  const now = await lockSnapshot(file);
  return now && now.st.ino === snapshot.st.ino && now.st.dev === snapshot.st.dev && now.bytes === snapshot.bytes;
}

async function lockDataDir(dataDir, previousLock = null) {
  const file = path.join(dataDir, '.relay.lock');
  const owner = JSON.stringify({ pid: process.pid, at: new Date().toISOString() }) + '\n';
  try { await publishLock(file, owner); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const snapshot = await lockSnapshot(file);
    if (!snapshot) return lockDataDir(dataDir, previousLock);
    if (snapshot.stale) {
      // Serialize removal of the main lock. Dead reclaim owners are recoverable too;
      // compare inode and payload before removing either kind of stale lock.
      const reclaimFile = `${file}.reclaim`;
      let reclaim;
      for (let attempt = 0; attempt < 8; attempt++) {
        try { await publishLock(reclaimFile, owner); reclaim = await lockSnapshot(reclaimFile); break; }
        catch (e) {
          if (e.code !== 'EEXIST') throw e;
          const old = await lockSnapshot(reclaimFile);
          if (!old) continue;
          if (!old.stale) throw new Error(`Relay dataDir is locked for stale-lock recovery (${reclaimFile})`);
          if (await sameLock(reclaimFile, old)) await fsp.unlink(reclaimFile).catch((e) => { if (e.code !== 'ENOENT') throw e; });
        }
      }
      if (!reclaim) throw new Error(`Relay dataDir is locked for stale-lock recovery (${reclaimFile})`);
      try {
        if (await sameLock(file, snapshot)) {
          await fsp.unlink(file);
          return await lockDataDir(dataDir, snapshot.bytes);
        }
      } finally { if (await sameLock(reclaimFile, reclaim)) await fsp.unlink(reclaimFile); }
    }
    throw new Error(`Relay dataDir is locked (${file}); another relay holds it or the lock owner cannot be verified.`);
  }
  return async (failed = false) => {
    if (failed && previousLock !== null) {
      // Failed validation preserves the prior lock without ever truncating the live file.
      await publishLock(file, previousLock, true);
    } else await fsp.unlink(file);
  };
}

/** The response has ended: finished, or closed with its client. */
function ended(res) {
  if (res.writableFinished || res.destroyed) return Promise.resolve();
  return new Promise((resolve) => { res.once('finish', resolve); res.once('close', resolve); });
}

function clampInt(value, fallback, min, max) {
  if (value === null || value === '') return fallback;
  if (!/^\d+$/.test(value)) throw new HttpError(400, 'Invalid integer parameter');
  return Math.max(min, Math.min(max, Number(value)));
}

function send(res, status, json, headers = {}) {
  const body = Buffer.from(JSON.stringify(json));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length, 'cache-control': 'no-store', ...headers });
  res.end(body);
}

/** A home's stream, on Bun's built-in `ws` module, on the same HTTP/TLS listener. A relay with
 * no home slot needs none. A relay with home slots on another runtime is refused at start-up:
 * a home that silently served no stream would leave clients polling without knowing why. */
async function enableStreams(server, relay) {
  if (!relay.homes) return;
  if (!globalThis.Bun) {
    throw new Error('A relay with home slots needs Bun (bun relay/server.js): its stream uses Bun\'s built-in WebSocket server');
  }
  const { WebSocketServer } = await import('ws');
  const streams = new WebSocketServer({ noServer: true, clientTracking: false, maxPayload: STREAM_MESSAGE_BYTES });
  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => socket.destroy());
    if (req.headers.upgrade?.toLowerCase() !== 'websocket') { socket.destroy(); return; }
    const connect = (onOpen) => {
      if (!socket.destroyed) streams.handleUpgrade(req, socket, head, onOpen);
    };
    relay.upgrade(req, connect).catch((error) => {
      if (socket.destroyed) return;
      const httpError = error instanceof HttpError;
      if (!httpError) console.error(error);
      const status = httpError ? error.status : 500;
      const body = JSON.stringify(httpError ? (error.body ?? { error: error.message }) : { error: 'Internal relay error' });
      const headers = Object.entries(httpError ? error.headers : {}).map(([name, value]) => `${name}: ${value}\r\n`).join('');
      socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\n${headers}Connection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    });
  });
}

/** `metrics`: absent or `{tokenSha256}` (64 hex: the SHA-256 of the bearer token that may read
 * `GET /metrics`). Returns the digest's bytes, or null when metrics are off. */
function metricsConfig(metrics) {
  if (metrics === undefined || metrics === null) return null;
  if (typeof metrics !== 'object' || Array.isArray(metrics) || typeof metrics.tokenSha256 !== 'string' || !HEX64.test(metrics.tokenSha256)) {
    throw new Error('metrics.tokenSha256 must be the 64-hex SHA-256 of the token that may read GET /metrics');
  }
  return Buffer.from(metrics.tokenSha256, 'hex');
}

/** Starts an HTTP (or HTTPS when `tls` holds PEM `cert` and `key`) server. With
 * `privateListen`, a second, plain HTTP server serves provisioning (`/v1/provision`) and the
 * operator API (`/v1/operator/*`), which the public server then answers 404 for: `{path}`, a Unix
 * domain socket (preferred: made mode 0600, nothing on a network carries the token), or
 * `{host, port}` on a loopback or private address (any other refuses start-up unless
 * `privateListenAllowPublic`). */
export async function startRelay({ host = '127.0.0.1', port = 8787, tls, privateListen, privateListenAllowPublic = false, ...options }) {
  if (privateListen !== undefined && privateListen !== null) checkPrivateListen(privateListen, privateListenAllowPublic);
  if (privateListen?.path) {
    // A socket left by an earlier run is replaced; anything else at that path refuses start-up.
    const st = await fsp.lstat(privateListen.path).catch((error) => { if (error.code === 'ENOENT') return null; throw error; });
    if (st && !st.isSocket()) throw new Error(`privateListen.path ${privateListen.path} exists and is not a socket`);
    if (st) await fsp.unlink(privateListen.path);
  }
  const relay = await createRelay({ ...options, privateApi: Boolean(privateListen) });
  const make = (handler, secure) => {
    const server = secure ? https.createServer({ cert: tls.cert, key: tls.key }, handler) : http.createServer(handler);
    server.requestTimeout = 60_000;
    server.headersTimeout = 20_000;
    return server;
  };
  const listen = (server, p, h) => new Promise((resolve, reject) => {
    server.once('error', reject);
    if (typeof p === 'object') server.listen(p, resolve); else server.listen(p, h, resolve);
  });
  const server = make(relay.listener, Boolean(tls));
  const privateServer = privateListen ? make(relay.privateListener, false) : null;
  try {
    await enableStreams(server, relay); // the stream is on the public listener only
    await listen(server, port, host);
    if (privateServer && privateListen.path) {
      // Made private before it is bound: only this user may connect.
      const mask = process.umask(0o177);
      try { await listen(privateServer, { path: privateListen.path }); } finally { process.umask(mask); }
      await fsp.chmod(privateListen.path, 0o600);
    } else if (privateServer) await listen(privateServer, privateListen.port, privateListen.host);
  } catch (error) {
    if (server.listening) await new Promise((resolve) => server.close(() => resolve()));
    await relay.close();
    throw error;
  }
  const address = server.address();
  const privateAddress = privateServer?.address();
  return { server, relay, host: address.address, port: address.port,
    ...(privateServer ? (typeof privateAddress === 'string' ? { privateServer, privatePath: privateAddress }
      : { privateServer, privateHost: privateAddress.address, privatePort: privateAddress.port }) : {}),
    close: async () => {
      const stopped = [server, privateServer].filter(Boolean).map((x) => new Promise((resolve) => x.close(() => resolve())));
      try { await relay.close(); }
      finally { server.closeAllConnections?.(); privateServer?.closeAllConnections?.(); await Promise.all(stopped); }
    } };
}
