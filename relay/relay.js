// Colophon 0.3 reference relay (spec §8). Stores opaque records per library slot.
// Dependency-free: node:http, node:https, node:fs, node:path and node:crypto only.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants as fsc, promises as fsp, writeSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { HomeKey, HomeModule, HomeSlot } from './home.js';
import {
  ProvisionTable, TABLE_FILE, clientAddressConfig, tableKind, clientAddressResolver, isJsonType, memberRequest, parseProvisionBody,
  provisionConfig, provisionGate,
} from './provision.js';
import path from 'node:path';

export const PROTOCOL = 'colophon/relay/3';
export const DEFAULT_LIMITS = Object.freeze({
  recordBytes: 16 * 1024 * 1024,
  blobBytes: 65536 + 16,
  pageEntries: 1000,
  waitSeconds: 30,
  slotBytes: 0, // 0 = no per-slot quota
  // Home slots only (not published at GET {base}):
  authorityBodyBytes: 16 * 1024 * 1024,
  pendingBodyBytes: 12 * 1024 * 1024,
  replayRows: 65536, // replay rows per slot, shared out per principal by the home module
  requestsPerMinute: 1200, // per address; 0 = unlimited
});

const SLOT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HEX64 = /^[0-9a-f]{64}$/;

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
      headers['access-control-allow-methods'] = CORS_METHODS;
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
    if (old) this.bytes -= old.size;
    if (e.deleted) this.current.delete(e.path);
    else { this.current.set(e.path, { size: e.size, sha256: e.sha256 }); this.bytes += e.size; }
  }

  async log(e) {
    const handle = await fsp.open(path.join(this.root, 'log.jsonl'), 'a', 0o600);
    try { await handle.write(JSON.stringify(e) + '\n'); await handle.sync(); } finally { await handle.close(); }
    this.indexEntry(e);
    const waiters = [...this.waiters];
    this.waiters.clear();
    for (const wake of waiters) wake();
  }

  /** Serializes mutations within the slot; reads use the in-memory index. */
  exclusive(fn) {
    const run = this.chain.then(fn, fn);
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

  waitForEntry(ms) {
    return new Promise((resolve) => {
      const wake = () => { clearTimeout(timer); this.waiters.delete(wake); resolve(); };
      const timer = setTimeout(wake, ms);
      this.waiters.add(wake);
    });
  }

  async putImmutable(p, body) {
    return this.exclusive(async () => {
      const digest = sha256(body);
      const existing = this.current.get(p);
      if (existing) {
        if (existing.sha256 === digest && existing.size === body.length) return 200;
        throw new HttpError(412, 'A different record already exists at this path');
      }
      this.checkQuota(body.length);
      const file = await this.target(p, true);
      const staged = await this.stage(body);
      try {
        await fsp.link(staged, file);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const old = await this.readFile(p);
        if (!old.equals(body)) throw new HttpError(412, 'A different record already exists at this path');
      } finally { await fsp.rm(staged, { force: true }); }
      await syncDir(path.dirname(file));
      await this.log({ path: p, size: body.length, sha256: digest });
      return 201;
    });
  }

  async replaceRequest(p, body, expected) {
    return this.exclusive(async () => {
      const digest = sha256(body);
      const existing = this.current.get(p);
      if (existing && existing.sha256 === digest) return 200;
      if (expected !== undefined && (!existing || `"${existing.sha256}"` !== expected)) throw new HttpError(412, 'Live slot changed');
      this.checkQuota(body.length - (existing ? existing.size : 0));
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

  checkQuota(added) {
    if (this.limits.slotBytes > 0 && this.bytes + added > this.limits.slotBytes) {
      throw new HttpError(507, 'Library slot quota exceeded');
    }
  }

  async stage(body) {
    const staged = path.join(this.root, 'tmp', randomBytes(12).toString('hex'));
    const handle = await fsp.open(staged, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
    try { await handle.write(body); await handle.sync(); } finally { await handle.close(); }
    return staged;
  }
}

async function ensureRealDir(dir) {
  const st = await fsp.lstat(dir).catch(() => null);
  if (!st) { await fsp.mkdir(dir, { mode: 0o700 }).catch((e) => { if (e.code !== 'EEXIST') throw e; }); return ensureRealDir(dir); }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`Relay storage must be a plain directory: ${dir}`);
}

async function syncDir(dir) {
  const handle = await fsp.open(dir, fsc.O_RDONLY);
  try { await handle.sync(); } catch (error) { if (error.code !== 'EINVAL' && error.code !== 'EPERM') throw error; }
  finally { await handle.close(); }
}

async function writeDurable(file, bytes, tmpDir) {
  const staged = path.join(tmpDir, randomBytes(12).toString('hex'));
  const handle = await fsp.open(staged, 'wx', 0o600);
  try { await handle.write(bytes); await handle.sync(); } finally { await handle.close(); }
  await fsp.rename(staged, file);
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

/**
 * Creates the relay. `libraries` maps slot names to `{ tokenSha256 }`, `{ token }` or
 * `{ open: true }` (no bearer token; local testing only).
 */
export async function createRelay({ dataDir, libraries, limits = {}, home, clock = Date.now, resolve, tickMs = 0, tracing = false, cors, provision, clientAddress: addressConfig, crashAt, hook }) {
  if (!dataDir) throw new Error('dataDir is required');
  if (cors !== undefined && cors !== null && (typeof cors !== 'object' || Array.isArray(cors))) throw new Error('cors must be an object with origins, an array of origins');
  const origins = corsOrigins(cors?.origins);
  const provisioning = provisionConfig(provision);
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
  await fsp.mkdir(dataDir, { recursive: true, mode: 0o700 });
  await ensureRealDir(path.resolve(dataDir));
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
  let homeModule = null; let homeKey = null;
  if (Object.values(libraries ?? {}).some((e) => e && e.home) || provisioning.enabled || table.size > 0) {
    if (!home?.wasm || !home?.key) throw new Error('A home slot, and provisioning, need home.wasm (the module path) and home.key (a private P-256 JWK)');
    homeModule = home.wasm instanceof HomeModule ? home.wasm : await HomeModule.load(home.wasm);
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
  const configured = new Set(Object.keys(libraries ?? {}));
  const slots = new Map();
  const opening = new Map();
  const notProvisioned = () => new HttpError(404, 'Not provisioned', {}, { result: 'refused:notProvisioned' });
  async function slot(name) {
    if (slots.has(name)) return slots.get(name);
    // Never opened for a name this relay does not hold (a released slot is not reopened).
    if (!homeSlots.has(name) && !auth.has(name)) throw notProvisioned();
    if (!opening.has(name)) {
      opening.set(name, (async () => {
        const isHome = homeSlots.has(name);
        // A home slot's path grammar is the module's (the engine's paths).
        const homeClassify = (p) => homeModule.call({ op: 'classify', path: p }).kind;
        const s = new Slot(path.join(path.resolve(dataDir), name), name, effective, isHome ? homeClassify : classifyPath);
        await s.open();
        if (isHome) {
          s.home = new HomeSlot({
            slot: s, wasm: homeModule, key: homeKey, base: homeSlots.get(name).base, account: homeSlots.get(name).account,
            clock, resolve, tracing,
            deps: { HttpError, send, readBody, clampInt, clientAddress, reach },
            limits: { ...effective, requestsPerMinute: effective.requestsPerMinute ?? 0 },
          });
          await s.home.open();
        }
        slots.set(name, s);
        return s;
      })());
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
  const claimed = (s) => { const st = s.home.status(); return Boolean(st.appointed || st.held > 0); };

  /**
   * Release one provisioned slot that holds no genesis (never appointed). Under the
   * provisioning lock, so no provision of the name proceeds until this ends. The slot is marked
   * closing and taken out of dispatch (new requests answer refused:notProvisioned, long polls
   * are woken and end), the work in flight on it is drained, and "nothing held" is checked again
   * under its lock: only then are its directory and its row removed. If something is held by
   * then, the release is abandoned and the slot returns to service. A late use of the released
   * Slot fails closed (its locks refuse), never on a later slot's directory. A crash between the
   * directory and the row leaves the row: the slot is opened fresh and released at the next
   * start-up.
   */
  async function release(name, e) {
    const s = await slot(name);
    if (await s.home.lock(async () => claimed(s))) return;
    s.closing = true;
    homeSlots.delete(name);
    for (const wake of [...s.waiters]) wake();
    await reach(`release draining ${name}`);
    await drained(s);
    await reach(`release drained ${name}`);
    const removed = await s.home.lock(async () => {
      if (claimed(s)) return false;
      const refuse = () => Promise.reject(new Error(`slot ${name} was released`));
      s.released = true;
      s.home.lock = refuse; s.home.replayLock = refuse; s.exclusive = refuse;
      slots.delete(name); opening.delete(name);
      await fsp.rm(s.root, { recursive: true, force: true });
      return true;
    });
    if (!removed) { s.closing = false; homeSlots.set(name, { base: e.base, account: e.account }); await reach(`release abandoned ${name}`); return; }
    await table.write(name, null);
    await reach(`released ${name}`);
  }

  /** A provisioned slot holding no genesis `unclaimedHours` after it was provisioned is
   * released (on the relay's clock). Configured slots never are. An appointed home is never
   * released: it witnesses and receipts until the account's revocation of it is final. */
  async function releaseUnclaimed() {
    const now = clock();
    for (const name of [...table.keys()]) {
      const e = table.get(name);
      if (configured.has(name) || now - e.at < provisioning.unclaimedHours * 3_600_000) continue;
      await release(name, e);
    }
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
    const answer = await provisionLock(async () => {
      await releaseUnclaimed();
      const valid = typeof asked.slot === 'string' && SLOT.test(asked.slot);
      const occupied = valid && (configured.has(asked.slot)
        || (!table.get(asked.slot) && await fsp.lstat(path.join(path.resolve(dataDir), asked.slot)).then(() => true, () => false)));
      const verdict = admitProvision({ ...asked, address, authorization: req.headers.authorization,
        held: { entry: table.get(asked.slot), occupied, count: table.size } });
      if (!verdict.admit) {
        throw new HttpError(verdict.status, verdict.error ?? 'Refused', verdict.retryAfter ? { 'retry-after': String(verdict.retryAfter) } : {},
          verdict.result ? { result: verdict.result } : undefined);
      }
      if (verdict.existing) return Buffer.from(verdict.existing.request, 'base64');
      const request = await memberRequest({ wasm: homeModule, key: homeKey, account: asked.account, base: asked.base, now: clock() });
      // Durable before answered: a crash after this write leaves a row the same request completes.
      await table.write(asked.slot, { account: asked.account, base: asked.base, at: clock(), request: request.toString('base64') });
      await reach('provision written');
      homeSlots.set(asked.slot, { base: asked.base, account: asked.account });
      await slot(asked.slot);
      return request;
    });
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': answer.length });
    res.end(answer);
  }

  async function handle(req, res, work) {
    const url = new URL(req.url, 'http://relay.invalid');
    if (url.pathname === '/healthz' && req.method === 'GET') return send(res, 200, { ok: true });
    if (provisioning.enabled && url.pathname === '/v1/provision') return door(req, res);
    const route = /^\/v1\/libraries\/([^/]+)(?:\/(changes|records|head|authority|pending|predecessor)(?:\/(.*))?)?$/.exec(url.pathname);
    if (!route) throw new HttpError(404, 'Not found');
    const [, name, section, recordPath] = route;
    // With provisioning on, a slot this home does not hold is named as such (an app asks for its
    // slot at the door); off, it is the 0.3 answer, unchanged.
    if (provisioning.enabled && !homeSlots.has(name) && !auth.has(name)) {
      throw notProvisioned();
    }
    if (!SLOT.test(name)) throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Bearer' });
    if (!homeSlots.has(name)) authorize(req, name);
    const s = await slot(name);
    // Counted from here until the response has ended and this handler has settled.
    if (s.closing || s.released) throw notProvisioned();
    enter(s); work.slot = s;
    if (s.home && await s.home.handle(req, res, url, section, recordPath)) return undefined;
    if (!s.home && ['head', 'authority', 'pending', 'predecessor'].includes(section)) throw new HttpError(404, 'Not found');
    if (!section) {
      if (req.method !== 'GET') throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      const { slotBytes, authorityBodyBytes, pendingBodyBytes, replayRows, requestsPerMinute, ...published } = effective;
      return send(res, 200, { protocol: PROTOCOL, slot: name, limits: published, ...(slotBytes ? { quotaBytes: slotBytes } : {}),
        ...(s.home ? { home: { member: s.home.key.memberId } } : {}) });
    }
    if (section === 'changes') {
      if (req.method !== 'GET' || recordPath !== undefined) throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      const after = url.searchParams.get('after') ?? '';
      const limit = clampInt(url.searchParams.get('limit'), 500, 1, effective.pageEntries);
      const wait = clampInt(url.searchParams.get('wait'), 0, 0, effective.waitSeconds);
      const namespaces = url.searchParams.getAll('namespace').filter((n) => n.length > 0);
      let page = s.changes(after, limit, namespaces);
      if (page.entries.length === 0 && wait > 0) {
        await Promise.race([s.waitForEntry(wait * 1000), closed(res)]);
        if (res.destroyed) return undefined;
        if (s.closing) throw notProvisioned(); // woken by a release
        page = s.changes(after, limit, namespaces);
      }
      return send(res, 200, page);
    }
    const kind = s.classify(recordPath);
    if (!kind) throw new HttpError(400, 'Invalid record path');
    if (url.search) throw new HttpError(400, 'Record URLs take no query');
    if (req.method === 'GET' || req.method === 'HEAD') {
      const entry = s.current.get(recordPath);
      if (!entry) throw new HttpError(404, 'Not found');
      const bytes = await s.readFile(recordPath);
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': bytes.length,
        etag: `"${sha256(bytes)}"`, 'cache-control': 'no-store' });
      return res.end(req.method === 'HEAD' ? undefined : bytes);
    }
    if (req.method === 'PUT') {
      const max = kind === 'blob' ? effective.blobBytes : effective.recordBytes;
      const body = await readBody(req, max);
      if (kind === 'blob' && sha256(body) !== recordPath.slice(6)) throw new HttpError(400, 'Blob name must be the SHA-256 of its bytes');
      const conditional = req.headers['if-none-match'];
      let status;
      if (conditional === '*') status = await s.putImmutable(recordPath, body);
      else if (conditional !== undefined) throw new HttpError(400, 'Only If-None-Match: * is supported');
      else if (kind === 'state') {
        const expected = req.headers['if-match'];
        if (!expected || !/^"[0-9a-f]{64}"$/.test(expected)) throw new HttpError(428, 'Live replacement requires If-Match');
        status = await s.replaceRequest(recordPath, body, expected);
      }
      else if (kind === 'request') status = await s.replaceRequest(recordPath, body);
      else throw new HttpError(428, 'Immutable records require If-None-Match: *');
      res.writeHead(status, { etag: `"${sha256(body)}"`, 'content-length': 0 });
      return res.end();
    }
    if (req.method === 'DELETE') {
      if (kind !== 'request') throw new HttpError(405, 'Only requests/ records can be deleted', { allow: 'GET, PUT' });
      const status = await s.deleteRequest(recordPath);
      res.writeHead(status); return res.end();
    }
    throw new HttpError(405, 'Method not allowed', { allow: kind === 'request' ? 'GET, PUT, DELETE' : 'GET, PUT' });
  }

  function listener(req, res) {
    const listed = enforceAnswerHeaders(req, res, origins);
    if (req.method === 'OPTIONS') { answerOptions(req, res, listed); return; }
    const work = { slot: null };
    const settled = handle(req, res, work).catch((error) => {
      if (res.headersSent || res.destroyed) { res.destroy(); return; }
      if (error instanceof HttpError) send(res, error.status, error.body !== undefined ? error.body : { error: error.message }, error.headers);
      else { console.error(error); send(res, 500, { error: 'Internal relay error' }); }
    });
    Promise.all([settled, ended(res)]).then(() => { if (work.slot) leave(work.slot); });
  }

  // The scheduler: recording entries, heads and forwarding for every home slot, on the relay's clock.
  // Slots tick concurrently (each runs one pass at a time), so one slot never waits on another.
  const tickAll = async () => {
    await Promise.all([...homeSlots.keys()].map(async (name) => {
      let s;
      try { s = await slot(name); } catch { return; }
      if (s.closing || s.released) return;
      enter(s);
      try { await s.home.tick(); } catch (error) { console.error(`home tick failed for slot ${name}: ${error.message}`); } finally { leave(s); }
    }));
  };
  let timer = null;
  if (homeSlots.size > 0) for (const name of homeSlots.keys()) await slot(name);
  if (table.size > 0) await provisionLock(releaseUnclaimed);
  // The timer runs whenever a home slot may exist: provisioning adds slots at run time, and
  // `tickAll` reads the slot table on every pass.
  if ((homeSlots.size > 0 || provisioning.enabled) && tickMs > 0) { timer = setInterval(() => { tickAll(); }, tickMs); timer.unref?.(); }

  return { listener, limits: effective, slot, tickAll, close: () => { if (timer) clearInterval(timer); } };
}

// The response (not the request, which closes once its body is read) closes with the client.
function closed(res) { return new Promise((resolve) => res.once('close', resolve)); }

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

/** Starts an HTTP (or HTTPS when `tls` holds PEM `cert` and `key`) server. */
export async function startRelay({ host = '127.0.0.1', port = 8787, tls, ...options }) {
  const relay = await createRelay(options);
  const server = tls ? https.createServer({ cert: tls.cert, key: tls.key }, relay.listener) : http.createServer(relay.listener);
  server.requestTimeout = 60_000;
  server.headersTimeout = 20_000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  const address = server.address();
  return { server, relay, host: address.address, port: address.port,
    close: () => new Promise((resolve) => { relay.close(); server.closeAllConnections?.(); server.close(() => resolve()); }) };
}
