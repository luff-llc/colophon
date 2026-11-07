// Colophon 0.3 reference relay (spec §8). Stores opaque records per library slot.
// Dependency-free: node:http, node:https, node:fs, node:path and node:crypto only.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants as fsc, promises as fsp } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';

export const PROTOCOL = 'colophon/relay/3';
export const DEFAULT_LIMITS = Object.freeze({
  recordBytes: 16 * 1024 * 1024,
  blobBytes: 65536 + 16,
  pageEntries: 1000,
  waitSeconds: 30,
  slotBytes: 0, // 0 = no per-slot quota
});

const SLOT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

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
  constructor(status, message, headers = {}) { super(message); this.status = status; this.headers = headers; }
}

/** One library slot on disk: records/<path>, an append-only log.jsonl and meta.json. */
class Slot {
  constructor(root, name, limits) {
    this.root = root; this.name = name; this.limits = limits;
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
        if (!classifyPath(e.path)) return null;
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
        else if (ent.isFile() && classifyPath(relPath)) found.set(relPath, { size: (await fsp.lstat(full)).size });
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
export async function createRelay({ dataDir, libraries, limits = {} }) {
  if (!dataDir) throw new Error('dataDir is required');
  const effective = { ...DEFAULT_LIMITS, ...limits };
  await fsp.mkdir(dataDir, { recursive: true, mode: 0o700 });
  await ensureRealDir(path.resolve(dataDir));
  const auth = new Map();
  for (const [name, entry] of Object.entries(libraries ?? {})) {
    if (!SLOT.test(name)) throw new Error(`Invalid library slot name: ${name}`);
    if (entry && entry.open === true) auth.set(name, null);
    else if (entry && typeof entry.tokenSha256 === 'string' && HEX64.test(entry.tokenSha256)) auth.set(name, Buffer.from(entry.tokenSha256, 'hex'));
    else if (entry && typeof entry.token === 'string' && entry.token.length >= 16) auth.set(name, createHash('sha256').update(entry.token).digest());
    else throw new Error(`Library slot ${name} needs tokenSha256, a token of at least 16 characters, or open: true`);
  }
  const slots = new Map();
  const opening = new Map();
  async function slot(name) {
    if (slots.has(name)) return slots.get(name);
    if (!opening.has(name)) {
      opening.set(name, (async () => {
        const s = new Slot(path.join(path.resolve(dataDir), name), name, effective);
        await s.open();
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

  async function handle(req, res) {
    const url = new URL(req.url, 'http://relay.invalid');
    if (url.pathname === '/healthz' && req.method === 'GET') return send(res, 200, { ok: true });
    const route = /^\/v1\/libraries\/([^/]+)(?:\/(changes|records)(?:\/(.*))?)?$/.exec(url.pathname);
    if (!route) throw new HttpError(404, 'Not found');
    const [, name, section, recordPath] = route;
    if (!SLOT.test(name)) throw new HttpError(401, 'Unauthorized', { 'www-authenticate': 'Bearer' });
    authorize(req, name);
    const s = await slot(name);
    if (!section) {
      if (req.method !== 'GET') throw new HttpError(405, 'Method not allowed', { allow: 'GET' });
      const { slotBytes, ...published } = effective;
      return send(res, 200, { protocol: PROTOCOL, slot: name, limits: published, ...(slotBytes ? { quotaBytes: slotBytes } : {}) });
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
        page = s.changes(after, limit, namespaces);
      }
      return send(res, 200, page);
    }
    const kind = classifyPath(recordPath);
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
    handle(req, res).catch((error) => {
      if (res.headersSent || res.destroyed) { res.destroy(); return; }
      if (error instanceof HttpError) send(res, error.status, { error: error.message }, error.headers);
      else { console.error(error); send(res, 500, { error: 'Internal relay error' }); }
    });
  }

  return { listener, limits: effective, slot };
}

// The response (not the request, which closes once its body is read) closes with the client.
function closed(res) { return new Promise((resolve) => res.once('close', resolve)); }

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
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }) };
}
