// Provisioning for the reference relay (operator behaviour, not protocol): the door an app uses
// to create its own account's home slot without a restart, the durable table of provisioned
// slots, the gate that decides who may provision, and the client address both the provisioning
// limits and the home's request limit count against. Dependency-free.
//
// The member request the door answers is built and verified by the Rust home module (op
// `member_request`) and signed by the relay's home key, as heads and receipts are: this file
// holds no protocol rule.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants as fsc, promises as fsp } from 'node:fs';
import net from 'node:net';
import path from 'node:path';

const HEX64 = /^[0-9a-f]{64}$/;
const SLOT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HOUR = 3_600_000;
/** The table's file in the data directory. A slot of this name is never allowed. */
export const TABLE_FILE = 'provisioned.json';

export const PROVISION_DEFAULTS = Object.freeze({
  enabled: false,
  maxSlots: 200,
  perAddressPerHour: 10,
  unclaimedHours: 24,
  slotPattern: '^[a-z0-9][a-z0-9._-]{7,63}$',
  gate: 'open',
});

const positiveInt = (v) => Number.isSafeInteger(v) && v > 0;

/** Checks the `provision` config and returns it with defaults, or throws (the relay refuses to
 * start). Off when absent. */
export function provisionConfig(raw) {
  if (raw === undefined || raw === null) return { ...PROVISION_DEFAULTS, slotRegex: new RegExp(PROVISION_DEFAULTS.slotPattern) };
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('provision must be an object');
  const known = new Set(['enabled', 'prefix', 'maxSlots', 'perAddressPerHour', 'unclaimedHours', 'slotPattern', 'gate', 'tokenSha256']);
  for (const k of Object.keys(raw)) if (!known.has(k)) throw new Error(`provision.${k} is not a setting`);
  const c = { ...PROVISION_DEFAULTS, ...raw };
  if (typeof c.enabled !== 'boolean') throw new Error('provision.enabled must be true or false');
  if (!positiveInt(c.maxSlots)) throw new Error('provision.maxSlots must be a positive integer');
  if (!positiveInt(c.perAddressPerHour)) throw new Error('provision.perAddressPerHour must be a positive integer');
  if (typeof c.unclaimedHours !== 'number' || !(c.unclaimedHours > 0) || !Number.isFinite(c.unclaimedHours)) throw new Error('provision.unclaimedHours must be a positive number');
  if (typeof c.slotPattern !== 'string') throw new Error('provision.slotPattern must be a string');
  try { c.slotRegex = new RegExp(c.slotPattern); } catch (error) { throw new Error(`provision.slotPattern is not a regular expression: ${error.message}`); }
  if (c.gate !== 'open' && c.gate !== 'token') throw new Error(`provision.gate ${JSON.stringify(c.gate)} is not built: use "open" or "token"`);
  if (c.gate === 'token' && (typeof c.tokenSha256 !== 'string' || !HEX64.test(c.tokenSha256))) {
    throw new Error('provision.gate "token" needs provision.tokenSha256, the 64-hex SHA-256 of the token (bun relay/server.js token prints one)');
  }
  if (c.gate !== 'token' && c.tokenSha256 !== undefined) throw new Error('provision.tokenSha256 is used only with gate "token"');
  if (c.enabled && c.prefix === undefined) throw new Error('provision.prefix is required when provisioning is on: the public https URL prefix of the slots, ending in "/" (base = prefix + slot)');
  if (c.prefix !== undefined) {
    let url = null;
    try { url = new URL(c.prefix); } catch { url = null; }
    // §9.1: a service endpoint is https. Plain http only to a loopback host, for tests.
    const loopback = url && (url.hostname === 'localhost' || /^127\.\d+\.\d+\.\d+$/.test(url.hostname) || url.hostname === '[::1]');
    if (typeof c.prefix !== 'string' || !url || !(url.protocol === 'https:' || (url.protocol === 'http:' && loopback))
      || !c.prefix.endsWith('/') || url.search || url.hash || url.username || url.password) {
      throw new Error('provision.prefix must be the public https URL prefix of the slots, ending in "/" (base = prefix + slot); plain http only to a loopback host, for tests');
    }
  }
  return c;
}

/** Checks the `clientAddress` config: `{header, trustedPeers}`, or none (the socket address). */
export function clientAddressConfig(raw) {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('clientAddress must be an object: {"header": "CF-Connecting-IP", "trustedPeers": ["127.0.0.1", "::1"]}');
  for (const k of Object.keys(raw)) if (k !== 'header' && k !== 'trustedPeers') throw new Error(`clientAddress.${k} is not a setting`);
  if (typeof raw.header !== 'string' || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(raw.header)) throw new Error('clientAddress.header must be a header name');
  if (!Array.isArray(raw.trustedPeers) || raw.trustedPeers.length === 0) throw new Error('clientAddress.trustedPeers must list the proxy addresses the header is read from');
  const peers = new Set();
  for (const p of raw.trustedPeers) {
    if (typeof p !== 'string' || net.isIP(p) === 0) throw new Error(`clientAddress.trustedPeers: ${JSON.stringify(p)} is not an IP address`);
    peers.add(normalIp(p));
  }
  return { header: raw.header.toLowerCase(), trustedPeers: peers };
}

/** An IPv4-mapped IPv6 address as IPv4; IPv6 lower case. */
function normalIp(a) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(a);
  return mapped ? mapped[1] : a.toLowerCase();
}

/** The address a trusted proxy sent without a usable client address: one bucket for all such. */
export const SHARED_BUCKET = 'proxy:no-client-address';

/**
 * The one function that says which address a request counts against, for the provisioning
 * limits and the home's request limit. Limits only, never access. Without config it is the
 * socket address, as before. With config, the header is read only when the socket peer is a
 * trusted proxy; from a trusted peer, a missing or malformed header (a list, two headers, not an
 * IP address) counts against one shared bucket, never an unlimited one; from any other peer the
 * header is ignored.
 */
export function clientAddressResolver(cfg) {
  if (!cfg) return (req) => req.socket?.remoteAddress ?? '';
  return (req) => {
    const peer = req.socket?.remoteAddress ?? '';
    if (!cfg.trustedPeers.has(normalIp(peer))) return peer;
    const value = req.headers[cfg.header];
    if (typeof value !== 'string') return SHARED_BUCKET;
    const text = value.trim();
    if (net.isIP(text) === 0) return SHARED_BUCKET;
    return normalIp(text);
  };
}

/** The most bytes a stored member request may hold (decoded); its body is bounded at 16 KiB. */
export const MAX_REQUEST_BYTES = 32 * 1024;
/** A row's bound in the file: the request in base64 and the other fields. */
const MAX_ROW_BYTES = Math.ceil(MAX_REQUEST_BYTES / 3) * 4 + 1024;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ROW_FIELDS = ['account', 'base', 'at', 'request'];

/** What is at `<dataDir>/provisioned.json`: nothing, a regular file (a table), or something else
 * (a 0.3 slot directory of that name, a link). Only an lstat: nothing is read. */
export async function tableKind(dataDir) {
  const st = await fsp.lstat(path.join(dataDir, TABLE_FILE)).catch((error) => { if (error.code === 'ENOENT') return null; throw error; });
  if (!st) return 'none';
  return st.isFile() ? 'file' : 'other';
}

/** The bytes the relay writes for `rows`: sorted slots, each row's fields in one order. A table
 * on disk must be exactly this, so a duplicate key, an unknown field or a hand edit is seen. */
function serialize(rows) {
  const out = Object.create(null);
  for (const [slot, e] of [...rows].sort(([a], [b]) => (a < b ? -1 : 1))) {
    out[slot] = { account: e.account, base: e.base, at: e.at, request: e.request };
  }
  return JSON.stringify(out) + '\n';
}

/** The durable table of provisioned slots: slot -> {account, base, at, request}. `request` is
 * the member request answered for it (base64), kept so a repeated request answers the same
 * bytes. Written staged, fsynced and renamed, then the directory fsynced. It is read only when
 * provisioning is on or a regular file is there, and never repaired: a bad table refuses
 * start-up, naming the row. */
export class ProvisionTable {
  constructor(dataDir, rows) { this.dataDir = dataDir; this.rows = rows; }

  /** No table in use (provisioning off and no table file): nothing on disk is touched. */
  static empty(dataDir) { return new ProvisionTable(dataDir, new Map()); }

  /** Reads the table: at most `maxSlots` rows' worth of bytes, each row's shape checked, and the
   * file exactly as the relay writes it. Stale staging files from an interrupted write go. */
  static async load(dataDir, { maxSlots }) {
    for (const name of await fsp.readdir(dataDir)) {
      if (name.startsWith(`.${TABLE_FILE}.`)) await fsp.rm(path.join(dataDir, name), { force: true });
    }
    const file = path.join(dataDir, TABLE_FILE);
    const bound = MAX_ROW_BYTES * Math.max(maxSlots, PROVISION_DEFAULTS.maxSlots) + 64;
    let handle;
    try { handle = await fsp.open(file, fsc.O_RDONLY | fsc.O_NOFOLLOW); } catch (error) {
      if (error.code === 'ENOENT') return ProvisionTable.empty(dataDir);
      throw new Error(`${file} cannot be opened (${error.code}): it must be a regular file`);
    }
    let text;
    try {
      const st = await handle.stat();
      if (!st.isFile()) throw new Error(`${file} is not a regular file`);
      if (st.size > bound) throw new Error(`${file} is ${st.size} bytes, over its bound of ${bound}: it is not a table this relay wrote`);
      text = (await handle.readFile()).toString('utf8');
    } finally { await handle.close(); }
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new Error(`${file} is not JSON: repair or remove it`); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${file} must map slots to rows`);
    const rows = new Map();
    for (const slot of Object.keys(parsed)) {
      const e = parsed[slot];
      const name = `${file}: the row for ${JSON.stringify(slot)}`;
      if (!SLOT.test(slot) || slot === TABLE_FILE) throw new Error(`${name} is not a slot name`);
      if (!e || typeof e !== 'object' || Array.isArray(e) || Object.keys(e).sort().join() !== [...ROW_FIELDS].sort().join()) {
        throw new Error(`${name} is not exactly {account, base, at, request}`);
      }
      if (typeof e.account !== 'string' || !HEX64.test(e.account)) throw new Error(`${name}: account is not 64 lower-case hex`);
      if (typeof e.base !== 'string') throw new Error(`${name}: base is not a string`);
      if (!Number.isSafeInteger(e.at) || e.at < 0) throw new Error(`${name}: at is not a time`);
      if (typeof e.request !== 'string' || !BASE64.test(e.request) || e.request.length > MAX_ROW_BYTES - 1024) {
        throw new Error(`${name}: request is not base64 within ${MAX_REQUEST_BYTES} bytes`);
      }
      rows.set(slot, { account: e.account, base: e.base, at: e.at, request: e.request });
    }
    if (serialize(rows) !== text) throw new Error(`${file} is not as this relay writes it (a duplicate key, or an edit): repair or remove it`);
    return new ProvisionTable(dataDir, rows);
  }

  /** Every row against this relay's settings and key: the slot pattern, `base === prefix +
   * slot`, and `verify(row)` (the module: a member request signed by this home's key naming the
   * row's account and endpoint). Throws naming the first bad row. */
  validate(cfg, verify) {
    for (const [slot, e] of this.rows) {
      const name = `${path.join(this.dataDir, TABLE_FILE)}: the row for ${JSON.stringify(slot)}`;
      if (!cfg.slotRegex.test(slot)) throw new Error(`${name}: the slot does not match provision.slotPattern`);
      if (typeof cfg.prefix !== 'string') throw new Error(`${name}: provisioned slots need provision.prefix (with enabled false they stay served without the door)`);
      if (e.base !== cfg.prefix + slot) throw new Error(`${name}: base ${JSON.stringify(e.base)} is not provision.prefix + slot`);
      try { verify(slot, e); } catch (error) { throw new Error(`${name}: request: ${error.message}`); }
    }
  }

  get(slot) { return this.rows.get(slot); }
  get size() { return this.rows.size; }
  keys() { return this.rows.keys(); }

  /** Writes the table with `slot` set to `entry` (or removed when `entry` is null), durably,
   * and only then changes it in memory. */
  async write(slot, entry) {
    const next = new Map(this.rows);
    if (entry) next.set(slot, entry); else next.delete(slot);
    const bytes = Buffer.from(serialize(next));
    const staged = path.join(this.dataDir, `.${TABLE_FILE}.${randomBytes(8).toString('hex')}`);
    const handle = await fsp.open(staged, 'wx', 0o600);
    try { await handle.write(bytes); await handle.sync(); } finally { await handle.close(); }
    await fsp.rename(staged, path.join(this.dataDir, TABLE_FILE));
    const dir = await fsp.open(this.dataDir, 'r');
    try { await dir.sync(); } catch (error) { if (error.code !== 'EINVAL' && error.code !== 'EPERM') throw error; } finally { await dir.close(); }
    this.rows = next;
  }
}

/**
 * The gate: one function every provisioning decision goes through (on, the address's share,
 * who may provision, bounds, the slot's holder, room). A later entitlement presented in
 * `Authorization` is checked here and nowhere else. Returns `{admit: true, existing}` or a
 * refusal `{status, result | error, retryAfter?}`. It counts against the address's hourly share
 * every new slot it admits and every request whose token is missing or wrong.
 */
export function provisionGate(cfg, clock) {
  const rows = new Map(); // address -> times (ms) of counted requests in the last hour
  const expected = cfg.gate === 'token' ? Buffer.from(cfg.tokenSha256, 'hex') : null;
  const recent = (address, now) => {
    const times = (rows.get(address) ?? []).filter((t) => now - t < HOUR && t <= now);
    if (times.length) rows.set(address, times); else rows.delete(address);
    return times;
  };
  const count = (address, now) => {
    if (rows.size > 10_000) for (const a of [...rows.keys()]) recent(a, now);
    rows.set(address, [...recent(address, now), now]);
  };
  const tokenOk = (authorization) => {
    const m = /^Bearer (\S+)$/.exec(authorization ?? '');
    const given = createHash('sha256').update(m ? m[1] : '').digest();
    return timingSafeEqual(given, expected) && m !== null;
  };

  return function admitProvision({ slot, account, base, address, authorization, held }) {
    const now = clock();
    if (!cfg.enabled) return { status: 404, error: 'Not found' };
    // The share first: a guesser over its share learns nothing about its token.
    const times = recent(address, now);
    if (times.length >= cfg.perAddressPerHour || (!rows.has(address) && rows.size > 10_000)) {
      const retryAfter = times.length ? Math.max(1, Math.ceil((times[0] + HOUR - now) / 1000)) : 3600;
      return { status: 429, result: 'refused:overQuota', retryAfter };
    }
    if (expected && !tokenOk(authorization)) { count(address, now); return { status: 403, result: 'refused:noEntitlement' }; }
    if (typeof slot !== 'string' || !SLOT.test(slot) || slot === TABLE_FILE || !cfg.slotRegex.test(slot)
      || typeof account !== 'string' || !HEX64.test(account) || base !== cfg.prefix + slot) {
      return { status: 400, result: 'malformed' };
    }
    if (held.entry) {
      if (held.entry.account === account && held.entry.base === base) return { admit: true, existing: held.entry };
      return { status: 409, error: 'This slot is provisioned for another account' };
    }
    if (held.occupied) return { status: 409, error: 'This slot name is in use on this relay' };
    if (held.count >= cfg.maxSlots) return { status: 507, result: 'refused:overQuota' };
    count(address, now);
    return { admit: true, existing: null };
  };
}

/** The door's body: exactly `{"slot","base","account"}`, strings. Anything else is null. */
export function parseProvisionBody(bytes) {
  let v;
  try { v = JSON.parse(bytes.toString('utf8')); } catch { return null; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const keys = Object.keys(v).sort();
  if (keys.join() !== 'account,base,slot') return null;
  if (typeof v.slot !== 'string' || typeof v.base !== 'string' || typeof v.account !== 'string') return null;
  return { slot: v.slot, base: v.base, account: v.account };
}

/** The door's Content-Type rule: the media type is `application/json` (a browser cannot send
 * it cross-origin without a preflight). Parameters such as `charset` are allowed. */
export function isJsonType(value) {
  if (typeof value !== 'string') return false;
  return value.split(';')[0].trim().toLowerCase() === 'application/json';
}

/**
 * The home's signed member request (§9.1) naming `account`, with `base/` as its endpoint: the
 * module builds the body, the home key signs it, the module assembles and verifies the envelope.
 * The agreement key is made here and thrown away (the home never decrypts for an account), as
 * `apps/test-home` did.
 */
export async function memberRequest({ wasm, key, account, base, now }) {
  const agreement = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const point = Buffer.from(await crypto.subtle.exportKey('raw', agreement.publicKey));
  const ask = { op: 'member_request', account, signing: key.point.toString('base64'), agreement: point.toString('base64'),
    endpoint: `${base}/`, now };
  const { sign } = wasm.call(ask);
  const signature = await key.sign(Buffer.from(sign.body, 'base64'));
  return Buffer.from(wasm.call({ ...ask, signature: signature.toString('base64') }).request, 'base64');
}
