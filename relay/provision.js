// Provisioning for the reference relay (operator behaviour, not protocol): the door an app uses
// to create its own account's home slot without a restart, the durable table of provisioned
// slots, the gate that decides who may provision, and the client address both the provisioning
// limits and the home's request limit count against. Dependency-free.
//
// The member request the door answers is built and verified by the Rust home module (op
// `member_request`) and signed by the relay's home key, as heads and receipts are; a grant's call
// is judged by the module too (op `provision_access`): this file holds no protocol rule.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants as fsc, promises as fsp } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { appendLines, readLogRows, replayRow, writeAll } from './files.js';

const HEX64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[0-9a-f]{32}$/; // a member or key ID: the first 32 hex characters of SHA-256 of its point
const SLOT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HOUR = 3_600_000;
/** The table's file in the data directory. A slot of this name is never allowed. */
export const TABLE_FILE = 'provisioned.json';

/** The provisioning replay table's directory in the data directory (gate "grant"). A slot of
 * this name is never allowed while the grant gate is on. */
export const REPLAY_DIR = 'provision-replay';
/** The purpose a provisioning call names (the module checks it; here only for messages). */
export const PROVISION_PURPOSE = 'home.provision';
const GATES = ['open', 'token', 'grant'];

export const PROVISION_DEFAULTS = Object.freeze({
  enabled: false,
  maxSlots: 200,
  perAddressPerHour: 10,
  unclaimedHours: 24,
  slotPattern: '^[a-z0-9][a-z0-9._-]{7,63}$',
  gate: 'open',
});
/** Defaults that apply only with gate "grant". */
export const GRANT_DEFAULTS = Object.freeze({
  grantMaxSlots: 20,
  grantPerHour: 30,
  grantAttemptsPerAddressPerHour: 120,
  replayRows: 4096,
});
const GRANT_FIELDS = ['operator', 'audience', 'grants', ...Object.keys(GRANT_DEFAULTS)];

const positiveInt = (v) => Number.isSafeInteger(v) && v > 0;

/** The gate setting as a set: one value, or a list of them (no duplicates; "open" and "token" not
 * together, since "open" admits everything "token" would). Throws on anything else. */
function gateSet(gate) {
  const list = Array.isArray(gate) ? gate : [gate];
  if (list.length === 0 || list.some((g) => typeof g !== 'string' || !GATES.includes(g))) {
    throw new Error(`provision.gate ${JSON.stringify(gate)} is not built: use "open", "token", "grant", or a list of them`);
  }
  const set = new Set(list);
  if (set.size !== list.length) throw new Error(`provision.gate ${JSON.stringify(gate)} lists a gate twice`);
  if (set.has('open') && set.has('token')) throw new Error('provision.gate cannot list both "open" and "token": "open" admits everything "token" would');
  return set;
}

/** Checks the `provision` config and returns it with defaults, or throws (the relay refuses to
 * start). Off when absent. `gates` is the gate setting as a set. */
export function provisionConfig(raw) {
  if (raw === undefined || raw === null) return { ...PROVISION_DEFAULTS, gates: new Set(['open']), slotRegex: new RegExp(PROVISION_DEFAULTS.slotPattern) };
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('provision must be an object');
  const known = new Set(['enabled', 'prefix', 'maxSlots', 'perAddressPerHour', 'unclaimedHours', 'slotPattern', 'gate', 'tokenSha256', ...GRANT_FIELDS]);
  for (const k of Object.keys(raw)) if (!known.has(k)) throw new Error(`provision.${k} is not a setting`);
  const c = { ...PROVISION_DEFAULTS, ...raw };
  if (typeof c.enabled !== 'boolean') throw new Error('provision.enabled must be true or false');
  if (!positiveInt(c.maxSlots)) throw new Error('provision.maxSlots must be a positive integer');
  if (!positiveInt(c.perAddressPerHour)) throw new Error('provision.perAddressPerHour must be a positive integer');
  if (typeof c.unclaimedHours !== 'number' || !(c.unclaimedHours > 0) || !Number.isFinite(c.unclaimedHours)) throw new Error('provision.unclaimedHours must be a positive number');
  if (typeof c.slotPattern !== 'string') throw new Error('provision.slotPattern must be a string');
  try { c.slotRegex = new RegExp(c.slotPattern); } catch (error) { throw new Error(`provision.slotPattern is not a regular expression: ${error.message}`); }
  c.gates = gateSet(c.gate);
  if (c.gates.has('token') && (typeof c.tokenSha256 !== 'string' || !HEX64.test(c.tokenSha256))) {
    throw new Error('provision.gate "token" needs provision.tokenSha256, the 64-hex SHA-256 of the token (bun relay/server.js token prints one)');
  }
  if (!c.gates.has('token') && c.tokenSha256 !== undefined) throw new Error('provision.tokenSha256 is used only with gate "token"');
  if (c.gates.has('grant')) grantConfig(c);
  else for (const k of GRANT_FIELDS) if (raw[k] !== undefined) throw new Error(`provision.${k} is used only with gate "grant"`);
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
  if (c.gates.has('grant') && typeof c.prefix === 'string' && c.audience.startsWith(c.prefix)) {
    throw new Error('provision.audience must not be a slot base (prefix + slot): it is the door\'s own audience');
  }
  return c;
}

/** The grant gate's settings, checked in place with their defaults. The audience's grammar
 * (§10.1) is the module's, checked when the relay starts. */
function grantConfig(c) {
  for (const [k, v] of Object.entries(GRANT_DEFAULTS)) if (c[k] === undefined) c[k] = v;
  const op = c.operator;
  if (!op || typeof op !== 'object' || Array.isArray(op) || Object.keys(op).sort().join() !== 'account,slot') {
    throw new Error('provision.gate "grant" needs provision.operator: {"account": "<64-hex operator account ID>", "slot": "<this home\'s slot for it>"}');
  }
  if (typeof op.account !== 'string' || !HEX64.test(op.account)) throw new Error('provision.operator.account must be the operator account\'s 64 lower-case hex ID');
  if (typeof op.slot !== 'string' || !SLOT.test(op.slot) || op.slot === TABLE_FILE || op.slot === REPLAY_DIR) throw new Error('provision.operator.slot must be a slot name of this home');
  if (typeof c.audience !== 'string' || c.audience.length === 0) throw new Error('provision.gate "grant" needs provision.audience, the door\'s canonical audience (an https URL of its own, such as https://home.example/v1/provision)');
  for (const k of Object.keys(GRANT_DEFAULTS)) if (!positiveInt(c[k])) throw new Error(`provision.${k} must be a positive integer`);
  const grants = c.grants ?? {};
  if (typeof grants !== 'object' || grants === null || Array.isArray(grants)) throw new Error('provision.grants must map member IDs to {"maxSlots", "perHour"}');
  for (const [id, o] of Object.entries(grants)) {
    if (!KEY_ID.test(id)) throw new Error(`provision.grants: ${JSON.stringify(id)} is not a member ID (32 lower-case hex)`);
    if (!o || typeof o !== 'object' || Array.isArray(o)) throw new Error(`provision.grants.${id} must be {"maxSlots", "perHour"}`);
    for (const [k, v] of Object.entries(o)) {
      if (k !== 'maxSlots' && k !== 'perHour') throw new Error(`provision.grants.${id}.${k} is not a setting`);
      if (!positiveInt(v)) throw new Error(`provision.grants.${id}.${k} must be a positive integer`);
    }
  }
  c.grants = grants;
}

/** Checks the `clientAddress` config: `{header, trustedPeers}`, or none (the socket address). */
export function clientAddressConfig(raw) {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('clientAddress must be an object: {"header": "CF-Connecting-IP", "trustedPeers": ["127.0.0.1", "::1"]}');
  for (const k of Object.keys(raw)) if (k !== 'header' && k !== 'trustedPeers') throw new Error(`clientAddress.${k} is not a setting`);
  if (typeof raw.header !== 'string' || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(raw.header)) throw new Error('clientAddress.header must be a header name');
  if (!Array.isArray(raw.trustedPeers) || raw.trustedPeers.length === 0) throw new Error('clientAddress.trustedPeers must list the proxy addresses the header is read from');
  const peers = new Set();
  const ranges = [];
  for (const p of raw.trustedPeers) {
    const range = typeof p === 'string' ? parseRange(p) : undefined;
    if (range === null) throw new Error(`clientAddress.trustedPeers: ${JSON.stringify(p)} is not an IP range: write it as address/prefix with no host bits set, for example 10.0.0.0/8 (a /0 is refused: it would trust every peer)`);
    if (range) { ranges.push(range); continue; }
    if (typeof p !== 'string' || net.isIP(p) === 0) throw new Error(`clientAddress.trustedPeers: ${JSON.stringify(p)} is not an IP address or range`);
    peers.add(normalIp(p));
  }
  const trusted = (peer) => {
    const a = normalIp(peer);
    if (peers.has(a)) return true;
    if (ranges.length === 0) return false;
    const n = ipBits(a);
    return n !== null && ranges.some((r) => r.family === n.family && (n.value >> r.shift) === r.network);
  };
  return { header: raw.header.toLowerCase(), trustedPeers: peers, trusted };
}

/**
 * A CIDR range (`10.0.0.0/8`, `fd00::/8`): `{family, shift, network}`; null for a malformed one
 * (a bad prefix, host bits set, or a /0, which would trust every peer); undefined when `text` has
 * no `/` (an exact address, checked by the caller). An IPv4-mapped IPv6 range is not accepted:
 * peers are normalized to IPv4 first, so write the IPv4 range.
 */
function parseRange(text) {
  const at = text.indexOf('/');
  if (at < 0) return undefined;
  const bits = ipBits(text.slice(0, at));
  const prefix = text.slice(at + 1);
  if (!bits || !/^\d{1,3}$/.test(prefix) || /^::ffff:/i.test(text)) return null;
  const width = bits.family === 4 ? 32 : 128;
  const n = Number(prefix);
  if (n < 1 || n > width) return null;
  const shift = BigInt(width - n);
  const network = bits.value >> shift;
  if ((network << shift) !== bits.value) return null;
  return { family: bits.family, shift, network };
}

/** An address as `{family, value}` (value a BigInt), or null. Accepts what net.isIP accepts, without a zone. */
function ipBits(text) {
  const family = net.isIP(text);
  if (family === 4) return { family, value: text.split('.').reduce((v, o) => (v << 8n) | BigInt(Number(o)), 0n) };
  if (family !== 6 || text.includes('%')) return null;
  let s = text.toLowerCase();
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4) {
    const o = v4[1].split('.').map(Number);
    s = s.slice(0, -v4[1].length) + `${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const [head, tail] = s.includes('::') ? s.split('::') : [s, undefined];
  const left = head ? head.split(':') : [];
  const right = tail === undefined ? [] : tail ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  if (groups.length !== 8) return null;
  return { family, value: groups.reduce((v, g) => (v << 16n) | BigInt(parseInt(g, 16)), 0n) };
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
    if (!(cfg.trusted ? cfg.trusted(peer) : cfg.trustedPeers.has(normalIp(peer)))) return peer;
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

/** A row's `by` (who provisioned it): `{"gate":"open"}`, `{"gate":"token"}`, or
 * `{"gate":"grant","member","key","call"}` (the grant's member ID, the acting key's ID and the
 * call's digest). Older rows have none: unknown. */
function validBy(by) {
  if (!by || typeof by !== 'object' || Array.isArray(by)) return false;
  const keys = Object.keys(by).sort().join();
  if (by.gate === 'open' || by.gate === 'token') return keys === 'gate';
  return by.gate === 'grant' && keys === 'call,gate,key,member'
    && [by.member, by.key].every((v) => typeof v === 'string' && KEY_ID.test(v)) && typeof by.call === 'string' && HEX64.test(by.call);
}
function copyBy(by) {
  return by.gate === 'grant' ? { gate: 'grant', member: by.member, key: by.key, call: by.call } : { gate: by.gate };
}

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
    out[slot] = { account: e.account, base: e.base, at: e.at, request: e.request, ...(e.by ? { by: copyBy(e.by) } : {}) };
  }
  return JSON.stringify(out) + '\n';
}

/** The durable table of provisioned slots: slot -> {account, base, at, request, by?}. `request`
 * is the member request answered for it (base64), kept so a repeated request answers the same
 * bytes; `by` names the gate (and for a grant, the member, key and call) that made it. Written staged, fsynced and renamed, then the directory fsynced. It is read only when
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
      const fields = e && typeof e === 'object' && !Array.isArray(e) ? Object.keys(e).filter((k) => k !== 'by').sort().join() : null;
      if (fields !== [...ROW_FIELDS].sort().join()) throw new Error(`${name} is not exactly {account, base, at, request} and an optional by`);
      if (e.by !== undefined && !validBy(e.by)) throw new Error(`${name}: by is not {"gate":"open"}, {"gate":"token"} or {"gate":"grant","member","key","call"}`);
      if (typeof e.account !== 'string' || !HEX64.test(e.account)) throw new Error(`${name}: account is not 64 lower-case hex`);
      if (typeof e.base !== 'string') throw new Error(`${name}: base is not a string`);
      if (!Number.isSafeInteger(e.at) || e.at < 0) throw new Error(`${name}: at is not a time`);
      if (typeof e.request !== 'string' || !BASE64.test(e.request) || e.request.length > MAX_ROW_BYTES - 1024) {
        throw new Error(`${name}: request is not base64 within ${MAX_REQUEST_BYTES} bytes`);
      }
      rows.set(slot, { account: e.account, base: e.base, at: e.at, request: e.request, ...(e.by ? { by: copyBy(e.by) } : {}) });
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
  /** Slots held that the grant `member` made, claimed or not. */
  heldBy(member) { let n = 0; for (const e of this.rows.values()) if (e.by?.gate === 'grant' && e.by.member === member) n += 1; return n; }
  keys() { return this.rows.keys(); }

  /** Writes the table with `slot` set to `entry` (or removed when `entry` is null), durably,
   * and only then changes it in memory. */
  async write(slot, entry) {
    const next = new Map(this.rows);
    if (entry) next.set(slot, entry); else next.delete(slot);
    const bytes = Buffer.from(serialize(next));
    const staged = path.join(this.dataDir, `.${TABLE_FILE}.${randomBytes(8).toString('hex')}`);
    const handle = await fsp.open(staged, 'wx', 0o600);
    try { await writeAll(handle, bytes); await handle.sync(); } finally { await handle.close(); }
    await fsp.rename(staged, path.join(this.dataDir, TABLE_FILE));
    const dir = await fsp.open(this.dataDir, 'r');
    try { await dir.sync(); } catch (error) { if (error.code !== 'EINVAL' && error.code !== 'EPERM') throw error; } finally { await dir.close(); }
    this.rows = next;
  }
}

/** Times (ms) per address within the last hour, bounded in addresses. */
function hourly() {
  const rows = new Map();
  const recent = (address, now) => {
    const times = (rows.get(address) ?? []).filter((t) => now - t < HOUR && t <= now);
    if (times.length) rows.set(address, times); else rows.delete(address);
    return times;
  };
  return {
    recent,
    count(address, now) {
      if (rows.size > 10_000) for (const a of [...rows.keys()]) recent(a, now);
      rows.set(address, [...recent(address, now), now]);
    },
    /** Over `limit` (or too many live addresses, when this one is new): the seconds to wait. */
    over(address, now, limit) {
      const times = recent(address, now);
      if (times.length >= limit || (!rows.has(address) && rows.size > 10_000)) {
        return times.length ? Math.max(1, Math.ceil((times[0] + HOUR - now) / 1000)) : 3600;
      }
      return 0;
    },
  };
}

/** Which path of the gate a request takes, by its `Authorization`: a `Colophon` call to the grant
 * path when "grant" is listed (its refusal is final); a `Bearer` token to the token path when
 * "token" is listed; otherwise the open path when "open" is listed; otherwise none (403
 * `refused:noEntitlement`). */
export function provisionRoute(cfg, authorization) {
  const a = typeof authorization === 'string' ? authorization : '';
  if (cfg.gates.has('grant') && a.startsWith('Colophon ')) return 'grant';
  if (cfg.gates.has('token') && a.startsWith('Bearer ')) return 'token';
  if (cfg.gates.has('open')) return 'open';
  return 'none';
}

/** The limits one grant (a member of the operator account, with every link under it) has. */
export function grantLimits(cfg, member) {
  const o = cfg.grants?.[member] ?? {};
  return { maxSlots: o.maxSlots ?? cfg.grantMaxSlots, perHour: o.perHour ?? cfg.grantPerHour };
}

/**
 * The gate: one function every provisioning decision goes through (on, the address's share,
 * who may provision, bounds, the slot's holder, room). A later entitlement presented in
 * `Authorization` is checked here and nowhere else, as one more path. Resolves to
 * `{admit: true, existing, by, grant?}` or a refusal `{status, result | error, retryAfter?}`.
 *
 * Each path keeps its own bounds. Open: `perAddressPerHour` counts every new slot it admits.
 * Token: the same share, which also counts every request whose token is missing or wrong (and a
 * request no listed path takes). Grant: every request is charged first against
 * `grantAttemptsPerAddressPerHour`; a request refused before or by verification (a malformed
 * body, a bad call) counts against the address's own grant share of `perAddressPerHour`, which,
 * once full, refuses the address's grant requests before the module runs; an admitted one counts
 * against nothing per address. A verified call (a new slot, the same slot again, or one refused
 * by the slot's holder or the room) is bounded by its grant: `grantPerHour` calls, counted by the
 * module from the durable replay table before any history work, and `grantMaxSlots` slots held.
 * A verified call that is refused carries `reserve`: the door records it, completed with no
 * effect, before answering, so it spends the budget too. All paths: the home-wide `maxSlots`.
 * `grant`, for a grant request, is the relay's side: `replay` (the provisioning replay table),
 * `heldBy(member)` (slots that grant made) and `verify()` (the module's judgement of the call,
 * under the operator slot's lock).
 */
export function provisionGate(cfg, clock) {
  const open = hourly(); // the open and token paths: new slots, refused tokens
  const attempts = hourly(); // the grant path: every request
  const refusals = hourly(); // the grant path: refused requests
  const expected = cfg.gates.has('token') ? Buffer.from(cfg.tokenSha256, 'hex') : null;
  const tokenOk = (authorization) => {
    const m = /^Bearer (\S+)$/.exec(authorization ?? '');
    const given = createHash('sha256').update(m ? m[1] : '').digest();
    return timingSafeEqual(given, expected) && m !== null;
  };
  const wellFormed = ({ slot, account, base }) => typeof slot === 'string' && SLOT.test(slot) && slot !== TABLE_FILE
    && !(cfg.gates.has('grant') && slot === REPLAY_DIR) && cfg.slotRegex.test(slot)
    && typeof account === 'string' && HEX64.test(account) && base === cfg.prefix + slot;
  /** The slot's holder and the home's room, the same for every path. */
  const room = ({ account, base }, held) => {
    if (held.entry) {
      if (held.entry.account === account && held.entry.base === base) return { existing: held.entry };
      return { status: 409, error: 'This slot is provisioned for another account' };
    }
    if (held.occupied) return { status: 409, error: 'This slot name is in use on this relay' };
    if (held.count >= cfg.maxSlots) return { status: 507, result: 'refused:overQuota' };
    return { existing: null };
  };

  async function grantPath(asked, address, held, grant, now) {
    const wait = attempts.over(address, now, cfg.grantAttemptsPerAddressPerHour);
    if (wait) return { status: 429, result: 'refused:overQuota', retryAfter: wait };
    attempts.count(address, now);
    const shared = refusals.over(address, now, cfg.perAddressPerHour);
    if (shared) return { status: 429, result: 'refused:overQuota', retryAfter: shared };
    if (!wellFormed(asked)) { refusals.count(address, now); return { status: 400, result: 'malformed' }; }
    const full = grant.replay.full(now, cfg.replayRows);
    if (full) return { status: 429, result: 'refused:overQuota', retryAfter: full };
    const v = await grant.verify();
    if (!v.allowed) {
      if (v.status === 403) refusals.count(address, now);
      return { status: v.status, result: v.result, retryAfter: v.retryAfter };
    }
    // Verified: from here a refusal (the slot's holder, the room, the grant's slots held) has no
    // effect but still spends the call, recorded completed, against the grant's `perHour`.
    const limits = grantLimits(cfg, v.member);
    const r = room(asked, held);
    if (r.status) return { ...r, reserve: v.reserve };
    if (!r.existing && grant.heldBy(v.member) >= limits.maxSlots) return { status: 507, result: 'refused:overQuota', reserve: v.reserve };
    return { admit: true, existing: r.existing, by: { gate: 'grant', member: v.member, key: v.key, call: v.reserve.digest }, grant: v };
  }

  return async function admitProvision({ slot, account, base, address, authorization, held, grant }) {
    const now = clock();
    if (!cfg.enabled) return { status: 404, error: 'Not found' };
    const asked = { slot, account, base };
    const route = provisionRoute(cfg, authorization);
    if (route === 'grant') return grantPath(asked, address, held, grant, now);
    // The share first: a guesser over its share learns nothing about its token.
    const wait = open.over(address, now, cfg.perAddressPerHour);
    if (wait) return { status: 429, result: 'refused:overQuota', retryAfter: wait };
    if (route === 'none' || (route === 'token' && !tokenOk(authorization))) {
      open.count(address, now);
      return { status: 403, result: 'refused:noEntitlement' };
    }
    if (!wellFormed(asked)) return { status: 400, result: 'malformed' };
    const r = room(asked, held);
    if (r.status) return r;
    if (r.existing) return { admit: true, existing: r.existing };
    open.count(address, now);
    return { admit: true, existing: null, by: { gate: route } };
  };
}

/**
 * The provisioning replay table (gate "grant"): its own table, apart from every slot's (sync of
 * the operator account and provisioning never share rows or shares), at
 * `<dataDir>/provision-replay/replay.log`, in the same durable format as a slot's: a reservation
 * line (fsynced) before any effect, a completion line after it, compaction to the rows §12.4
 * keeps (the module says which: 7,260 s), so `grantPerHour` is counted from durable rows and
 * survives a restart. A reservation left pending by a crash is resolved from
 * `provisioned.json`: completed if a row names its call's digest, else abandoned; either way the
 * row stays and the call is a replay. Never by re-running.
 */
export class ProvisionReplay {
  constructor(dir, wasm, clock) {
    this.dir = dir; this.wasm = wasm; this.clock = clock;
    this.retentionMs = wasm.call({ op: 'limits' }).retentionMs;
    this.rows = new Map(); // key -> {digest, at, signer, t (its outcome, once it has one)}
    this.inFlight = new Map(); // key -> the effect a reservation has not ended yet
    this.bySigner = new Map();
    this.logLines = 0;
  }

  file(name) { return path.join(this.dir, name); }

  static async open(dataDir, { wasm, clock, table }) {
    const dir = path.join(dataDir, REPLAY_DIR);
    const st = await fsp.lstat(dir).catch((error) => { if (error.code === 'ENOENT') return null; throw error; });
    if (!st) await fsp.mkdir(dir, { mode: 0o700 });
    else if (!st.isDirectory() || st.isSymbolicLink()) throw new Error(`${dir} is not a directory: it holds the provisioning replay table`);
    for (const name of await fsp.readdir(dir)) {
      if (name !== 'replay.log' && !name.startsWith('.replay.')) throw new Error(`${dir} holds ${name}: it is the provisioning replay table, not a slot (rename that slot before turning gate "grant" on)`);
      if (name.startsWith('.replay.')) await fsp.rm(path.join(dir, name), { force: true });
    }
    const r = new ProvisionReplay(dir, wasm, clock);
    await r.load(table);
    return r;
  }

  async load(table) {
    // Fails closed, as a home slot's replay log does.
    const entries = await readLogRows(this.file('replay.log'), replayRow((e) => typeof e.slot === 'string'), 'The provisioning replay log');
    const pending = new Map();
    for (const e of entries) {
      this.logLines += 1;
      if (typeof e.r === 'string') {
        this.addRow(e.r, { digest: e.d, at: e.at, signer: e.s, t: e.t });
        if (e.e && !e.t) pending.set(e.r, e.e); else pending.delete(e.r);
      } else if (typeof e.c === 'string') {
        pending.delete(e.c);
        const row = this.rows.get(e.c);
        if (row) row.t = e.t;
      }
    }
    const rows = [...pending].map(([key, effect]) => ({ key, present: table.get(effect.slot)?.by?.call === this.rows.get(key).digest }));
    if (rows.length) for (const s of this.wasm.call({ op: 'replay_recover', rows }).states) this.rows.get(s.key).t = s.state;
    await this.compact();
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
      this.inFlight.delete(key);
      const set = this.bySigner.get(row.signer);
      set?.delete(key);
      if (set && set.size === 0) this.bySigner.delete(row.signer);
    }
  }

  /** Drop the rows §12.4 no longer keeps (the module says which), in memory. */
  prune(now) {
    const all = [...this.rows].map(([key, r]) => ({ key, at: r.at }));
    if (all.length === 0) return;
    const keep = new Set(this.wasm.call({ op: 'replay_keep', now, rows: all }).keep);
    this.dropRows(all.map((r) => r.key).filter((k) => !keep.has(k)));
  }

  /** The hard cap: with `cap` rows kept, the seconds until the oldest leaves; else 0. */
  full(now, cap) {
    if (this.rows.size < cap) return 0;
    this.prune(now);
    if (this.rows.size < cap) return 0;
    const oldest = Math.min(...[...this.rows.values()].map((r) => r.at));
    return Math.max(1, Math.ceil((oldest + this.retentionMs + 1 - now) / 1000));
  }

  /** The row for a call's key, and its principal's rows, for the module. */
  lookup(key, signer) {
    const row = this.rows.get(key);
    return {
      existing: row ? { at: row.at, digest: row.digest } : null,
      signerRows: [...(this.bySigner.get(signer) ?? [])].map((k) => ({ key: k, at: this.rows.get(k).at })),
    };
  }

  /** Rewrite the log with the rows kept, plus `extra` lines, staged and renamed. */
  async compact(extra = []) {
    this.prune(this.clock());
    // Each row keeps its outcome; a reservation whose effect has not ended stays pending.
    const lines = [...this.rows].map(([key, r]) => {
      const effect = this.inFlight.get(key);
      return JSON.stringify({ r: key, d: r.digest, s: r.signer, at: r.at, ...(effect ? { e: effect } : { t: r.t ?? 'completed' }) });
    });
    for (const e of extra) lines.push(JSON.stringify(e));
    const staged = this.file(`.replay.${randomBytes(8).toString('hex')}`);
    const handle = await fsp.open(staged, 'wx', 0o600);
    try { await writeAll(handle, lines.map((l) => l + '\n').join('')); await handle.sync(); } finally { await handle.close(); }
    await fsp.rename(staged, this.file('replay.log'));
    const dir = await fsp.open(this.dir, 'r');
    try { await dir.sync(); } catch (error) { if (error.code !== 'EINVAL' && error.code !== 'EPERM') throw error; } finally { await dir.close(); }
    this.logLines = lines.length;
  }

  async append(entry, durable) {
    if (this.broken) throw this.broken; // a part of a line could not be cut back
    const handle = await fsp.open(this.file('replay.log'), fsc.O_WRONLY | fsc.O_APPEND | fsc.O_CREAT | fsc.O_NOFOLLOW, 0o600);
    try { await appendLines(handle, JSON.stringify(entry) + '\n', durable); }
    catch (error) { if (error.unrepaired) this.broken = error; throw error; }
    finally { await handle.close(); }
    this.logLines += 1;
  }

  /** The reservation, durable before any effect. A new slot's names its effect (the slot), so
   * recovery can tell from `provisioned.json` whether it happened; an idempotent answer has no
   * effect and is written completed. */
  async reserve(row, effect) {
    const line = { r: row.key, d: row.digest, s: row.signer, at: row.at, ...(effect ? { e: effect } : { t: 'completed' }) };
    await this.append(line, true);
    this.addRow(row.key, { digest: row.digest, at: row.at, signer: row.signer, t: effect ? undefined : 'completed' });
    if (effect) this.inFlight.set(row.key, effect);
    if (this.logLines > 2 * this.rows.size + 1024) await this.compact();
  }
  async complete(key, t) {
    await this.append({ c: key, t }, false);
    this.inFlight.delete(key);
    const row = this.rows.get(key);
    if (row) row.t = t;
  }
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
