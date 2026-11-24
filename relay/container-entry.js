#!/usr/bin/env bun
// The container's entry point: a Colophon home configured by environment variables alone, with
// everything it keeps under one volume. It prepares the volume and a relay config, then runs
// `server.js` in this process (PID 1), so the relay's own config checks, data-directory lock and
// SIGTERM handling are the ones that run. It writes no protocol rule and holds no key in memory
// beyond the key generation the relay's own CLI does.
//
//   <data>/config.json                  if present, used as-is (the escape hatch); nothing is generated
//   <data>/run/relay-config.json        otherwise: the config written from the environment at each start
//   <data>/records-dir/                 the relay's dataDir (slots, provisioned.json, .relay.lock)
//   <data>/secrets/home-key.jwk         the home's private P-256 JWK, made once by `server.js home-key`
//   <data>/secrets/provision-token.sha256  the SHA-256 of the provisioning token (gate "token"); the
//                                       token itself is printed once, at the start that makes it
//   <data>/.container.lock              held by the running container; see acquireContainerLock
//
// The image runs it as UID 65532. Started as root instead (a platform whose volumes are root's,
// such as Railway with RAILWAY_RUN_UID=0), it gives the volume to that user and becomes it before
// anything else: see dropRoot.
//
//   bun container-entry.js              prepare and run the relay
//   bun container-entry.js identity <key file>   print {"member": "<home ID>"} for a key (used at start)
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { closeSync, constants as fsc, fstat, fstatSync, fsyncSync, futimes, lchownSync, linkSync, lstatSync, mkdirSync, openSync, promises as fsp, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeSync, chmodSync, existsSync } from 'node:fs';
import { promisify } from 'node:util';
import { hostname } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(here, 'server.js');
export const DEFAULT_WASM = path.join(here, 'colophon_home_wasm.wasm');
const HEX64 = /^[0-9a-f]{64}$/;

/** A setting the operator got wrong: the message names the variable. */
export class SettingError extends Error {}

const int = (env, name, { min = 0, fallback } = {}) => {
  const v = env[name];
  if (v === undefined || v.trim() === '') return fallback;
  if (!/^\d+$/.test(v.trim()) || Number(v) < min || !Number.isSafeInteger(Number(v))) throw new SettingError(`${name} must be an integer of at least ${min}, not ${JSON.stringify(v)}`);
  return Number(v);
};
const list = (v) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

/**
 * The environment, read and checked. Pure: no file is touched. The relay checks the config it is
 * given again at start-up (provisionConfig, corsOrigins, clientAddressConfig), so this only checks
 * what it must interpret itself.
 */
export function readSettings(env) {
  const port = int(env, 'PORT', { min: 0, fallback: 8080 }); // 0: a free port (tests)
  if (port > 65535) throw new SettingError('PORT must be at most 65535');
  const rawUrl = env.COLOPHON_PUBLIC_URL;
  if (!rawUrl) throw new SettingError('COLOPHON_PUBLIC_URL is required: the https:// origin clients reach this home at, for example https://home.example.org');
  let url;
  try { url = new URL(rawUrl); } catch { throw new SettingError(`COLOPHON_PUBLIC_URL is not a URL: ${JSON.stringify(rawUrl)}`); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) throw new SettingError('COLOPHON_PUBLIC_URL must be https:// (plain http only to a loopback host, for tests)');
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash || url.username || url.password) {
    throw new SettingError('COLOPHON_PUBLIC_URL must be an origin only, with no path, query or credentials: slots are served at <origin>/v1/libraries/<slot>');
  }
  const origin = url.origin;
  const provisionText = (env.COLOPHON_PROVISION ?? 'on').trim().toLowerCase();
  if (!['on', 'off', 'true', 'false', '1', '0'].includes(provisionText)) throw new SettingError('COLOPHON_PROVISION must be on or off');
  const provisioning = ['on', 'true', '1'].includes(provisionText);
  const gates = list(env.COLOPHON_PROVISION_GATE ?? 'token');
  if (gates.length === 0) throw new SettingError('COLOPHON_PROVISION_GATE must name a gate: token, open or grant (or a list such as grant,token)');
  const tokenSha256 = env.COLOPHON_PROVISION_TOKEN_SHA256?.trim().toLowerCase() || undefined;
  if (tokenSha256 !== undefined && !HEX64.test(tokenSha256)) throw new SettingError('COLOPHON_PROVISION_TOKEN_SHA256 must be 64 hex characters (the SHA-256 of the token, not the token)');
  let operator;
  if (gates.includes('grant')) {
    const account = env.COLOPHON_PROVISION_OPERATOR_ACCOUNT; const slot = env.COLOPHON_PROVISION_OPERATOR_SLOT;
    if (!account || !slot) throw new SettingError('gate grant needs COLOPHON_PROVISION_OPERATOR_ACCOUNT and COLOPHON_PROVISION_OPERATOR_SLOT');
    operator = { account, slot };
  }
  const header = env.COLOPHON_CLIENT_IP_HEADER?.trim() || undefined;
  const proxies = list(env.COLOPHON_TRUSTED_PROXIES);
  if (Boolean(header) !== (proxies.length > 0)) throw new SettingError('COLOPHON_CLIENT_IP_HEADER and COLOPHON_TRUSTED_PROXIES go together: the header is read only from those peers');
  return {
    port,
    host: env.COLOPHON_HOST?.trim() || '0.0.0.0',
    origin,
    prefix: `${origin}/v1/libraries/`,
    provisioning,
    gates,
    tokenSha256,
    operator,
    maxSlots: int(env, 'COLOPHON_MAX_SLOTS', { min: 1 }),
    perAddressPerHour: int(env, 'COLOPHON_PROVISION_PER_ADDRESS_PER_HOUR', { min: 1 }),
    unclaimedHours: int(env, 'COLOPHON_PROVISION_UNCLAIMED_HOURS', { min: 1 }),
    slotBytes: int(env, 'COLOPHON_SLOT_BYTES', { min: 0 }),
    corsOrigins: list(env.COLOPHON_CORS_ORIGINS),
    clientAddress: header ? { header, trustedPeers: proxies } : undefined,
    wasm: env.COLOPHON_HOME_WASM || DEFAULT_WASM,
  };
}

/** The relay config for these settings. Pure. `tokenSha256` is the stored or supplied hash. */
export function relayConfig(s, { dataDir, keyFile, tokenSha256 }) {
  const config = {
    host: s.host,
    port: s.port,
    dataDir,
    home: { keyFile, wasm: s.wasm },
    cors: { origins: s.corsOrigins },
  };
  if (s.slotBytes !== undefined) config.limits = { slotBytes: s.slotBytes };
  if (s.clientAddress) config.clientAddress = s.clientAddress;
  // The prefix stays set when provisioning is off: a table written while it was on is checked
  // against it at start-up.
  const provision = { enabled: s.provisioning, prefix: s.prefix };
  if (s.provisioning) {
    provision.gate = s.gates.length === 1 ? s.gates[0] : s.gates;
    if (s.gates.includes('token')) provision.tokenSha256 = tokenSha256;
    if (s.operator) { provision.operator = s.operator; provision.audience = `${s.origin}/v1/provision`; }
    for (const k of ['maxSlots', 'perAddressPerHour', 'unclaimedHours']) if (s[k] !== undefined) provision[k] = s[k];
  }
  config.provision = provision;
  return config;
}

/** Write all of `data` (a string or bytes) to `fd`: a write may take fewer bytes than it is
 * given, so the rest is written until none is left. */
export function writeAllSync(fd, data, write = writeSync) {
  const bytes = typeof data === 'string' ? Buffer.from(data) : data;
  let done = 0;
  while (done < bytes.length) {
    const n = write(fd, bytes, done, bytes.length - done);
    if (!(n > 0)) throw new Error('a write made no progress');
    done += n;
  }
}

/** Writes `bytes` to `file` (mode 0600) by a staged, fsynced file renamed into place. */
function writeAtomic(file, bytes) {
  const staged = `${file}.${process.pid}.new`;
  const fd = openSync(staged, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_TRUNC | fsc.O_NOFOLLOW, 0o600);
  try { writeAllSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(staged, file);
  syncDir(path.dirname(file));
}

/** Creates `file` (mode 0600) only if it does not exist: staged, fsynced, then linked into place. */
function writeNew(file, bytes) {
  const staged = `${file}.${process.pid}.new`;
  const fd = openSync(staged, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
  try { writeAllSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  try { linkSync(staged, file); } finally { unlinkSync(staged); }
  syncDir(path.dirname(file));
}

function syncDir(dir) {
  const fd = openSync(dir, fsc.O_RDONLY);
  try { fsyncSync(fd); } catch { /* not every file system syncs a directory */ } finally { closeSync(fd); }
}

function privateDir(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = statSync(dir);
  if (!st.isDirectory()) throw new Error(`${dir} is not a directory`);
  if ((st.mode & 0o077) !== 0) chmodSync(dir, 0o700);
}

/** Runs one of server.js's commands (`home-key`, `token`) and returns its JSON output. */
function serverCommand(command) {
  const r = spawnSync(process.execPath, [SERVER, command], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '' }, timeout: 30_000 });
  if (r.status !== 0) throw new Error(`server.js ${command} failed (status ${r.status}): ${r.stderr}`);
  return JSON.parse(r.stdout);
}

/** The home's member ID for a key file, by the relay's own key check (in a short child process,
 * so this process never loads the key or a second copy of the module). */
export function memberIdOf(keyFile, wasm) {
  const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), 'identity', keyFile], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', COLOPHON_HOME_WASM: wasm }, timeout: 30_000 });
  if (r.status !== 0) throw new Error(`the home key in ${keyFile} does not load: ${r.stderr.trim()}`);
  return JSON.parse(r.stdout).member;
}

/**
 * Prepares the volume for a start. Returns `{configFile, dataDir, generated, memberId, token}`
 * (`token` only on the start that made it; the caller prints it once and drops it) and the env
 * changes the relay needs (`env`: keys to set, `unset`: keys to remove).
 */
export function prepare(dataRoot, env) {
  privateDir(dataRoot);
  const userConfig = path.join(dataRoot, 'config.json');
  if (existsSync(userConfig)) {
    const config = JSON.parse(readFileSync(userConfig, 'utf8'));
    const set = {};
    if (!config.home?.wasm && !env.COLOPHON_HOME_WASM) set.COLOPHON_HOME_WASM = DEFAULT_WASM;
    if (config.host === undefined && env.COLOPHON_RELAY_HOST === undefined) set.COLOPHON_RELAY_HOST = env.COLOPHON_HOST?.trim() || '0.0.0.0';
    if (config.port === undefined && env.COLOPHON_RELAY_PORT === undefined) set.COLOPHON_RELAY_PORT = String(int(env, 'PORT', { min: 0, fallback: 8080 }));
    const dataDir = path.resolve(dataRoot, env.COLOPHON_RELAY_DATA ?? config.dataDir ?? './relay-data');
    const keyFile = env.COLOPHON_HOME_KEY_FILE ?? (config.home?.keyFile && path.resolve(dataRoot, config.home.keyFile));
    const wasm = set.COLOPHON_HOME_WASM ?? env.COLOPHON_HOME_WASM ?? config.home?.wasm;
    const memberId = keyFile && existsSync(keyFile) && wasm ? memberIdOf(keyFile, path.resolve(dataRoot, wasm)) : undefined;
    return { configFile: userConfig, dataDir, generated: false, memberId, env: set, unset: [] };
  }
  const s = readSettings(env);
  refuseLegacyDataDir(dataRoot);
  const secrets = path.join(dataRoot, 'secrets');
  const dataDir = path.join(dataRoot, 'records-dir');
  const run = path.join(dataRoot, 'run');
  for (const d of [secrets, dataDir, run]) privateDir(d);

  // The home key: made once by the relay's own `home-key` command, checked by the relay's own key
  // import (x, y against d) before it is put in place, never overwritten, never printed.
  const keyFile = path.join(secrets, 'home-key.jwk');
  if (!existsSync(keyFile)) {
    const jwk = serverCommand('home-key');
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d) throw new Error('server.js home-key did not print a private P-256 JWK');
    const staged = `${keyFile}.check`;
    writeAtomic(staged, JSON.stringify(jwk) + '\n');
    try { memberIdOf(staged, s.wasm); writeNew(keyFile, readFileSync(staged)); } finally { unlinkSync(staged); }
  }
  if ((statSync(keyFile).mode & 0o077) !== 0) chmodSync(keyFile, 0o600);
  const memberId = memberIdOf(keyFile, s.wasm);

  // The provisioning token (gate "token"): supplied as a hash, or made once by the relay's own
  // `token` command. Only its SHA-256 is stored; the token goes back to the caller to print once.
  let tokenSha256; let token;
  if (s.provisioning && s.gates.includes('token')) {
    const hashFile = path.join(secrets, 'provision-token.sha256');
    if (s.tokenSha256) tokenSha256 = s.tokenSha256;
    else if (existsSync(hashFile)) {
      tokenSha256 = readFileSync(hashFile, 'utf8').trim();
      if (!HEX64.test(tokenSha256)) throw new Error(`${hashFile} does not hold a SHA-256; remove it to make a new token`);
    } else {
      const made = serverCommand('token');
      writeNew(hashFile, made.tokenSha256 + '\n');
      tokenSha256 = made.tokenSha256; token = made.token;
    }
  }

  const configFile = path.join(run, 'relay-config.json');
  writeAtomic(configFile, JSON.stringify(relayConfig(s, { dataDir, keyFile, tokenSha256 }), null, 2) + '\n');
  // Variables server.js reads that would override the generated config, or that are test hooks.
  const unset = ['COLOPHON_RELAY_HOST', 'COLOPHON_RELAY_PORT', 'COLOPHON_RELAY_DATA', 'COLOPHON_RELAY_CONFIG',
    'COLOPHON_RELAY_CORS_ORIGINS', 'COLOPHON_HOME_KEY', 'COLOPHON_HOME_KEY_FILE', 'COLOPHON_HOME_WASM',
    'COLOPHON_RELAY_CLOCK_FILE', 'COLOPHON_RELAY_TRACE', 'COLOPHON_RELAY_RESOLVE_FILE', 'COLOPHON_RELAY_TLS_CERT', 'COLOPHON_RELAY_TLS_KEY'];
  return { configFile, dataDir, generated: true, memberId, token, settings: s, env: {}, unset };
}

/**
 * "Never two relays on one data directory", across containers. The relay's own lock
 * (`<dataDir>/.relay.lock`) names a process ID, and each container has its own PID namespace: a
 * second container cannot tell a live owner from a dead one by PID, and after an unclean stop
 * (SIGKILL, OOM, power loss) the restarted relay sees its own PID in the stale lock and refuses
 * for ever. So the container holds a lock of its own on the volume, kept fresh by a heartbeat (its
 * mtime, every `beatMs`): another start refuses while it is fresher than `staleMs`, and takes it
 * over once it is older. Holding it, a relay lock left in the data directory can only be from a
 * container that is gone, so it is removed before the relay starts; the relay then takes its own
 * lock as always. If the lock is taken from under a running holder (it was frozen longer than
 * `staleMs`), the holder exits at its next beat instead of writing beside the new one.
 *
 * A lock that names this container's own host name and process ID is an earlier run of this same
 * container (restarted after a hard stop): no other container has its host name. A live holder
 * beats every `beatMs`, so such a lock is stale after two missed beats rather than `staleMs`.
 */
export function acquireContainerLock(dataRoot, { staleMs = 30_000, beatMs = 5_000, now = Date.now, onLost, host = hostname(), pid = process.pid, schedule = later, io = LOCK_IO } = {}) {
  const file = path.join(dataRoot, '.container.lock');
  // Each lock file carries a random ID: a file system may give a new file a removed one's inode
  // number at once (Linux does), so the inode cannot say whose lock a file is.
  const id = randomBytes(16).toString('hex');
  const owner = JSON.stringify({ host, pid, at: new Date(now()).toISOString(), id }) + '\n';
  const idOf = (f) => { try { return JSON.parse(readFileSync(f, 'utf8'))?.id ?? null; } catch { return null; } };
  const ownStaleMs = Math.min(staleMs, 2 * beatMs + 1_000);
  // The holder keeps its lock file open: the heartbeat touches it through this descriptor, so it
  // can only ever touch this holder's own file, and while it is open that file's inode is not
  // reused, so a path that names another inode is another owner's lock.
  let fd = null;
  const take = () => {
    const opened = openSync(file, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
    try { writeAllSync(opened, owner); fsyncSync(opened); } catch (e) { closeSync(opened); throw e; }
    fd = opened;
    return true;
  };
  let taken = false;
  for (let attempt = 0; attempt < 3 && !taken; attempt++) {
    try { taken = take(); break; } catch (e) { if (e.code !== 'EEXIST') throw e; }
    let st;
    try { st = statSync(file); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    const age = now() - st.mtimeMs;
    let held = {};
    try { held = JSON.parse(readFileSync(file, 'utf8')) ?? {}; } catch { /* torn */ }
    const own = held.host === host && held.pid === pid;
    const limit = own ? ownStaleMs : staleMs;
    if (age < limit) {
      const err = new Error(own
        ? `this container's earlier run left ${file} (heartbeat ${Math.round(age / 1000)}s ago); starting once it is ${Math.ceil(limit / 1000)}s old, in ${Math.ceil((limit - age) / 1000)}s.`
        : `another container holds this volume (${file}, host ${held.host || 'unknown'}, heartbeat ${Math.round(age / 1000)}s ago); a relay never shares its data directory. Stop the other container, or wait ${Math.ceil((limit - age) / 1000)}s if it is gone.`);
      err.code = 'ELOCKED';
      throw err;
    }
    // Stale: move it aside by rename (atomic), then check that what moved is the stale lock seen
    // above, not one another starter made meanwhile; if not, put it back and refuse.
    const aside = `${file}.stale.${process.pid}`;
    try { renameSync(file, aside); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    // `held.id` is the stale lock's (undefined for one that was torn or written before IDs); a
    // lock its holder touched since it was judged stale is not stale any more.
    let movedAge = 0;
    try { movedAge = now() - statSync(aside).mtimeMs; } catch { movedAge = 0; }
    if (idOf(aside) !== (held.id ?? null) || movedAge < limit) {
      try { linkSync(aside, file); } catch { /* the new owner's lock is back or replaced */ }
      unlinkSync(aside);
      const err = new Error(`another container took this volume while this one was starting (${file})`);
      err.code = 'ELOCKED';
      throw err;
    }
    unlinkSync(aside);
  }
  if (!taken) throw new Error(`could not take ${file}`);
  let lost = false; let stopped = false; let cancel = null;
  const same = (a, b) => a.ino === b.ino && a.dev === b.dev;
  const mine = () => { try { return same(lstatSync(file), fstatSync(fd)); } catch { return false; } };
  /** Whether the path still names this holder's file: false only for a verified other file (or
   * none); an I/O error is thrown, a failed beat, not a lost lock. */
  const owned = async () => {
    const [at, own] = await Promise.all([io.lstat(file).catch((e) => { if (e.code === 'ENOENT') return null; throw e; }), io.fstat(fd)]);
    return at !== null && same(at, own);
  };
  // The beats run off the event loop's thread (asynchronous file calls), one at a time: the next
  // is scheduled only when this one has ended, so a slow disk delays beats and never stacks them.
  const health = { lastBeatAt: now(), failures: 0, error: null };
  const beat = async () => {
    cancel = null;
    const t = new Date(now());
    try {
      await io.futimes(fd, t, t); // this holder's own file, whatever the path names now
      if (stopped) return;
      if (!(await owned())) {
        if (stopped) return;
        lost = true;
        (onLost ?? (() => { console.error(`colophon-home: ${file} was taken by another container; stopping at once`); process.exit(70); }))();
        return;
      }
      Object.assign(health, { lastBeatAt: t.getTime(), failures: 0, error: null });
    } catch (e) {
      if (stopped) return;
      health.failures += 1; health.error = e.message;
      console.error(`colophon-home: heartbeat failed: ${e.message}`);
    }
    if (!stopped) cancel = schedule(beat, beatMs);
  };
  cancel = schedule(beat, beatMs);
  return {
    file,
    /** `ok` while the last beat succeeded and it is no older than two beats and a second (what
     * this container's own restart would take as stale); when it last did; failures since. */
    health() {
      const ageMs = now() - health.lastBeatAt;
      return { ok: health.failures === 0 && ageMs <= ownStaleMs, ...health, ageMs };
    },
    release() {
      stopped = true;
      cancel?.(); cancel = null;
      if (!lost && mine()) { try { unlinkSync(file); } catch { /* already gone */ } }
      if (fd !== null) { try { closeSync(fd); } catch { /* closed */ } fd = null; }
    },
  };
}

/** The lock's asynchronous file calls (a test replaces them). */
const LOCK_IO = { futimes: promisify(futimes), fstat: promisify(fstat), lstat: (f) => fsp.lstat(f) };

/** `fn` after `ms`, on a timer that does not keep the process alive; returns its cancel. */
function later(fn, ms) {
  const timer = setTimeout(fn, ms);
  timer.unref?.();
  return () => clearTimeout(timer);
}

/**
 * Generated mode keeps the relay's data under `records-dir/`. A relay data directory mounted at
 * the volume's root instead (an existing home's slots, its provisioning table, or its lock) is
 * refused, never started beside as a new, empty home with a new key.
 */
function refuseLegacyDataDir(dataRoot) {
  const ours = new Set(['secrets', 'records-dir', 'run', 'config.json', '.container.lock', 'lost+found']);
  const found = [];
  for (const entry of readdirSync(dataRoot, { withFileTypes: true })) {
    const name = entry.name;
    if (ours.has(name) || name.startsWith('.container.lock.')) continue;
    if (['provisioned.json', 'provision-replay', '.relay.lock', '.relay.lock.reclaim'].includes(name)) found.push(name);
    else if (entry.isDirectory() && ['meta.json', 'home-state.json', 'log.jsonl'].some((f) => existsSync(path.join(dataRoot, name, f)))) found.push(`${name}/`);
  }
  if (found.length) {
    throw new SettingError(`${dataRoot} already holds a relay data directory (${found.slice(0, 5).join(', ')}): this image keeps its own under ${path.join(dataRoot, 'records-dir')} and would start a new, empty home with a new key beside it. To move an existing home in, stop the relay that serves it first, then add ${path.join(dataRoot, 'config.json')} naming its dataDir and its home key (docs/self-hosting/docker.md, "Moving an existing home into the container").`);
  }
}

/**
 * The relay locks (`.relay.lock`, `.relay.lock.reclaim`) in `dataDir`, removed only when they can
 * only be this container's own from an earlier run: in the container's data root, and naming
 * this process's ID (the relay runs in this process, so an earlier run of this container wrote
 * that ID; a relay outside the container, whose process cannot be seen from here, did not). Any
 * other relay lock is left in place and the start refused: the relay that wrote it may be
 * running. Call only while holding the container lock.
 */
export function clearDeadRelayLock(dataDir, { dataRoot, pid = process.pid } = {}) {
  const inside = dataRoot !== undefined && !path.relative(path.resolve(dataRoot), path.resolve(dataDir)).startsWith('..');
  const removable = [];
  for (const name of ['.relay.lock', '.relay.lock.reclaim']) {
    const f = path.join(dataDir, name);
    let text;
    try { text = readFileSync(f, 'utf8'); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    let owner = null;
    try { owner = JSON.parse(text); } catch { owner = null; }
    if (!inside || !Number.isSafeInteger(owner?.pid) || owner.pid !== pid) {
      const err = new Error(`${f} may belong to another relay serving this data directory (${owner && Number.isSafeInteger(owner.pid) ? `process ${owner.pid}` : 'no readable owner'}), which this container cannot see. A relay never shares its data directory: stop the other relay (it removes its lock), or, if you are sure none is running, remove ${f} yourself; then start again.`);
      err.code = 'ELOCKED';
      throw err;
    }
    removable.push(name);
  }
  for (const name of removable) {
    try { unlinkSync(path.join(dataDir, name)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  return removable;
}

/** The user the image runs the home as (distroless "nonroot"). */
export const RUN_UID = 65532;

/** Gives `root` and everything under it to `uid:gid`, following no symbolic link. Returns how many entries changed owner. */
export function giveTree(root, uid, gid) {
  let changed = 0;
  const visit = (p) => {
    const st = lstatSync(p);
    if (st.uid !== uid || st.gid !== gid) { lchownSync(p, uid, gid); changed++; }
    if (st.isDirectory()) for (const name of readdirSync(p)) visit(path.join(p, name));
  };
  visit(root);
  return changed;
}

/**
 * Started as root, the home gives its volume to the unprivileged user and becomes that user, for
 * good (groups, group, then user), before it reads a setting or opens a file of its own. Some
 * platforms mount a volume owned by root and can only start the container as root to use it.
 * Started as any other user it does nothing.
 */
export function dropRoot(dataRoot, { uid = RUN_UID, gid = RUN_UID } = {}) {
  if (process.getuid?.() !== 0) return false;
  mkdirSync(dataRoot, { recursive: true, mode: 0o700 });
  const changed = giveTree(dataRoot, uid, gid);
  process.setgroups([gid]); process.setgid(gid); process.setuid(uid);
  if (process.getuid() !== uid || process.geteuid() !== uid || process.getgid() !== gid) throw new Error('could not leave root');
  console.error(`colophon-home: started as root; now UID ${uid}${changed ? `, after giving it ${changed} entries under ${dataRoot}` : ''}`);
  return true;
}

async function main() {
  process.umask(0o077);
  // As PID 1 a signal with no handler is ignored. Until server.js installs its own (after the
  // relay has started), a stop exits at once: every write before that point is crash-safe.
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.on(signal, () => { if (process.listenerCount(signal) === 1) process.exit(128 + (signal === 'SIGTERM' ? 15 : 2)); });
  }
  const dataRoot = path.resolve(process.env.COLOPHON_DATA || '/data');
  let lock; let prepared;
  try {
    dropRoot(dataRoot);
    privateDir(dataRoot);
    lock = acquireContainerLock(dataRoot);
    process.on('exit', () => lock.release());
    // /healthz answers 503 while the lock's heartbeat fails: another container could take the
    // volume over once the lock looks stale.
    const { addHealthCheck } = await import('./health.js');
    addHealthCheck('container lock', () => lock.health());
    prepared = prepare(dataRoot, process.env);
  } catch (error) {
    console.error(`colophon-home: ${error.message}`);
    lock?.release();
    process.exit(error instanceof SettingError || error.code === 'ELOCKED' ? 2 : 1);
  }
  let removed;
  try { removed = clearDeadRelayLock(prepared.dataDir, { dataRoot }); }
  catch (error) {
    console.error(`colophon-home: ${error.message}`);
    lock.release();
    process.exit(error.code === 'ELOCKED' ? 2 : 1);
  }
  if (removed.length) console.error(`colophon-home: removed ${removed.join(', ')} left by an earlier run of this container`);
  const s = prepared.settings;
  const info = { colophonHome: { config: prepared.generated ? 'generated' : prepared.configFile, member: prepared.memberId ?? null,
    ...(s ? { base: s.prefix + '<slot>', provisioning: s.provisioning ? s.gates : false } : {}) } };
  process.stdout.write(JSON.stringify(info) + '\n');
  if (prepared.token) {
    // The one time the token is shown. Only its SHA-256 is kept on the volume.
    process.stdout.write([
      '',
      '==================== COLOPHON PROVISIONING TOKEN (shown once) ====================',
      `COLOPHON_PROVISION_TOKEN=${prepared.token}`,
      'Apps provision a home slot with: Authorization: Bearer <this token>',
      'It is not stored: only its SHA-256 is, in secrets/provision-token.sha256. To make a',
      'new one, remove that file and restart.',
      '===================================================================================',
      '',
    ].join('\n') + '\n');
    prepared.token = undefined;
  }
  for (const k of prepared.unset) delete process.env[k];
  Object.assign(process.env, prepared.env);
  process.chdir(dataRoot);
  process.argv = [process.argv[0], SERVER, '--config', prepared.configFile];
  await import(pathToFileURL(SERVER).href);
}

if (import.meta.main) {
  if (process.argv[2] === 'identity') {
    const { HomeKey, HomeModule } = await import('./home.js');
    try {
      const module = await HomeModule.load(process.env.COLOPHON_HOME_WASM || DEFAULT_WASM);
      const key = await HomeKey.fromJwk(JSON.parse(readFileSync(process.argv[3], 'utf8')), module);
      process.stdout.write(JSON.stringify({ member: key.memberId }) + '\n');
    } catch (error) { console.error(error.message); process.exit(1); }
  } else await main();
}
