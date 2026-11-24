#!/usr/bin/env bun
// Command-line entry for the reference relay.
//   node relay/server.js                     start with env/config settings
//   node relay/server.js --config file.json  start with a JSON config file
//   node relay/server.js token               print a new bearer token and its SHA-256
//   node relay/server.js provisioned <config> list the provisioned slots: account, when, by
//                                            which gate or grant, claimed or not
import { existsSync, readFileSync } from 'node:fs';
import { HomeModule, moduleMemoryBytes } from './home.js';
import { webcrypto } from 'node:crypto';
import path from 'node:path';
import { ProvisionTable, TABLE_FILE, checkPrivateListen, clientAddressConfig, parsePrivateListen, provisionConfig } from './provision.js';
import { corsOrigins, newToken, startRelay } from './relay.js';
import { streamOptions } from './stream.js';

/** A test hook: wait at `point` the first time it is reached, until `file` exists. */
function pauseOnce(point, file) {
  let armed = true;
  return async (at) => {
    if (at !== point || !armed) return;
    armed = false;
    while (!existsSync(file)) await new Promise((resolve) => setTimeout(resolve, 5));
    process.stderr.write(`trace resumed ${point}\n`);
  };
}

function loadConfig(argv, env) {
  const index = argv.indexOf('--config');
  const file = index >= 0 ? argv[index + 1] : env.COLOPHON_RELAY_CONFIG;
  const config = file ? JSON.parse(readFileSync(file, 'utf8')) : {};
  const libraries = { ...(config.libraries ?? {}) };
  // Development convenience: COLOPHON_RELAY_TOKENS="home=<token>,work=<token>".
  for (const pair of (env.COLOPHON_RELAY_TOKENS ?? '').split(',').filter(Boolean)) {
    const at = pair.indexOf('=');
    if (at < 1) throw new Error('COLOPHON_RELAY_TOKENS entries are slot=token');
    libraries[pair.slice(0, at)] = { token: pair.slice(at + 1) };
  }
  for (const name of (env.COLOPHON_RELAY_OPEN ?? '').split(',').filter(Boolean)) libraries[name] = { open: true };
  const tls = config.tls ?? (env.COLOPHON_RELAY_TLS_CERT && env.COLOPHON_RELAY_TLS_KEY
    ? { certFile: env.COLOPHON_RELAY_TLS_CERT, keyFile: env.COLOPHON_RELAY_TLS_KEY } : undefined);
  // Home slots (0.5), provisioned for one account each:
  // COLOPHON_RELAY_HOME_SLOTS="slot=<account ID>@https://base,…".
  for (const pair of (env.COLOPHON_RELAY_HOME_SLOTS ?? '').split(',').filter(Boolean)) {
    const at = pair.indexOf('=');
    const rest = pair.slice(at + 1);
    const amp = rest.indexOf('@');
    if (at < 1 || amp < 1) throw new Error('COLOPHON_RELAY_HOME_SLOTS entries are slot=<account ID>@<base URL>');
    const { token, tokenSha256, ...kept } = libraries[pair.slice(0, at)] ?? {};
    libraries[pair.slice(0, at)] = { ...kept, home: true, account: rest.slice(0, amp), base: rest.slice(amp + 1) };
  }
  // The key file is preferred: a key in the environment is readable from the process. It is
  // removed from this process's environment once read.
  const keyText = env.COLOPHON_HOME_KEY ?? (env.COLOPHON_HOME_KEY_FILE ? readFileSync(env.COLOPHON_HOME_KEY_FILE, 'utf8') : config.home?.keyFile ? readFileSync(config.home.keyFile, 'utf8') : undefined);
  if (env.COLOPHON_HOME_KEY) delete env.COLOPHON_HOME_KEY;
  const wasm = env.COLOPHON_HOME_WASM ?? config.home?.wasm;
  // The module memory past which its instance is replaced (MiB); checked here so a bad value
  // refuses start-up with its message.
  const moduleMemoryMB = env.COLOPHON_MODULE_MEMORY_MB ?? config.home?.moduleMemoryMB;
  moduleMemoryBytes(moduleMemoryMB);
  // A test hook: the clock is the number of milliseconds in this file. It works only when the
  // relay is started with --test-clock; without that flag the relay refuses to start with it.
  const clockFile = env.COLOPHON_RELAY_CLOCK_FILE;
  if (clockFile && !argv.includes('--test-clock')) {
    throw new Error('COLOPHON_RELAY_CLOCK_FILE is a test hook: start the relay with --test-clock to use it, or unset it');
  }
  if (!clockFile && argv.includes('--test-clock')) throw new Error('--test-clock needs COLOPHON_RELAY_CLOCK_FILE');
  // Origins a browser page may reach this relay from: COLOPHON_RELAY_CORS_ORIGINS (comma
  // separated) or cors.origins in the config file. Default none: no CORS header is sent. A bad
  // entry refuses start-up (checked again by createRelay).
  const corsEnv = env.COLOPHON_RELAY_CORS_ORIGINS;
  const origins = corsEnv !== undefined
    ? (corsEnv.trim() === '' ? [] : corsEnv.split(',').map((o) => o.trim()))
    : config.cors?.origins;
  if (config.cors !== undefined && (config.cors === null || typeof config.cors !== 'object' || Array.isArray(config.cors))) {
    throw new Error('cors in the config file must be an object: {"origins": ["https://app.example"]}');
  }
  corsOrigins(origins);
  // Provisioning (the door at POST /v1/provision) and the client address behind a proxy: config
  // file only. Checked here so a bad setting refuses start-up with its message (and again by
  // createRelay).
  provisionConfig(config.provision);
  clientAddressConfig(config.clientAddress);
  streamOptions(config.stream);
  // The private listener: provisioning and the operator API, on an address only the operator's
  // own network reaches (COLOPHON_PRIVATE_LISTEN=host:port, or privateListen in the config file).
  // A Unix socket (unix:/path) is preferred; a host must be loopback or private unless
  // COLOPHON_PRIVATE_LISTEN_ALLOW_PUBLIC=1 (or privateListenAllowPublic) allows another.
  const privateListen = env.COLOPHON_PRIVATE_LISTEN
    ? parsePrivateListen(env.COLOPHON_PRIVATE_LISTEN, 'COLOPHON_PRIVATE_LISTEN')
    : config.privateListen;
  const privateListenAllowPublic = env.COLOPHON_PRIVATE_LISTEN_ALLOW_PUBLIC === '1' || config.privateListenAllowPublic === true;
  if (privateListen !== undefined) checkPrivateListen(privateListen, privateListenAllowPublic);
  const tracing = Boolean(clockFile) && env.COLOPHON_RELAY_TRACE === '1';
  return {
    cors: { origins: origins ?? [] },
    provision: config.provision,
    clientAddress: config.clientAddress,
    stream: config.stream,
    metrics: env.COLOPHON_METRICS_TOKEN_SHA256 ? { tokenSha256: env.COLOPHON_METRICS_TOKEN_SHA256.trim().toLowerCase() } : config.metrics,
    // Test hooks with the trace: the relay kills itself at the named point, or waits there (the
    // first time it is reached) until the file COLOPHON_RELAY_RESUME_FILE exists.
    crashAt: tracing ? env.COLOPHON_RELAY_CRASH_AT : undefined,
    hook: tracing && env.COLOPHON_RELAY_PAUSE_AT && env.COLOPHON_RELAY_RESUME_FILE ? pauseOnce(env.COLOPHON_RELAY_PAUSE_AT, env.COLOPHON_RELAY_RESUME_FILE) : undefined,
    home: keyText && wasm ? { key: JSON.parse(keyText), wasm, moduleMemoryMB } : undefined,
    // The test clock: a reading taken while a test rewrites the file can be empty; read again
    // rather than take 0 (which would put every entry in the future).
    clock: clockFile ? () => {
      for (let i = 0; i < 1000; i += 1) {
        const v = Number(readFileSync(clockFile, 'utf8').trim());
        if (Number.isFinite(v) && v > 0) return v;
      }
      throw new Error('the test clock file holds no time');
    } : undefined,
    tracing,
    tickMs: Number(env.COLOPHON_RELAY_TICK_MS ?? config.tickMs ?? 2000),
    // Test builds only: another home's address read from a file at each use, so tests can start
    // every relay on port 0 and tell each the others' ports afterwards (and after a restart).
    resolve: clockFile && env.COLOPHON_RELAY_RESOLVE_FILE ? () => {
      try { return JSON.parse(readFileSync(env.COLOPHON_RELAY_RESOLVE_FILE, 'utf8')); } catch { return config.resolve ?? {}; }
    } : config.resolve,
    host: env.COLOPHON_RELAY_HOST ?? config.host ?? '127.0.0.1',
    port: Number(env.COLOPHON_RELAY_PORT ?? config.port ?? 8787),
    privateListen,
    privateListenAllowPublic,
    dataDir: env.COLOPHON_RELAY_DATA ?? config.dataDir ?? './relay-data',
    libraries,
    limits: config.limits ?? {},
    tls: tls && { cert: readFileSync(tls.certFile), key: readFileSync(tls.keyFile) },
  };
}

/**
 * The operator's view of the provisioning table, read-only (the relay may be running): each slot
 * with its account, when it was made, by which gate (for a grant, the member ID and the label the
 * operator account gives it, and whether that member is revoked now), and whether the slot is
 * claimed (appointed, or holding a first upload). Removing a grant is revoking that member in the
 * operator account; its slots are left alone (an appointed one keeps being witnessed, an
 * unclaimed one is released after unclaimedHours).
 */
async function listProvisioned(argv, env) {
  const file = argv.find((a) => !a.startsWith('--')) ?? env.COLOPHON_RELAY_CONFIG;
  const config = file ? JSON.parse(readFileSync(file, 'utf8')) : {};
  const provision = provisionConfig(config.provision);
  const dataDir = path.resolve(env.COLOPHON_RELAY_DATA ?? config.dataDir ?? './relay-data');
  const wasm = env.COLOPHON_HOME_WASM ?? config.home?.wasm;
  if (!wasm) throw new Error('the listing needs the home module: COLOPHON_HOME_WASM or home.wasm');
  const clockFile = env.COLOPHON_RELAY_CLOCK_FILE;
  if (clockFile && !argv.includes('--test-clock')) throw new Error('COLOPHON_RELAY_CLOCK_FILE is a test hook: pass --test-clock to use it, or unset it');
  const now = clockFile ? Number(readFileSync(clockFile, 'utf8').trim()) : Date.now();
  const module = await HomeModule.load(wasm);
  const table = existsSync(path.join(dataDir, TABLE_FILE)) ? await ProvisionTable.load(dataDir, provision) : ProvisionTable.empty(dataDir);
  const stateOf = (slot) => {
    try { return JSON.parse(readFileSync(path.join(dataDir, slot, 'home-state.json'), 'utf8')); } catch { return null; }
  };
  const members = new Map();
  const operatorState = provision.operator ? stateOf(provision.operator.slot) : null;
  if (operatorState) {
    try { for (const m of module.call({ op: 'provision_access', query: 'members', state: operatorState, now }).members) members.set(m.id, m); }
    catch (error) { process.stderr.write(`the operator slot's members cannot be read: ${error.message}\n`); }
  }
  const out = [];
  for (const slot of [...table.keys()].sort()) {
    const e = table.get(slot);
    const state = stateOf(slot);
    let claimed = false;
    if (state) { try { const st = module.call({ op: 'status', state, now }); claimed = Boolean(st.appointed || st.held > 0); } catch { claimed = false; } }
    const by = e.by ?? { gate: 'unknown' };
    const grant = by.gate === 'grant' ? members.get(by.member) : undefined;
    out.push({ slot, account: e.account, at: new Date(e.at).toISOString(), by,
      ...(by.gate === 'grant' ? { label: grant?.label ?? null, revoked: grant ? grant.revoked : null } : {}), claimed });
  }
  return out;
}

if (process.argv[2] === 'provisioned') {
  try { process.stdout.write(JSON.stringify(await listProvisioned(process.argv.slice(3), process.env), null, 2) + '\n'); } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
} else if (process.argv[2] === 'home-key') {
  // A new home key as a private JWK. Keep it secret: it signs this home's receipts and heads.
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  process.stdout.write(JSON.stringify(await webcrypto.subtle.exportKey('jwk', pair.privateKey)) + '\n');
} else if (process.argv[2] === 'token') {
  const { token, tokenSha256 } = newToken();
  process.stdout.write(JSON.stringify({ token, tokenSha256 }, null, 2) + '\n');
} else {
  let config;
  try { config = loadConfig(process.argv.slice(2), process.env); } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
  if (Object.keys(config.libraries).length === 0 && config.provision?.enabled !== true && !existsSync(path.join(config.dataDir, TABLE_FILE))) {
    console.error('No library slots configured. Set COLOPHON_RELAY_TOKENS=slot=token or pass --config.');
    process.exit(2);
  }
  const running = await startRelay(config);
  // The first stdout line is machine-readable, so tests and supervisors can use port 0.
  process.stdout.write(JSON.stringify({ listening: { host: running.host, port: running.port, tls: Boolean(config.tls),
    ...(running.privatePort !== undefined ? { private: { host: running.privateHost, port: running.privatePort } } : {}),
    ...(running.privatePath !== undefined ? { private: { path: running.privatePath } } : {}) } }) + '\n');
  // Test builds only (--test-clock): each line `tick` on stdin runs one scheduler pass over every
  // home slot (recording entries, heads) and answers {"ticked":true} on stdout once it is done, so
  // a test publishes heads when it asks instead of waiting for the timer (start the relay with
  // COLOPHON_RELAY_TICK_MS=0 for no timer at all). Without --test-clock stdin is never read.
  if (process.argv.includes('--test-clock')) {
    let queue = Promise.resolve();
    let pending = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      pending += chunk;
      let at;
      while ((at = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, at).trim();
        pending = pending.slice(at + 1);
        if (line !== 'tick') continue;
        queue = queue.then(() => running.relay.tickAll()).catch((error) => console.error(`test tick failed: ${error.message}`))
          .then(() => { process.stdout.write('{"ticked":true}\n'); });
      }
    });
    process.stdin.on('error', () => {});
  }
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    try { await running.close(); process.exit(0); }
    catch (error) { console.error(error.message); process.exit(1); }
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
