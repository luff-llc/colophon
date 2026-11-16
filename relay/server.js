#!/usr/bin/env bun
// Command-line entry for the reference relay.
//   node relay/server.js                     start with env/config settings
//   node relay/server.js --config file.json  start with a JSON config file
//   node relay/server.js token               print a new bearer token and its SHA-256
import { existsSync, readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import path from 'node:path';
import { TABLE_FILE, clientAddressConfig, provisionConfig } from './provision.js';
import { corsOrigins, newToken, startRelay } from './relay.js';

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
  const tracing = Boolean(clockFile) && env.COLOPHON_RELAY_TRACE === '1';
  return {
    cors: { origins: origins ?? [] },
    provision: config.provision,
    clientAddress: config.clientAddress,
    // Test hooks with the trace: the relay kills itself at the named point, or waits there (the
    // first time it is reached) until the file COLOPHON_RELAY_RESUME_FILE exists.
    crashAt: tracing ? env.COLOPHON_RELAY_CRASH_AT : undefined,
    hook: tracing && env.COLOPHON_RELAY_PAUSE_AT && env.COLOPHON_RELAY_RESUME_FILE ? pauseOnce(env.COLOPHON_RELAY_PAUSE_AT, env.COLOPHON_RELAY_RESUME_FILE) : undefined,
    home: keyText && wasm ? { key: JSON.parse(keyText), wasm } : undefined,
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
    resolve: config.resolve,
    host: env.COLOPHON_RELAY_HOST ?? config.host ?? '127.0.0.1',
    port: Number(env.COLOPHON_RELAY_PORT ?? config.port ?? 8787),
    dataDir: env.COLOPHON_RELAY_DATA ?? config.dataDir ?? './relay-data',
    libraries,
    limits: config.limits ?? {},
    tls: tls && { cert: readFileSync(tls.certFile), key: readFileSync(tls.keyFile) },
  };
}

if (process.argv[2] === 'home-key') {
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
  process.stdout.write(JSON.stringify({ listening: { host: running.host, port: running.port, tls: Boolean(config.tls) } }) + '\n');
  const stop = () => running.close().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
