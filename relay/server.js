#!/usr/bin/env node
// Command-line entry for the reference relay.
//   node relay/server.js                     start with env/config settings
//   node relay/server.js --config file.json  start with a JSON config file
//   node relay/server.js token               print a new bearer token and its SHA-256
import { readFileSync } from 'node:fs';
import { newToken, startRelay } from './relay.js';

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
  return {
    host: env.COLOPHON_RELAY_HOST ?? config.host ?? '127.0.0.1',
    port: Number(env.COLOPHON_RELAY_PORT ?? config.port ?? 8787),
    dataDir: env.COLOPHON_RELAY_DATA ?? config.dataDir ?? './relay-data',
    libraries,
    limits: config.limits ?? {},
    tls: tls && { cert: readFileSync(tls.certFile), key: readFileSync(tls.keyFile) },
  };
}

if (process.argv[2] === 'token') {
  const { token, tokenSha256 } = newToken();
  process.stdout.write(JSON.stringify({ token, tokenSha256 }, null, 2) + '\n');
} else {
  const config = loadConfig(process.argv.slice(2), process.env);
  if (Object.keys(config.libraries).length === 0) {
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
