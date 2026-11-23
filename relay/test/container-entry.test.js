// The container entry point: settings from the environment, the relay config written from them,
// the volume's layout and modes, the key and token made once, the escape hatch, and the
// container lock. The relay itself is not started here except in the last test, which runs the
// entry point as a process.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync, symlinkSync, utimesSync, writeFileSync, mkdirSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { SettingError, acquireContainerLock, clearDeadRelayLock, dropRoot, giveTree, prepare, readSettings, relayConfig } from '../container-entry.js';
import { clientAddressConfig, provisionConfig } from '../provision.js';
import { corsOrigins } from '../relay.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.env.CARGO_TARGET_DIR ?? path.join(here, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');
const ready = existsSync(wasm);
if (!ready) {
  if (process.env.CI) throw new Error(`CI: the home module is missing (${wasm}); run scripts/test-home.sh, which builds it`);
  console.error(`SKIPPED: the container volume tests need the module (${wasm})`);
}
const sha = (s) => createHash('sha256').update(s).digest('hex');
const mode = (f) => statSync(f).mode & 0o777;
const URL_ = 'https://home.example.org';

describe('settings from the environment', () => {
  test('defaults: port 8080 on 0.0.0.0, provisioning on with gate token', () => {
    const s = readSettings({ COLOPHON_PUBLIC_URL: 'https://Home.Example.org/' });
    assert.equal(s.port, 8080);
    assert.equal(s.host, '0.0.0.0');
    assert.equal(s.origin, URL_);
    assert.equal(s.prefix, `${URL_}/v1/libraries/`);
    assert.equal(s.provisioning, true);
    assert.deepEqual(s.gates, ['token']);
    assert.equal(s.clientAddress, undefined);
  });
  test('every variable lands where the relay reads it, and the relay accepts the result', () => {
    const s = readSettings({
      PORT: '9000', COLOPHON_PUBLIC_URL: 'https://home.example.org:8443', COLOPHON_MAX_SLOTS: '5', COLOPHON_SLOT_BYTES: '1048576',
      COLOPHON_PROVISION_PER_ADDRESS_PER_HOUR: '3', COLOPHON_PROVISION_UNCLAIMED_HOURS: '48',
      COLOPHON_CORS_ORIGINS: 'https://app.example, https://other.example', COLOPHON_CLIENT_IP_HEADER: 'X-Real-IP',
      COLOPHON_TRUSTED_PROXIES: '172.16.0.0/12, 10.0.0.2', COLOPHON_PROVISION_TOKEN_SHA256: 'AB'.repeat(32),
    });
    const c = relayConfig(s, { dataDir: '/data/records-dir', keyFile: '/data/secrets/home-key.jwk', tokenSha256: s.tokenSha256 });
    assert.deepEqual(c, {
      host: '0.0.0.0', port: 9000, dataDir: '/data/records-dir',
      home: { keyFile: '/data/secrets/home-key.jwk', wasm: s.wasm },
      cors: { origins: ['https://app.example', 'https://other.example'] },
      limits: { slotBytes: 1048576 },
      clientAddress: { header: 'X-Real-IP', trustedPeers: ['172.16.0.0/12', '10.0.0.2'] },
      provision: { enabled: true, prefix: 'https://home.example.org:8443/v1/libraries/', gate: 'token', tokenSha256: 'ab'.repeat(32), maxSlots: 5, perAddressPerHour: 3, unclaimedHours: 48 },
    });
    assert.equal(provisionConfig(c.provision).maxSlots, 5);
    assert.ok(clientAddressConfig(c.clientAddress).trusted('172.20.1.1'));
    assert.deepEqual([...corsOrigins(c.cors.origins)], ['https://app.example', 'https://other.example']);
  });
  test('gate open, a gate list with grant, and provisioning off', () => {
    const open = relayConfig(readSettings({ COLOPHON_PUBLIC_URL: URL_, COLOPHON_PROVISION_GATE: 'open' }), { dataDir: 'd', keyFile: 'k' });
    assert.deepEqual(open.provision, { enabled: true, prefix: `${URL_}/v1/libraries/`, gate: 'open' });
    const grant = relayConfig(readSettings({ COLOPHON_PUBLIC_URL: URL_, COLOPHON_PROVISION_GATE: 'grant,token',
      COLOPHON_PROVISION_OPERATOR_ACCOUNT: 'cd'.repeat(32), COLOPHON_PROVISION_OPERATOR_SLOT: 'operator-home' }), { dataDir: 'd', keyFile: 'k', tokenSha256: 'ef'.repeat(32) });
    assert.deepEqual(grant.provision.gate, ['grant', 'token']);
    assert.equal(grant.provision.audience, `${URL_}/v1/provision`);
    assert.deepEqual(grant.provision.operator, { account: 'cd'.repeat(32), slot: 'operator-home' });
    assert.equal(provisionConfig(grant.provision).audience, `${URL_}/v1/provision`);
    const off = relayConfig(readSettings({ COLOPHON_PUBLIC_URL: URL_, COLOPHON_PROVISION: 'off' }), { dataDir: 'd', keyFile: 'k' });
    assert.deepEqual(off.provision, { enabled: false, prefix: `${URL_}/v1/libraries/` }, 'the prefix stays for a table made while it was on');
  });
  test('a wrong setting names its variable', () => {
    const bad = [
      [{}, /COLOPHON_PUBLIC_URL is required/],
      [{ COLOPHON_PUBLIC_URL: 'http://home.example.org' }, /https/],
      [{ COLOPHON_PUBLIC_URL: 'https://home.example.org/colophon' }, /origin only/],
      [{ COLOPHON_PUBLIC_URL: 'not a url' }, /not a URL/],
      [{ COLOPHON_PUBLIC_URL: URL_, PORT: 'eighty' }, /PORT/],
      [{ COLOPHON_PUBLIC_URL: URL_, PORT: '70000' }, /PORT/],
      [{ COLOPHON_PUBLIC_URL: URL_, COLOPHON_MAX_SLOTS: '0' }, /COLOPHON_MAX_SLOTS/],
      [{ COLOPHON_PUBLIC_URL: URL_, COLOPHON_SLOT_BYTES: '-1' }, /COLOPHON_SLOT_BYTES/],
      [{ COLOPHON_PUBLIC_URL: URL_, COLOPHON_PROVISION: 'maybe' }, /COLOPHON_PROVISION/],
      [{ COLOPHON_PUBLIC_URL: URL_, COLOPHON_PROVISION_TOKEN_SHA256: 'secret-token' }, /64 hex/],
      [{ COLOPHON_PUBLIC_URL: URL_, COLOPHON_CLIENT_IP_HEADER: 'X-Real-IP' }, /go together/],
      [{ COLOPHON_PUBLIC_URL: URL_, COLOPHON_TRUSTED_PROXIES: '10.0.0.0/8' }, /go together/],
      [{ COLOPHON_PUBLIC_URL: URL_, COLOPHON_PROVISION_GATE: 'grant' }, /OPERATOR/],
    ];
    for (const [env, re] of bad) assert.throws(() => readSettings(env), (e) => e instanceof SettingError && re.test(e.message), JSON.stringify(env));
    assert.equal(readSettings({ COLOPHON_PUBLIC_URL: 'http://127.0.0.1:8080' }).origin, 'http://127.0.0.1:8080', 'loopback http, for tests');
  });
});

describe('the volume', { skip: ready ? false : `build the module first (${wasm})` }, () => {
  let root;
  const env = (extra = {}) => ({ COLOPHON_PUBLIC_URL: URL_, COLOPHON_HOME_WASM: wasm, ...extra });
  before(async () => { root = await mkdtemp(path.join(tmpdir(), 'colophon-container-')); });
  after(async () => { await rm(root, { recursive: true, force: true }); });

  test('the first start makes the key and the token; later starts keep both', () => {
    const data = path.join(root, 'first');
    const one = prepare(data, env());
    assert.equal(one.generated, true);
    assert.match(one.memberId, /^[0-9a-f]{32}$/);
    assert.match(one.token, /^[A-Za-z0-9_-]{43}$/);
    const key = path.join(data, 'secrets/home-key.jwk');
    const jwk = JSON.parse(readFileSync(key, 'utf8'));
    assert.equal(jwk.kty, 'EC'); assert.equal(jwk.crv, 'P-256'); assert.ok(jwk.d);
    const hash = readFileSync(path.join(data, 'secrets/provision-token.sha256'), 'utf8').trim();
    assert.equal(hash, sha(one.token), 'only the hash is stored');
    const config = JSON.parse(readFileSync(one.configFile, 'utf8'));
    assert.equal(config.provision.tokenSha256, hash);
    assert.equal(config.dataDir, path.join(data, 'records-dir'));
    assert.equal(config.home.keyFile, key);
    for (const f of [key, path.join(data, 'secrets/provision-token.sha256'), one.configFile]) assert.equal(mode(f), 0o600, f);
    for (const d of [data, path.join(data, 'secrets'), path.join(data, 'records-dir'), path.join(data, 'run')]) assert.equal(mode(d), 0o700, d);
    for (const f of [key, one.configFile]) assert.ok(!readFileSync(f, 'utf8').includes(one.token), 'the token is written nowhere');
    const keyBytes = readFileSync(key);

    const two = prepare(data, env({ COLOPHON_MAX_SLOTS: '7' }));
    assert.equal(two.memberId, one.memberId, 'the same home identity');
    assert.equal(two.token, undefined, 'the token is shown once');
    assert.deepEqual(readFileSync(key), keyBytes);
    const again = JSON.parse(readFileSync(two.configFile, 'utf8'));
    assert.equal(again.provision.tokenSha256, hash);
    assert.equal(again.provision.maxSlots, 7, 'the config follows the environment at every start');
    assert.ok(!existsSync(path.join(data, 'config.json')), 'the generated config is not the escape hatch');
    assert.ok(two.unset.includes('COLOPHON_RELAY_DATA') && two.unset.includes('COLOPHON_HOME_KEY'));
  });
  test('a supplied token hash is used and nothing is made; gate open makes no token', () => {
    const a = prepare(path.join(root, 'hash'), env({ COLOPHON_PROVISION_TOKEN_SHA256: 'ab'.repeat(32) }));
    assert.equal(a.token, undefined);
    assert.ok(!existsSync(path.join(root, 'hash/secrets/provision-token.sha256')));
    assert.equal(JSON.parse(readFileSync(a.configFile, 'utf8')).provision.tokenSha256, 'ab'.repeat(32));
    const b = prepare(path.join(root, 'open'), env({ COLOPHON_PROVISION_GATE: 'open' }));
    assert.equal(b.token, undefined);
    assert.equal(JSON.parse(readFileSync(b.configFile, 'utf8')).provision.tokenSha256, undefined);
  });
  test('a config.json on the volume is used as-is', () => {
    const data = path.join(root, 'hatch');
    mkdirSync(data, { mode: 0o700 });
    writeFileSync(path.join(data, 'config.json'), JSON.stringify({ dataDir: './mine', libraries: { lib: { open: true } } }));
    const p = prepare(data, { PORT: '9001' });
    assert.equal(p.generated, false);
    assert.equal(p.configFile, path.join(data, 'config.json'));
    assert.equal(p.dataDir, path.join(data, 'mine'));
    assert.deepEqual(p.unset, []);
    assert.equal(p.env.COLOPHON_RELAY_PORT, '9001');
    assert.equal(p.env.COLOPHON_RELAY_HOST, '0.0.0.0');
    assert.ok(!existsSync(path.join(data, 'secrets')), 'no key or token is made');
    assert.equal(p.memberId, undefined);
  });
});

describe('the container lock', () => {
  let root;
  before(async () => { root = await mkdtemp(path.join(tmpdir(), 'colophon-lock-')); });
  after(async () => { await rm(root, { recursive: true, force: true }); });

  test('a second holder is refused while the heartbeat is fresh; a stale lock is taken over', () => {
    const a = acquireContainerLock(root, { staleMs: 30_000, beatMs: 60_000 });
    assert.equal(mode(a.file), 0o600);
    assert.throws(() => acquireContainerLock(root, { host: 'another-box' }), (e) => e.code === 'ELOCKED' && /another container holds this volume/.test(e.message));
    assert.throws(() => acquireContainerLock(root), (e) => e.code === 'ELOCKED' && /earlier run/.test(e.message));
    // As after a SIGKILL: the lock stays, its heartbeat stops.
    const old = new Date(Date.now() - 60_000);
    utimesSync(a.file, old, old);
    let lost = false;
    const b = acquireContainerLock(root, { staleMs: 30_000, beatMs: 60_000, onLost: () => { lost = true; } });
    a.release();
    assert.ok(existsSync(b.file), 'the old holder does not remove the new holder\'s lock');
    b.release();
    assert.ok(!existsSync(b.file));
    assert.equal(lost, false);
  });
  test('a holder whose lock was taken stops at its next beat', async () => {
    let lost;
    const seen = new Promise((resolve) => { lost = resolve; });
    const a = acquireContainerLock(root, { beatMs: 20, onLost: lost });
    const old = new Date(Date.now() - 60_000);
    utimesSync(a.file, old, old);
    // A frozen holder: the next starter takes the lock before the holder's next beat.
    const b = acquireContainerLock(root, { staleMs: 30_000, beatMs: 60_000 });
    await seen;
    a.release();
    assert.ok(existsSync(b.file));
    b.release();
  });
  test('its own earlier run\'s lock is stale after two missed beats; another container\'s only after staleMs', () => {
    const opts = { staleMs: 30_000, beatMs: 5_000 };
    const a = acquireContainerLock(root, { ...opts, host: 'box-a', pid: 1, onLost: () => {} });
    const age = (ms) => { const t = new Date(Date.now() - ms); utimesSync(a.file, t, t); };
    // One beat late: the holder may be alive, whoever asks.
    age(6_000);
    assert.throws(() => acquireContainerLock(root, { ...opts, host: 'box-a', pid: 1 }), (e) => e.code === 'ELOCKED' && /earlier run/.test(e.message));
    // Two beats missed: another container still waits, as does another process in this one.
    age(12_000);
    assert.throws(() => acquireContainerLock(root, { ...opts, host: 'box-b', pid: 1 }), (e) => e.code === 'ELOCKED' && /another container/.test(e.message));
    assert.throws(() => acquireContainerLock(root, { ...opts, host: 'box-a', pid: 7 }), (e) => e.code === 'ELOCKED');
    const b = acquireContainerLock(root, { ...opts, host: 'box-a', pid: 1 });
    a.release();
    assert.ok(existsSync(b.file));
    b.release();
  });
  test('started as another user than root, nothing is given away; a tree is given without following links', () => {
    assert.equal(dropRoot(root), process.getuid() === 0 ? true : false);
    const tree = path.join(root, 'tree');
    mkdirSync(path.join(tree, 'in'), { recursive: true });
    writeFileSync(path.join(tree, 'in', 'file'), 'x');
    symlinkSync('/', path.join(tree, 'link'));
    // To its present owner: every entry is visited, none changes, and the link is not followed.
    assert.equal(giveTree(tree, process.getuid(), statSync(tree).gid), 0);
  });
  test('a dead container\'s relay lock is removed', () => {
    const dir = path.join(root, 'records');
    mkdirSync(dir);
    writeFileSync(path.join(dir, '.relay.lock'), JSON.stringify({ pid: 1 }));
    assert.deepEqual(clearDeadRelayLock(dir), ['.relay.lock']);
    assert.deepEqual(clearDeadRelayLock(dir), []);
  });
});

describe('the entry point as a process', { skip: ready ? false : `build the module first (${wasm})` }, () => {
  test('starts the relay from the environment alone, prints the token once, and stops cleanly on SIGTERM', async () => {
    const data = await mkdtemp(path.join(tmpdir(), 'colophon-entry-'));
    const run = () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(here, '../container-entry.js')], {
        // COLOPHON_RELAY_PORT would override the generated config if it reached server.js.
        env: { PATH: process.env.PATH, COLOPHON_DATA: data, COLOPHON_HOME_WASM: wasm, COLOPHON_PUBLIC_URL: 'http://127.0.0.1:8080', PORT: '0', COLOPHON_HOST: '127.0.0.1', COLOPHON_RELAY_PORT: '9' },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let out = ''; let err = ''; let health;
      child.stdout.on('data', async (d) => {
        out += d;
        const m = /\{"listening":\{"host":"[^"]+","port":(\d+)/.exec(out);
        if (m && health === undefined) {
          health = null;
          try { health = await (await fetch(`http://127.0.0.1:${m[1]}/healthz`)).json(); } catch (e) { health = String(e); }
          child.kill('SIGTERM');
        }
      });
      child.stderr.on('data', (d) => { err += d; });
      child.on('error', reject);
      child.on('exit', (code, signal) => resolve({ code, signal, out, err, health }));
    });
    try {
      const first = await run();
      assert.equal(first.code, 0, first.out + first.err);
      assert.deepEqual(first.health, { ok: true });
      assert.ok(!existsSync(path.join(data, '.container.lock')), 'released at exit');
      assert.ok(!existsSync(path.join(data, 'records-dir/.relay.lock')), 'the relay released its own lock');
      const token = /COLOPHON_PROVISION_TOKEN=(\S+)/.exec(first.out)?.[1];
      assert.ok(token, first.out);
      assert.equal(readFileSync(path.join(data, 'secrets/provision-token.sha256'), 'utf8').trim(), sha(token));
      const member = JSON.parse(first.out.split('\n')[0]).colophonHome.member;
      assert.match(member, /^[0-9a-f]{32}$/);
      assert.ok(!(first.out + first.err).includes(JSON.parse(readFileSync(path.join(data, 'secrets/home-key.jwk'), 'utf8')).d), 'the key is never printed');

      const second = await run();
      assert.equal(second.code, 0, second.out + second.err);
      assert.ok(!second.out.includes('PROVISIONING TOKEN') && !second.out.includes(token), 'the token is shown once');
      assert.equal(JSON.parse(second.out.split('\n')[0]).colophonHome.member, member);
    } finally { await rm(data, { recursive: true, force: true }); }
  });
});
