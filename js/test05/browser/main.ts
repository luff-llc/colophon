// The page of the browser run: the same journeys as under Bun, and what only a browser has (IndexedDB, CryptoKey
// handles kept across a reload, a real WebAuthn ceremony with the PRF extension). The relays are started by the test
// server on request and reached through its same-origin proxy (the relay sends no CORS headers).
import {
  ColophonSession, FetchHomeTransport, glue, IndexedDBMedium, IndexedDBPrivateStore, init, keyIdOf, MemoryMedium, PasskeyProvider,
  WebCryptoDeviceSecrets, WebCryptoKeyProvider, WebCryptoKeyStore, type HomeConfiguration, type KeyDescriptor,
} from '../../src/session/index.js';
import { journey, journeys } from '../journey.ts';
import { admitted, assert, Device, equal, note, RelayHome, sleep, type RelayHost } from '../support.ts';

const lines: string[] = [];
const failures: string[] = [];
const log = (line: string): void => { lines.push(line); console.log(line); };
const report = { done: false, failures, lines };
(globalThis as unknown as { __colophon: typeof report }).__colophon = report;

const control = async <T>(path: string, body?: unknown): Promise<T> => {
  const response = await fetch(`/control/${path}`, { method: 'POST', body: JSON.stringify(body ?? {}) });
  if (!response.ok) throw new Error(`control ${path}: ${response.status} ${await response.text()}`);
  return await response.json() as T;
};
const host: RelayHost = {
  freePort: async () => (await control<{ port: number }>('port')).port,
  start: async spec => { await control('start', spec); },
  local: port => `${location.origin}/relay/${port}`,
  touchClock: async () => { /* the proxy sets the relay's clock before it forwards */ },
  stopAll: async () => { await control('stop'); },
};

async function run(name: string, body: () => Promise<void>): Promise<void> {
  const started = performance.now();
  try { await body(); log(`PASS ${name} [${Math.round(performance.now() - started)} ms]`); }
  catch (error) { failures.push(name); log(`FAIL ${name}: ${error instanceof Error ? `${error.message}\n${error.stack ?? ''}` : String(error)}`); }
}
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const rejects = async (promise: Promise<unknown>, check: (error: unknown) => boolean, what: string): Promise<void> => {
  let error: unknown; let threw = false;
  try { await promise; } catch (e) { threw = true; error = e; }
  assert(threw && check(error), () => `${what}: ${threw ? String(error) : 'did not fail'}`);
};
const settle = async (device: { session: ColophonSession }): Promise<boolean> => {
  for (let n = 0; n < 40; n++) {
    if (await device.session.syncNow() && device.session.homeIssues.length === 0 && device.session.homeFaults.length === 0) return true;
    await sleep(150);
  }
  return false;
};

async function main(): Promise<void> {
  await init('/colophon_wasm_bg.wasm');
  log(`engine: ${navigator.userAgent}`);

  for (const [name, history, homes] of journeys) await run(name, () => journey(host, history, homes, log));

  await run('an IndexedDB batch is all or none, survives a reopen, and a second tab cannot make it replace a record', async () => {
    const name = `colophon-test-${crypto.randomUUID()}`;
    const a = await IndexedDBMedium.open(name);
    await a.write([{ path: 'ops/b.json', bytes: text('held') }]);
    await rejects(a.write([{ path: 'ops/a.json', bytes: text('a') }, { path: 'ops/b.json', bytes: text('different') }, { path: 'ops/c.json', bytes: text('c') }]),
      e => (e as { reason?: string }).reason === 'conflict', 'a conflict in the middle refuses the batch');
    await rejects(a.write([{ path: 'ops/ok.json', bytes: text('1') }, { path: '../escape', bytes: text('x') }]), e => (e as { reason?: string }).reason === 'invalidPath', 'a bad path refuses the batch');
    equal(a.listing().map(e => e.path).join(), 'ops/b.json', 'nothing of a refused batch is in memory');
    // A second instance over the same database (another tab) writes a record this instance has not read yet.
    const b = await IndexedDBMedium.open(name);
    equal(b.listing().map(e => e.path).join(), 'ops/b.json', 'nothing of a refused batch is in the database');
    let hinted = 0;
    a.changes(() => { hinted++; });
    const fromB = b.write([{ path: 'ops/z.json', bytes: text('from b') }]);
    // Sent before `a` hears of it: the transaction itself finds the record, and none of this batch is stored.
    const stale = a.write([{ path: 'ops/y.json', bytes: text('y') }, { path: 'ops/z.json', bytes: text('from a') }, { path: 'state/s.json', bytes: text('s') }]);
    await fromB;
    await rejects(stale, e => (e as { reason?: string }).reason === 'conflict', 'the database, not the stale copy, decides');
    for (let n = 0; n < 100 && !a.listing().some(e => e.path === 'ops/z.json'); n++) await sleep(10);
    equal(a.listing().map(e => e.path).join(), 'ops/b.json,ops/z.json', 'the first instance re-read what the second wrote, and holds none of its own refused batch');
    assert(hinted > 0, 'a change in another instance wakes this one');
    await a.write([{ path: 'state/s.json', bytes: text('1') }, { path: 'blobs/chunk', bytes: new Uint8Array(70_000).fill(7) }]);
    await a.write([{ path: 'state/s.json', bytes: text('2') }]);
    a.close(); b.close();
    const again = await IndexedDBMedium.open(name);
    equal(again.listing().map(e => e.path).join(), 'blobs/chunk,ops/b.json,ops/z.json,state/s.json', 'a reopen holds exactly what was committed');
    equal(new TextDecoder().decode(again.read('state/s.json')), '2', 'a replaceable path holds its latest bytes');
    equal(again.readBlob('blobs/chunk').length, 70_000, 'a blob chunk reads back');
    equal(again.readBlob('blobs/none').length, 0, 'a chunk not held is empty');
    again.close();
    await IndexedDBMedium.destroy(name);
  });

  await run('device keys are non-extractable CryptoKeys that survive a reopen; the sealed-state key is derived, never stored', async () => {
    const store = new WebCryptoKeyStore(`colophon-keys-${crypto.randomUUID()}`);
    const first = await WebCryptoKeyProvider.openOrCreate('member', store);
    const [racedA, racedB] = await Promise.all([WebCryptoKeyProvider.openOrCreate('raced', store), WebCryptoKeyProvider.openOrCreate('raced', store)]);
    equal(await keyIdOf(racedA), await keyIdOf(racedB), 'two opens racing end with one key');
    await store.close();
    const reopened = new WebCryptoKeyStore(store.name);
    const second = await WebCryptoKeyProvider.openOrCreate('member', reopened);
    equal(await keyIdOf(second), await keyIdOf(first), 'the same key after a reopen');
    const pairs = await reopened.read('member');
    assert(pairs && !pairs.signing.privateKey.extractable && !pairs.agreement.privateKey.extractable, 'the stored private keys are non-extractable');
    await rejects(crypto.subtle.exportKey('pkcs8', pairs.signing.privateKey), () => true, 'the browser refuses to export the private key');
    await rejects(crypto.subtle.exportKey('jwk', pairs.agreement.privateKey), () => true, 'the browser refuses to export the agreement key');
    assert((await second.sign(text('x'))).length === 64, 'it signs');
    const secrets = new WebCryptoDeviceSecrets(`colophon-device-${crypto.randomUUID()}`);
    const account = 'a'.repeat(64);
    const k1 = await secrets.key(account); const k2 = await secrets.key(account); const other = await secrets.key('b'.repeat(64));
    const hex = (s: typeof k1): string => s.lend(b => [...b].join(','));
    assert(k1.size === 32 && hex(k1) === hex(k2) && hex(k1) !== hex(other), 'the device key is stable per account and differs between accounts');
    await secrets.remove(account);
    const k3 = await secrets.key(account);
    assert(hex(k3) !== hex(k1), 'a removed device key cannot be made again');
    for (const k of [k1, k2, k3, other]) k.close();
  });

  await run('a browser hides a redirect: nothing is followed and the pass would be abandoned', async () => {
    const transport = new FetchHomeTransport({ allowingLoopbackHttp: true });
    await rejects(transport.send({ method: 'GET', url: `${location.origin}/redirect/head`, headers: [{ name: 'Authorization', value: 'Colophon x' }], body: new Uint8Array(0) }),
      e => (e as { reason?: string }).reason === 'redirected', 'an opaque redirect is refused');
    const reached = await (await fetch('/control/redirect-target-hits', { method: 'POST', body: '{}' })).json() as { hits: number };
    equal(reached.hits, 0, 'the redirect target was never asked');
    await rejects(new FetchHomeTransport().send({ method: 'GET', url: 'http://127.0.0.1:9/head', headers: [], body: new Uint8Array(0) }),
      e => (e as { reason?: string }).reason === 'insecureEndpoint', 'plain http is refused without the testing option');
  });

  await run('a passkey owner (WebAuthn with PRF) creates an account on browser storage, signs in again after a reload, and approves a device', async () => {
    const tag = crypto.randomUUID().slice(0, 8);
    const relay = await RelayHome.make(host, `https://home.test/v1/accounts/passkey-${tag}`);
    const homes = (creating: boolean): HomeConfiguration[] => [{ endpoint: `${relay.base}/`, transport: relay.transport(),
      request: creating ? async account => { await relay.start(account, []); return relay.memberRequest(account); } : undefined }];
    const passkey = await PasskeyProvider.register({ rpId: location.hostname, rpName: 'Colophon test', userName: 'owner' });
    const descriptor: KeyDescriptor = await passkey.keyDescriptor();
    equal(descriptor.authorityOrigins.join(), location.origin, 'the passkey names this origin as an authority origin');
    assert(descriptor.origins.includes(location.origin), 'an authority origin is also among the origins');
    const names = { medium: `colophon-lib-${tag}`, private: `colophon-private-${tag}`, keys: `colophon-keys-${tag}`, device: `colophon-device-${tag}` };
    const open = async (owner: PasskeyProvider, creating: boolean) => {
      const medium = await IndexedDBMedium.open(names.medium);
      const privateStore = new IndexedDBPrivateStore(names.private); const keyStore = new WebCryptoKeyStore(names.keys); const secrets = new WebCryptoDeviceSecrets(names.device);
      const session = new ColophonSession({ memberLabel: 'Browser', namespaces: ['notes'], medium, privateStore, keys: await WebCryptoKeyProvider.openOrCreate('member', keyStore),
        ownerController: owner, homes: homes(creating), deviceSecrets: secrets, history: 'members' });
      return { session, medium, close: async () => { session.shutdown(); medium.close(); await privateStore.close(); await keyStore.close(); await secrets.close(); } };
    };
    const describe = (s: ColophonSession): string => `${JSON.stringify(s.phase)} ${s.lastError ?? ''} ${JSON.stringify(s.homeIssues)}`;
    const first = await open(passkey, true);
    await first.session.create();
    first.session.stopSync();
    equal(first.session.phase.kind, 'ready', `created with a passkey: ${describe(first.session)}`);
    await note(first.session, 'from the browser');
    assert(await settle(first), () => `the browser syncs with the home: ${describe(first.session)}`);
    const member = first.session.memberId;
    await first.session.flushCheckpoint();
    await first.close();

    // A reload: nothing but the databases and the passkey's public descriptor is carried over.
    const again = await open(new PasskeyProvider(descriptor), false);
    await again.session.restore();
    again.session.stopSync();
    equal(again.session.phase.kind, 'ready', `signed in again: ${describe(again.session)}`);
    equal(again.session.memberId, member, 'the same device key after the reload');
    equal(await admitted(again.session), 1, 'the note is read after the reload');
    equal(again.session.worker.engineForTests()!.run(e => { const i = e.open_info(); const m = i.mode; i.free(); return m; }), glue.OpenMode.Resumed, 'the saved state was resumed');
    // A second device asks; the passkey owner unlocks its PRF slot and signs the approval by assertion.
    const asking = await Device.make({ medium: new MemoryMedium([...again.medium.listing()].filter(e => e.path.startsWith('authority/')).map(e => [e.path, again.medium.read(e.path)] as const)),
      homes: homes(false) });
    await asking.session.restore();
    asking.session.stopSync();
    await again.session.importRequest(await asking.session.exportRequest());
    await again.session.approve(again.session.requests[0]!);
    assert(again.session.members.some(m => m.id === asking.session.memberId), 'the passkey owner approved the second device');
    assert(await settle(again), () => describe(again.session));
    for (let n = 0; n < 20 && asking.session.phase.kind !== 'ready'; n++) { await asking.session.syncNow(); await asking.session.refresh(); await sleep(100); }
    equal(asking.session.phase.kind, 'ready', `the second device learnt its approval: ${asking.describe()}`);
    assert(await settle(asking), () => asking.describe());
    equal(await admitted(asking.session), 1, 'the second device reads the note');
    // Locking drops the engine; unlocking the member is silent (no passkey prompt is needed to read).
    again.session.lock();
    equal(again.session.phase.kind, 'locked', 'locked');
    await again.session.unlock();
    equal(again.session.phase.kind, 'ready', 'unlocked without the passkey');
    asking.close();
    await again.close();
    for (const name of Object.values(names)) await new Promise<void>(resolve => { const r = indexedDB.deleteDatabase(name); r.onsuccess = r.onerror = r.onblocked = () => resolve(); });
  });

  await run('a passkey without PRF is refused: there is no fallback secret', async () => {
    await control('authenticator', { prf: false });
    try {
      let outcome = 'registered';
      let provider: PasskeyProvider | undefined;
      try { provider = await PasskeyProvider.register({ rpId: location.hostname, rpName: 'Colophon test', userName: 'no-prf' }); }
      catch (error) { outcome = (error as { outcome?: string }).outcome ?? String(error); }
      if (provider) {
        // An authenticator that does not say at registration: the first PRF evaluation must fail, not invent a secret.
        await rejects(provider.prf(crypto.getRandomValues(new Uint8Array(32))), e => (e as { outcome?: string }).outcome === 'unsupportedHere', 'a PRF evaluation with no output fails');
        const device = await Device.make({ owner: provider });
        await device.session.create();
        assert(device.session.phase.kind !== 'ready', 'an account is not created over a passkey with no PRF');
        device.close();
      } else equal(outcome, 'unsupportedHere', 'registration refuses a passkey with no PRF');
    } finally { await control('authenticator', { prf: true }); }
  });

  await host.stopAll();
}

main().catch(error => { failures.push('main'); log(`FAIL main: ${error instanceof Error ? error.stack ?? error.message : String(error)}`); }).finally(() => { report.done = true; });
