// Unit tests of the session layer under Bun: the rules the other SDKs' checks found broken, each shown not to be here.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, readdirSync, readFileSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  attachPageLifecycle, FetchHomeTransport, gateContent, glue, HomeLimits, HomeTransportError, init, KeyCustody, KeyCustodyError, MemoryDeviceSecrets, MemoryMedium,
  MemoryPrivateStore, plain, putBlob, SecretBytes, SessionError, StorageError, WebCryptoKeyProvider,
  type AccessRequest, type AsyncKeyProvider, type EpochAgreement, type HomeConfiguration, type HomeTransport, type PrfRequest, type RequestInfo, type UnlockInput,
} from '../src/session/index.js';
import { FileMedium, FilePrivateStore, type FileMediumStep } from '../src/session/node.js';
import { decodeSaved, encodeSaved, SessionJournal } from '../src/session/private.js';
import { raceAbort } from '../src/session/errors.js';
import { admitted, approveByScan, Device, note, pairByCode, RelayHome, sleep } from './support.ts';
import { BunRelayHost } from './relay-bun.ts';

const host = new BunRelayHost();
const scratch: string[] = [];
const temporary = (): string => { const d = mkdtempSync(join(tmpdir(), 'colophon-js-unit-')); scratch.push(d); return d; };
beforeAll(async () => { await init(); });
afterAll(async () => { await host.stopAll(); for (const d of scratch) rmSync(d, { recursive: true, force: true }); });
const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

describe('the loopback rule', () => {
  test('https is allowed; http only to a literal loopback address with the testing option', () => {
    const allowed = (url: string, loopback = true): boolean => HomeLimits.isAllowed(url, loopback);
    expect(allowed('https://home.example/v1')).toBe(true);
    expect(allowed('http://127.0.0.1:8787/v1')).toBe(true);
    expect(allowed('http://127.9.8.7/v1')).toBe(true);
    expect(allowed('http://localhost:1/v1')).toBe(true);
    expect(allowed('http://[::1]:8787/v1')).toBe(true);
    expect(allowed('http://127.0.0.1:8787/v1', false)).toBe(false);
    // A name that only starts like a loopback address is a remote host.
    for (const url of ['http://127.attacker.example/', 'http://127.0.0.1.attacker.example/', 'http://localhost.attacker.example/', 'http://127.0.0.1@attacker.example/',
      'http://user:pw@127.0.0.1/', 'http://128.0.0.1/', 'http://10.0.0.1/', 'http://[::2]/', 'http://0.0.0.0/', 'ftp://127.0.0.1/', 'not a url', 'http://']) {
      expect([url, allowed(url)]).toEqual([url, false]);
    }
    expect(allowed('https://user:pw@home.example/')).toBe(false);
    expect(HomeLimits.isLoopbackLiteral('127.attacker.example')).toBe(false);
    expect(HomeLimits.isLoopbackLiteral('0127.0.0.1')).toBe(false);
  });
});

describe('the fetch transport', () => {
  const servers: { stop(force?: boolean): unknown }[] = [];
  afterAll(() => { for (const s of servers) void s.stop(true); });
  const serve = (handler: (request: Request) => Response | Promise<Response>): string => {
    const server = Bun.serve({ port: 0, hostname: '127.0.0.1', fetch: handler });
    servers.push(server);
    return `http://127.0.0.1:${server.port}`;
  };
  const get = (url: string) => ({ method: 'GET' as const, url, headers: [{ name: 'Authorization', value: 'Colophon test' }], body: new Uint8Array(0) });

  test('plain http is refused before anything is sent, loopback included, unless the testing option is on', async () => {
    let hits = 0;
    const origin = serve(() => { hits++; return new Response('ok'); });
    await expect(new FetchHomeTransport().send(get(`${origin}/head`))).rejects.toMatchObject({ reason: 'insecureEndpoint' });
    await expect(new FetchHomeTransport({ allowingLoopbackHttp: true }).send(get('http://127.attacker.example/head'))).rejects.toMatchObject({ reason: 'insecureEndpoint' });
    expect(hits).toBe(0);
    expect((await new FetchHomeTransport({ allowingLoopbackHttp: true }).send(get(`${origin}/head`))).status).toBe(200);
  });

  test('a redirect is never followed, and the credential never reaches its target', async () => {
    let reached = 0;
    const target = serve(() => { reached++; return new Response('secret'); });
    const origin = serve(() => new Response(null, { status: 302, headers: { location: `${target}/elsewhere` } }));
    const answer = await new FetchHomeTransport({ allowingLoopbackHttp: true }).send(get(`${origin}/head`));
    expect(answer.status).toBe(302);
    expect(reached).toBe(0);
  });

  test('a response over its bound is refused, declared or not', async () => {
    const big = new Uint8Array(64 * 1024 + 1);
    const declared = serve(() => new Response(big));
    await expect(new FetchHomeTransport({ allowingLoopbackHttp: true }).send(get(`${declared}/head`))).rejects.toMatchObject({ reason: 'responseTooLarge', limit: 64 * 1024 });
    const streamed = serve(() => new Response(new ReadableStream({
      async pull(controller) { controller.enqueue(new Uint8Array(16 * 1024)); await sleep(1); },
    })));
    await expect(new FetchHomeTransport({ allowingLoopbackHttp: true }).send(get(`${streamed}/head`))).rejects.toMatchObject({ reason: 'responseTooLarge' });
    expect((await new FetchHomeTransport({ allowingLoopbackHttp: true }).send(get(`${serve(() => new Response(new Uint8Array(64 * 1024)))}/head`))).body.length).toBe(64 * 1024);
  });

  test('one deadline covers the whole request, a stalled body included', async () => {
    const stalled = serve(() => new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(10)); } })));
    const started = performance.now();
    await expect(new FetchHomeTransport({ allowingLoopbackHttp: true, requestTimeMs: 300 }).send(get(`${stalled}/authority`))).rejects.toMatchObject({ reason: 'timeout' });
    expect(performance.now() - started).toBeLessThan(5000);
  });

  test('an aborted signal ends the request', async () => {
    const stalled = serve(() => new Promise<Response>(() => {}));
    const stop = new AbortController();
    setTimeout(() => stop.abort(), 100);
    await expect(new FetchHomeTransport({ allowingLoopbackHttp: true }).send(get(`${stalled}/authority`), stop.signal)).rejects.toBeInstanceOf(HomeTransportError);
  });
});

describe('secrets', () => {
  const agreement = (recipient: string): EpochAgreement => ({ namespace: 'notes', epoch: 1n, recipient, recipientPoint: new Uint8Array(65), peer: new Uint8Array(65) });
  const provider = (secret: SecretBytes | Error, extra: Partial<AsyncKeyProvider> = {}): AsyncKeyProvider => ({
    publicKeys: async () => ({ signing: new Uint8Array(65), agreement: new Uint8Array(65) }),
    sign: async () => new Uint8Array(64),
    sharedSecret: async () => { if (secret instanceof Error) throw secret; return secret; },
    ...extra,
  });

  test('a later provider that fails leaves no earlier secret unwiped (epochs, unlock routes, PRF answers)', async () => {
    const first = SecretBytes.adopt(new Uint8Array(32).fill(7));
    const second = SecretBytes.adopt(new Uint8Array(32).fill(8));
    const custody = new KeyCustody(new Map([['a', provider(first)], ['b', provider(second)], ['c', provider(new Error('third route failed'))]]));
    await expect(custody.answerEpochs([agreement('a'), agreement('b'), agreement('c')])).rejects.toBeInstanceOf(KeyCustodyError);
    expect([first.closed, second.closed]).toEqual([true, true]);

    const unlockSecret = SecretBytes.adopt(new Uint8Array(32).fill(9));
    const input = (controller: string, kind = glue.UnlockKind.Ecdh): UnlockInput => ({ kind, controller, enc: new Uint8Array(65), salt: new Uint8Array(32) });
    const unlock = new KeyCustody(new Map([['a', provider(unlockSecret)], ['b', provider(new Error('no'))]]));
    await expect(unlock.answerUnlock([input('a'), input('b', glue.UnlockKind.Prf)])).rejects.toMatchObject({ outcome: 'unsupportedHere' });
    expect(unlockSecret.closed).toBe(true);

    const prfOut = SecretBytes.adopt(new Uint8Array(32).fill(5));
    const request = (controller: string): PrfRequest => ({ controller, rp: 'x', credential: new Uint8Array(4), salt: new Uint8Array(32), challenge: new Uint8Array(32) });
    const assertion = { signature: new Uint8Array(70), authenticatorData: new Uint8Array(37), clientData: new Uint8Array(10) };
    const prf = new KeyCustody(new Map([
      ['a', provider(new Error('unused'), { assert: async () => ({ ...assertion, prf: prfOut }) })],
      // A passkey that returns no PRF output: a failure, never a stand-in secret.
      ['b', provider(new Error('unused'), { assert: async () => ({ ...assertion }) })],
    ]));
    await expect(prf.answer([request('a'), request('b')])).rejects.toMatchObject({ outcome: 'unsupportedHere' });
    expect(prfOut.closed).toBe(true);
  });

  test('a secret that arrives after its prompt was abandoned is wiped', async () => {
    const late = SecretBytes.adopt(new Uint8Array(32).fill(3));
    const stop = new AbortController();
    let deliver!: (s: SecretBytes) => void;
    const pending = raceAbort(new Promise<SecretBytes>(resolve => { deliver = resolve; }), stop.signal, s => s.close());
    stop.abort();
    await expect(pending).rejects.toMatchObject({ code: 'cancelled' });
    deliver(late);
    await sleep(1);
    expect(late.closed).toBe(true);
  });

  test('a closed secret is zero, cannot be lent, and never prints', () => {
    const raw = new Uint8Array(32).fill(1);
    const secret = SecretBytes.adopt(raw);
    expect(`${String(secret)} ${JSON.stringify({ secret })}`).not.toContain('1,1');
    secret.close();
    expect(raw.every(b => b === 0)).toBe(true);
    expect(() => secret.lend(b => b)).toThrow();
  });

  test('a WebCrypto key is non-extractable, signs and agrees', async () => {
    const a = await WebCryptoKeyProvider.generate(); const b = await WebCryptoKeyProvider.generate();
    const shared = await a.sharedSecret((await b.publicKeys()).agreement);
    const other = await b.sharedSecret((await a.publicKeys()).agreement);
    expect(shared.lend(x => [...x])).toEqual(other.lend(x => [...x]));
    expect((await a.sign(bytes('body'))).length).toBe(64);
    const pairs = (a as unknown as { pairs: { signing: CryptoKeyPair; agreement: CryptoKeyPair } }).pairs;
    expect([pairs.signing.privateKey.extractable, pairs.agreement.privateKey.extractable]).toEqual([false, false]);
    await expect(crypto.subtle.exportKey('pkcs8', pairs.signing.privateKey)).rejects.toThrow();
    const extractable = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    await expect(WebCryptoKeyProvider.from({ signing: extractable, agreement: pairs.agreement })).rejects.toMatchObject({ outcome: 'unsupportedHere' });
  });
});

describe('stores are all or none', () => {
  const batch = [{ path: 'ops/a.json', bytes: bytes('a') }, { path: 'ops/b.json', bytes: bytes('b') }, { path: 'state/x.json', bytes: bytes('x1') }];

  test('a memory batch with a conflict in the middle stores nothing', async () => {
    const medium = new MemoryMedium([['ops/b.json', bytes('other')]]);
    await expect(medium.write(batch)).rejects.toMatchObject({ reason: 'conflict', path: 'ops/b.json' });
    expect(medium.listing().map(e => e.path)).toEqual(['ops/b.json']);
    await expect(medium.write([{ path: '../escape', bytes: bytes('x') }])).rejects.toMatchObject({ reason: 'invalidPath' });
    await expect(medium.write([{ path: 'ops/ok.json', bytes: bytes('1') }, { path: '.hidden/x', bytes: bytes('x') }])).rejects.toBeInstanceOf(StorageError);
    expect(medium.listing().map(e => e.path)).toEqual(['ops/b.json']);
    // An identical record is idempotent; a replaceable path is replaced.
    await medium.write([{ path: 'ops/b.json', bytes: bytes('other') }, { path: 'state/x.json', bytes: bytes('x1') }]);
    await medium.write([{ path: 'state/x.json', bytes: bytes('x2') }]);
    expect(new TextDecoder().decode(medium.read('state/x.json'))).toBe('x2');
  });

  test('a file batch interrupted at any step is whole or absent after the next open', async () => {
    const points: [FileMediumStep, number | undefined, 'none' | 'all'][] = [
      ['staged', undefined, 'none'], ['committed', undefined, 'all'], ['applied', 0, 'all'], ['applied', 1, 'all'], ['applied', 2, 'all'], ['cleaned', undefined, 'all'],
    ];
    for (const [at, index, expected] of points) {
      const root = temporary();
      const crashing = new FileMedium(root, { onStep: (step, i) => { if (step === at && i === index) throw new Error(`crash at ${step} ${i ?? ''}`); } });
      await expect(crashing.write(batch)).rejects.toThrow();
      // Whatever a reader sees next is the whole batch or none of it.
      const paths = new FileMedium(root).listing().map(e => e.path);
      expect([at, index, paths]).toEqual([at, index, expected === 'all' ? ['ops/a.json', 'ops/b.json', 'state/x.json'] : []]);
      expect(readdirSync(join(root, '.colophon.nosync')).filter(n => n !== 'lock')).toEqual([]);
    }
  });

  test('a file batch survives a real SIGKILL at every step', async () => {
    for (const at of ['staged', 'committed', 'applied:0', 'applied:1', 'cleaned']) {
      const root = temporary();
      const child = Bun.spawn([process.execPath, join(import.meta.dir, 'kill-child.ts'), root, at], { stdout: 'ignore', stderr: 'pipe' });
      const code = await child.exited;
      expect([at, code === 0]).toEqual([at, false]);
      const paths = new FileMedium(root).listing().map(e => e.path);
      expect([at, paths.length === 0 || paths.length === 3]).toEqual([at, true]);
      expect([at, paths.length]).toEqual([at, at === 'staged' ? 0 : 3]);
    }
  }, 60_000);

  test('a committed batch that cannot be completed is kept, never dropped, and the store says so', async () => {
    const root = temporary();
    const crashing = new FileMedium(root, { onStep: step => { if (step === 'committed') throw new Error('crash'); } });
    await expect(crashing.write(batch)).rejects.toThrow();
    const journal = join(root, '.colophon.nosync');
    const commit = readdirSync(journal).find(n => n.startsWith('commit-'))!;
    rmSync(join(journal, commit, '1.bin'));
    expect(() => new FileMedium(root)).toThrow(/cannot be completed/);
    expect(existsSync(join(journal, commit))).toBe(true);
  });

  test('a reader never sees a file batch half applied: while one is being published it waits or fails, never part', async () => {
    const root = temporary();
    const reader = new FileMedium(root);
    const seen: string[] = [];
    const look = (path: string): string => { try { reader.read(path); return 'held'; } catch (error) { return (error as Error).message.includes('in use') ? 'refused' : 'absent'; } };
    const writer = new FileMedium(root, { onStep: (step, index) => {
      // Between the first and the second rename of the batch, from another medium over the same folder.
      if (step === 'applied' && index === 0) seen.push(look('ops/a.json'), look('ops/b.json'));
    } });
    expect([look('ops/a.json'), look('ops/b.json')]).toEqual(['absent', 'absent']);
    await writer.write(batch);
    expect(seen).toEqual(['refused', 'refused']);
    expect([look('ops/a.json'), look('ops/b.json')]).toEqual(['held', 'held']);
    // A reader that arrives after a writer died in the middle completes the batch before it answers.
    const second = temporary();
    let crashed = false;
    const crashing = new FileMedium(second, { onStep: (step, index) => { if (!crashed && step === 'applied' && index === 0) { crashed = true; throw new Error('crash'); } } });
    await expect(crashing.write(batch)).rejects.toThrow();
    expect(new TextDecoder().decode(crashing.read('ops/b.json'))).toBe('b');
  }, 20_000);

  test('the file lock: a dead holder is taken over, a live one is waited for, a displaced holder commits nothing', async () => {
    const root = temporary();
    new FileMedium(root);
    const lock = join(root, '.colophon.nosync', 'lock');
    // A process ID that is not running (the largest a system allows is far below this).
    writeFileSync(lock, '999999999:left-by-a-killed-process');
    const medium = new FileMedium(root);
    await medium.write([{ path: 'ops/a.json', bytes: bytes('a') }]);
    expect(existsSync(lock)).toBe(false);
    // A live holder (this process, another token) is not displaced.
    writeFileSync(lock, `${process.pid}:another-live-holder`);
    expect(() => medium.listing()).toThrow(/in use by another process/);
    expect(new TextDecoder().decode(readFileSync(lock))).toBe(`${process.pid}:another-live-holder`);
    rmSync(lock);
    // The lock is lost between staging and the commit point: nothing of the batch is published.
    const displaced = new FileMedium(root, { onStep: step => { if (step === 'staged') writeFileSync(lock, '999999999:took-it'); } });
    await expect(displaced.write(batch)).rejects.toMatchObject({ reason: 'unavailable' });
    expect(new FileMedium(root).listing().map(e => e.path)).toEqual(['ops/a.json']);
    expect(readdirSync(join(root, '.colophon.nosync'))).toEqual([]);
  });

  test('a file medium refuses conflicts, bad paths and symbolic links, and reads what it wrote', async () => {
    const root = temporary();
    const medium = new FileMedium(root);
    await medium.write(batch);
    await expect(medium.write([{ path: 'ops/new.json', bytes: bytes('n') }, { path: 'ops/a.json', bytes: bytes('different') }])).rejects.toMatchObject({ reason: 'conflict' });
    expect(medium.listing().map(e => e.path)).toEqual(['ops/a.json', 'ops/b.json', 'state/x.json']);
    expect(new TextDecoder().decode(medium.read('ops/a.json'))).toBe('a');
    expect(medium.readBlob('blobs/none').length).toBe(0);
    expect(() => medium.read('ops/none.json')).toThrow(StorageError);
    expect(() => medium.read('../outside')).toThrow(StorageError);
  });
});

describe('private state', () => {
  test('the journal and the saved state round trip, and garbage is refused or ignored', () => {
    const j = new SessionJournal();
    j.account = 'a'.repeat(64); j.shownSeq = 18446744073709551615n; j.seenActivations.add(9007199254740993n); j.routes.set('h', true);
    j.signedChanges.set('d', '{"policy":{}}'); j.answeredRemovals.add(4n); j.shownTransitions = ['t'];
    const back = SessionJournal.decode(j.encode());
    expect([back.account, back.shownSeq, [...back.seenActivations], back.routes.get('h'), back.signedChanges.get('d'), [...back.answeredRemovals], back.shownTransitions])
      .toEqual([j.account, j.shownSeq, [9007199254740993n], true, '{"policy":{}}', [4n], ['t']]);
    expect(() => SessionJournal.decode(bytes('[1]'))).toThrow(StorageError);
    const saved = { verifier: bytes('v'), checkpoint: bytes('c'), parts: [{ namespace: 'notes', bytes: bytes('p') }] };
    expect(decodeSaved(encodeSaved(saved))).toEqual(saved);
    expect(() => decodeSaved(encodeSaved(saved).slice(0, 9))).toThrow();
  });
});

describe('the engine boundary', () => {
  test('a returned record is freed even when one of its getters throws; published state is frozen', async () => {
    let freed = 0;
    class Fake { get good(): number { return 1; } get bad(): number { throw new Error('getter failed'); } free(): void { freed++; } }
    expect(() => plain(new Fake())).toThrow('getter failed');
    expect(freed).toBe(1);
    const device = await Device.make();
    expect(Object.isFrozen(device.session.state)).toBe(true);
    await device.session.create();
    expect(Object.isFrozen(device.session.state)).toBe(true);
    device.close();
  });
});

describe('the gate', () => {
  test('content is shown only while usable; every other phase is a screen', () => {
    expect(gateContent({ phase: { kind: 'ready' } }, true)).toEqual({ kind: 'content', actions: [] });
    expect(gateContent({ phase: { kind: 'ready' } }, false).kind).toBe('screen');
    expect(gateContent({ phase: { kind: 'retry' } }, true)).toMatchObject({ kind: 'content', status: 'Refresh failed' });
    expect(gateContent({ phase: { kind: 'locked' } }, true)).toMatchObject({ kind: 'screen', id: 'library.locked', actions: ['unlock'] });
    expect(gateContent({ phase: { kind: 'denied' } }, true)).toMatchObject({ kind: 'screen', id: 'library.denied' });
    expect(gateContent({ phase: { kind: 'waitingForApproval' } }, false)).toMatchObject({ kind: 'screen', id: 'library.waiting' });
    // The joining device shows no code of its own (spec §9.1): the six digits appear only while it pairs.
    expect((gateContent({ phase: { kind: 'waitingForApproval' } }, false) as { message: string }).message).toContain('same code');
    expect(gateContent({ phase: { kind: 'updateRequired' } }, false)).toMatchObject({ id: 'library.updateRequired', actions: [] });
  });
});

describe('the page lifecycle', () => {
  test('a hidden page locks the session and a shown one unlocks it', async () => {
    const device = await Device.make();
    await device.session.create();
    const listeners: (() => void)[] = [];
    const page = { visibilityState: 'visible' as DocumentVisibilityState, addEventListener: (_: string, l: () => void) => { listeners.push(l); }, removeEventListener: () => { listeners.length = 0; } };
    const detach = attachPageLifecycle(device.session, { document: page as unknown as Document });
    page.visibilityState = 'hidden'; listeners.forEach(l => l());
    expect(device.session.phase.kind).toBe('locked');
    expect(device.session.worker.engineForTests()).toBeUndefined();
    page.visibilityState = 'visible'; listeners.forEach(l => l());
    for (let n = 0; n < 200 && device.session.phase.kind !== 'ready'; n++) await sleep(5);
    expect(device.session.phase.kind).toBe('ready');
    expect(await admitted(device.session)).toBe(0);
    detach();
    expect(listeners.length).toBe(0);
    device.close();
  });
});

describe('a session without a home', () => {
  test('creation refuses without a home unless the host opts out, and warns when there is none', async () => {
    const refused = await Device.make({ createWithoutHome: false, homes: [] });
    await refused.session.create();
    expect(refused.session.phase.kind).toBe('noLibrary');
    expect(refused.session.lastError).toContain('no home');
    refused.close();
    const insecure = await Device.make({ homes: [{ endpoint: 'http://home.example/v1/' }] });
    await insecure.session.create();
    expect(insecure.session.lastError).toContain('HTTPS');
    insecure.close();
    const device = await Device.make();
    await device.session.create();
    expect(device.session.phase.kind).toBe('ready');
    expect(device.session.notices.noHome).toBe(true);
    expect(device.session.duties.soleDevice).toBe(true);
    device.close();
  });

  test('a write is bound to its observed revision; a relaunch over files resumes; lock hides content', async () => {
    const root = temporary(); const privateDirectory = temporary();
    const secrets = new MemoryDeviceSecrets();
    const member = await WebCryptoKeyProvider.generate(); const owner = await WebCryptoKeyProvider.generate();
    const make = () => Device.make({ medium: new FileMedium(root), privateStore: new FilePrivateStore(privateDirectory), secrets, member, owner });
    const device = await make();
    await device.session.create();
    expect(device.session.phase.kind).toBe('ready');
    const stale = device.session.observedRevision;
    await note(device.session, 'one');
    await expect(device.session.perform({ namespace: 'notes', kind: 'note.put', payloadJson: '{"id":"two","text":"two"}' }, stale)).rejects.toMatchObject({ code: 'staleRevision' });
    await expect(device.session.perform({ namespace: 'other', kind: 'note.put', payloadJson: '{}' }, device.session.observedRevision)).rejects.toMatchObject({ code: 'invalidCommand' });
    await expect(device.session.perform({ namespace: 'notes', kind: 'note.put', payloadJson: '[1]' }, device.session.observedRevision)).rejects.toMatchObject({ code: 'invalidCommand' });
    expect(await admitted(device.session)).toBe(1);
    await device.session.flushCheckpoint();
    device.session.lock();
    expect(device.session.phase.kind).toBe('locked');
    await expect(device.session.view('notes')).rejects.toMatchObject({ code: 'notReady' });
    await device.session.unlock();
    expect(await admitted(device.session)).toBe(1);
    device.close();

    const again = await make();
    await again.session.restore();
    expect(again.session.phase.kind).toBe('ready');
    expect(await admitted(again.session)).toBe(1);
    expect(again.session.worker.engineForTests()!.run(e => e.open_info().mode)).toBe(glue.OpenMode.Resumed);
    again.close();
  });

  test('a store that refuses a finished write leaves nothing half applied and the session recovers', async () => {
    const device = await Device.make();
    await device.session.create();
    await note(device.session, 'one');
    const before = (device.medium as MemoryMedium).listing().length;
    (device.medium as MemoryMedium).failNextWrite = StorageError.unavailable('disk full');
    await expect(note(device.session, 'two')).rejects.toBeInstanceOf(StorageError);
    expect((device.medium as MemoryMedium).listing().length).toBe(before);
    await device.session.refresh();
    expect(device.session.phase.kind).toBe('ready');
    expect(await admitted(device.session)).toBe(1);
    await note(device.session, 'two');
    expect(await admitted(device.session)).toBe(2);
    device.close();
  });

  test('locking while a blob is being stored ends its writer: no chunk is encrypted after lock', async () => {
    const device = await Device.make();
    await device.session.create();
    const medium = device.medium as MemoryMedium;
    const real = medium.write.bind(medium);
    let chunkWrites = 0; let release!: () => void;
    const blocked = new Promise<void>(resolve => { release = resolve; });
    medium.write = async writes => { if (writes.some(w => w.path.startsWith('blobs/'))) { chunkWrites++; await blocked; } return real(writes); };
    const storing = putBlob(device.session, new Uint8Array(200_000).fill(4), { namespace: 'notes', mediaType: 'text/plain', reference: 'r' }).then(() => 'stored', error => error as Error);
    for (let n = 0; n < 200 && chunkWrites === 0; n++) await sleep(5);
    expect(chunkWrites).toBe(1);
    device.session.lock();
    release();
    const outcome = await storing;
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as { kind?: string }).kind).toBe('Locked');
    expect(chunkWrites).toBe(1);
    device.close();
  });

  test('a key prompt nobody answers does not hold lock, and the session works afterwards', async () => {
    const real = await WebCryptoKeyProvider.generate();
    let hang = false; let prompts = 0;
    const owner: AsyncKeyProvider = {
      publicKeys: () => real.publicKeys(),
      sign: (body, signal) => { if (!hang) return real.sign(body, signal); prompts++; return new Promise<Uint8Array>(() => {}); },
      sharedSecret: (peer, signal) => real.sharedSecret(peer, signal),
    };
    const first = await Device.make({ owner });
    await first.session.create();
    const asking = await Device.make({ medium: (first.medium as MemoryMedium).copy(p => p.startsWith('authority/')) });
    await asking.session.restore();
    const scanned = await first.session.scanRequest(await asking.session.exportRequest());
    hang = true;
    const approving = first.session.approve(scanned.request, scanned.pairing);
    const outcome = approving.then(() => 'approved', error => error as Error);
    for (let n = 0; n < 200 && prompts === 0; n++) await sleep(5);
    expect(prompts).toBe(1);
    const started = performance.now();
    first.session.lock();
    expect(performance.now() - started).toBeLessThan(100);
    expect(first.session.phase.kind).toBe('locked');
    expect(first.session.worker.engineForTests()).toBeUndefined();
    const result = await Promise.race([outcome, sleep(2000).then(() => 'still waiting')]);
    expect(result).toBeInstanceOf(Error);
    expect(first.session.phase.kind).toBe('locked');
    hang = false;
    await first.session.unlock();
    expect(first.session.phase.kind).toBe('ready');
    // The interrupted approval spent its pairing: a new scan approves.
    await approveByScan(asking.session, first.session);
    expect(first.session.members.some(m => m.id === asking.session.memberId)).toBe(true);
    first.close(); asking.close();
  });
});

describe('the refreshing phase', () => {
  // A refresh moves `ready` to `refreshing` while it runs, and a finished refresh never leaves it there. Before the fix a
  // command that failed while a refresh was in flight, with a failure that sets no phase (a cancelled key prompt), made the
  // refresh skip its snapshot and left the session `refreshing` until some later refresh. No time passes: the key prompt
  // holds the worker, so the refresh is queued behind the command exactly as long as the test says.
  test('a command whose failure sets no phase, failing while a refresh waits, leaves the refresh to decide the phase', async () => {
    const real = await WebCryptoKeyProvider.generate();
    let hold = false; let prompted!: () => void; let cancel!: (error: Error) => void;
    const prompt = new Promise<void>(resolve => { prompted = resolve; });
    const owner: AsyncKeyProvider = {
      publicKeys: () => real.publicKeys(),
      sign: (body, signal) => {
        if (!hold) return real.sign(body, signal);
        prompted();
        return new Promise<Uint8Array>((_, reject) => { cancel = reject; });
      },
      sharedSecret: (peer, signal) => real.sharedSecret(peer, signal),
    };
    const first = await Device.make({ owner });
    await first.session.create();
    const asking = await Device.make({ medium: (first.medium as MemoryMedium).copy(p => p.startsWith('authority/')) });
    await asking.session.restore();
    const scanned = await first.session.scanRequest(await asking.session.exportRequest());
    await first.session.flushExternalChanges();
    expect(first.session.phase.kind).toBe('ready');
    hold = true;
    const approving = first.session.approve(scanned.request, scanned.pairing).then(() => 'approved', error => error as Error);
    await prompt;
    const refreshing = first.session.refresh();
    for (let n = 0; n < 100 && first.session.phase.kind !== 'refreshing'; n++) await Promise.resolve();
    expect(first.session.phase.kind).toBe('refreshing');
    cancel(new KeyCustodyError('cancelled', 'The person cancelled the prompt.'));
    const outcome = await approving;
    expect(outcome).toBeInstanceOf(KeyCustodyError);
    expect((outcome as KeyCustodyError).outcome).toBe('cancelled');
    await refreshing;
    expect(first.session.phase.kind).toBe('ready');
    hold = false;
    first.close(); asking.close();
  });

  // The refreshes held at `refreshWillFinish`, numbered in the order they reach it: a held one waits there (its worker has
  // answered, its outcome is not published) until the test releases it, with or without an error.
  const refreshHolds = (holding: number[]) => {
    let count = 0;
    const arrived = new Map<number, () => void>(); const arrivals = new Map<number, Promise<void>>();
    const gates = new Map<number, { release: () => void; fail: (error: Error) => void }>();
    for (const n of holding) arrivals.set(n, new Promise<void>(resolve => { arrived.set(n, resolve); }));
    return {
      reached: (): Promise<void> => {
        const n = ++count;
        if (!holding.includes(n)) return Promise.resolve();
        return new Promise<void>((release, fail) => { gates.set(n, { release, fail }); arrived.get(n)!(); });
      },
      waiting: (n: number): Promise<void> => arrivals.get(n)!,
      release: (n: number, error?: Error): void => { const gate = gates.get(n)!; if (error) gate.fail(error); else gate.release(); },
    };
  };
  // R1 is held after its worker answered; another refresh publishes `ready`; R2 marks `refreshing` and is held. R1, now stale,
  // finishes or fails afterwards: its outcome is dropped and the phase follows R2.
  for (const failing of [false, true]) {
    test(`a stale refresh that ${failing ? 'fails' : 'finishes'} after a newer one marked refreshing is dropped`, async () => {
      const device = await Device.make();
      await device.session.create();
      await device.session.flushExternalChanges();
      expect(device.session.phase.kind).toBe('ready');
      const holds = refreshHolds([1, 3]);
      device.session.refreshWillFinish = holds.reached;
      const r1 = device.session.refresh();
      await holds.waiting(1);
      expect(device.session.phase.kind).toBe('refreshing');
      await device.session.refresh(); // the second to reach the hold, not held: it publishes `ready`
      expect(device.session.phase.kind).toBe('ready');
      const r2 = device.session.refresh();
      await holds.waiting(3);
      expect(device.session.phase.kind).toBe('refreshing');
      holds.release(1, failing ? StorageError.unavailable('the disk is gone') : undefined);
      await r1;
      expect(device.session.phase.kind).toBe('refreshing');
      holds.release(3);
      await r2;
      expect(device.session.phase.kind).toBe('ready');
      device.close();
    });
  }
});

describe('a cancelled or broken pass never leaves the engine waiting', () => {
  /** One device with the real relay as its home, and a switch on its transport. */
  async function withHome(exchangeTimeMs?: number): Promise<{ device: Device; mode: { value: 'pass' | 'hang' | 'hangDeaf' | 'abortAfter' | 'offline' }; stop: AbortController[] }> {
    const relay = await RelayHome.make(host, `https://home.test/v1/accounts/unit-${crypto.randomUUID().slice(0, 8)}`);
    const inner = relay.transport();
    const mode = { value: 'pass' as 'pass' | 'hang' | 'hangDeaf' | 'abortAfter' | 'offline' };
    const stop: AbortController[] = [];
    const transport: HomeTransport = {
      send: async (request, signal) => {
        if (mode.value === 'offline') throw new HomeTransportError('offline', 'no network');
        if (mode.value === 'hang') return new Promise((_, reject) => { signal?.addEventListener('abort', () => reject(new HomeTransportError('offline', 'aborted'))); });
        if (mode.value === 'hangDeaf') return new Promise(() => {});
        const answer = await inner.send(request, signal);
        // The caller is cancelled after the home answered and before the engine is given the answer.
        if (mode.value === 'abortAfter') stop.at(-1)?.abort();
        return answer;
      },
    };
    const homes: HomeConfiguration[] = [{ endpoint: `${relay.base}/`, transport, request: async account => { await relay.start(account, []); return relay.memberRequest(account); } }];
    const device = await Device.make({ homes, exchangeTimeMs });
    await device.session.create();
    device.session.stopSync();
    return { device, mode, stop };
  }
  const settled = async (device: Device): Promise<boolean> => {
    for (let n = 0; n < 40; n++) {
      if (await device.session.syncNow() && device.session.homeIssues.length === 0 && device.session.homeFaults.length === 0) return true;
      await sleep(100);
    }
    return false;
  };
  const waiting = (device: Device, home: string): boolean => {
    const step = device.session.worker.engineForTests()!.run(e => e.exchange_next(home));
    const kind = step.kind; step.free();
    return kind === glue.ExchangeStepKind.Waiting;
  };

  test('a creation whose home setup fails is finished by retry: no account is left that nobody can enter', async () => {
    for (const failAt of ['home request', 'member request'] as const) {
      const relay = await RelayHome.make(host, `https://home.test/v1/accounts/setup-${crypto.randomUUID().slice(0, 8)}`);
      let failing = true; let requests = 0;
      const realMember = await WebCryptoKeyProvider.generate();
      // The member key signs its own request after the homes are appointed: failing there interrupts the setup later.
      const member: AsyncKeyProvider = { publicKeys: () => realMember.publicKeys(), sharedSecret: (p, s) => realMember.sharedSecret(p, s),
        sign: (body, signal) => { if (failing && failAt === 'member request') throw new Error('member key unavailable'); return realMember.sign(body, signal); } };
      const homes: HomeConfiguration[] = [{ endpoint: `${relay.base}/`, transport: relay.transport(), request: async account => {
        requests++;
        if (failing && failAt === 'home request') throw new Error('home setup failed');
        await relay.start(account, []); return relay.memberRequest(account);
      } }];
      const device = await Device.make({ homes, member });
      await device.session.create();
      device.session.stopSync();
      expect([failAt, device.session.phase.kind, device.session.state.setupPending]).toEqual([failAt, 'failed', true]);
      await device.session.refresh();
      expect([failAt, device.session.phase.kind]).toEqual([failAt, 'failed']);
      expect(gateContent(device.session.state, device.session.hasUsableContent)).toMatchObject({ kind: 'screen', actions: ['retry'] });
      failing = false;
      await device.session.retry();
      device.session.stopSync();
      expect([failAt, device.session.phase.kind, device.session.state.setupPending, device.session.homes.length]).toEqual([failAt, 'ready', false, 1]);
      // The home was appointed once: a resumed setup does not appoint it again.
      expect([failAt, requests]).toEqual([failAt, failAt === 'home request' ? 2 : 1]);
      await note(device.session, 'after setup');
      let ok = false;
      for (let n = 0; n < 40 && !ok; n++) { ok = await device.session.syncNow() && device.session.homeIssues.length === 0 && device.session.homeFaults.length === 0; if (!ok) await sleep(100); }
      expect([failAt, ok]).toEqual([failAt, true]);
      device.close();
    }
  }, 120_000);

  // An engine that answers `Waiting` again after the one recovery: the pass cannot finish. Before the fix the loop ended on
  // the second `Waiting` with no fault and `syncNow()` returned true. The Swift and Kotlin sessions have the same test.
  test('a pass that still waits after its recovery is a failed sync', async () => {
    const { device } = await withHome();
    expect(await settled(device)).toBe(true);
    device.session.worker.nextStepOverride = () => ({ kind: glue.ExchangeStepKind.Waiting });
    try {
      expect(await device.session.syncNow()).toBe(false);
      expect(device.session.homeIssues.map(i => i.problem.kind)).toEqual(['stillWaiting']);
      expect(device.session.state.syncState.kind).toBe('error');
    } finally { device.session.worker.nextStepOverride = undefined; }
    expect(await settled(device)).toBe(true);
    device.close();
  }, 60_000);

  test('cancelled while the transport waits, cancelled after it answered, offline, and a home that never answers', async () => {
    const { device, mode, stop } = await withHome(1500);
    expect(await settled(device)).toBe(true);
    const home = device.session.homes[0]!.id;
    for (const failure of ['hang', 'abortAfter', 'offline', 'hangDeaf'] as const) {
      await note(device.session, `note-${failure}`);
      mode.value = failure;
      const controller = new AbortController(); stop.push(controller);
      if (failure === 'hang') setTimeout(() => controller.abort(), 150);
      const ok = await device.session.syncNow(controller.signal);
      expect([failure, ok && device.session.homeIssues.length === 0]).toEqual([failure, false]);
      if (failure === 'hangDeaf') expect(device.session.homeIssues.map(i => i.problem.kind)).toEqual(['tooSlow']);
      if (failure === 'offline') expect(device.session.state.syncState.kind).toBe('offline');
      // The engine is not left waiting for an answer nobody will give: the very next step is a fresh request.
      expect([failure, waiting(device, home)]).toEqual([failure, false]);
      device.session.worker.engineForTests()!.run(e => e.exchange_abort(home)).free();
      mode.value = 'pass';
      expect([failure, await settled(device)]).toEqual([failure, true]);
    }
    device.close();
  }, 120_000);

  test('locking in the middle of a pass ends it and the next unlock syncs', async () => {
    const { device, mode } = await withHome();
    expect(await settled(device)).toBe(true);
    await note(device.session, 'before lock');
    mode.value = 'hang';
    const syncing = device.session.syncNow();
    await sleep(100);
    device.session.lock();
    expect(await Promise.race([syncing, sleep(3000).then(() => 'stuck')])).toBe(false);
    mode.value = 'pass';
    await device.session.unlock();
    expect(device.session.phase.kind).toBe('ready');
    expect(await settled(device)).toBe(true);
    device.close();
  }, 60_000);
});

// Approval spends a confirmed pairing for exactly the request's key (spec §7.3, §9.1): no code from a member ID, no
// approval from the list or the bytes alone, from an unconfirmed pairing, for another device, or twice.
describe('approval and pairing', () => {
  async function world(): Promise<[Device, Device]> {
    const first = await Device.make();
    await first.session.create();
    const second = await Device.make({ medium: first.medium });
    await second.session.restore();
    return [first, second];
  }
  function requestView(raw: Uint8Array): AccessRequest {
    const info = plain<RequestInfo>(glue.account_request_info(raw));
    return { id: info.member, label: info.label, kind: info.kind, termsJson: info.termsJson, record: info.raw, namespaces: [], access: [] };
  }
  async function isMember(device: Device, owner: Device): Promise<boolean> {
    await owner.session.refresh();
    return owner.session.members.some(m => m.id === device.session.memberId);
  }

  test('a listed request carries no code and the joining device shows none', async () => {
    const [first, second] = await world();
    expect(second.session.phase).toEqual({ kind: 'waitingForApproval' });
    await first.session.refresh();
    const listed = first.session.requests[0]!;
    expect(listed.id).toBe(second.session.memberId!);
    expect('pairingCode' in listed).toBe(false);
    first.close(); second.close();
  });

  test('a code the person did not confirm approves nothing', async () => {
    const [first, second] = await world();
    const raw = await second.session.exportRequest();
    const j = await second.session.beginJoinPairing();
    const start = await first.session.beginApproval(j.commitment());
    const reveal = j.receive_nonce(start.nonce)!;
    await first.session.approvalCode(start.pairing, reveal.e, reveal.nb);
    // The request travels with the commitment; a scan now would be refused (one ceremony at a time).
    const request = requestView(raw);
    await expect(first.session.approve(request, start.pairing)).rejects.toThrow();
    expect(await isMember(second, first)).toBe(false);
    first.close(); second.close();
  });

  test('a pairing for one device does not approve another, and is spent by the refusal', async () => {
    const [first, second] = await world();
    const attacker = await Device.make({ medium: first.medium });
    await attacker.session.restore();
    const { pairing } = await pairByCode(second.session, first.session);
    const substituted = (await first.session.scanRequest(await attacker.session.exportRequest())).request;
    await expect(first.session.approve(substituted, pairing)).rejects.toThrow();
    expect(await isMember(attacker, first)).toBe(false);
    const real = (await first.session.scanRequest(await second.session.exportRequest())).request;
    await expect(first.session.approve(real, pairing)).rejects.toThrow();
    first.close(); second.close(); attacker.close();
  });

  test('one pairing approves once', async () => {
    const [first, second] = await world();
    const scanned = await first.session.scanRequest(await second.session.exportRequest());
    await first.session.approve(scanned.request, scanned.pairing);
    expect(await isMember(second, first)).toBe(true);
    expect(scanned.pairing.stage()).toBe(glue.PairingStage.Spent);
    await expect(first.session.approve(scanned.request, scanned.pairing)).rejects.toThrow();
    first.close(); second.close();
  });

  test("the joining device's own pairing does not approve", async () => {
    const [first, second] = await world();
    const j = await second.session.beginJoinPairing();
    const start = await first.session.beginApproval(j.commitment());
    j.receive_nonce(start.nonce);
    j.confirm();
    const request = requestView(await second.session.exportRequest());
    await expect(first.session.approve(request, j)).rejects.toThrow();
    expect(await isMember(second, first)).toBe(false);
    first.close(); second.close();
  });

  test('scanning a request stores nothing', async () => {
    const [first, second] = await world();
    const raw = await second.session.exportRequest();
    const before = (first.medium as MemoryMedium).listing().map(e => e.path).sort();
    const scanned = await first.session.scanRequest(raw);
    expect(scanned.request.id).toBe(second.session.memberId!);
    expect((first.medium as MemoryMedium).listing().map(e => e.path).sort()).toEqual(before);
    first.close(); second.close();
  });

  test('mismatches abort on both devices and are bounded five an hour', async () => {
    const [first, second] = await world();
    for (let attempt = 0; attempt < 5; attempt++) {
      const j = await second.session.beginJoinPairing();
      const start = await first.session.beginApproval(j.commitment());
      const reveal = j.receive_nonce(start.nonce)!;
      if (attempt % 2 === 0) {
        await expect(first.session.approvalCode(start.pairing, reveal.e, new Uint8Array(32))).rejects.toThrow();
      } else {
        await first.session.approvalCode(start.pairing, reveal.e, reveal.nb);
        await first.session.rejectPairing(start.pairing);
      }
      await second.session.rejectPairing(j);
      expect(j.stage()).toBe(glue.PairingStage.Spent);
      expect(start.pairing.stage()).toBe(glue.PairingStage.Spent);
    }
    const j = await second.session.beginJoinPairing();
    await expect(first.session.beginApproval(j.commitment())).rejects.toThrow();
    first.close(); second.close();
  });

  test('a failed creation is not erased by a sync pass', async () => {
    // Deterministic: the pass runs after the failure (the Kotlin session showed the race as "noLibrary, no error").
    const device = await Device.make({ homes: [{ endpoint: 'http://home.example/v1/' }] });
    await device.session.create();
    const phase = device.session.phase, error = device.session.lastError;
    expect(phase.kind).toBe('failed');
    expect(error).toContain('HTTPS');
    expect(await device.session.syncNow()).toBe(false);
    expect(device.session.phase).toEqual(phase);
    expect(device.session.lastError).toBe(error);
    device.close();
  });

  // The approving device's ledger: one ceremony at a time, every start counted (§7.3).
  class FlakyStore extends MemoryPrivateStore {
    failLedger = false;
    override async write(name: string, bytes: Uint8Array): Promise<void> {
      if (this.failLedger && name === 'pairing-ledger.bin') throw new Error('disk full');
      return super.write(name, bytes);
    }
  }
  async function ledgerWorld(): Promise<{ first: Device; second: Device; store: FlakyStore; secrets: MemoryDeviceSecrets; member: AsyncKeyProvider; owner: AsyncKeyProvider }> {
    const store = new FlakyStore(); const secrets = new MemoryDeviceSecrets();
    const member = await WebCryptoKeyProvider.generate(); const owner = await WebCryptoKeyProvider.generate();
    const first = await Device.make({ privateStore: store, secrets, member, owner });
    await first.session.create();
    const second = await Device.make({ medium: first.medium });
    await second.session.restore();
    return { first, second, store, secrets, member, owner };
  }
  const commitment = async (s: Device) => (await s.session.beginJoinPairing()).commitment();

  test('a second commitment while one ceremony is live is refused and yields no nonce', async () => {
    const { first, second } = await ledgerWorld();
    const live = await first.session.beginApproval(await commitment(second));
    await expect(first.session.beginApproval(await commitment(second))).rejects.toMatchObject({ code: 'pairing:busy' });
    await first.session.abandonApproval(live.pairing);
    await first.session.beginApproval(await commitment(second));
    first.close(); second.close();
  });

  test('many starts through one session yield one nonce (its worker serializes them; the core lets one live)', async () => {
    const { first, second } = await ledgerWorld();
    const commitments: Uint8Array[] = [];
    for (let i = 0; i < 40; i++) commitments.push(await commitment(second));
    const results = await Promise.allSettled(commitments.map(c => first.session.beginApproval(c)));
    expect(results.filter(r => r.status === 'fulfilled').length).toBe(1);
    first.close(); second.close();
  });

  test('abandoned ceremonies stay counted: five close the hour', async () => {
    const { first, second } = await ledgerWorld();
    for (let i = 0; i < 5; i++) await first.session.abandonApproval((await first.session.beginApproval(await commitment(second))).pairing);
    await expect(first.session.beginApproval(await commitment(second))).rejects.toMatchObject({ code: 'pairing:limit' });
    first.close(); second.close();
  });

  test('when the ledger cannot be persisted, no nonce is produced', async () => {
    const { first, second, store } = await ledgerWorld();
    store.failLedger = true;
    await expect(first.session.beginApproval(await commitment(second))).rejects.toThrow('disk full');
    first.close(); second.close();
  });

  test('the ledger alone rolled back (its recorded generation kept), or deleted, does not restore the budget after a relaunch', async () => {
    const { first, second, store, secrets, member, owner } = await ledgerWorld();
    await first.session.abandonApproval((await first.session.beginApproval(await commitment(second))).pairing);
    const early = (await store.read('pairing-ledger.bin'))!;
    for (let i = 0; i < 4; i++) await first.session.abandonApproval((await first.session.beginApproval(await commitment(second))).pairing);
    await store.write('pairing-ledger.bin', early);
    const relaunched = await Device.make({ medium: first.medium, privateStore: store, secrets, member, owner });
    await relaunched.session.restore();
    await expect(relaunched.session.beginApproval(await commitment(second))).rejects.toThrow();
    relaunched.close();
    await store.remove('pairing-ledger.bin');
    const again = await Device.make({ medium: first.medium, privateStore: store, secrets, member, owner });
    await again.session.restore();
    await expect(again.session.beginApproval(await commitment(second))).rejects.toThrow();
    again.close(); first.close(); second.close();
  });

  test('two sessions over one store (two tabs, two workers) yield exactly one nonce', async () => {
    const { first, second, store, secrets, member, owner } = await ledgerWorld();
    const other = await Device.make({ medium: first.medium, privateStore: store, secrets, member, owner });
    await other.session.restore();
    const commitments: Uint8Array[] = [];
    for (let i = 0; i < 20; i++) commitments.push(await commitment(second));
    const sessions = [first.session, other.session];
    const results = await Promise.allSettled(commitments.map((c, i) => sessions[i % 2]!.beginApproval(c)));
    expect(results.filter(r => r.status === 'fulfilled').length).toBe(1);
    other.close(); first.close(); second.close();
  });

  test('the residual limit: a wholesale restore of the ledger and its generation restores the budget', async () => {
    const { first, second, store, secrets, member, owner } = await ledgerWorld();
    await first.session.abandonApproval((await first.session.beginApproval(await commitment(second))).pairing);
    const early = (await store.read('pairing-ledger.bin'))!;
    const earlyFloor = (await store.read('pairing-ledger.generation'))!;
    for (let i = 0; i < 4; i++) await first.session.abandonApproval((await first.session.beginApproval(await commitment(second))).pairing);
    await store.write('pairing-ledger.bin', early);
    await store.write('pairing-ledger.generation', earlyFloor);
    const relaunched = await Device.make({ medium: first.medium, privateStore: store, secrets, member, owner });
    await relaunched.session.restore();
    await relaunched.session.beginApproval(await commitment(second));
    relaunched.close(); first.close(); second.close();
  });
});
