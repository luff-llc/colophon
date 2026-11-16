// Freeze package, stream W3-G, under Bun: a stopped account in the session (spec §1 "A stop"), a home's refusals shown raw
// (§14, §19), and a joining device that is waiting for approval rather than revoked.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  gateContent, glue, homeRefusal, HomeWords, init, isResultCode, MemoryDeviceSecrets, MemoryMedium, MemoryPrivateStore, StoppedWords,
  WebCryptoKeyProvider, type HomeAnswer, type HomeConfiguration, type HomeRequest, type HomeTransport,
} from '../src/session/index.js';
import { admitted, Device, note, RelayHome } from './support.ts';
import { BunRelayHost } from './relay-bun.ts';

const host = new BunRelayHost();
beforeAll(async () => { await init(); });
afterAll(async () => { await host.stopAll(); });
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const b64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
const hex = async (bytes: Uint8Array): Promise<string> =>
  [...new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes).buffer as ArrayBuffer))].map(b => b.toString(16).padStart(2, '0')).join('');
/** A home's error body: the result, and bytes a session must never echo. */
const refusalBody = (result: string): Uint8Array => utf8(JSON.stringify({ result, detail: 'SECRET-BODY-BYTES' }));

/**
 * **Test-only, below the 0.5 builders**: a transition raising the account's layout to `layout` (spec §20 "The upgrade
 * door"), signed by the owner controller and written to the device's store. 0.5's write side deliberately builds no
 * `layout` component, so this helper writes the canonical body itself (every value is plain ASCII, keys in order): the
 * account, the anchor (the verified head), the owner as `by` and only signer, the change, the clock. The session's own
 * refresh then records the `activate` (`record_due`), final at once in an account with no home: the device is stopped.
 */
export async function raiseLayout(device: Device, layout = 3, nowMs = Date.now()): Promise<void> {
  const account = device.session.state.libraryId!;
  const last = device.medium.listing().map(e => e.path).filter(p => p.startsWith('authority/')).sort().at(-1)!;
  const envelope = JSON.parse(new TextDecoder().decode(device.medium.read(last))) as { body: string };
  const headBody = Uint8Array.from(atob(envelope.body), c => c.charCodeAt(0));
  const seq = Number(last.slice('authority/'.length, 'authority/'.length + 8));
  const owner = glue.account_key_id((await device.owner.publicKeys()).signing);
  const issued = glue.account_format_date(BigInt(nowMs));
  const body = utf8(`{"account":"${account}","anchor":{"digest":"${await hex(headBody)}","seq":${seq}},"by":"${owner}",`
    + `"change":{"layout":${layout}},"issued":"${issued}","protocol":"colophon/transition/5","signers":["${owner}"]}`);
  const signature = await device.owner.sign(body);
  await device.medium.write([{ path: `transitions/${await hex(body)}.json`, bytes: utf8(`{"body":"${b64(body)}","signature":"${b64(signature)}"}`) }]);
}

describe('a stopped account', () => {
  test('a final raise stops the account: readable, nothing written, no exchange, kept across relaunch; lock and sign-out work', async () => {
    const medium = new MemoryMedium(); const privateStore = new MemoryPrivateStore(); const secrets = new MemoryDeviceSecrets();
    const member = await WebCryptoKeyProvider.generate(); const owner = await WebCryptoKeyProvider.generate();
    let sent = 0;
    // A home is configured (so a sync loop exists) but not appointed: the raise is final at once. Any request fails.
    const transport: HomeTransport = { send: async () => { sent++; return { status: 500, headers: [], body: new Uint8Array() }; } };
    const homes: HomeConfiguration[] = [{ endpoint: 'https://home.example/', transport }];
    const make = () => Device.make({ medium, privateStore, secrets, member, owner, homes, createWithoutHome: true });
    const device = await make();
    await device.session.create();
    expect(device.session.phase.kind).toBe('ready');
    await note(device.session, 'before');
    expect(await admitted(device.session)).toBe(1);
    const head = medium.listing().filter(e => e.path.startsWith('authority/')).length;

    await raiseLayout(device);
    await device.session.flushExternalChanges();
    expect(device.session.phase).toEqual({ kind: 'stopped', seq: head + 1, layout: 3 });
    expect(device.session.lastError).toBeUndefined();
    // Reads go on, as of the stop.
    expect(device.session.hasUsableContent).toBe(true);
    expect(await admitted(device.session)).toBe(1);
    expect(gateContent(device.session.state, true)).toEqual({ kind: 'content', status: StoppedWords.status, actions: [] });
    expect(gateContent(device.session.state, false)).toMatchObject({ kind: 'screen', id: 'library.stopped', actions: [] });
    // A write is refused, and the phase stays.
    await expect(note(device.session, 'after')).rejects.toBeInstanceOf(Error);
    expect(device.session.phase.kind).toBe('stopped');
    expect(medium.listing().filter(e => e.path.startsWith('ops/')).length).toBe(1);
    // No exchange runs: not a failure, and no home is contacted.
    expect(await device.session.syncNow()).toBe(true);
    expect(device.session.state.syncState).toEqual({ kind: 'disabled' });
    expect(sent).toBe(0);
    // Lock and unlock: back to stopped.
    device.session.lock();
    expect(device.session.phase.kind).toBe('locked');
    await device.session.unlock();
    expect(device.session.phase.kind).toBe('stopped');
    device.close();
    // Relaunch: still stopped, still readable; sign-out works.
    const again = await make();
    await again.session.restore();
    again.session.stopSync();
    expect(again.session.phase).toEqual({ kind: 'stopped', seq: head + 1, layout: 3 });
    expect(await admitted(again.session)).toBe(1);
    await again.session.leave();
    expect(again.session.phase.kind).toBe('noLibrary');
    again.close();
  });

  test('a stop survives its evidence going missing: a store without the raise relaunches stopped and writes nothing', async () => {
    const medium = new MemoryMedium(); const privateStore = new MemoryPrivateStore(); const secrets = new MemoryDeviceSecrets();
    const member = await WebCryptoKeyProvider.generate(); const owner = await WebCryptoKeyProvider.generate();
    const device = await Device.make({ medium, privateStore, secrets, member, owner });
    await device.session.create();
    await note(device.session, 'kept');
    const before = new Set(medium.listing().map(e => e.path));
    await raiseLayout(device);
    await device.session.flushExternalChanges();
    expect(device.session.phase.kind).toBe('stopped');
    device.close();
    // A hostile store: every authority and pending file the raise added is gone.
    const reduced = new MemoryMedium();
    await reduced.write(medium.listing().map(e => e.path)
      .filter(p => before.has(p) || !(p.startsWith('authority/') || p.startsWith('transitions/')))
      .map(p => ({ path: p, bytes: medium.read(p) })));
    const again = await Device.make({ medium: reduced, privateStore, secrets, member, owner });
    await again.session.restore();
    expect(again.session.phase.kind).toBe('stopped');
    await expect(note(again.session, 'after')).rejects.toBeInstanceOf(Error);
    expect(await admitted(again.session)).toBe(1);
    again.close();
  });

  test('a record that arrives after the stop is not admitted', async () => {
    const member = await WebCryptoKeyProvider.generate(); const owner = await WebCryptoKeyProvider.generate();
    const device = await Device.make({ member, owner });
    await device.session.create();
    await note(device.session, 'one');
    const copyMedium = new MemoryMedium();
    await copyMedium.write(device.medium.listing().map(e => ({ path: e.path, bytes: device.medium.read(e.path) })));
    const held = new Set(device.medium.listing().map(e => e.path));
    const copy = await Device.make({ medium: copyMedium, member, owner });
    await copy.session.restore();
    expect(copy.session.phase.kind).toBe('ready');
    await note(copy.session, 'late');
    const late = copyMedium.listing().map(e => e.path).filter(p => p.startsWith('ops/') && !held.has(p));
    expect(late.length).toBe(1);
    await raiseLayout(device);
    await device.session.flushExternalChanges();
    expect(device.session.phase.kind).toBe('stopped');
    const shown = await admitted(device.session);
    await device.medium.write(late.map(p => ({ path: p, bytes: copyMedium.read(p) })));
    await device.session.flushExternalChanges();
    expect(await admitted(device.session)).toBe(shown);
    copy.close(); device.close();
  });

  test('a raise that is not yet recorded stops nothing', async () => {
    const device = await Device.make();
    await device.session.create();
    await raiseLayout(device, 3, Date.now() + 3_600_000);
    await device.session.flushExternalChanges();
    expect(device.session.phase.kind).not.toBe('stopped');
    device.close();
  });
});

describe("a home's refusals", () => {
  test('the result grammar is bounded and nothing else is read', () => {
    for (const good of ['refused:overQuota', 'refused:noEntitlement', 'refused:closed', 'refused:notProvisioned', 'refused:somethingNew2', 'unavailable']) expect(isResultCode(good)).toBe(true);
    for (const bad of ['refused:', 'refused:Upper', 'refused:a-b', 'refused:<script>', 'refused:' + 'a'.repeat(49), 'nope', 'refused:é']) expect(isResultCode(bad)).toBe(false);
    expect(homeRefusal({ status: 410, headers: [{ name: 'Retry-After', value: '30' }], body: refusalBody('refused:closed') })).toEqual({ status: 410, code: 'refused:closed', retryAfterSeconds: 30 });
    expect(homeRefusal({ status: 410, headers: [], body: refusalBody('refused:<x>') })).toBeUndefined();
    expect(homeRefusal({ status: 200, headers: [], body: refusalBody('refused:closed') })).toBeUndefined();
    expect(homeRefusal({ status: 429, headers: [{ name: 'retry-after', value: 'Tue, 1 Dec' }], body: new Uint8Array() })).toBeUndefined();
  });

  async function world(): Promise<{ relay: RelayHome; transport: HomeTransport; answer: { fn?: (r: HomeRequest) => HomeAnswer | undefined }; sent: { n: number } }> {
    const relay = await RelayHome.make(host, `https://home.test/v1/accounts/refusal-${crypto.randomUUID().slice(0, 8)}`);
    const inner = relay.transport();
    const answer: { fn?: (r: HomeRequest) => HomeAnswer | undefined } = {};
    const sent = { n: 0 };
    const transport: HomeTransport = { send: async (request, signal) => { sent.n++; return answer.fn?.(request) ?? inner.send(request, signal); } };
    return { relay, transport, answer, sent };
  }

  test('unknown and reserved names refuse only that request; Retry-After is honoured; a 503 is an unavailable home', async () => {
    const { relay, transport, answer, sent } = await world();
    const homes: HomeConfiguration[] = [{ endpoint: `${relay.base}/`, transport, request: async account => { await relay.start(account, []); return relay.memberRequest(account); } }];
    const device = await Device.make({ homes, history: 'public' });
    await device.session.create();
    device.session.stopSync();
    expect(await device.session.syncNow()).toBe(true);
    for (const [code, status] of [['refused:overQuota', 507], ['refused:noEntitlement', 402], ['refused:closed', 410], ['refused:somethingNew', 409]] as const) {
      answer.fn = r => (r.method === 'PUT' && r.url.includes('/records/ops/') ? { status, headers: [], body: refusalBody(code) } : undefined);
      await note(device.session, `n-${status}`);
      await device.session.syncNow();
      expect(device.session.homeIssues.some(i => i.problem.kind === 'remoteCallRefused' && i.problem.code === code)).toBe(true);
      expect(JSON.stringify(device.session.homeIssues)).not.toContain('SECRET');
      expect(device.session.phase.kind).toBe('ready');
    }
    // `refused:notProvisioned` (403) ends the pass, as a refused call does, and is only the home's word.
    answer.fn = r => (r.url.endsWith('/head') ? undefined : { status: 403, headers: [], body: refusalBody('refused:notProvisioned') });
    await device.session.syncNow();
    expect(device.session.homeIssues.some(i => i.problem.kind === 'remoteCallRefused' && i.problem.code === 'refused:notProvisioned')).toBe(true);
    // A refusal by name to a request that carried no call is not retried with a call.
    expect(device.session.homeIssues.some(i => i.problem.kind === 'callRefused')).toBe(false);
    expect(device.session.phase.kind).toBe('ready');
    // `503 {"result":"unavailable"}`: the home is not available, retried with backoff; never the device being stopped.
    answer.fn = () => ({ status: 503, headers: [], body: refusalBody('unavailable') });
    expect(await device.session.syncNow()).toBe(false);
    expect(device.session.state.syncState).toEqual({ kind: 'offline', reason: HomeWords.unavailable });
    expect(device.session.homeIssues.some(i => i.problem.kind === 'homeUnavailable')).toBe(true);
    expect(device.session.phase.kind).not.toBe('stopped');
    expect(device.session.hasUsableContent).toBe(true);
    // `Retry-After` is honoured: not contacted again before then.
    answer.fn = () => ({ status: 429, headers: [{ name: 'Retry-After', value: '120' }], body: refusalBody('refused:window') });
    await device.session.syncNow();
    expect(device.session.homeIssues.some(i => JSON.stringify(i.problem) === JSON.stringify({ kind: 'remoteCallRefused', code: 'refused:window', retryAfterSeconds: 120 }))).toBe(true);
    const count = sent.n;
    await device.session.syncNow(); await device.session.syncNow();
    expect(sent.n).toBe(count);
    device.close();
  });

  test('a joining device is waiting for approval, not revoked; an approved one sees the refusal as received', async () => {
    const { relay, transport, answer } = await world();
    const creator: HomeConfiguration[] = [{ endpoint: `${relay.base}/`, transport, request: async account => { await relay.start(account, []); return relay.memberRequest(account); } }];
    const first = await Device.make({ homes: creator, history: 'public' });
    await first.session.create();
    first.session.stopSync();
    const joining = await Device.make({ medium: first.medium, homes: [{ endpoint: `${relay.base}/`, transport }], createWithoutHome: false });
    await joining.session.restore();
    joining.session.stopSync();
    expect(joining.session.phase.kind).toBe('waitingForApproval');
    answer.fn = r => (r.url.endsWith('/head') ? undefined : { status: 403, headers: [], body: refusalBody('refused:revoked') });
    await joining.session.syncNow();
    expect(joining.session.homeIssues.some(i => i.problem.kind === 'waitingForApproval')).toBe(true);
    expect(joining.session.homeIssues.some(i => i.problem.kind === 'remoteCallRefused')).toBe(false);
    expect(joining.session.phase.kind).toBe('waitingForApproval');
    await first.session.syncNow();
    expect(first.session.homeIssues.some(i => i.problem.kind === 'remoteCallRefused' && i.problem.code === 'refused:revoked')).toBe(true);
    expect(first.session.phase.kind).toBe('ready');
    joining.close(); first.close();
  });
});
