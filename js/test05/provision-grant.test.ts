// Provisioning a home slot by a grant (the reference home's gate "grant", relay/README.md "Provisioning by a grant"),
// through the JavaScript session against the REAL relay: an operator account on the relay's own slot, a test rig that
// asks for `services` and is approved with an expiry and a slot condition, and the rig's `provisionRequest` plugged into
// a fresh account's `HomeConfiguration.request`.
//
// Nothing here depends on real elapsed time: every session and the relay run on one fixed clock the test moves, and the
// relay has no scheduler timer: its heads are published by its test hook (`RelayHome.tick`), never by waiting.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import {
  init, MemoryMedium, narrowedTerms, ProvisionRefusal, WebCryptoKeyProvider, type AsyncKeyProvider, type HomeConfiguration,
} from '../src/session/index.js';
import { terms } from '../src/session/worker.js';
import { authorityOnly } from './journey.ts';
import { BunRelayHost } from './relay-bun.ts';
import { admitted, approveByScan, assert, Device, equal, note, RelayHome } from './support.ts';

const host = new BunRelayHost();
beforeAll(async () => { await init(); });
afterAll(async () => { await host.stopAll(); });

const PREFIX = 'https://door.test/v1/libraries/';
const AUDIENCE = 'https://door.test/v1/provision';
const PURPOSE = 'home.provision';
const RELEASE = 'home.release';
/** "The slot starts with `ci-`, or the call names no slot" (a home read): §10.4, a missing path makes `prefix` false. */
const SLOT_PREFIX = { any: [{ prefix: ['args.slot', 'ci-'] }, { not: { prefix: ['args.slot', ''] } }] };
const T0 = Date.parse('2026-11-20T09:00:00Z');
const iso = (ms: number): string => new Date(ms).toISOString().replace('.000Z', 'Z');

/** The rig's member key, counting the signatures it is asked for. */
class CountingKeys implements AsyncKeyProvider {
  readonly form;
  signs = 0;
  constructor(private readonly inner: AsyncKeyProvider) { this.form = inner.form; }
  publicKeys() { return this.inner.publicKeys(); }
  sign(body: Uint8Array, signal?: AbortSignal) { this.signs++; return this.inner.sign(body, signal); }
  sharedSecret(peer: Uint8Array, signal?: AbortSignal) { return this.inner.sharedSecret(peer, signal); }
}

test('services in request terms, and a grant that narrows them', () => {
  const services = [{ audience: AUDIENCE, purposes: [PURPOSE, 'home.read'] }];
  expect(terms([], ['read', 'write'], undefined, undefined, services)).toBe(`{"services":[{"audience":"${AUDIENCE}","purposes":["home.provision","home.read"]}]}`);
  expect(terms(['notes'], ['read'], undefined, undefined, services))
    .toBe(`{"records":[{"access":"read","namespace":"notes"}],"services":[{"audience":"${AUDIENCE}","purposes":["home.provision","home.read"]}]}`);
  expect(terms(['notes'], ['read', 'write'], '2026-12-01T00:00:00Z', 5n)).toBe('{"expires":"2026-12-01T00:00:00Z","records":[{"access":"write","namespace":"notes"}],"writes":5}');
  const asked = terms([], ['read'], undefined, undefined, services);
  expect(narrowedTerms(asked, { services: [{ audience: AUDIENCE, purposes: [PURPOSE] }], expires: '2026-12-01T00:00:00Z', conditions: [{ prefix: ['args.slot', 'ci-'] }] }))
    .toBe(`{"conditions":[{"prefix":["args.slot","ci-"]}],"expires":"2026-12-01T00:00:00Z","services":[{"audience":"${AUDIENCE}","purposes":["home.provision"]}]}`);
  expect(narrowedTerms(asked, {})).toBe(asked);
  const wider = [
    { services: [{ audience: 'https://other.test/x', purposes: [PURPOSE] }] },
    { services: [{ audience: AUDIENCE, purposes: [RELEASE] }] },
    { services: [{ audience: AUDIENCE, purposes: ['*'] }] },
    { services: [] },
  ];
  for (const grant of wider) expect(() => narrowedTerms(asked, grant)).toThrow();
  // Finite requested bounds: an expiry later than requested is refused; the requested write budget is kept as asked.
  const bounded = '{"expires":"2026-11-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}],"writes":5}';
  expect(() => narrowedTerms(bounded, { expires: '2026-12-01T00:00:00Z' })).toThrow();
  expect(narrowedTerms(bounded, { expires: '2026-10-01T00:00:00Z' })).toBe('{"expires":"2026-10-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}],"writes":5}');
  expect(narrowedTerms('{"services":[{"audience":"urn:x","purposes":["*"]}]}', { services: [{ audience: 'urn:x', purposes: ['a'] }] })).toBe('{"services":[{"audience":"urn:x","purposes":["a"]}]}');
});

test('a rig granted by the operator provisions a fresh account; refused for a withheld purpose, outside its prefix, once revoked, and once expired', async () => {
  let now = T0;
  const clock = (): number => now;
  const tag = crypto.randomUUID().slice(0, 8);
  const relay = await RelayHome.make(host, `https://door.test/v1/accounts/operator-${tag}`, clock);
  const provision = (account: string) => ({ enabled: true, prefix: PREFIX, gate: ['grant'], operator: { account, slot: 'home' }, audience: AUDIENCE });
  /** Exchanges until clean, one relay pass after each exchange (the pass publishes the head covering what was uploaded). */
  const settle = async (device: Device): Promise<void> => {
    for (let n = 0; n < 6; n++) {
      now += 1000;
      const ok = await device.session.syncNow();
      await relay.tick();
      if (ok && device.session.homeIssues.length === 0 && device.session.homeFaults.length === 0) return;
    }
    throw new Error(`did not settle: ${device.describe()}`);
  };
  /** A device that asked learns its approval through the home, once the relay's pass covered it. */
  const untilApproved = async (device: Device): Promise<void> => {
    for (let n = 0; n < 6; n++) {
      now += 1000;
      await device.session.syncNow();
      await device.session.refresh();
      if (device.session.phase.kind === 'ready') return;
      await relay.tick();
    }
    throw new Error(`not approved: ${device.describe()}`);
  };
  const devices: Device[] = [];
  try {
    // The operator account lives on the relay's own slot `home`, which the door names as its operator slot.
    const operator = await Device.make({ now: clock, homes: [{ endpoint: `${relay.base}/`, transport: relay.transport(),
      request: async account => { await relay.start(account, [], { provision: provision(account) }); return relay.memberRequest(account); } }] });
    devices.push(operator);
    await operator.session.create();
    operator.session.stopSync();
    equal(operator.session.phase.kind, 'ready', operator.describe());
    await settle(operator);

    // The rig joins the operator account asking for two of the door's purposes, and no namespace.
    const keys = new CountingKeys(await WebCryptoKeyProvider.generate());
    const rig = await Device.make({ now: clock, member: keys, medium: authorityOnly(operator.medium as MemoryMedium), namespaces: [],
      services: [{ audience: AUDIENCE, purposes: [PURPOSE, RELEASE] }], homes: [{ endpoint: `${relay.base}/`, transport: relay.transport() }] });
    devices.push(rig);
    await rig.session.restore();
    rig.session.stopSync();
    equal(rig.session.phase.kind, 'waitingForApproval', rig.describe());
    const scanned = await operator.session.scanRequest(await rig.session.exportRequest());
    expect(scanned.request.services).toEqual([{ audience: AUDIENCE, purposes: [PURPOSE, RELEASE] }]);
    expect(scanned.request.namespaces).toEqual([]);
    // A grant wider than the request is refused before anything is signed (another audience's service).
    await expect(operator.session.approve(scanned.request, scanned.pairing, { services: [{ audience: 'https://other.test/v1/provision', purposes: [PURPOSE] }] }))
      .rejects.toMatchObject({ code: 'invalidCommand' });
    // The grant: provisioning only (release is withheld), until T0 + 240 s, and ci- slots.
    const expires = T0 + 240_000;
    const again = await operator.session.scanRequest(await rig.session.exportRequest());
    await operator.session.approve(again.request, again.pairing, { services: [{ audience: AUDIENCE, purposes: [PURPOSE] }], expires: iso(expires), conditions: [SLOT_PREFIX] });
    const granted = operator.session.members.find(m => m.id === rig.session.memberId);
    equal(granted?.expiresMs, BigInt(expires), 'the grant carries its expiry');
    await settle(operator);
    await untilApproved(rig);

    // The signer's own check. A purpose never asked for, or another audience: refused before the key is asked.
    const args = { account: 'ab'.repeat(32), base: `${PREFIX}ci-${tag}-x`, slot: `ci-${tag}-x` };
    let signs = keys.signs;
    await expect(rig.session.signCall(AUDIENCE, 'home.other', args)).rejects.toMatchObject({ kind: 'Refused', code: 'refused:outOfScope' });
    await expect(rig.session.signCall('https://other.test/v1/provision', PURPOSE, args)).rejects.toMatchObject({ kind: 'Refused', code: 'refused:outOfScope' });
    equal(keys.signs, signs, 'the key was not asked');
    // A purpose asked for but withheld by the grant: the key signs, the core's check refuses, and no call is returned.
    await expect(rig.session.signCall(AUDIENCE, RELEASE, args)).rejects.toMatchObject({ kind: 'Refused', code: 'refused:outOfScope' });
    equal(keys.signs, signs + 1, 'the key was asked once, and its call was refused');
    signs = keys.signs;
    const signed = await rig.session.signCall(AUDIENCE, PURPOSE, args);
    assert(/^[A-Za-z0-9_-]+$/.test(signed), 'the call is base64url');

    // A fresh account whose home request is the rig's provisionRequest: provisioned, written, read on a second device.
    const slot = `ci-${tag}`;
    const base = PREFIX + slot;
    const reaching = (request?: HomeConfiguration['request']): HomeConfiguration[] => [{ endpoint: `${base}/`, transport: relay.slotTransport(base, slot), request }];
    const app = await Device.make({ now: clock, homes: reaching(account => rig.session.provisionRequest(relay.door, AUDIENCE, slot, base, account, { transport: relay.doorTransport() })) });
    devices.push(app);
    await app.session.create();
    app.session.stopSync();
    equal(app.session.phase.kind, 'ready', app.describe());
    equal(app.session.homes.length, 1, 'the provisioned home is appointed');
    await note(app.session, 'a');
    await settle(app);
    const second = await Device.make({ now: clock, medium: authorityOnly(app.medium as MemoryMedium), homes: reaching() });
    devices.push(second);
    await second.session.restore();
    second.session.stopSync();
    await approveByScan(second.session, app.session);
    await settle(app);
    await untilApproved(second);
    await settle(second);
    equal(await admitted(second.session), 1, 'the second device reads what the first wrote through the provisioned slot');

    // A slot outside the grant's prefix: the rig's own check refuses it (the grant's condition is false), nothing is sent.
    const outside = `other-${tag}`;
    await expect(rig.session.provisionRequest(relay.door, AUDIENCE, outside, PREFIX + outside, 'cd'.repeat(32), { transport: relay.doorTransport() }))
      .rejects.toMatchObject({ kind: 'Refused', code: 'refused:outOfScope' });
    // The door's own refusal is final: a call for one slot carried with another slot's body is 403, and nothing is made.
    const call = await rig.session.signCall(AUDIENCE, PURPOSE, { account: 'cd'.repeat(32), base: `${PREFIX}ci-${tag}-y`, slot: `ci-${tag}-y` });
    const body = new TextEncoder().encode(JSON.stringify({ account: 'cd'.repeat(32), base: PREFIX + outside, slot: outside }));
    const refused = await relay.doorTransport().send({ method: 'POST', url: relay.door, body, headers: [
      { name: 'Content-Type', value: 'application/json' }, { name: 'Content-Length', value: String(body.length) }, { name: 'Authorization', value: `Colophon ${call}` }] });
    equal(refused.status, 403, 'refused by the door');
    expect(JSON.parse(new TextDecoder().decode(refused.body))).toEqual({ result: 'refused:outOfScope' });

    // The operator revokes the rig: the rig, which has not synced the revocation, signs; the door refuses with revoked.
    const rigId = rig.session.memberId;
    assert(rigId !== undefined, 'the rig has a member ID');
    await operator.session.revoke(rigId);
    await settle(operator);
    const after = `ci-${tag}-z`;
    const refusal = await rig.session.provisionRequest(relay.door, AUDIENCE, after, PREFIX + after, 'ef'.repeat(32), { transport: relay.doorTransport() })
      .then(() => undefined, (error: unknown) => error);
    assert(refusal instanceof ProvisionRefusal, () => `a refusal from the door: ${String(refusal)}`);
    equal(refusal.status, 403, 'the door refuses a revoked grant');
    equal(refusal.code, 'refused:revoked', 'with the core\'s code');

    // The clock passes the grant's expiry (the heads the rig holds are still fresh): its own check refuses as expired.
    assert(now < expires, 'the journey ran inside the grant');
    now = expires + 10_000;
    await expect(rig.session.signCall(AUDIENCE, PURPOSE, args)).rejects.toMatchObject({ kind: 'Refused', code: 'refused:expired' });
  } finally {
    for (const d of devices) d.close();
  }
}, 180_000);
