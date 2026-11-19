// Provisioning a home slot by a grant (the reference home's gate "grant", relay/README.md "Provisioning by a grant"),
// through the JavaScript session against the REAL relay: an operator account on the relay's own slot, a test rig that
// asks for `services` and is approved with an expiry and a slot prefix, and the rig's `provisionRequest` plugged into a
// fresh account's `HomeConfiguration.request`. The relay runs on a clock the test sets to now before each request;
// nothing waits on elapsed time beyond the home's own head tick, which `settle` and `untilApproved` poll for.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { init, MemoryMedium, narrowedTerms, ProvisionRefusal, type HomeConfiguration } from '../src/session/index.js';
import { terms } from '../src/session/worker.js';
import { authorityOnly, settle, untilApproved } from './journey.ts';
import { BunRelayHost } from './relay-bun.ts';
import { admitted, approveByScan, assert, Device, equal, note, RelayHome } from './support.ts';

const host = new BunRelayHost();
beforeAll(async () => { await init(); });
afterAll(async () => { await host.stopAll(); });

const PREFIX = 'https://door.test/v1/libraries/';
const AUDIENCE = 'https://door.test/v1/provision';
const PURPOSE = 'home.provision';
/** "The slot starts with `ci-`, or the call names no slot" (a home read): §10.4, a missing path makes `prefix` false. */
const SLOT_PREFIX = { any: [{ prefix: ['args.slot', 'ci-'] }, { not: { prefix: ['args.slot', ''] } }] };
const day = (ms: number): string => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');

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
    { services: [{ audience: AUDIENCE, purposes: ['home.release'] }] },
    { services: [{ audience: AUDIENCE, purposes: ['*'] }] },
    { services: [] },
  ];
  for (const grant of wider) expect(() => narrowedTerms(asked, grant)).toThrow();
  expect(() => narrowedTerms('{"expires":"2026-11-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}]}', { expires: '2026-12-01T00:00:00Z' })).toThrow();
  expect(narrowedTerms('{"services":[{"audience":"urn:x","purposes":["*"]}]}', { services: [{ audience: 'urn:x', purposes: ['a'] }] })).toBe('{"services":[{"audience":"urn:x","purposes":["a"]}]}');
});

test('a rig granted by the operator provisions a fresh account; refused outside its prefix, for another purpose, and once revoked', async () => {
  const tag = crypto.randomUUID().slice(0, 8);
  const relay = await RelayHome.make(host, `https://door.test/v1/accounts/operator-${tag}`);
  const provision = (account: string) => ({ enabled: true, prefix: PREFIX, gate: ['grant'], operator: { account, slot: 'home' }, audience: AUDIENCE });
  const devices: Device[] = [];
  try {
    // The operator account lives on the relay's own slot `home`, which the door names as its operator slot.
    const operator = await Device.make({ homes: [{ endpoint: `${relay.base}/`, transport: relay.transport(),
      request: async account => { await relay.start(account, [], { provision: provision(account) }); return relay.memberRequest(account); } }] });
    devices.push(operator);
    await operator.session.create();
    operator.session.stopSync();
    equal(operator.session.phase.kind, 'ready', operator.describe());
    assert(await settle(operator), () => operator.describe());

    // The rig joins the operator account asking only for the door's service.
    const rig = await Device.make({ medium: authorityOnly(operator.medium as MemoryMedium), namespaces: [], services: [{ audience: AUDIENCE, purposes: [PURPOSE] }],
      homes: [{ endpoint: `${relay.base}/`, transport: relay.transport() }] });
    devices.push(rig);
    await rig.session.restore();
    rig.session.stopSync();
    equal(rig.session.phase.kind, 'waitingForApproval', rig.describe());
    const scanned = await operator.session.scanRequest(await rig.session.exportRequest());
    expect(scanned.request.services).toEqual([{ audience: AUDIENCE, purposes: [PURPOSE] }]);
    expect(scanned.request.namespaces).toEqual([]);
    // A grant wider than the request is refused before anything is signed (another audience's service).
    await expect(operator.session.approve(scanned.request, scanned.pairing, { services: [{ audience: 'https://other.test/v1/provision', purposes: [PURPOSE] }] }))
      .rejects.toMatchObject({ code: 'invalidCommand' });
    const again = await operator.session.scanRequest(await rig.session.exportRequest());
    // The slot condition is written so it holds where there is no slot: conditions bind every call of the member (spec
    // §12.3 step 7), its reads of the operator account's history at the home included, whose args name no slot.
    await operator.session.approve(again.request, again.pairing, { expires: day(Date.now() + 86_400_000), conditions: [SLOT_PREFIX] });
    const granted = operator.session.members.find(m => m.id === rig.session.memberId);
    assert(granted !== undefined && granted.expiresMs !== undefined, 'the grant carries its expiry');
    assert(await settle(operator), () => operator.describe());
    await untilApproved(rig);
    equal(rig.session.phase.kind, 'ready', rig.describe());

    // The signer's own check: a purpose or an audience the rig was not granted is refused here, and nothing is sent.
    const args = { account: 'ab'.repeat(32), base: `${PREFIX}ci-${tag}-x`, slot: `ci-${tag}-x` };
    await expect(rig.session.signCall(AUDIENCE, 'home.release', args)).rejects.toMatchObject({ kind: 'Refused', code: 'refused:outOfScope' });
    await expect(rig.session.signCall('https://other.test/v1/provision', PURPOSE, args)).rejects.toMatchObject({ kind: 'Refused', code: 'refused:outOfScope' });
    const signed = await rig.session.signCall(AUDIENCE, PURPOSE, args);
    assert(/^[A-Za-z0-9_-]+$/.test(signed), 'the call is base64url');

    // A fresh account whose home request is the rig's provisionRequest: provisioned, written, read on a second device.
    const slot = `ci-${tag}`;
    const base = PREFIX + slot;
    const reaching = (request?: HomeConfiguration['request']): HomeConfiguration[] => [{ endpoint: `${base}/`, transport: relay.slotTransport(base, slot), request }];
    const app = await Device.make({ homes: reaching(account => rig.session.provisionRequest(relay.door, AUDIENCE, slot, base, account, { transport: relay.doorTransport() })) });
    devices.push(app);
    await app.session.create();
    app.session.stopSync();
    equal(app.session.phase.kind, 'ready', app.describe());
    equal(app.session.homes.length, 1, 'the provisioned home is appointed');
    await note(app.session, 'a');
    assert(await settle(app), () => app.describe());
    const second = await Device.make({ medium: authorityOnly(app.medium as MemoryMedium), homes: reaching() });
    devices.push(second);
    await second.session.restore();
    second.session.stopSync();
    await approveByScan(second.session, app.session);
    assert(await settle(app), () => app.describe());
    await untilApproved(second);
    assert(await settle(second), () => second.describe());
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
    assert(await settle(operator), () => operator.describe());
    const after = `ci-${tag}-z`;
    const refusal = await rig.session.provisionRequest(relay.door, AUDIENCE, after, PREFIX + after, 'ef'.repeat(32), { transport: relay.doorTransport() })
      .then(() => undefined, (error: unknown) => error);
    assert(refusal instanceof ProvisionRefusal, () => `a refusal from the door: ${String(refusal)}`);
    equal(refusal.status, 403, 'the door refuses a revoked grant');
    equal(refusal.code, 'refused:revoked', 'with the core\'s code');
  } finally {
    for (const d of devices) d.close();
  }
}, 180_000);
