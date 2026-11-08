import assert from 'node:assert/strict';
import { createECDH } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';
import test from 'node:test';

// The browser uses bundler resolution; Node's built-in TS loader needs the suffix.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === './core' && context.parentURL === new URL('../src/session.ts', import.meta.url).href) {
      return nextResolve(new URL('../src/core.ts', import.meta.url).href, context);
    }
    return nextResolve(specifier, context);
  },
});

const { Library, WebCryptoKeys, controllerID } = await import('@colophon/core');
const { DeviceSession } = await import('../src/session.ts');
const { seedLibrary } = await import('../src/seed.ts');
const { runActTurn } = await import('../src/agent.ts');

const device = async () => ({ owner: await WebCryptoKeys.generate(), member: await WebCryptoKeys.generate() });
const decode = raw => JSON.parse(Buffer.from(JSON.parse(new TextDecoder().decode(raw)).body, 'base64'));
const bodies = library => [...library.records].filter(([path]) => /^authority\/\d+\.json$/.test(path)).sort(([a], [b]) => a.localeCompare(b)).map(([, raw]) => decode(raw));
const success = outcome => { assert.equal(outcome.ok, true, outcome.detail); return outcome.value; };

test('knock → grant → act → end uses separate principals and survives reopening', async () => {
  const keys = await device();
  let session = await DeviceSession.create({ ...keys, label: 'Playground', memberLabel: 'Ada', namespaces: ['listening.podcasts', 'notes', 'reading.saved'] });
  const initial = bodies(session.library);
  assert.deepEqual(initial.map(body => body.kind), ['genesis', 'rekey', 'grant', 'layout']);
  assert.equal(initial[3].layout, 2);
  const ring = session.library.keyring();
  assert.equal(ring.threshold, 1);
  assert.equal(ring.recoverThreshold, 0);
  assert.deepEqual(ring.controllers[0].roles, ['approve', 'control']);
  assert.notEqual(await controllerID(keys.owner.signingPublicKey), session.library.me().id);
  assert.equal(new Set([keys.owner.signingPublicKey, keys.owner.agreementPublicKey, keys.member.signingPublicKey, keys.member.agreementPublicKey].map(key => Buffer.from(key).toString('hex'))).size, 4);
  await seedLibrary(session.library);

  const agentKeys = await WebCryptoKeys.generate();
  const request = await Library.requestAccess({ libraryID: session.library.id, keys: agentKeys, label: 'Muse', kind: 'agent', namespaces: ['listening.podcasts', 'notes'], access: ['read', 'write'] });
  const agent = await Library.open(session.library.records, agentKeys);
  assert.equal(agent.view('notes').reason, 'notGranted');
  // Reopening loses the unlocked vault. Session approval must open its owner slot.
  session = await DeviceSession.open(session.library.records, keys);
  success(await session.approve(request.record, { writeBudget: 5 }));
  agent.merge(session.library.records);
  await agent.ready();
  assert.equal((await agent.call('reading.saved__read', {})).reason, 'notGranted');
  await runActTurn(agent, { model: 'scripted' }, 'What did the foghorn ledger keep in its margins?', () => {});
  session.library.merge(agent.records);
  await session.library.ready();
  const notes = success(session.library.view('notes'));
  assert.equal(notes.state.notes.length, 3);
  assert(notes.state.notes.every(note => note.origin === 'ai'));

  session = await DeviceSession.open(session.library.records, keys);
  success(await session.revoke(request.id));
  agent.merge(session.library.records);
  assert.equal((await agent.call('notes__read', {})).reason, 'revoked');
  assert.deepEqual(success(session.library.view('notes')).state, notes.state);
});

// These deliberately public fixture seeds belong to the landed W5 binding flow.
async function fixtureKeys(seedByte) {
  async function pair(counter, algorithm, usages) {
    const material = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(seedByte), 'HKDF', false, ['deriveBits']);
    const info = new Uint8Array(8);
    new DataView(info.buffer).setBigUint64(0, BigInt(counter));
    const scalar = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('colophon/entropy/3'), info }, material, 256));
    const ecdh = createECDH('prime256v1');
    ecdh.setPrivateKey(scalar);
    const point = ecdh.getPublicKey();
    const jwk = { kty: 'EC', crv: 'P-256', x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url'), d: Buffer.from(scalar).toString('base64url') };
    return {
      privateKey: await crypto.subtle.importKey('jwk', jwk, { name: algorithm, namedCurve: 'P-256' }, false, usages),
      publicKey: await crypto.subtle.importKey('raw', point, { name: algorithm, namedCurve: 'P-256' }, true, algorithm === 'ECDSA' ? ['verify'] : []),
    };
  }
  return WebCryptoKeys.fromKeyPairs(await pair(0, 'ECDSA', ['sign']), await pair(1, 'ECDH', ['deriveBits']));
}

test('a kit alone restores a fresh controller and member without replacing the old keyring', async () => {
  const fixture = JSON.parse(await readFile(new URL('../../crates/colophon-ffi/tests/keys-flow.json', import.meta.url)));
  const oldMember = await fixtureKeys(12);
  const kit = await fixtureKeys(13);
  const existing = await Library.open(new Map(Object.entries(fixture.records).map(([path, raw]) => [path, new Uint8Array(raw)])), oldMember);
  success(await existing.write('notes', 'createNotebook', { id: 'inbox', title: 'Inbox' }));
  success(await existing.write('notes', 'addNote', { id: 'history', notebook: 'inbox', text: 'Before restoration' }));
  const prior = existing.keyring();
  const view = success(existing.view('notes'));
  const keys = await device();
  const restored = await DeviceSession.restore({ ...keys, records: existing.records, recoveryKit: kit, memberLabel: 'New device' });
  assert.deepEqual(success(restored.library.view('notes')), view);
  for (const controller of prior.controllers) assert(restored.library.keyring().controllers.some(current => JSON.stringify(current) === JSON.stringify(controller)));
  for (const slot of prior.slots) assert(restored.library.keyring().slots.some(current => JSON.stringify(current) === JSON.stringify(slot)));
  assert.deepEqual(restored.library.keyring().vault, prior.vault);
  const added = bodies(restored.library).slice(-2);
  assert.equal(added[0].kind, 'keyring');
  assert.equal(added[0].by, await controllerID(kit.signingPublicKey));
  assert.equal(added[1].kind, 'grant');
  assert.equal(added[1].by, await controllerID(keys.owner.signingPublicKey));
  assert.notEqual(restored.library.me().id, await controllerID(keys.owner.signingPublicKey));
  success(await restored.library.write('notes', 'addNote', { id: 'after', notebook: 'inbox', text: 'After restoration' }));
});

test('recovery below the control threshold adds only approve authority', async () => {
  const keys = await device();
  const session = await DeviceSession.create({ ...keys, label: 'Threshold', memberLabel: 'Ada', namespaces: ['notes'] });
  const ring = session.library.keyring();
  const other = await WebCryptoKeys.generate();
  const kit = await WebCryptoKeys.generate();
  for (const [provider, roles] of [[other, ['control']], [kit, ['recover']]]) {
    const controller = { key: { form: 'raw', signing: Buffer.from(provider.signingPublicKey).toString('base64'), agreement: Buffer.from(provider.agreementPublicKey).toString('base64') }, label: 'Fixture controller', roles };
    ring.controllers.push(controller);
    ring.slots.push(session.library.buildSealedSlot(controller, controller.label));
  }
  // Controller ordering is by key ID, not by public point.
  const ids = new Map(await Promise.all(ring.controllers.map(async c => [c.key.signing, await controllerID(Buffer.from(c.key.signing, 'base64'))])));
  ring.controllers.sort((a, b) => ids.get(a.key.signing).localeCompare(ids.get(b.key.signing)));
  ring.threshold = 2;
  ring.recoverThreshold = 1;
  // Fixture setup uses an ordinary control-rule keyring change, never application creation.
  success(await session.library.replaceKeyring(ring, undefined, [await controllerID(keys.owner.signingPublicKey)]));
  const fresh = await device();
  const restored = await DeviceSession.restore({ ...fresh, records: session.library.records, recoveryKit: kit, memberLabel: 'Replacement' });
  const addedID = await controllerID(fresh.owner.signingPublicKey);
  const added = restored.library.keyring().controllers.find(controller => !ids.has(controller.key.signing));
  assert(added);
  assert.equal(await controllerID(Buffer.from(added.key.signing, 'base64')), addedID);
  assert.deepEqual(added.roles, ['approve']);
  assert.equal(restored.library.me().grant.access.includes('write'), true);
});

test('creation with a supplied kit stops explicitly at the missing genesis API', async () => {
  await assert.rejects(DeviceSession.create({ ...await device(), recoveryKit: await WebCryptoKeys.generate(), label: 'Kit', memberLabel: 'Ada', namespaces: ['notes'] }), /cannot include a recovery-kit controller and slot in genesis/);
});
