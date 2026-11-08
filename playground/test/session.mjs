import assert from 'node:assert/strict';
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

test('knock → grant → act → end → restore uses separate principals after reopening', async () => {
  const keys = await device();
  const kit = await WebCryptoKeys.generate();
  let session = await DeviceSession.create({ ...keys, recoveryKit: kit, label: 'Playground', memberLabel: 'Ada', namespaces: ['listening.podcasts', 'notes', 'reading.saved'] });
  const initial = bodies(session.library);
  assert.deepEqual(initial.map(body => body.kind), ['genesis', 'rekey', 'grant', 'layout']);
  assert.equal(initial[3].layout, 2);
  const ring = session.library.keyring();
  assert.equal(ring.threshold, 1);
  assert.equal(ring.recoverThreshold, 1);
  assert.equal(ring.controllers.length, 2);
  const ownerID = await controllerID(keys.owner.signingPublicKey);
  const kitID = await controllerID(kit.signingPublicKey);
  assert.deepEqual(ring.controllers.find(c => c.key.signing === Buffer.from(keys.owner.signingPublicKey).toString('base64')).roles, ['approve', 'control']);
  assert.deepEqual(ring.controllers.find(c => c.key.signing === Buffer.from(kit.signingPublicKey).toString('base64')).roles, ['recover']);
  assert.deepEqual(ring.slots.map(slot => slot.controllers[0]).sort(), [ownerID, kitID].sort());
  assert(ring.slots.every(slot => slot.kind === 'sealed'));
  assert.deepEqual(initial[0].keyring, ring);
  assert(initial.every(body => body.by === ownerID));
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
  const events = [];
  await runActTurn(agent, { model: 'scripted' }, 'What did the foghorn ledger keep in its margins?', event => { events.push(event); });
  session.library.merge(agent.records);
  await session.library.ready();
  const notes = success(session.library.view('notes'));
  assert.equal(notes.state.notes.length, 3, JSON.stringify(events));
  assert(notes.state.notes.every(note => note.origin === 'ai'));

  session = await DeviceSession.open(session.library.records, keys);
  success(await session.revoke(request.id));
  agent.merge(session.library.records);
  assert.equal((await agent.call('notes__read', {})).reason, 'revoked');
  assert.deepEqual(success(session.library.view('notes')).state, notes.state);
  const storedKit = structuredClone(kit.keyPairs());
  const restoredKit = await WebCryptoKeys.fromKeyPairs(storedKit.signing, storedKit.agreement);
  const restored = await DeviceSession.restore({ ...await device(), records: session.library.records, recoveryKit: restoredKit, memberLabel: 'New device' });
  for (const namespace of ['listening.podcasts', 'notes', 'reading.saved']) {
    assert.deepEqual(success(restored.library.view(namespace)), success(session.library.view(namespace)));
  }
  agent.merge(restored.library.records);
  assert.equal((await agent.call('notes__read', {})).reason, 'revoked');
});

test('a kit alone restores a fresh controller and member without replacing the old keyring', async () => {
  const kit = await WebCryptoKeys.generate();
  const original = await DeviceSession.create({ ...await device(), recoveryKit: kit, label: 'Recovery', memberLabel: 'Ada', namespaces: ['notes'] });
  const existing = original.library;
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
  const kit = await WebCryptoKeys.generate();
  const session = await DeviceSession.create({ ...keys, recoveryKit: kit, label: 'Threshold', memberLabel: 'Ada', namespaces: ['notes'] });
  const ring = session.library.keyring();
  const other = await WebCryptoKeys.generate();
  const controller = { key: { form: 'raw', signing: Buffer.from(other.signingPublicKey).toString('base64'), agreement: Buffer.from(other.agreementPublicKey).toString('base64') }, label: 'Second control key', roles: ['control'] };
  ring.controllers.push(controller);
  ring.slots.push(session.library.buildSealedSlot(controller, controller.label));
  // Controller ordering is by key ID, not by public point.
  const ids = new Map(await Promise.all(ring.controllers.map(async c => [c.key.signing, await controllerID(Buffer.from(c.key.signing, 'base64'))])));
  ring.controllers.sort((a, b) => ids.get(a.key.signing).localeCompare(ids.get(b.key.signing)));
  ring.threshold = 2;
  ring.recoverThreshold = 1;
  // Raise the control threshold to exercise recovery’s approve-only limit.
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

test('genesis kit supplies only public keys and all creation signatures come from owner/member', async () => {
  const keys = await device();
  const kit = await WebCryptoKeys.generate();
  const publicKit = {
    form: 'raw',
    signingPublicKey: kit.signingPublicKey,
    agreementPublicKey: kit.agreementPublicKey,
    sign() { throw new Error('Kit must not sign creation'); },
    agree() { throw new Error('Kit must not open during creation'); },
  };
  const session = await DeviceSession.create({ ...keys, recoveryKit: publicKit, recoveryLabel: 'Offline kit', importedFrom: '0123456789abcdef0123456789abcdef', label: 'Kit', memberLabel: 'Ada', namespaces: ['notes'] });
  const entries = bodies(session.library);
  assert.deepEqual(entries.map(body => body.kind), ['genesis', 'rekey', 'grant', 'layout']);
  assert.equal(entries[0].importedFrom, '0123456789abcdef0123456789abcdef');
  const kitID = await controllerID(kit.signingPublicKey);
  assert.equal(entries[0].keyring.slots.find(slot => slot.controllers[0] === kitID).label, 'Offline kit');
  const opened = await Library.open(session.library.records, await WebCryptoKeys.generate());
  await opened.unlockVault([kit]);
});

test('owner-only genesis remains available when no kit is supplied', async () => {
  const session = await DeviceSession.create({ ...await device(), label: 'No kit', memberLabel: 'Ada', namespaces: ['notes'] });
  assert.equal(session.library.keyring().recoverThreshold, 0);
  assert.equal(session.library.keyring().controllers.length, 1);
  assert.equal(session.library.keyring().slots.length, 1);
});
