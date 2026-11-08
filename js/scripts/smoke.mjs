import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { Library, WebCryptoKeys, controllerID, init } from '../dist/index.js';

await init();
const owner = await WebCryptoKeys.generate();
const controller = await WebCryptoKeys.generate();
const kit = await WebCryptoKeys.generate();
const agent = await WebCryptoKeys.generate();
for (const provider of [owner, controller, kit, agent]) {
  for (const { privateKey } of Object.values(provider.keyPairs())) {
    assert.equal(privateKey.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('jwk', privateKey));
  }
}
const library = await Library.createWith({ owner, controller, kit, label: 'Smoke library', ownerLabel: 'Owner', namespaces: ['reading.saved', 'listening.podcasts', 'notes'] });
assert.equal((await library.write('notes', 'createNotebook', { id: 'inbox', title: 'Inbox' })).ok, true);
const request = await Library.requestAccess({ libraryID: library.id, keys: agent, label: 'Research agent', kind: 'agent', namespaces: ['reading.saved', 'notes'], access: ['read', 'write'] });
assert.match(request.pairingCode, /^\d{6}$/);
// Open before approval, then test synchronous merge plus explicit asynchronous key opening.
const agentLibrary = await Library.open(library.records, agent);
assert.equal(agentLibrary.view('notes').reason, 'notGranted');
await assert.rejects(library.approve(request.record, { unknownRestriction: true }));
const approval = await library.approve(request.record, { namespaces: ['notes'], writeBudget: 1 });
assert.equal(approval.ok, true);
assert.equal(approval.value.kind, 'agent');
assert(library.ledger().some(entry => entry.event === 'requested' && entry.actor === request.id));
agentLibrary.merge(library.records);
await agentLibrary.ready();
assert.equal(agentLibrary.view('reading.saved').reason, 'notGranted');
assert(agentLibrary.tools().some(t => t.name === 'notes__addNote'));
assert(!agentLibrary.tools().some(t => t.name.startsWith('reading.saved__')));
const written = await agentLibrary.call('notes__addNote', { id: 'agent-note', notebook: 'inbox', text: 'An agent contribution', origin: 'person', extension: { retained: true } });
assert.equal(written.ok, true);
assert.equal(written.value.origin, 'ai');
assert.equal((await agentLibrary.write('notes', 'addNote', { id: 'over-budget', notebook: 'inbox', text: 'No' })).reason, 'budgetSpent');
library.merge(agentLibrary.records);
await library.ready();
assert.equal((await library.revoke(request.id)).ok, true);
agentLibrary.merge(library.records);
assert.equal((await agentLibrary.write('notes', 'addNote', { id: 'revoked', notebook: 'inbox', text: 'No' })).reason, 'revoked');
const notes = library.view('notes');
assert.equal(notes.ok, true);
assert.equal(notes.value.state.notes.length, 1);
assert.equal(notes.value.state.notes[0].origin, 'ai');
assert.equal(notes.value.state.notes[0].extensions.extension.retained, true);
assert(notes.value.admitted.some(op => op.id === written.value.id));
const cells = await library.call('notes__cells', { notebook: 'inbox', limit: 1 });
assert.equal(cells.ok, true);
assert.equal(cells.value.value.rows[0].id, 'agent-note');
assert.equal(cells.value.value.rows[0].kind, 'markdown');
assert.equal(cells.value.value.total, 1);
const cell = await library.call('notes__cell', { notebook: 'inbox', id: 'agent-note' });
assert.equal(cell.value.value.source, 'An agent contribution');
assert.equal(cell.value.value.cell.origin, 'ai');
assert(library.ledger().some(entry => entry.event === 'revoked'));
assert.equal((await agentLibrary.call('reading.saved__read', {})).reason, 'notGranted');

// A new device has only the kit and records, plus fresh independent member/controller keys.
const restoredKeys = await WebCryptoKeys.generate();
const restoredController = await WebCryptoKeys.generate();
const recovery = await Library.open(library.records, restoredKeys);
assert.equal(recovery.view('notes').reason, 'notGranted');
const beforeRecovery = recovery.keyring();
assert.equal(beforeRecovery.threshold, 1);
assert.equal(beforeRecovery.recoverThreshold, 1);
const kitID = await controllerID(kit.signingPublicKey);
recovery.setControllers([kit]);
await recovery.unlockVault([kit]);
const added = {
  key: {
    form: 'raw',
    signing: Buffer.from(restoredController.signingPublicKey).toString('base64'),
    agreement: Buffer.from(restoredController.agreementPublicKey).toString('base64'),
  },
  label: 'Recovered owner controller',
  roles: ['approve', 'control'], // Both thresholds are 1 in this library.
};
const slot = recovery.buildSealedSlot(added, added.label);
assert.equal((await recovery.recoveryAdd(added, slot, [kitID])).ok, true);
const afterRecovery = recovery.keyring();
assert.equal(afterRecovery.controllers.length, beforeRecovery.controllers.length + 1);
assert.deepEqual(afterRecovery.slots, [...beforeRecovery.slots, slot]);
assert.deepEqual(afterRecovery.controllers.filter(c => c.key.signing !== added.key.signing), beforeRecovery.controllers);
assert.deepEqual(afterRecovery.vault, beforeRecovery.vault);
assert.equal(afterRecovery.threshold, beforeRecovery.threshold);
assert.equal(afterRecovery.recoverThreshold, beforeRecovery.recoverThreshold);
assert.equal(recovery.view('notes').reason, 'notGranted'); // Controllers do not become members.

// Reopen to prove the new controller's published slot opens on its own.
const restored = await Library.open(recovery.records, restoredKeys);
restored.setControllers([restoredController]);
restored.selectController(await controllerID(restoredController.signingPublicKey));
await restored.unlockVault([restoredController]);
const restoredRequest = await Library.requestAccess({
  libraryID: restored.id, keys: restoredKeys, label: 'Recovered owner', kind: 'device',
  namespaces: ['reading.saved', 'listening.podcasts', 'notes'], access: ['read', 'write'],
});
assert.equal((await restored.approve(restoredRequest.record)).ok, true);
assert.deepEqual(restored.view('notes').value.state, notes.value.state);
assert.equal((await restored.write('reading.saved', 'capture', { id: 'new', url: 'https://example.org/' })).ok, true);
assert.equal((await restored.call('reading.saved__capture', { id: 'native', title: 'Native document' })).ok, true);
const savedItem = await restored.call('reading.saved__item', { id: 'native' });
assert.equal(savedItem.value.value.item.title, 'Native document');
assert.equal((await restored.call('reading.saved__setState', { id: 'native', consumption: 'inProgress', expect: savedItem.value.value.heads.state })).ok, true);
const savedPage = await restored.call('reading.saved__items', { limit: 1 });
assert.equal(savedPage.value.value.rows.length, 1);
assert.equal(savedPage.value.value.total, 2);
assert.equal(new Set(restored.tools().map(tool => tool.name)).size, restored.tools().length);
assert.equal((await restored.call('reading.saved__getPosition', { item: 'native' })).value.value, null);


// Replay the published 0.4 records byte-for-byte with its public fixture member keys.
const fixtureURL = new URL('../../conformance/0.4/library/', import.meta.url);
const expected = JSON.parse(await readFile(new URL('input.json', fixtureURL), 'utf8'));
const metadata = JSON.parse(await readFile(new URL('case.json', fixtureURL), 'utf8'));
const published = JSON.parse(await readFile(new URL('../../conformance/0.4/keys/keys.json', import.meta.url), 'utf8'));
const member = published.software.find(key => key.id === expected.memberID);
assert(member, 'Fixture member must have published keys');
async function fixturePair(scalar, encodedPoint, algorithm, usages) {
  const point = Buffer.from(encodedPoint, 'base64');
  const jwk = {
    kty: 'EC', crv: 'P-256', x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33).toString('base64url'), d: Buffer.from(scalar, 'base64').toString('base64url'),
  };
  const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: algorithm, namedCurve: 'P-256' }, false, usages);
  const publicKey = await crypto.subtle.importKey('raw', point, { name: algorithm, namedCurve: 'P-256' }, true, algorithm === 'ECDSA' ? ['verify'] : []);
  return { privateKey, publicKey };
}
const fixtureKeys = await WebCryptoKeys.fromKeyPairs(
  await fixturePair(member.signingScalar, member.public.signing, 'ECDSA', ['sign']),
  await fixturePair(member.agreementScalar, member.public.agreement, 'ECDH', ['deriveBits']),
);
assert.equal(await controllerID(fixtureKeys.signingPublicKey), expected.memberID);
async function readRecords(directory, prefix = '') {
  const records = new Map();
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = `${prefix}${entry.name}`;
    if (entry.isDirectory()) {
      for (const [child, bytes] of await readRecords(new URL(`${entry.name}/`, directory), `${path}/`)) records.set(child, bytes);
    } else records.set(path, new Uint8Array(await readFile(new URL(entry.name, directory))));
  }
  return records;
}
const fixtureRecords = await readRecords(new URL('records/', fixtureURL));
const fixture = await Library.open(fixtureRecords, fixtureKeys);
const genesis = JSON.parse(new TextDecoder().decode(fixtureRecords.get('authority/00000001.json')));
assert.equal(fixture.id, createHash('sha256').update(Buffer.from(genesis.body, 'base64')).digest('hex').slice(0, 32));
for (const [namespace, view] of Object.entries(expected.views)) {
  const actual = fixture.view(namespace);
  assert.equal(actual.ok, true, namespace);
  assert.deepEqual(actual.value, view, namespace);
}
assert.equal(fixture.view('notes').value.admitted[0].payload.optional, null);
const ring = fixture.keyring();
const summary = {
  controllers: await Promise.all(ring.controllers.map(async c => ({
    id: await controllerID(Uint8Array.from(Buffer.from(c.key.signing, 'base64'))), roles: c.roles,
  }))),
  threshold: ring.threshold,
  recoverThreshold: ring.recoverThreshold,
  vaultID: await controllerID(Uint8Array.from(Buffer.from(ring.vault.signing, 'base64'))),
  members: fixture.members().map(({ id, grant }) => ({ id, grant })).sort((a, b) => a.id.localeCompare(b.id)),
};
assert.deepEqual(summary, metadata.keyring);

// The retired authority format must fail at open, never yield a silently empty replica.
const legacy = JSON.parse(await readFile(new URL('../../conformance/0.3/library.json', import.meta.url), 'utf8'));
await assert.rejects(() => Library.open(new Map(Object.entries(legacy).map(([path, b64]) =>
  [path, Uint8Array.from(Buffer.from(b64, 'base64'))])), fixtureKeys));

// Generated bounded domain queries still operate on the verified 0.4 fixture.
const fixtureNotebook = await fixture.call('notes__notebook', { id: 'notebook' });
assert.equal(fixtureNotebook.ok, true);
assert.equal(fixtureNotebook.value.value.title, 'Notebook');
const fixtureSaved = await fixture.call('reading.saved__item', { id: 'saved' });
assert.equal(fixtureSaved.ok, true);
assert.equal(fixtureSaved.value.value.item.title, 'Synthetic document');
const shows = await fixture.call('listening.podcasts__shows', { limit: 1 });
assert.equal(shows.ok, true);
assert.equal(shows.value.value.rows[0].id, 'show');
assert.equal(shows.value.value.total, 1);
const show = await fixture.call('listening.podcasts__show', { id: 'show' });
assert.equal(show.ok, true);
assert.equal(show.value.value.show.title, 'Synthetic show');
const queue = await fixture.call('listening.podcasts__getQueue', { limit: 1 });
assert.equal(queue.ok, true);
assert.equal(queue.value.value.head, null);
assert.deepEqual(queue.value.value.page.rows, []);
assert.equal(queue.value.value.page.total, 0);
const book = await fixture.call('reading.books__book', { id: 'book' });
assert.equal(book.ok, true);
assert.equal(book.value.value.book.title, 'Synthetic book');
assert.equal((await fixture.call('reading.books__addBook', { id: 'js-book', title: 'JS book', creator: 'Example' })).ok, true);
assert.equal((await fixture.call('reading.books__book', { id: 'js-book' })).value.value.book.title, 'JS book');

// Exercise fractional numbers through the JSON host boundary and replay.
for (const [index, seconds] of [6.713554789312184e-10, 123456789.12345679].entries()) {
  const result = await restored.write('listening.podcasts', 'position', { id: `fraction-${index}`, seconds });
  assert.equal(result.ok, true);
  assert.equal(result.value.payload.seconds, seconds);
  const replayed = await Library.open(restored.records, restoredKeys);
  const operation = replayed.view('listening.podcasts').value.admitted.find(op => op.id === result.value.id);
  assert.equal(operation.payload.seconds, seconds);
  const entry = replayed.ledger().find(entry => entry.subject === result.value.id);
  assert.equal(entry.namespace, 'listening.podcasts');
  assert.equal(entry.kind, 'position');
  assert.equal(entry.origin, 'person');
}
console.log('Node 24 smoke passed: non-extractable keys, narrowed grants, tools, AI attribution, budget, revoke/keep, kit recovery, domain queries, fractional round trips, 0.4 fixture parity and 0.3 refusal.');
