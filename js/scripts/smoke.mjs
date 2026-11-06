import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Library, WebCryptoKeys, init } from '../dist/index.js';

await init();
const owner = await WebCryptoKeys.generate();
const agent = await WebCryptoKeys.generate();
for (const { privateKey } of Object.values(owner.keyPairs())) {
  assert.equal(privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('jwk', privateKey));
}
const root = await Library.create({ owner, label: 'Smoke library', ownerLabel: 'Owner', namespaces: ['reading.saved', 'listening.podcasts', 'notes'] });
assert.equal((await root.write('notes', 'createNotebook', { id: 'inbox', title: 'Inbox' })).ok, true);
const request = await Library.requestAccess({ libraryID: root.id, keys: agent, label: 'Research agent', kind: 'agent', namespaces: ['reading.saved', 'notes'], access: ['read', 'write'] });
assert.match(request.pairingCode, /^\d{6}$/);
// Open before approval, then test synchronous merge plus explicit asynchronous key opening.
const agentLibrary = await Library.open(root.records, agent);
assert.equal(agentLibrary.view('notes').reason, 'notGranted');
await assert.rejects(root.approve(request.record, { unknownRestriction: true }));
const approval = await root.approve(request.record, { namespaces: ['notes'], writeBudget: 1 });
assert.equal(approval.ok, true);
assert.equal(approval.value.kind, 'agent');
assert(root.ledger().some(entry => entry.event === 'requested' && entry.actor === request.id));
agentLibrary.merge(root.records);
await agentLibrary.ready();
assert.equal(agentLibrary.view('reading.saved').reason, 'notGranted');
assert(agentLibrary.tools().some(t => t.name === 'notes__addNote'));
assert(!agentLibrary.tools().some(t => t.name.startsWith('reading.saved__')));
const written = await agentLibrary.call('notes__addNote', { id: 'agent-note', notebook: 'inbox', text: 'An agent contribution', origin: 'person', extension: { retained: true } });
assert.equal(written.ok, true);
assert.equal(written.value.origin, 'ai');
assert.equal((await agentLibrary.write('notes', 'addNote', { id: 'over-budget', notebook: 'inbox', text: 'No' })).reason, 'budgetSpent');
root.merge(agentLibrary.records);
await root.ready();
assert.equal((await root.revoke(request.id)).ok, true);
agentLibrary.merge(root.records);
assert.equal((await agentLibrary.write('notes', 'addNote', { id: 'revoked', notebook: 'inbox', text: 'No' })).reason, 'revoked');
const notes = root.view('notes');
assert.equal(notes.ok, true);
assert.equal(notes.value.state.notes.length, 1);
assert.equal(notes.value.state.notes[0].origin, 'ai');
assert.equal(notes.value.state.notes[0].extensions.extension.retained, true);
assert(notes.value.admitted.some(op => op.id === written.value.id));
assert(root.ledger().some(entry => entry.event === 'revoked'));
assert.equal((await agentLibrary.call('reading.saved__read', {})).reason, 'notGranted');

// Recovery must restore data as well as signing authority through the same host steps.
const recovery = await Library.open(root.records, root.recoveryKeys);
const restoredKeys = await WebCryptoKeys.generate();
assert.equal((await recovery.recover(restoredKeys, 'Recovered owner')).ok, true);
const restored = await Library.open(recovery.records, restoredKeys);
assert.deepEqual(restored.view('notes').value.state, notes.value.state);
assert.equal((await restored.write('reading.saved', 'capture', { id: 'new', url: 'https://example.org/' })).ok, true);

// Replay Rust's fixed vectors through WASM with a host WebCrypto key derived solely for fixtures.
const encoded = JSON.parse(await readFile(new URL('../../conformance/0.2/library.json', import.meta.url), 'utf8'));
const expected = JSON.parse(await readFile(new URL('../../conformance/0.2/expected.json', import.meta.url), 'utf8'));
// Fixture seed 5 is deliberately public. Production callers use WebCryptoKeys.generate().
async function deriveScalar(seed, counter) {
  const material = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveBits']);
  const info = new Uint8Array(8); new DataView(info.buffer).setBigUint64(0, BigInt(counter));
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('colophon/entropy/2'), info }, material, 256));
}
const { createECDH } = await import('node:crypto');
async function fixturePair(counter, algorithm, usages) {
  const scalar = await deriveScalar(new Uint8Array(32).fill(5), counter);
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(scalar);
  const point = ecdh.getPublicKey();
  const jwk = { kty: 'EC', crv: 'P-256', x: point.subarray(1,33).toString('base64url'), y: point.subarray(33).toString('base64url'), d: Buffer.from(scalar).toString('base64url') };
  const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: algorithm, namedCurve: 'P-256' }, false, usages);
  const publicKey = await crypto.subtle.importKey('raw', point, { name: algorithm, namedCurve: 'P-256' }, true, algorithm === 'ECDSA' ? ['verify'] : []);
  return { privateKey, publicKey };
}
const fixtureKeys = await WebCryptoKeys.fromKeyPairs(await fixturePair(0, 'ECDSA', ['sign']), await fixturePair(1, 'ECDH', ['deriveBits']));
const fixture = await Library.open(new Map(Object.entries(encoded).map(([path,b64]) => [path, Uint8Array.from(Buffer.from(b64, 'base64'))])), fixtureKeys);
assert.equal(fixture.id, expected.libraryID);
for (const [namespace, view] of Object.entries(expected.views)) assert.deepEqual(fixture.view(namespace).value, view);
assert.deepEqual(fixture.ledger(), expected.ledger);
// Exercise fractional IDs through the JSON host boundary as well as native Rust.
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
console.log('Node 24 smoke passed: non-extractable keys, narrowed grants, tools, AI attribution, budget, revoke/keep, rekey, recovery, and Rust/WASM fixture parity.');

// The books fixture uses the same deliberately public seed-5 fixture identity.
const booksRecords = JSON.parse(await readFile(new URL('../../conformance/0.2/reading.books/records.json', import.meta.url), 'utf8'));
const booksExpected = JSON.parse(await readFile(new URL('../../conformance/0.2/reading.books/expected.json', import.meta.url), 'utf8'));
const booksFixture = await Library.open(new Map(Object.entries(booksRecords).map(([path, b64]) => [path, Uint8Array.from(Buffer.from(b64, 'base64'))])), fixtureKeys);
for (const { name, args, result } of booksExpected.queries) {
  const actual = await booksFixture.call(`reading.books__${name}`, args);
  assert.equal(actual.ok, true);
  assert.deepEqual(actual.value, result);
}
assert.equal((await booksFixture.call('reading.books__addBook', { id: 'js-book', title: 'JS book', creator: 'Example' })).ok, true);
assert.equal((await booksFixture.call('reading.books__book', { id: 'js-book' })).value.value.book.title, 'JS book');
console.log('Books Rust/WASM query parity and generated tools passed.');
