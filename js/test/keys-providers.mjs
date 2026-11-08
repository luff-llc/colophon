import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { Library, PasskeyProvider, WebCryptoKeys, WebCryptoOwnerKey, IndexedDBOwnerKeyStorage, keyProviderError, controllerID } from '../dist/index.js';
import { WasmLibrary } from '../dist/wasm/colophon_wasm.js';
Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
const f = JSON.parse(await readFile(new URL('../../crates/colophon-ffi/tests/keys-flow.json', import.meta.url)));
const u8 = value => new Uint8Array(value), repeated = value => new Uint8Array(32).fill(value);
const b64 = value => u8(Buffer.from(value, 'base64')), buf = value => u8(value).buffer;
const prf = f.stages.find(s => s.name === 'prf');
const credential = (response, extensions = {}) => ({ type: 'public-key', rawId: b64(f.passkey.key.credential).buffer, response, getClientExtensionResults: () => extensions });
function fakeCredentials() {
  return {
    requests: [], missingPRF: false, wrongCredential: false,
    async create(options) {
      this.requests.push(options);
      if (this.error) throw this.error;
      assert.equal(options.publicKey.pubKeyCredParams[0].alg, -7);
      assert.equal(options.publicKey.authenticatorSelection.userVerification, 'required');
      assert.deepEqual(options.publicKey.extensions, { prf: {} });
      return credential({ attestationObject: buf(f.registration) }, { prf: { results: { first: repeated(99).buffer } } });
    },
    async get(options) {
      this.requests.push(options);
      if (this.error) throw this.error;
      assert.equal(options.publicKey.rpId, f.passkey.key.rp);
      assert.equal(options.publicKey.userVerification, 'required');
      assert.equal(options.publicKey.allowCredentials.length, 1);
      assert.deepEqual(options.publicKey.allowCredentials[0].id, b64(f.passkey.key.credential));
      const result = credential({ signature: buf(prf.signature), authenticatorData: buf(prf.authenticatorData), clientDataJSON: buf(prf.clientData) },
        this.missingPRF ? {} : { prf: { results: { first: buf(prf.output) } } });
      if (this.wrongCredential) result.rawId = new Uint8Array([2]).buffer;
      return result;
    },
  };
}
function keys(name) { return [b64(f[name].signing), b64(f[name].agreement)]; }
function sign(action, name) {
  const stage = f.stages.find(s => s.name === name);
  for (let i = 0; i < action.count(); i++) { assert.deepEqual(action.body(i), u8(stage.signing[i].body)); action.sign(i, u8(stage.signing[i].signature)); }
  return action;
}

test('navigator register -> core-verified get with PRF -> publish and open slot (W5 fixture)', async () => {
  const fake = fakeCredentials();
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: fake } });
  const provider = await PasskeyProvider.register({ rp: { id: f.passkey.key.rp, name: 'Colophon' }, user: { id: new Uint8Array([1]), name: 'u', displayName: 'U' } });
  assert.deepEqual(provider.descriptor(), f.passkey.key);
  assert.equal(fake.requests.length, 1);
  const core = new WasmLibrary(...keys('member'));
  try {
    const first = core.begin_create('Keys', 'Device', JSON.stringify(['notes']), ...keys('owner'), repeated(21), f.now, repeated(22));
    core.commit(sign(sign(first, 'create').advance_create(), 'createFinal'));
    const ownerSlot = JSON.parse(core.begin_unlock_slots())[0];
    core.finish_unlock_slot(ownerSlot.index, JSON.stringify(f.openings.owner.map(bytes => ({ kind: 'ecdh', bytes }))));
    const action = core.begin_prf_slot(JSON.stringify(provider.descriptor()), repeated(31));
    const result = await provider.assert(action.challenge(), action.salt());
    assert.deepEqual(fake.requests.at(-1).publicKey.challenge, b64(prf.challenge.replace(/-/g, '+').replace(/_/g, '/')));
    assert.deepEqual(fake.requests.at(-1).publicKey.extensions.prf.eval.first, u8(prf.salt));
    assert.deepEqual(result.clientData, u8(prf.clientData)); assert.deepEqual(result.prf, u8(prf.output));
    const slot = core.finish_prf_slot(action, result.signature, result.authenticatorData, result.clientData, result.prf, 'Passkey', new Uint8Array(), repeated(32));
    const ownerID = JSON.parse(core.keyring()).slots[0].controllers[0];
    core.commit(sign(core.begin_add_passkey(JSON.stringify(f.passkey), slot, JSON.stringify([ownerID]), f.now), 'addPasskey'));
    const opened = new WasmLibrary(...keys('member'));
    try {
      for (let i = 0; i < core.record_count(); i++) opened.import_record(core.record_path(i), core.record(i));
      opened.merge();
      const option = JSON.parse(opened.begin_unlock_slots()).find(o => o.inputs.some(i => i.kind === 'prf'));
      const output = await provider.prf(u8(option.inputs[0].salt));
      assert.throws(() => opened.finish_unlock_slot(option.index, JSON.stringify([{ kind: 'prf', bytes: Array(32).fill(0) }])));
      opened.finish_unlock_slot(option.index, JSON.stringify([{ kind: 'prf', bytes: Array.from(output) }]));
    } finally { opened.free(); }
  } finally { core.free(); }
});

test('missing PRF and foreign credential fail explicitly; sign-only get needs no PRF', async () => {
  const fake = fakeCredentials(), provider = new PasskeyProvider(f.passkey.key, fake);
  fake.missingPRF = true;
  await assert.rejects(provider.assert(prf.challenge, u8(prf.salt)), e => e.outcome === 'unsupportedHere');
  assert.equal((await provider.assert(prf.challenge)).prf, undefined);
  assert.equal(fake.requests.at(-1).publicKey.extensions, undefined);
  fake.wrongCredential = true;
  await assert.rejects(provider.assert(prf.challenge), e => e.outcome === 'credentialMissing');
  for (const [name, outcome] of [['AbortError', 'cancelled'], ['NotAllowedError', 'presenceFailed'], ['NotFoundError', 'credentialMissing'], ['NotSupportedError', 'unsupportedHere'], ['UnknownError', 'hardwareUnavailable']]) {
    fake.error = new DOMException('platform failure', name);
    await assert.rejects(provider.assert(prf.challenge), e => e.outcome === outcome);
    assert.equal(keyProviderError(fake.error).outcome, outcome);
  }
});

test('registration uses the core parser and checks rawId', async () => {
  const fake = fakeCredentials();
  const options = { rp: { id: 'foreign.example', name: 'Foreign' }, user: { id: new Uint8Array([1]), name: 'u', displayName: 'U' } };
  await assert.rejects(PasskeyProvider.register(options, fake));
  fake.create = async () => ({ ...credential({ attestationObject: buf(f.registration) }), rawId: new Uint8Array([2]).buffer });
  await assert.rejects(PasskeyProvider.register({ ...options, rp: { ...options.rp, id: f.passkey.key.rp } }, fake), e => e.outcome === 'credentialMissing');
});

test('null browser results, malformed PRF length and extractable owner storage fail explicitly', async () => {
  const options = { rp: { id: f.passkey.key.rp, name: 'Colophon' }, user: { id: new Uint8Array([1]), name: 'u', displayName: 'U' } };
  const empty = { create: async () => null, get: async () => null };
  await assert.rejects(PasskeyProvider.register(options, empty), e => e.outcome === 'cancelled');
  await assert.rejects(new PasskeyProvider(f.passkey.key, empty).assert(prf.challenge), e => e.outcome === 'credentialMissing');
  const wrongLength = { get: async () => credential({ signature: buf(prf.signature), authenticatorData: buf(prf.authenticatorData), clientDataJSON: buf(prf.clientData) },
    { prf: { results: { first: new Uint8Array(31).buffer } } }) };
  await assert.rejects(new PasskeyProvider(f.passkey.key, wrongLength).assert(prf.challenge, repeated(1)), e => e.outcome === 'unsupportedHere');
  const signing = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const agreement = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  await assert.rejects(WebCryptoOwnerKey.openOrCreate('bad', { read: async () => ({ signing, agreement }) }), e => e.outcome === 'hardwareUnavailable');
});

// Event-driven IndexedDB fake tests the real adapter's commit, abort, duplicate insert,
// and CryptoKey structured clone paths without an additional dependency.
function fakeIndexedDB() {
  const databases = new Map(), state = { closes: 0, fail: false };
  state.open = name => {
    const request = {};
    setImmediate(() => {
      const fresh = !databases.has(name);
      if (fresh) databases.set(name, new Map());
      const records = databases.get(name);
      request.result = { createObjectStore() {}, close() { state.closes++; }, transaction() {
        const tx = { objectStore: () => ({ get: key => execute(() => structuredClone(records.get(key))), add: (value, key) => execute(() => {
          if (records.has(key)) throw new DOMException('duplicate', 'ConstraintError');
          records.set(key, structuredClone(value)); return key;
        }) }) };
        function execute(work) {
          const op = {};
          setImmediate(() => {
            try { if (state.fail) throw new DOMException('unavailable', 'UnknownError'); op.result = work(); tx.oncomplete?.(); }
            catch (error) { op.error = error; tx.error = error; tx.onabort?.(); }
          });
          return op;
        }
        return tx;
      } };
      if (fresh) request.onupgradeneeded?.(); request.onsuccess?.();
    });
    return request;
  };
  return state;
}

test('IndexedDB persists separate non-extractable owners, including concurrent first opens', async () => {
  const idb = fakeIndexedDB(), storage = new IndexedDBOwnerKeyStorage('test', idb);
  const [owner, other] = await Promise.all([WebCryptoOwnerKey.openOrCreate('owner', storage), WebCryptoOwnerKey.openOrCreate('owner', storage)]);
  assert.deepEqual(owner.signingPublicKey, other.signingPublicKey);
  assert.notDeepEqual(owner.signingPublicKey, owner.agreementPublicKey);
  assert.equal(owner.custody, 'software/browser');
  const stored = await storage.read('owner');
  for (const pair of [stored.signing, stored.agreement]) { assert.equal(pair.privateKey.extractable, false); await assert.rejects(crypto.subtle.exportKey('pkcs8', pair.privateKey)); }
  const body = new TextEncoder().encode('body');
  assert(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, stored.signing.publicKey, await owner.sign(body), body));
  const peer = await WebCryptoKeys.generate();
  assert.deepEqual(await owner.agree(peer.agreementPublicKey), await peer.agree(owner.agreementPublicKey));
  idb.fail = true;
  await assert.rejects(WebCryptoOwnerKey.openOrCreate('owner', storage), e => e.outcome === 'hardwareUnavailable');
  assert(idb.closes > 0);
  await assert.rejects(WebCryptoOwnerKey.openOrCreate('no-idb', new IndexedDBOwnerKeyStorage('none')), e => e.outcome === 'unsupportedHere');
});

test('createWith signs importedFrom and includes a recovery kit slot', async () => {
  const owner = await WebCryptoKeys.generate(), member = await WebCryptoKeys.generate(), kit = await WebCryptoKeys.generate();
  const importedFrom = '0123456789abcdef0123456789abcdef';
  const lib = await Library.createWith({ owner: member, controller: owner, kit, recoveryLabel: 'Kit', importedFrom, label: 'Copied', ownerLabel: 'Owner', namespaces: ['notes'] });
  const ring = lib.keyring();
  assert.equal(ring.controllers.length, 2); assert.equal(ring.recoverThreshold, 1); assert.equal(ring.slots.length, 2);
  const kitID = await controllerID(kit.signingPublicKey);
  assert(ring.slots.some(slot => slot.controllers[0] === kitID && slot.label === 'Kit'));
  const genesis = JSON.parse(Buffer.from(JSON.parse(new TextDecoder().decode(lib.records.get('authority/00000001.json'))).body, 'base64').toString());
  assert.equal(genesis.importedFrom, importedFrom);
  const reopened = await Library.open(lib.records, member); await reopened.unlockVault([kit]);
});
