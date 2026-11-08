import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import init, { WasmLibrary } from '../dist/wasm/colophon_wasm.js';
const fixture = JSON.parse(await readFile(new URL('../../crates/colophon-ffi/tests/keys-flow.json', import.meta.url)));
await init({ module_or_path: await readFile(new URL('../dist/wasm/colophon_wasm_bg.wasm', import.meta.url)) });
const u8 = value => new Uint8Array(value);
const repeated = value => new Uint8Array(32).fill(value);
const keyID = controller => createHash('sha256').update(Buffer.from(controller.key.signing, 'base64')).digest('hex').slice(0,32);
const keys = name => [u8(Buffer.from(fixture[name].signing, 'base64')), u8(Buffer.from(fixture[name].agreement, 'base64'))];
let cursor = 0;
function stage(name) { const value = fixture.stages[cursor++]; assert.equal(value.name, name); return value; }
function sign(action, name) {
  const expected = stage(name).signing;
  assert.equal(action.count(), expected.length);
  for (let i=0; i<expected.length; i++) {
    const result = expected[i];
    assert.deepEqual(action.body(i), u8(result.body));
    if (result.assertion) action.assert(i,u8(result.signature),u8(result.assertion.authenticatorData),u8(result.assertion.clientData));
    else action.sign(i,u8(result.signature));
  }
  return action;
}
const core = new WasmLibrary(...keys('member'));
const first = core.begin_create('Keys','Device',JSON.stringify(['notes']),...keys('owner'),repeated(21),fixture.now,repeated(22));
const final = sign(first,'create').advance_create();
core.commit(sign(final,'createFinal'));
const ownerID = JSON.parse(core.keyring()).slots[0].controllers[0];
function unlock(session, name, id) {
  const option = JSON.parse(session.begin_unlock_slots()).find(o => o.inputs.every(i=> i.kind==='ecdh' && i.controller===id));
  assert(option);
  session.finish_unlock_slot(option.index, JSON.stringify(fixture.openings[name].map(bytes=>({kind:'ecdh',bytes}))));
}
function reopen(session) {
  const result = new WasmLibrary(...keys('member'));
  for (let i=0; i<session.record_count(); i++) result.import_record(session.record_path(i),session.record(i));
  result.merge(); return result;
}
unlock(core,'owner',ownerID);
assert.deepEqual(JSON.parse(WasmLibrary.parse_registration(u8(fixture.registration),'id.luff.works')), fixture.passkey.key);
assert.throws(()=>WasmLibrary.parse_registration(u8(fixture.registration),'foreign.example'));
function prf(newSeed, byte) {
  const action = core.begin_prf_slot(JSON.stringify(fixture.passkey.key),repeated(byte));
  const result = stage('prf');
  assert.equal(action.challenge(),result.challenge); assert.deepEqual(action.salt(),u8(result.salt));
  return core.finish_prf_slot(action,u8(result.signature),u8(result.authenticatorData),u8(result.clientData),u8(result.output),'Passkey',newSeed,repeated(byte+1));
}
const passkeySlot=prf(new Uint8Array(),31);
core.commit(sign(core.begin_add_passkey(JSON.stringify(fixture.passkey),passkeySlot,JSON.stringify([ownerID]),fixture.now),'addPasskey'));
const opened=reopen(core);
const option=JSON.parse(opened.begin_unlock_slots()).find(o=>o.inputs.some(i=>i.kind==='prf'));
assert.throws(()=>opened.finish_unlock_slot(option.index,JSON.stringify([{kind:'prf',bytes:Array(32).fill(0)}])));
opened.finish_unlock_slot(option.index,JSON.stringify([{kind:'prf',bytes:Array(32).fill(71)}]));
const recoverySlot=core.build_sealed_slot(JSON.stringify(fixture.recovery),'Recovery',new Uint8Array(),repeated(33));
const ring=JSON.parse(core.keyring());
ring.controllers.push(fixture.recovery); ring.controllers.sort((a,b)=>keyID(a).localeCompare(keyID(b)));
ring.recoverThreshold=1; ring.slots.push(JSON.parse(recoverySlot));
core.commit(sign(core.begin_keyring(JSON.stringify(ring),new Uint8Array(),JSON.stringify([ownerID]),fixture.now,repeated(34)),'enableRecovery'));
const rotated=prf(repeated(41),35);
const recoveryRotated=core.build_sealed_slot(JSON.stringify(fixture.recovery),'Recovery',repeated(41),repeated(37));
core.commit(sign(core.begin_remove_controller(ownerID,repeated(41),JSON.stringify([JSON.parse(rotated),JSON.parse(recoveryRotated)]),JSON.stringify([ownerID]),fixture.now,repeated(38)),'removeDevice'));
const recovering=reopen(core), recoveryID=keyID(fixture.recovery);
unlock(recovering,'recovery',recoveryID);
const addedSlot=recovering.build_sealed_slot(JSON.stringify(fixture.added),'Replacement',new Uint8Array(),repeated(39));
recovering.commit(sign(recovering.begin_recovery_add(JSON.stringify(fixture.added),addedSlot,JSON.stringify([recoveryID]),fixture.now),'recoveryAdd'));
const passkeyID=keyID(fixture.passkey);
recovering.commit(sign(recovering.prepare_authority(JSON.stringify({kind:'layout',layout:2}),passkeyID,JSON.stringify([passkeyID]),fixture.now),'passkeyLayout'));
const records={}; for(let i=0;i<recovering.record_count();i++) records[recovering.record_path(i)]=Array.from(recovering.record(i));
assert.deepEqual(records,fixture.records);
assert.equal(cursor,fixture.stages.length);
unlock(reopen(recovering),'added',keyID(fixture.added));
console.log('W5 WASM keyring flow passed (exact native records)');
