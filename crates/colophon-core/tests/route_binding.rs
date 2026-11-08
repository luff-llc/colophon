//! Checked vault routes bind every participant's descriptor (independent review, 858a0a3).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]
mod support;
use colophon_core::{authority::{Action,Controller,Role}, crypto::Entropy, keys::{testing::SyntheticAuthenticator,KeyDescriptor}, library::{CombinedPart,SignatureResult}, slots::{self,OpeningInput,OpeningSecret,Slot}, vault};
use serde_json::json;
use sha2::{Digest,Sha256};
const RP: &str="id.luff.works";
fn ceremony(lib: &colophon_core::library::Library, key: KeyDescriptor) -> (colophon_core::library::PrfPreparation, SignatureResult) {
 let p=lib.begin_prf_slot(key,[151;32]).unwrap();
 let mut ad=Sha256::digest(RP.as_bytes()).to_vec(); ad.extend([5,0,0,0,0]);
 let cd=serde_json::to_vec(&json!({"type":"webauthn.get","challenge":p.challenge,"origin":"https://id.luff.works"})).unwrap();
 let a=SyntheticAuthenticator::new().unwrap().sign_bytes(ad,cd,false).unwrap();
 (p,SignatureResult{signature:a.signature,assertion:Some(a.assertion)})
}
fn controller()->Controller {Controller{key:SyntheticAuthenticator::new().unwrap().descriptor(RP,None).unwrap(), label:"Passkey".into(), roles:vec![Role::Approve],verification:None}}
fn substitute(c:&Controller, field:&str)->Controller {let mut c=c.clone(); if let KeyDescriptor::WebAuthn{credential,rp,origins,..}=&mut c.key {match field {"credential"=>*credential=vec![0xee;16],"rp"=>*rp="other.example".into(),"origins"=>*origins=Some(vec!["android:apk-key-hash:other".into()]),_=>panic!()}} c}
fn build(lib:&mut colophon_core::library::Library,c:&Controller,combined:bool,rotate:bool)->Slot {
 let (p,a)=ceremony(lib,c.key.clone());
 if combined {
  let proof=lib.finish_prf_part(p,a,&[41;32]).unwrap();
  let raw=lib.authority().keyring.controller(&support::keys(201).public().id()).unwrap().clone();
  let p=lib.begin_combined_slot(vec![CombinedPart::Sealed{controller:raw},CombinedPart::Prf{controller:c.clone(),verified:proof}],"Combined",rotate.then_some([203;32]),[152;32]).unwrap();
  let enc=match p.begin_open().unwrap()[0] {OpeningInput::Ecdh{enc,..}=>enc,_=>panic!()};
  let dh=support::keys(201).agree(enc).unwrap();
  lib.finish_combined_slot(p,&[OpeningSecret::Ecdh(&dh),OpeningSecret::Prf(&[41;32])]).unwrap()
 } else if rotate {lib.finish_prf_slot_for(p,a,&[41;32],"Passkey",[203;32],[152;32]).unwrap()} else {lib.finish_prf_slot(p,a,&[41;32],"Passkey",[152;32]).unwrap()}
}
#[test] fn all_routes_bind_rp_credential_and_origins() {
 for combined in [false,true] {for rotate in [false,true] {
  let (mut lib,member,owner)=support::create();let c=controller();let slot=build(&mut lib,&c,combined,rotate);
  for field in ["credential","rp","origins"] {
   let mut k=lib.authority().keyring.clone(); k.controllers.push(substitute(&c,field));k.controllers.sort_by_key(Controller::id);
   if rotate {k.vault=vault::derive([203;32]).unwrap().public();k.slots=vec![slot.clone()]}else{k.slots.push(slot.clone())}
   let e=lib.begin_keyring(k.clone(),rotate.then_some([203;32]),&[owner.public().id()],support::NOW,[153;32]).err().unwrap();
   assert!(e.0.starts_with("malformed"),"{combined} {rotate} {field}: {e:?}");
   let e=lib.prepare_authority(Action::Keyring{keyring:k,shares:rotate.then(Vec::new),epochs:rotate.then(Vec::new)},&owner.public().id(),&[owner.public().id()],support::NOW).err().unwrap();
   assert!(e.0.starts_with("malformed"));
   if !combined && !rotate {assert!(lib.begin_add_passkey(substitute(&c,field),slot.clone(),&[owner.public().id()],support::NOW).is_err());}
  }
  let mut k=lib.authority().keyring.clone(); k.controllers.push(c);k.controllers.sort_by_key(Controller::id);
  if rotate{k.vault=vault::derive([203;32]).unwrap().public();k.slots=vec![slot.clone()]}else{k.slots.push(slot.clone())}
  let p=lib.begin_keyring(k,rotate.then_some([203;32]),&[owner.public().id()],support::NOW,[154;32]).unwrap();
  support::apply(&mut lib,p,&member);
 }}
}
#[test] fn unchecked_routes_fail_every_writer_entry() {
 for combined in [false,true] {
 let (lib,_,owner)=support::create();let c=controller();let v=&lib.authority().keyring.vault;
 let slot=if combined {Slot::combined(&[202;32],&v.id(),&[owner.public().id(),c.id()],"Unchecked",&[slots::NewPart::Sealed{agreement:&owner.public().agreement},slots::NewPart::Prf{salt:&[4;32],output:&[5;32]}],&mut Entropy::new([160;32])).unwrap()}else{Slot::from_prf(&[202;32],&v.id(),&c.id(),"Unchecked",&[4;32],&[5;32],&mut Entropy::new([160;32])).unwrap()};
 assert!(lib.begin_add_controller(c.clone(),Some(slot.clone()),&[owner.public().id()],support::NOW).is_err());
 assert!(lib.begin_recovery_add(c.clone(),Some(slot.clone()),&[owner.public().id()],support::NOW).is_err());
 if !combined {assert!(lib.begin_add_passkey(c.clone(),slot.clone(),&[owner.public().id()],support::NOW).is_err())}
 let mut k=lib.authority().keyring.clone();k.controllers.push(c);k.controllers.sort_by_key(Controller::id);k.slots.push(slot);
 assert!(lib.begin_keyring(k.clone(),None,&[owner.public().id()],support::NOW,[161;32]).is_err());
 assert!(lib.prepare_authority(Action::Keyring{keyring:k,shares:None,epochs:None},&owner.public().id(),&[owner.public().id()],support::NOW).is_err());
 }
}
#[test] fn combined_rotation_refuses_a_substituted_sealed_agreement() {
 let (mut lib,_member,owner)=support::create();let c=controller();let slot=build(&mut lib,&c,true,true);
 let replacement=support::keys(210);
 let mut k=lib.authority().keyring.clone();k.controllers.push(c.clone());k.controllers.sort_by_key(Controller::id);
 if let KeyDescriptor::Raw{agreement,..}=&mut k.controllers.iter_mut().find(|x|x.id()==owner.public().id()).unwrap().key {*agreement=Some(replacement.public().agreement);}
 k.vault=vault::derive([203;32]).unwrap().public();k.slots=vec![slot.clone()];
 let refused=lib.begin_keyring(k,Some([203;32]),&[owner.public().id()],support::NOW,[175;32]).err().map(|e|e.0).unwrap_or_default();
 assert!(refused.starts_with("malformed"),"{refused}");
}
