//! `record_due` against a reference copy of its earlier body, which took the rollback snapshot
//! before looking for anything due. The two must agree on every recording, its bytes and order,
//! every error, and the account they leave behind: when nothing is due, when some is, and when a
//! recording fails partway through.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::v05::account::{CreateParams, CreateProgress, Creation, Identity};
use crate::v05::vault::SoftwareIdentity;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use std::cell::Cell;
use std::collections::BTreeMap;

const T0: i64 = 1_794_384_000_000;

thread_local! {
    /// The index of the recording to fail, for the fault cases.
    static FAULT_AT: Cell<Option<usize>> = const { Cell::new(None) };
}

/// The test seam `record_due` calls in place of `finish`: the recording at `FAULT_AT` fails
/// as a refused `finish` does, having applied nothing.
pub(super) fn finish_or_fault(
    a: &mut Account,
    index: usize,
    action: PendingAction,
) -> Result<Finished> {
    if FAULT_AT.with(Cell::get) == Some(index) {
        return Err(Failure::Refused(Reason::Rollback));
    }
    a.finish(action, Vec::new())
}

impl Account {
    /// The earlier body of `record_due`, verbatim: the snapshot is taken first, always.
    fn record_due_reference(&mut self) -> Result<Vec<Finished>> {
        let snapshot = (
            self.objects.clone(),
            self.records.clone(),
            self.persisted.clone(),
            self.now_ms,
            self.first_seen.clone(),
        );
        let mut out = Vec::new();
        let bound = self.objects.pending.len() + self.d.auth.state().activations().len() + 8;
        let mut failure = None;
        for _ in 0..bound {
            let Some(batch) = self.next_recording() else {
                break;
            };
            let action = self.batch_action("record", batch);
            let finished = finish_or_fault(self, out.len(), action);
            match finished {
                Ok(f) => out.push(f),
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        match failure {
            None => Ok(out),
            Some(e) => {
                if !out.is_empty() {
                    let (o, r, p, n, seen) = snapshot;
                    if let Ok(d) = self.candidate(&o, &r, &p, n) {
                        self.d = d;
                        self.objects = o;
                        self.records = r;
                        self.persisted = p;
                        self.now_ms = n;
                        self.first_seen = seen;
                    }
                }
                Err(e)
            }
        }
    }
}

struct Keys {
    ids: BTreeMap<String, SoftwareIdentity>,
}
impl Keys {
    fn identity(&mut self, n: u8) -> String {
        let i = SoftwareIdentity::from_seed(&[n; 32]).unwrap();
        let id = i.id();
        self.ids.insert(id.clone(), i);
        id
    }
    fn controller(&self, id: &str, label: &str, roles: &[&str]) -> Value {
        let p = self.ids[id].public();
        json!({"key": {"form": "raw", "signing": STANDARD.encode(&p.signing),
                       "agreement": STANDARD.encode(&p.agreement)},
               "label": label, "roles": roles})
    }
    fn sign(&self, steps: &[SigningStep]) -> Vec<SignatureResult> {
        steps
            .iter()
            .map(|s| SignatureResult {
                signature: self.ids[s.signer()].sign(s.body()).to_vec(),
                assertion: None,
            })
            .collect()
    }
}

/// An account with a device key and a recovery key, and `windows.len()` policy transitions
/// signed by the device. Without a home, each is due as soon as it is held.
fn account_with(windows: &[u64]) -> (Account, String) {
    let mut keys = Keys {
        ids: BTreeMap::new(),
    };
    let d = keys.identity(10);
    let k = keys.identity(20);
    let params = CreateParams {
        label: "Account".into(),
        namespaces: vec!["notes".into()],
        controllers: vec![
            keys.controller(&d, "Device", &["approve", "control"]),
            keys.controller(&k, "Kit", &["recover"]),
        ],
        slots: vec![
            SlotPlan {
                controllers: vec![d.clone()],
                label: "Device".into(),
            },
            SlotPlan {
                controllers: vec![k.clone()],
                label: "Kit".into(),
            },
        ],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy: None,
        signers: vec![d.clone()],
        rekey_signers: vec![d.clone()],
        vault_seed: [1; 32],
        entropy: [2; 32],
        epoch_seed: [3; 32],
    };
    let creation = Creation::begin(params, Identity::Controller(d.clone()), T0).unwrap();
    let sigs = keys.sign(creation.steps());
    let mut progress = creation.provide_signatures(sigs).unwrap();
    let mut account = loop {
        match progress {
            CreateProgress::Continue(c) => {
                let sigs = keys.sign(c.steps());
                progress = c.provide_signatures(sigs).unwrap();
            }
            CreateProgress::Done(account) => break *account,
        }
    };
    for w in windows {
        let action = account
            .begin_transition(
                &Change::policy(json!({"callWindow": w})),
                std::slice::from_ref(&d),
                TransitionRule::Control,
            )
            .unwrap();
        let sigs = keys.sign(action.steps());
        account.finish(action, sigs).unwrap();
    }
    (account, d)
}

/// Everything observable about an account that `record_due` can change.
fn state(a: &Account) -> String {
    format!(
        "{:?}\n{:?}\n{:?}\n{}\n{:?}\n{:?}\n{:?}\n{:?}",
        a.objects,
        a.records,
        a.persisted,
        a.now_ms,
        a.first_seen,
        a.status(),
        a.pending(),
        a.policy()
    )
}

/// The recordings, or the error, as comparable text.
fn outcome(r: &Result<Vec<Finished>>) -> String {
    match r {
        Ok(v) => format!("ok {v:?}"),
        Err(e) => format!("err {} {e}", e.code()),
    }
}

/// Two accounts opened from the same objects: one runs the reference, one the current body.
fn compare(windows: &[u64], fault_at: Option<usize>) -> (Result<Vec<Finished>>, String, String) {
    let (base, d) = account_with(windows);
    let open = || {
        Account::open(
            base.objects().clone(),
            Vec::new(),
            None,
            Identity::Controller(d.clone()),
            base.now_ms(),
        )
        .unwrap()
    };
    let mut reference = open();
    let mut current = open();
    let before = state(&current);
    assert_eq!(state(&reference), before);
    FAULT_AT.with(|f| f.set(fault_at));
    let expected = reference.record_due_reference();
    let got = current.record_due();
    FAULT_AT.with(|f| f.set(None));
    assert_eq!(
        outcome(&got),
        outcome(&expected),
        "the same recordings, bytes and order, or error"
    );
    let after = state(&current);
    assert_eq!(after, state(&reference), "the same account afterwards");
    (got, before, after)
}

#[test]
fn record_due_with_nothing_due_matches_the_reference_and_changes_nothing() {
    let (got, before, after) = compare(&[], None);
    assert!(got.unwrap().is_empty());
    assert_eq!(after, before);
}

#[test]
fn record_due_with_due_writes_matches_the_reference_in_order() {
    let (got, before, after) = compare(&[600, 700, 800], None);
    let got = got.unwrap();
    assert_eq!(got.len(), 3, "each due transition is recorded");
    let seqs: Vec<u64> = got
        .iter()
        .flat_map(|f| f.entries.iter().map(|(s, _)| *s))
        .collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted, "recorded in history order");
    assert_ne!(after, before);
}

#[test]
fn record_due_failing_partway_matches_the_reference_and_applies_nothing() {
    for at in [0usize, 1, 2] {
        let (got, before, after) = compare(&[600, 700, 800], Some(at));
        assert!(got.is_err(), "the fault at {at} fails the call");
        assert_eq!(after, before, "nothing applied after a fault at {at}");
    }
}

#[test]
fn record_due_called_again_after_recording_finds_nothing() {
    let (mut a, _) = account_with(&[600, 700]);
    assert_eq!(a.record_due().unwrap().len(), 2);
    let before = state(&a);
    assert!(a.record_due().unwrap().is_empty());
    assert_eq!(state(&a), before);
}
