//! The account view and epoch keys an engine gives a 0.6 session endpoint
//! (`Account::session_account`, `Account::session_epochs`): two members of one account, each on
//! its own engine, seal and open each other's frames with only what their engines verified and
//! unlocked. A table without the epoch opens nothing.
#![allow(clippy::unwrap_used)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::terms::Access;
use colophon_core::v06::session::codec::{CellId, EpochKeys, EpochTable};
use colophon_core::v06::session::endpoint::{Clock, Endpoint};
use colophon_core::v06::session::{Command, Policy};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "notes";

#[test]
fn member_engines_give_endpoints_that_open_each_others_frames() {
    let (mut s, ids) = setup(NS, &[("A", 31, "write"), ("B", 32, "read")]);
    let host = std::mem::replace(&mut s.f.host, Host::new());
    let (a_src, b_src) = (device_source(&s), device_source(&s));
    let a = member_engine(&s.f, &host, &a_src, &ids[0], NOW);
    let b = member_engine(&s.f, &host, &b_src, &ids[1], NOW);

    let view = a.account().session_account(NOW);
    assert_eq!(
        view,
        b.account().session_account(NOW),
        "one history, one view"
    );
    assert_eq!(view.account(), a.account().id().as_str());
    assert_eq!(view.writers(NS, NOW), vec![ids[0].clone()]);
    assert_eq!(view.access(&ids[1], NS, NOW), Some(Access::Read));
    assert_eq!(view.member(&ids[0]).unwrap().session, 0);

    let (ka, kb) = (
        a.account().session_epochs(NS),
        b.account().session_epochs(NS),
    );
    let epoch = ka.current_epoch(NS).unwrap();
    assert_eq!(kb.current_epoch(NS), Some(epoch));
    assert_eq!(
        *ka.epoch_key(NS, epoch).unwrap(),
        *kb.epoch_key(NS, epoch).unwrap()
    );
    assert!(a
        .account()
        .session_epochs("other")
        .current_epoch("other")
        .is_none());

    let cell = CellId::new(a.account().id().as_str(), NS, "now-playing");
    let clock = Clock {
        mono_ms: 1_000,
        wall_ms: NOW,
    };
    let make = |me: &str, r: u8| {
        Endpoint::new(
            cell.clone(),
            me,
            Policy::default(),
            None,
            view.clone(),
            &mut [r; 32],
            [r; 16],
            clock,
        )
        .unwrap()
    };
    let (mut pa, mut pb) = (make(&ids[0], 7), make(&ids[1], 8));
    for (p, id) in [(&mut pa, &ids[0]), (&mut pb, &ids[1])] {
        let body = p.begin_delegation(NOW - 1_000, NOW + HOUR).unwrap();
        let sig = host.ids[id].sign(&body).to_vec();
        p.finish_delegation(&body, &sig, clock).unwrap();
    }
    let joined = pa.command(Command::Join { state: None }, clock, &ka);
    let hello = joined.frames().next().unwrap().to_vec();
    pb.command(Command::Join { state: None }, clock, &kb);
    assert_eq!(
        pb.receive(&hello, clock, &EpochTable::new())
            .dropped
            .map(|d| d.reason.code()),
        Some("noEpoch")
    );
    let got = pb.receive(&hello, clock, &kb);
    assert!(got.dropped.is_none(), "{:?}", got.dropped);
}
