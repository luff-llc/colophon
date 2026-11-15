//! The clock moving (E10): a clock that leaves the verified history as it was changes no
//! derived record layer (the judgement, folds and live slots stand), a clock that crosses a
//! grant's end rebuilds; either way the account equals a rebuild at the new time.
#![allow(clippy::unwrap_used)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use serde_json::json;
use support::*;

#[test]
fn the_clock_before_and_across_an_expiry_equals_a_rebuild() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(50);
    admit(
        &mut f,
        &agent,
        "Agent",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &agent, T0 + HOUR);
    for i in 0..5 {
        engine_write(
            &mut e,
            &mut host,
            &src,
            "notes",
            "createNotebook",
            json!({"id": format!("n{i}"), "title": "t"}),
        );
    }
    let rev = e.revision("notes");
    // A day on: the grant is still in force.
    let c = e.advance(T0 + 24 * HOUR).unwrap();
    e.account().verify_derivation().unwrap();
    assert_eq!(e.revision("notes"), rev);
    assert!(c.authority.members_revoked.is_empty());
    // Across the grant's end (seven days).
    e.advance(T0 + 8 * 24 * HOUR).unwrap();
    e.account().verify_derivation().unwrap();
    assert_eq!(e.account().now_ms(), T0 + 8 * 24 * HOUR);
    // A cold open at the later time reads the same.
    let mut cold = member_engine(&f, &host, &src, &agent, T0 + 8 * 24 * HOUR);
    cold.refresh(src.listing()).unwrap();
    assert_eq!(cold.revision("notes"), e.revision("notes"));
    assert_eq!(
        serde_json::to_string(&cold.view("notes").unwrap()).unwrap(),
        serde_json::to_string(&e.view("notes").unwrap()).unwrap()
    );
}
