//! Generate *the same* test-derived admitted operations and native reference
//! bytes for every host. No handwritten expected state. Run before hosts.
use colophon_core::{
    domain::Reducer,
    domains::notes::{Notes, NotesState},
    model::OperationView,
    records::{canonical, digest},
};
use serde_json::{json, Value};
use std::{fs, io::Write, path::PathBuf, time::Instant};

fn op(n: u64, kind: &str, payload: Value) -> OperationView {
    // Identity, dates and initial commands are from domain_notes.rs::op/base.
    OperationView {
        id: format!("r{n}"),
        kind: kind.into(),
        author: "writer".into(),
        author_label: "Writer".into(),
        origin: "person".into(),
        clock: n,
        created: "2026-11-04T12:00:00Z".into(),
        payload,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or("spikes/module-abi/out".into()));
    fs::create_dir_all(&out)?;
    let mut state = NotesState::default();
    fs::write(out.join("initial.json"), canonical(&state)?)?;
    let mut operations = fs::File::create(out.join("operations.jsonl"))?;
    let counts = [1_usize, 1_000, 10_000];
    let begin = Instant::now();
    let mut last_step = begin;
    let mut accumulated_ms = 0.0_f64;
    for n in 1..=10_000_usize {
        let operation = match n {
            1 => op(1, "createNotebook", json!({"id":"b","title":"Book"})),
            2 => op(2, "putEntry", json!({"id":"e","notebook":"b","title":"Entry","date":"2024-02-29","tags":["x"]})),
            3 => op(3, "putCell", json!({"id":"c","notebook":"b","entry":"e","kind":"markdown","source":"one"})),
            // Repeated *valid* CAS mutations model the putCell path from the
            // existing tests without growing conflict history quadratically.
            n => op(n as u64, "putCell", json!({"id":"c","notebook":"b","kind":"markdown",
                       "source":format!("updated-{n}"),"expect":format!("r{}",n-1)})),
        };
        let bytes = canonical(&operation)?;
        operations.write_all(&bytes)?;
        operations.write_all(b"\n")?;
        let before = Instant::now();
        Notes.apply(&mut state, &operation);
        let delta_ms = before.elapsed().as_secs_f64() * 1000.0;
        accumulated_ms += delta_ms;
        if counts.contains(&n) {
            let output = canonical(&state)?;
            let query = canonical(&Notes.query(&state, "noteCounts", &json!({}))?)?;
            fs::write(out.join(format!("expected-{n}.json")), &output)?;
            fs::write(out.join(format!("expected-query-{n}.json")), &query)?;
            let summary = json!({
                "host":"native-rust-direct",
                "operations":n,
                "apply_ms":accumulated_ms,
                "ms_per_op":accumulated_ms / n as f64,
                "elapsed_ms":begin.elapsed().as_secs_f64() * 1000.0,
                "state_bytes": output.len(),
                "state_sha256":digest(&output),
                "query_sha256":digest(&query),
                "peak_rss_bytes":Value::Null
            });
            fs::write(out.join(format!("native-{n}.json")), canonical(&summary)?)?;
            println!("{}", summary);
            last_step = Instant::now();
        }
    }
    let _ = last_step;
    Ok(())
}
