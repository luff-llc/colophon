//! Fixed-history transport benchmark. Setup and host signing are outside timed regions.
use colophon_core::{
    crypto::SoftwareKeys,
    library::{Call, CreateOptions, Library, PendingBatch},
    model::Outcome,
};
use colophon_ffi::{NativeLibrary, PreparedAction, PublicKeys};
use serde_json::json;
use std::{hint::black_box, sync::Arc, time::Instant};

const NOW: &str = "2026-11-06T00:00:00Z";
fn success<T>(value: Outcome<T>) -> T {
    match value {
        Outcome::Success { value, .. } => value,
        _ => panic!("unexpected refusal"),
    }
}
fn signatures(action: &PendingBatch, keys: &SoftwareKeys) -> Vec<Vec<u8>> {
    action.steps.iter().map(|s| keys.sign(&s.body)).collect()
}
/// Sign each creation step with whichever of the two keys it names.
fn creation_signatures(
    action: &PendingBatch,
    member: &SoftwareKeys,
    controller: &SoftwareKeys,
) -> Vec<Vec<u8>> {
    action
        .steps
        .iter()
        .map(|s| {
            if s.signing == controller.public().signing {
                controller.sign(&s.body)
            } else {
                member.sign(&s.body)
            }
        })
        .collect()
}
fn unlock(library: &mut Library, keys: &SoftwareKeys) {
    for step in library.begin_unlock() {
        library
            .finish_unlock(
                &step.namespace,
                step.epoch,
                &keys.agree(&step.peer).expect("agree"),
            )
            .expect("unlock");
    }
}
fn ffi_open(base: &Library, keys: &SoftwareKeys) -> Arc<NativeLibrary> {
    let public = keys.public();
    let library = NativeLibrary::open(
        base.records().clone().into_iter().collect(),
        PublicKeys {
            signing: public.signing,
            agreement: public.agreement,
        },
    )
    .expect("open");
    for step in library.begin_unlock().expect("steps") {
        let secret = keys.agree(&step.peer).expect("agree");
        library.finish_unlock(step, secret).expect("unlock");
    }
    library
}
fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}
fn sample(mut operation: impl FnMut(), count: usize) -> f64 {
    median(
        (0..count)
            .map(|_| {
                let start = Instant::now();
                operation();
                start.elapsed().as_secs_f64() * 1e6
            })
            .collect(),
    )
}
fn main() {
    let keys = SoftwareKeys::from_scalars(&[1; 32], &[2; 32]).expect("owner");
    let controller = SoftwareKeys::from_scalars(&[3; 32], &[4; 32]).expect("controller");
    let create = Library::begin_create(
        CreateOptions {
            owner: controller.public(),
            member: keys.public(),
            vault_seed: [6; 32],
            import_expires: None,
            recovery: None,
            imported_from: None,
            label: "Benchmark".into(),
            owner_label: "Owner".into(),
            namespaces: vec!["notes".into()],
        },
        NOW,
        [5; 32],
    )
    .expect("create");
    let first = creation_signatures(&create, &keys, &controller);
    let second = create.advance_create(first).expect("advance");
    let sigs = creation_signatures(&second, &keys, &controller);
    let mut base =
        Library::open(second.finish(sigs).expect("finish"), keys.public()).expect("open");
    unlock(&mut base, &keys);
    for i in 0..21 {
        let (kind, payload) = if i == 0 {
            ("createNotebook", json!({"id":"book", "title":"Ideas"}))
        } else {
            (
                "addNote",
                json!({"id":format!("note-{i}"), "notebook":"book", "text":"A typical note with enough text to represent a useful query result."}),
            )
        };
        let action = success(
            base.begin_write("notes", kind, payload, NOW, [i + 10; 32])
                .expect("write"),
        );
        let sigs = signatures(&action, &keys);
        base.finish(action, sigs).expect("commit");
    }
    let payload = json!({"id":"bench-note", "notebook":"book", "text":"One more note"});
    let action = success(
        base.begin_write("notes", "addNote", payload.clone(), NOW, [201; 32])
            .expect("write"),
    );
    let sigs = signatures(&action, &keys);
    std::fs::create_dir_all("target/ffi-bench").expect("fixture dir");
    std::fs::write(
        "target/ffi-bench/fixture.json",
        serde_json::to_vec(
            &json!({"records":base.records(), "signatures":sigs, "payload":payload, "now":NOW}),
        )
        .expect("encode"),
    )
    .expect("fixture");
    for (path, bytes) in base.records() {
        let path = std::path::Path::new("target/ffi-bench/records").join(path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("record dir");
        std::fs::write(path, bytes).expect("record");
    }
    std::fs::write("target/ffi-bench/signatures.bin", sigs.concat()).expect("signatures");
    std::fs::write("target/ffi-bench/signing.bin", keys.public().signing).expect("signing key");
    std::fs::write("target/ffi-bench/agreement.bin", keys.public().agreement)
        .expect("agreement key");
    let ffi = ffi_open(&base, &keys);
    // Warm instruction/data caches before sampling.
    black_box(
        base.begin_call("notes__read", json!({}), NOW, [0; 32])
            .expect("warm"),
    );
    black_box(
        ffi.begin_call(
            "notes__read".into(),
            b"{}".to_vec(),
            NOW.into(),
            vec![0; 32],
        )
        .expect("warm"),
    );
    let native_query = sample(
        || {
            let value = success(
                base.begin_call("notes__read", json!({}), NOW, [0; 32])
                    .expect("query"),
            );
            if let Call::Read { value } = value {
                black_box(serde_json::to_vec(&value).expect("json"));
            } else {
                panic!("read");
            }
        },
        100,
    );
    let ffi_query = sample(
        || {
            black_box(
                ffi.begin_call(
                    "notes__read".into(),
                    b"{}".to_vec(),
                    NOW.into(),
                    vec![0; 32],
                )
                .expect("query"),
            );
        },
        100,
    );
    let mut native_writes = vec![];
    let mut ffi_writes = vec![];
    for _ in 0..50 {
        let mut library = base.clone();
        let start = Instant::now();
        let action = success(
            library
                .begin_write("notes", "addNote", payload.clone(), NOW, [201; 32])
                .expect("write"),
        );
        library.finish(action, sigs.clone()).expect("commit");
        let view = success(library.view("notes", NOW).expect("view"));
        black_box(view.admitted.last().expect("written"));
        native_writes.push(start.elapsed().as_secs_f64() * 1e6);
        let library = ffi_open(&base, &keys);
        let start = Instant::now();
        let PreparedAction::Ready { action } = library
            .begin_write(
                "notes".into(),
                "addNote".into(),
                serde_json::to_vec(&payload).expect("payload"),
                NOW.into(),
                vec![201; 32],
            )
            .expect("write")
        else {
            panic!("ready");
        };
        library
            .commit(action.clone(), sigs.clone())
            .expect("commit");
        black_box(
            library
                .written_operation(action, "notes".into(), NOW.into())
                .expect("written"),
        );
        ffi_writes.push(start.elapsed().as_secs_f64() * 1e6);
    }
    println!(
        "{}",
        json!({"unit":"microseconds_median", "history_operations":21, "query_samples":100, "write_samples":50,
        "native_query":native_query, "rust_facade_query":ffi_query, "native_write":median(native_writes), "rust_facade_write":median(ffi_writes)})
    );
}
