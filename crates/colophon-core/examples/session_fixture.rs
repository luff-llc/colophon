//! Shared signed inputs for Swift/JVM session measurements. Fixed keys are test-only.
#![allow(clippy::unwrap_used)]
#[path = "../tests/support/mod.rs"]
mod support;
use colophon_core::{
    crypto::Entropy,
    engine::{Engine, EngineOptions, RecordSource},
    model::Records,
};
use std::{
    cell::RefCell,
    fs::File,
    io::{Read, Write},
    path::Path,
    rc::Rc,
};
use support::*;
#[derive(Clone)]
struct Source(Rc<RefCell<Records>>);
impl RecordSource for Source {
    fn read(&self, path: &str) -> colophon_core::Result<Vec<u8>> {
        RecordSource::read(&*self.0.borrow(), path)
    }
}
fn load(path: &Path) -> Records {
    fn length(f: &mut File) -> usize {
        let mut b = [0; 8];
        f.read_exact(&mut b).unwrap();
        u64::from_le_bytes(b) as usize
    }
    let mut f = File::open(path).unwrap();
    let mut records = Records::new();
    for _ in 0..length(&mut f) {
        let mut p = vec![0; length(&mut f)];
        f.read_exact(&mut p).unwrap();
        let mut b = vec![0; length(&mut f)];
        f.read_exact(&mut b).unwrap();
        records.insert(String::from_utf8(p).unwrap(), b);
    }
    records
}
fn save(path: &Path, records: &Records) {
    let mut f = File::create(path).unwrap();
    f.write_all(&(records.len() as u64).to_le_bytes()).unwrap();
    for (p, b) in records {
        f.write_all(&(p.len() as u64).to_le_bytes()).unwrap();
        f.write_all(p.as_bytes()).unwrap();
        f.write_all(&(b.len() as u64).to_le_bytes()).unwrap();
        f.write_all(b).unwrap();
    }
}
fn engine(source: Source) -> Engine<Source> {
    let owner = keys(1);
    let listing = source.0.borrow().keys().cloned().collect();
    let id = colophon_core::library::Library::open(
        source
            .0
            .borrow()
            .iter()
            .filter(|(p, _)| p.starts_with("authority/"))
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect(),
        owner.public(),
    )
    .unwrap()
    .id()
    .to_owned();
    let mut engine = Engine::open(
        source,
        listing,
        owner.public(),
        EngineOptions {
            library_id: id,
            checkpoint_key: [22; 32],
            content_cache_bytes: 0,
            namespaces: vec![],
        },
        None,
    )
    .unwrap();
    let shared = engine
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(shared).unwrap();
    engine
}
fn main() {
    let root = std::env::args()
        .nth(1)
        .unwrap_or("target/engine-sessions".into());
    let root = Path::new(&root);
    let mut entropy = Entropy::new([1; 32]);
    std::fs::write(
        root.join("signing-private.bin"),
        entropy.take::<32>().unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("agreement-private.bin"),
        entropy.take::<32>().unwrap(),
    )
    .unwrap();
    let owner = keys(1);
    std::fs::write(root.join("signing-public.bin"), owner.public().signing).unwrap();
    std::fs::write(root.join("agreement-public.bin"), owner.public().agreement).unwrap();
    let source = Source(Rc::new(RefCell::new(load(&root.join("100k.records")))));
    let mut engine = engine(source.clone());
    let mut suffix = Records::new();
    for i in 0..1000u64 {
        let mut seed = [0; 32];
        seed[..8].copy_from_slice(&i.to_le_bytes());
        let pending = success(
            engine
                .begin_write(
                    "listening.podcasts",
                    "position",
                    serde_json::json!({"id":"ep1","seconds":200000+i,"seek":true}),
                    NOW,
                    seed,
                )
                .unwrap(),
        );
        let records = finish(pending, &owner);
        let paths = records.keys().cloned().collect();
        source.0.borrow_mut().extend(records.clone());
        suffix.extend(records);
        engine.apply_paths(paths).unwrap();
    }
    save(&root.join("suffix.records"), &suffix);
    let (mut library, _, _) = create();
    write(
        &mut library,
        &owner,
        "listening.podcasts",
        "follow",
        serde_json::json!({"id":"show","url":"https://example.org/feed.xml"}),
        1,
    );
    write(
        &mut library,
        &owner,
        "listening.podcasts",
        "episode",
        serde_json::json!({"id":"ep","show":"show","title":"Episode"}),
        2,
    );
    let source = Source(Rc::new(RefCell::new(library.records().clone())));
    let mut taupe = engine_for_taupe(source.clone());
    for i in 0..10000u64 {
        let mut seed = [0; 32];
        seed[..8].copy_from_slice(&i.to_le_bytes());
        let pending = success(
            taupe
                .begin_write(
                    "listening.podcasts",
                    "position",
                    serde_json::json!({"id":"ep","seconds":i}),
                    NOW,
                    seed,
                )
                .unwrap(),
        );
        let records = finish(pending, &owner);
        let paths = records.keys().cloned().collect();
        source.0.borrow_mut().extend(records);
        taupe.apply_paths(paths).unwrap();
    }
    save(&root.join("taupe.records"), &source.0.borrow());
    println!("Wrote 1000 signed suffix operations and 10000 Taupe live samples");
}
fn engine_for_taupe(source: Source) -> Engine<Source> {
    engine(source)
}
