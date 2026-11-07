//! Storage-backed 100k benchmark. First generate the fixture with the `bench` example.
#![allow(clippy::unwrap_used)]
#[path = "../tests/support/mod.rs"]
mod support;
use colophon_core::{
    engine::{Engine, EngineOptions, RecordSource},
    library::Library,
    model::Records,
    Result,
};
use serde_json::json;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    rc::Rc,
    time::Instant,
};
use support::*;
#[derive(Clone)]
struct Source(Rc<RefCell<Records>>);
impl RecordSource for Source {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        RecordSource::read(&*self.0.borrow(), path)
    }
}
fn length(file: &mut File) -> usize {
    let mut b = [0; 8];
    file.read_exact(&mut b).unwrap();
    u64::from_le_bytes(b) as usize
}
fn load(path: &str) -> Records {
    let mut file = File::open(path).unwrap();
    let mut records = Records::new();
    for _ in 0..length(&mut file) {
        let mut path = vec![0; length(&mut file)];
        file.read_exact(&mut path).unwrap();
        let mut bytes = vec![0; length(&mut file)];
        file.read_exact(&mut bytes).unwrap();
        records.insert(String::from_utf8(path).unwrap(), bytes);
    }
    records
}
fn unlock<S: RecordSource>(engine: &mut Engine<S>, owner: &colophon_core::crypto::SoftwareKeys) {
    let results = engine
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(results).unwrap();
}
fn report(label: &str, start: Instant) {
    println!("{label}: {:.3} ms", start.elapsed().as_secs_f64() * 1000.0);
}
struct DiskSource {
    files: Vec<RefCell<File>>,
    index: BTreeMap<String, (usize, u64, usize)>,
}
impl DiskSource {
    fn open(path: &str) -> Self {
        let mut source = Self {
            files: Vec::new(),
            index: BTreeMap::new(),
        };
        source.extend(path);
        source
    }
    fn extend(&mut self, path: &str) {
        let mut file = File::open(path).unwrap();
        for _ in 0..length(&mut file) {
            let mut name = vec![0; length(&mut file)];
            file.read_exact(&mut name).unwrap();
            let size = length(&mut file);
            let offset = file.stream_position().unwrap();
            self.index.insert(
                String::from_utf8(name).unwrap(),
                (self.files.len(), offset, size),
            );
            file.seek(SeekFrom::Current(size as i64)).unwrap();
        }
        self.files.push(RefCell::new(file));
    }
}
impl RecordSource for DiskSource {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let (file, offset, size) = self.index[path];
        let mut file = self.files[file].borrow_mut();
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| colophon_core::Error(e.to_string()))?;
        let mut bytes = vec![0; size];
        file.read_exact(&mut bytes)
            .map_err(|e| colophon_core::Error(e.to_string()))?;
        Ok(bytes)
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let fixture = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("/tmp/colophon-engine-100k.records");
    let owner = keys(1);
    println!(
        "registered domains: {:?}",
        colophon_core::domain::NAMESPACES
    );
    for ns in colophon_core::domain::NAMESPACES {
        assert!(colophon_core::domain::module(ns).is_some());
    }
    if args
        .iter()
        .any(|a| a == "--disk-memory" || a == "--source-only")
    {
        let source = DiskSource::open(fixture);
        let listing = source.index.keys().cloned().collect::<Vec<_>>();
        let authority = listing
            .iter()
            .filter(|p| p.starts_with("authority/"))
            .map(|p| (p.clone(), source.read(p).unwrap()))
            .collect();
        let library = Library::open(authority, owner.public()).unwrap();
        let options = EngineOptions {
            library_id: library.id().into(),
            checkpoint_key: [61; 32],
            content_cache_bytes: 64 * 1024,
            namespaces: Vec::new(),
        };
        drop(library);
        if args.iter().any(|a| a == "--source-only") {
            println!("disk source baseline paths: {}", listing.len());
            return;
        }
        let started = Instant::now();
        let mut engine = Engine::open(source, listing, owner.public(), options, None).unwrap();
        unlock(&mut engine, &owner);
        report(
            "disk-source full rebuild (includes seeks and reads)",
            started,
        );
        println!("stats: {:?}", engine.stats());
        return;
    }
    if args
        .iter()
        .any(|a| a == "--cold-memory" || a == "--cold-suffix")
    {
        let mut source = DiskSource::open(fixture);
        let base = source.index.len();
        let suffix = args.iter().any(|a| a == "--cold-suffix");
        if suffix {
            source.extend("/tmp/colophon-engine-v2-suffix.records");
        }
        let added = source.index.len() - base;
        let listing = source.index.keys().cloned().collect::<Vec<_>>();
        let cp = std::fs::read("/tmp/colophon-engine-v2.checkpoint").unwrap();
        let authority = listing
            .iter()
            .filter(|p| p.starts_with("authority/"))
            .map(|p| (p.clone(), source.read(p).unwrap()))
            .collect();
        let library = Library::open(authority, owner.public()).unwrap();
        let options = EngineOptions {
            library_id: library.id().into(),
            checkpoint_key: [61; 32],
            content_cache_bytes: 64 * 1024,
            namespaces: Vec::new(),
        };
        drop(library);
        let started = Instant::now();
        let mut engine = Engine::open(source, listing, owner.public(), options, Some(&cp)).unwrap();
        unlock(&mut engine, &owner);
        report(
            if suffix {
                "fresh-process disk cold checkpoint + 1%"
            } else {
                "disk-source cold checkpoint"
            },
            started,
        );
        assert_eq!(engine.stats().records_read, added as u64);
        assert_eq!(engine.stats().payloads_decrypted, added as u64);
        if suffix {
            let expected: serde_json::Value = serde_json::from_slice(
                &std::fs::read("/tmp/colophon-engine-v2-suffix.expected.json").unwrap(),
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(
                    engine
                        .query("listening.podcasts", "read", json!({}), NOW)
                        .unwrap()
                )
                .unwrap(),
                expected
            );
        }
        drop(cp);
        println!("stats: {:?}", engine.stats());
        return;
    }
    let records = load(fixture);
    let count = records.keys().filter(|p| p.starts_with("ops/")).count();
    let authority = records
        .iter()
        .filter(|(p, _)| p.starts_with("authority/"))
        .map(|(p, r)| (p.clone(), r.clone()))
        .collect();
    let library = Library::open(authority, owner.public()).unwrap();
    let options = EngineOptions {
        library_id: library.id().into(),
        checkpoint_key: [61; 32],
        content_cache_bytes: 64 * 1024,
        namespaces: Vec::new(),
    };
    drop(library);
    let source = Source(Rc::new(RefCell::new(records)));
    let listing = source.0.borrow().keys().cloned().collect();
    let started = Instant::now();
    let mut engine = Engine::open(
        source.clone(),
        listing,
        owner.public(),
        options.clone(),
        None,
    )
    .unwrap();
    report("engine full / open authority", started);
    unlock(&mut engine, &owner);
    report("engine full rebuild total", started);
    println!("full stats: {:?}", engine.stats());
    let expected: BTreeMap<_, _> = engine
        .authority()
        .namespaces
        .iter()
        .map(|ns| {
            (
                ns.clone(),
                serde_json::to_value(engine.query(ns, "read", json!({}), NOW).unwrap()).unwrap(),
            )
        })
        .collect();
    let started = Instant::now();
    let cp = engine.checkpoint().unwrap();
    report("engine checkpoint serialization", started);
    println!("checkpoint bytes: {}", cp.len());
    std::fs::write("/tmp/colophon-engine-v2.checkpoint", &cp).unwrap();
    drop(engine);
    let listing = source.0.borrow().keys().cloned().collect();
    let started = Instant::now();
    let mut engine = Engine::open(
        source.clone(),
        listing,
        owner.public(),
        options.clone(),
        Some(&cp),
    )
    .unwrap();
    report("engine cold / authenticate and restore", started);
    unlock(&mut engine, &owner);
    report("engine cold unchanged total", started);
    println!("cold stats: {:?}", engine.stats());
    for (ns, expected) in &expected {
        assert_eq!(
            serde_json::to_value(engine.query(ns, "read", json!({}), NOW).unwrap()).unwrap(),
            *expected
        );
    }
    let mut suffix_paths = Vec::new();
    let started = Instant::now();
    let pending = success(
        engine
            .begin_write(
                "listening.podcasts",
                "position",
                json!({"id":"ep1","seconds":count+1}),
                NOW,
                [111; 32],
            )
            .unwrap(),
    );
    let records = finish(pending, &owner);
    let paths: Vec<_> = records.keys().cloned().collect();
    source.0.borrow_mut().extend(records);
    engine.apply_paths(paths.clone()).unwrap();
    suffix_paths.extend(paths);
    report(
        "engine local write incl sign persist(memory) verify apply",
        started,
    );
    // Prepare a genuine 1% new suffix; generation/signing is excluded from the next cold-open timer.
    for i in 1..count / 100 {
        let mut seed = [0; 32];
        seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let pending = success(
            engine
                .begin_write(
                    "listening.podcasts",
                    "position",
                    json!({"id":"ep1","seconds":count+i+1}),
                    NOW,
                    seed,
                )
                .unwrap(),
        );
        let records = finish(pending, &owner);
        let paths: Vec<_> = records.keys().cloned().collect();
        source.0.borrow_mut().extend(records);
        engine.apply_paths(paths.clone()).unwrap();
        suffix_paths.extend(paths);
    }
    let expected = serde_json::to_value(
        engine
            .query("listening.podcasts", "read", json!({}), NOW)
            .unwrap(),
    )
    .unwrap();
    let mut file = File::create("/tmp/colophon-engine-v2-suffix.records").unwrap();
    file.write_all(&(suffix_paths.len() as u64).to_le_bytes())
        .unwrap();
    for path in &suffix_paths {
        let records = source.0.borrow();
        let bytes = &records[path];
        file.write_all(&(path.len() as u64).to_le_bytes()).unwrap();
        file.write_all(path.as_bytes()).unwrap();
        file.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
        file.write_all(bytes).unwrap();
    }
    std::fs::write(
        "/tmp/colophon-engine-v2-suffix.expected.json",
        serde_json::to_vec(&expected).unwrap(),
    )
    .unwrap();
    drop(engine);
    let listing = source.0.borrow().keys().cloned().collect();
    let started = Instant::now();
    let mut engine =
        Engine::open(source.clone(), listing, owner.public(), options, Some(&cp)).unwrap();
    report("engine cold 1% / authenticate and restore", started);
    unlock(&mut engine, &owner);
    report("engine cold 1% total", started);
    println!("1% stats: {:?}", engine.stats());
    assert_eq!(
        serde_json::to_value(
            engine
                .query("listening.podcasts", "read", json!({}), NOW)
                .unwrap()
        )
        .unwrap(),
        expected
    );
    let started = Instant::now();
    engine.history("listening.podcasts", 0, 50, NOW).unwrap();
    report("lazy 50-operation history page", started);
    println!("history stats: {:?}", engine.stats());
    let started = Instant::now();
    engine.verify_batch(128).unwrap();
    report("background verify 128", started);
}
