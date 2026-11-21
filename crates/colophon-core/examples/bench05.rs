//! Synthetic v05 session benchmark. Run scripts/bench-05.sh; never use these fixed keys in an app.
#![allow(clippy::unwrap_used)]
#[path = "../tests/v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::{
    account::Identity,
    engine::{
        exchange::{Fault, Step},
        Engine, EngineOptions, OpenMode, RecordSource, Saved,
    },
    records::{EpochKeys, Level},
    write::{
        records::{prepare_operation_fast, OperationSpec, WriteBasis},
        SignatureResult,
    },
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
use support::*;
const NS: &str = "reading.saved";
const NOW: i64 = T0 + 3 * HOUR;

// Real filesystem reads, with an append-only overlay for each measurement child. The manifest
// is the host's coherent inventory. No record bodies are preloaded by the device source.
#[derive(Clone)]
struct Disk {
    base: PathBuf,
    overlay: PathBuf,
    prefix: bool,
}
impl Disk {
    fn listing(&self) -> Vec<String> {
        let name = if self.prefix {
            "prefix.json"
        } else {
            "paths.json"
        };
        let mut paths: BTreeSet<String> =
            serde_json::from_slice(&fs::read(self.base.join(name)).unwrap()).unwrap();
        fn walk(root: &Path, dir: &Path, paths: &mut BTreeSet<String>) {
            if !dir.exists() {
                return;
            }
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    walk(root, &entry.path(), paths);
                } else {
                    paths.insert(
                        entry
                            .path()
                            .strip_prefix(root)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                    );
                }
            }
        }
        walk(&self.overlay, &self.overlay, &mut paths);
        paths.into_iter().collect()
    }
    fn store(&self, stores: &[(String, Vec<u8>)]) {
        // Engine writes and catch-up are immutable single-file publications here. Each file
        // and its directory are synced before returning. This is not the native FolderMedium.
        for (p, b) in stores {
            put(&self.overlay, p, b, true);
        }
    }
}
fn put(root: &Path, p: &str, b: &[u8], durable: bool) {
    let path = root.join(p);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(b).unwrap();
    if durable {
        file.sync_all().unwrap();
        fs::File::open(path.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
    }
}
impl RecordSource for Disk {
    fn read(&self, p: &str) -> colophon_core::Result<Vec<u8>> {
        let overlay = self.overlay.join(p);
        fs::read(if overlay.exists() {
            overlay
        } else {
            self.base.join("files").join(p)
        })
        .map_err(|e| colophon_core::Error(e.to_string()))
    }
    fn read_blob(&self, p: &str) -> colophon_core::Result<colophon_core::blobs::BlobRead> {
        Ok(self.read(p).map_or(
            colophon_core::blobs::BlobRead::Missing,
            colophon_core::blobs::BlobRead::Available,
        ))
    }
}
fn write_json(p: &Path, v: &Value) {
    fs::write(p, serde_json::to_vec(v).unwrap()).unwrap();
}
fn write_saved(p: &Path, s: Saved) {
    let mut f = fs::File::create(p).unwrap();
    fn bytes(f: &mut fs::File, b: &[u8]) {
        f.write_all(&(b.len() as u64).to_le_bytes()).unwrap();
        f.write_all(b).unwrap();
    }
    bytes(&mut f, &s.verifier);
    bytes(&mut f, &s.checkpoint);
    f.write_all(&(s.parts.len() as u64).to_le_bytes()).unwrap();
    for (ns, b) in s.parts {
        bytes(&mut f, ns.as_bytes());
        bytes(&mut f, &b);
    }
}
fn read_saved(p: &Path) -> Saved {
    let mut f = fs::File::open(p).unwrap();
    fn length(f: &mut fs::File) -> usize {
        let mut b = [0; 8];
        f.read_exact(&mut b).unwrap();
        u64::from_le_bytes(b) as usize
    }
    fn bytes(f: &mut fs::File) -> Vec<u8> {
        let mut b = vec![0; length(f)];
        f.read_exact(&mut b).unwrap();
        b
    }
    let verifier = bytes(&mut f);
    let checkpoint = bytes(&mut f);
    let count = length(&mut f);
    let mut parts = BTreeMap::new();
    for _ in 0..count {
        let ns = String::from_utf8(bytes(&mut f)).unwrap();
        parts.insert(ns, bytes(&mut f));
    }
    Saved {
        verifier,
        checkpoint,
        parts,
    }
}
fn open(
    src: Disk,
    account: &str,
    member: &str,
    host: &Host,
    saved: Option<&Saved>,
) -> Engine<Disk> {
    let paths = src.listing();
    let mut e = Engine::open(
        src,
        paths,
        Identity::Member(member.into()),
        EngineOptions::new(account, DEVICE_KEY),
        saved,
        NOW,
    )
    .unwrap();
    let steps = e.begin_unlock_epochs();
    e.finish_unlock_epochs(host.answer_epochs(member, steps))
        .unwrap();
    assert!(e.source_faults().is_empty());
    assert!(e.missing_covered().is_empty());
    assert_eq!(e.stats().unread_paths, 0);
    e
}
fn fixture(root: &Path, n: usize) {
    fs::create_dir_all(root).unwrap();
    let mut f = create(&[NS]);
    let home = appoint_home(&mut f);
    let member = f.host.identity(31);
    admit(
        &mut f,
        &member,
        "Synthetic device",
        "device",
        terms_for(&[(NS, "write")]),
        terms_for(&[(NS, "write")]),
    );
    let mut seed = 80;
    while f.account.objects().entries.len() < 64 {
        let id = f.host.identity(seed);
        seed += 1;
        admit(
            &mut f,
            &id,
            "Synthetic member",
            "device",
            terms_for(&[(NS, "read")]),
            terms_for(&[(NS, "read")]),
        );
    }
    assert_eq!(f.account.objects().entries.len(), 64);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut e = member_engine(&f, &f.host, &src, &member, NOW);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    // 83 distinct required references, each with three chunks (131,089 plaintext bytes).
    for i in 0..83 {
        let mut bytes = vec![b'x'; 2 * 65_536 + 17];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        engine_blob(
            &mut e,
            &mut host,
            &src,
            NS,
            "text/plain",
            &bytes,
            &format!("original-{i}"),
            true,
        );
    }
    let auth =
        colophon_core::v05::records::RecordAuthority::from_objects(e.account().objects(), NOW)
            .unwrap();
    let request = auth.epoch_seal_request(NS, 1, &member).unwrap();
    let key = auth
        .open_epoch(
            NS,
            1,
            &member,
            &host.ids[&member].agree(&request.enc).unwrap(),
        )
        .unwrap();
    let mut keys = EpochKeys::new();
    keys.insert(key).unwrap();
    let last = e
        .account()
        .records()
        .iter()
        .filter_map(|r| {
            colophon_core::v05::records::OperationHeader::parse(&r.bytes)
                .ok()
                .map(|(h, _)| h)
        })
        .max_by_key(|h| h.clock)
        .unwrap();
    let mut tips = vec![colophon_core::v05::encoding::digest(&last.body)];
    let mut ordered: Vec<String> = e
        .account()
        .records()
        .iter()
        .map(|r| r.path.clone())
        .collect();
    ordered.sort();
    for i in 83..n {
        // Fixture-only fast builder: maintain the same clock and author chain as sequential
        // writes, without retaining a generator engine alongside the later measured process.
        let spec = OperationSpec {
            namespace: NS,
            author: &member,
            level: Level::Write,
            kind: "capture",
            payload: json!({"id":format!("item-{i:06}"),
                "title":format!("Synthetic saved item {i}"),
                "url":format!("https://example.invalid/{i}")}),
            clock: None,
        };
        let basis = WriteBasis {
            highest: i as u64,
            tips: &tips,
            reserved: i as u64,
            nonce_used: &|_, _, _| false,
        };
        let prepared =
            prepare_operation_fast(&auth, &keys, NOW, &spec, host.fresh(), &basis).unwrap();
        let sig = SignatureResult {
            signature: host.ids[&member].sign(prepared.step().body()).to_vec(),
            assertion: None,
        };
        let done = prepared.finish(sig).unwrap();
        tips = vec![done.digest];
        ordered.push(done.path.clone());
        src.put(&done.path, done.envelope);
    }
    drop(e);
    let paths = src.listing();
    let prefix_ops: BTreeSet<_> = ordered[..n / 10].iter().cloned().collect();
    let prefix: Vec<_> = paths
        .iter()
        .filter(|p| !p.starts_with("ops/") || prefix_ops.contains(*p))
        .cloned()
        .collect();
    for p in &paths {
        put(&root.join("files"), p, &src.get(p).unwrap(), false);
    }
    write_json(&root.join("paths.json"), &json!(paths));
    write_json(&root.join("prefix.json"), &json!(prefix));
    write_json(
        &root.join("meta.json"),
        &json!({"account":f.account.id().as_str(),"member":member,"home":home,"records":n,"authority":64,"blob_references":83,"chunks":249,"stored_files":paths.len()}),
    );
    // Serialize only public simulated-home state. Software keys are reconstructed from seeds.
    f.host = host;
    let sim = SimHome::new(&f, &home, "https://home.example", NOW);
    write_json(
        &root.join("home.json"),
        &serde_json::to_value(&sim.state).unwrap(),
    );
    for prefix in [true, false] {
        let disk = Disk {
            base: root.into(),
            overlay: root.join("unused"),
            prefix,
        };
        let mut e = open(disk, f.account.id().as_str(), &member, &f.host, None);
        assert_eq!(
            e.stats().signatures_verified,
            if prefix { n / 10 } else { n } as u64
        );
        assert!(ordered
            .iter()
            .take(if prefix { n / 10 } else { n })
            .all(|p| e.record_verdict(p).as_deref() == Some("admitted")));
        write_saved(
            &root.join(if prefix {
                "prefix-saved.bin"
            } else {
                "saved.bin"
            }),
            e.save([23; 32]).unwrap(),
        );
    }
    eprintln!("fixture {n}: 64 authority, {n} operations (83 manifests), 249 chunks; saved full and 10% state");
}
fn host() -> Host {
    let mut h = Host::new();
    h.identity(31);
    h.identity(70);
    h
}
// Darwin getrusage(2): two timeval fields, then fourteen long counters. ru_maxrss is bytes.
#[cfg(target_os = "macos")]
fn rss() -> u64 {
    #[repr(C)]
    struct Usage {
        times: [i64; 4],
        maxrss: i64,
        counters: [i64; 13],
    }
    unsafe extern "C" {
        fn getrusage(who: i32, usage: *mut Usage) -> i32;
    }
    let mut u = Usage {
        times: [0; 4],
        maxrss: 0,
        counters: [0; 13],
    };
    // SAFETY: Darwin's rusage layout above, valid writable pointer, RUSAGE_SELF = 0.
    assert_eq!(unsafe { getrusage(0, &mut u) }, 0);
    u.maxrss as u64
}
#[cfg(not(target_os = "macos"))]
fn rss() -> u64 {
    panic!("RSS benchmark currently supports macOS only")
}
fn child(root: &Path, case: &str, run: usize) {
    let meta: Value = serde_json::from_slice(&fs::read(root.join("meta.json")).unwrap()).unwrap();
    let account = meta["account"].as_str().unwrap();
    let member = meta["member"].as_str().unwrap();
    let home = meta["home"].as_str().unwrap();
    let n = meta["records"].as_u64().unwrap();
    let host = host();
    let overlay = root.join(format!("run-{case}-{run}"));
    assert!(
        !overlay.exists(),
        "use a new output directory for each benchmark invocation"
    );
    fs::create_dir_all(&overlay).unwrap();
    let src = Disk {
        base: root.into(),
        overlay,
        prefix: case == "catchup",
    };
    let mut sim = if case == "catchup" {
        let state = serde_json::from_slice(&fs::read(root.join("home.json")).unwrap()).unwrap();
        let mut files = BTreeMap::new();
        let mut entries = BTreeMap::new();
        for p in serde_json::from_slice::<Vec<String>>(&fs::read(root.join("paths.json")).unwrap())
            .unwrap()
        {
            let b = src.read(&p).unwrap();
            if p.starts_with("authority/") {
                entries.insert(entry_seq(&b), b.clone());
            }
            files.insert(p, b);
        }
        let log = files.keys().cloned().collect();
        Some(SimHome {
            id: home.into(),
            base: "https://home.example".into(),
            state,
            entries,
            files,
            log,
            requests: vec![],
            account: account.into(),
        })
    } else {
        None
    };
    let uptime = String::from_utf8(Command::new("uptime").output().unwrap().stdout).unwrap();
    let start = Instant::now();
    let saved = if case == "cold" {
        None
    } else {
        Some(read_saved(&root.join(if case == "catchup" {
            "prefix-saved.bin"
        } else {
            "saved.bin"
        })))
    };
    let saved_ms = start.elapsed().as_secs_f64() * 1000.;
    let phase = Instant::now();
    let listing = src.listing();
    let listing_ms = phase.elapsed().as_secs_f64() * 1000.;
    let phase = Instant::now();
    let mut e = Engine::open(
        src.clone(),
        listing,
        Identity::Member(member.into()),
        EngineOptions::new(account, DEVICE_KEY),
        saved.as_ref(),
        NOW,
    )
    .unwrap();
    let authority_checkpoint_ms = phase.elapsed().as_secs_f64() * 1000.;
    let phase = Instant::now();
    let steps = e.begin_unlock_epochs();
    e.finish_unlock_epochs(host.answer_epochs(member, steps))
        .unwrap();
    let unlock_load_ms = phase.elapsed().as_secs_f64() * 1000.;
    assert_eq!(
        *e.open_mode(),
        if case == "cold" {
            OpenMode::Cold
        } else {
            OpenMode::Resumed
        }
    );
    let mut requests = 0;
    let mut passes = 0;
    if let Some(sim) = &mut sim {
        loop {
            passes += 1;
            assert!(passes <= 10);
            let mut more = false;
            loop {
                match e.exchange_next(home).unwrap() {
                    Step::Done => break,
                    Step::Waiting => panic!("unanswered request"),
                    Step::NeedCall(c) => e
                        .exchange_provide_call(
                            home,
                            c.ticket,
                            format!("call-{}", c.ticket).as_bytes(),
                        )
                        .unwrap(),
                    Step::Request(r) => {
                        requests += 1;
                        let a = sim.call(&host, &r, NOW);
                        let report = e.exchange_answer(home, r.ticket, a).unwrap();
                        for fault in report.faults {
                            assert!(matches!(fault, Fault::More { .. }), "{fault:?}");
                            more = true;
                        }
                        src.store(&report.store);
                    }
                }
            }
            if !more {
                break;
            }
        }
    }
    let ms = start.elapsed().as_secs_f64() * 1000.;
    let peak = rss();
    let stats = e.stats();
    let held = e.account().records().len();
    assert_eq!(held as u64, n);
    assert_eq!(
        stats.signatures_verified,
        if case == "cold" {
            n
        } else if case == "catchup" {
            n - n / 10
        } else {
            0
        }
    );
    assert!(e.source_faults().is_empty());
    assert!(e.missing_covered().is_empty());
    assert_eq!(stats.unread_paths, 0);
    println!(
        "{}",
        json!({"size":n,"case":case,"run":run,"ms":ms,"peak_rss_bytes":peak,"requests":requests,"passes":passes,"records_read":stats.records_read,"signatures_verified":stats.signatures_verified,"payloads_decrypted":stats.payloads_decrypted,"held_operations":held,"open_mode":format!("{:?}",e.open_mode()),"phases_ms":{"saved_read":saved_ms,"inventory":listing_ms,"authority_checkpoint":authority_checkpoint_ms,"unlock_load":unlock_load_ms,"exchange":ms-saved_ms-listing_ms-authority_checkpoint_ms-unlock_load_ms},"uptime":uptime.trim()})
    );
    if case == "resumed" {
        let start = Instant::now();
        e.advance(NOW).unwrap();
        e.refresh(src.listing()).unwrap();
        for w in e.record_due().unwrap() {
            src.store(&w.stores);
        }
        let refresh_ms = start.elapsed().as_secs_f64() * 1000.;
        let phase = Instant::now();
        let a = e
            .begin_write(
                NS,
                "capture",
                json!({"id":"one-new-item","title":"One new synthetic record"}),
                Level::Write,
                [245; 32],
            )
            .unwrap()
            .unwrap();
        let signatures = host.sign(a.steps());
        let prepare_sign_ms = phase.elapsed().as_secs_f64() * 1000.;
        let phase = Instant::now();
        let w = e.finish_write(a, signatures).unwrap();
        let finish_ms = phase.elapsed().as_secs_f64() * 1000.;
        let phase = Instant::now();
        assert_eq!(w.stores.len(), 1);
        src.store(&w.stores);
        assert_eq!(src.read(&w.stores[0].0).unwrap(), w.stores[0].1);
        let store_ms = phase.elapsed().as_secs_f64() * 1000.;
        let ms = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(
            e.record_verdict(&w.stores[0].0).as_deref(),
            Some("admitted")
        );
        println!(
            "{}",
            json!({"size":n,"case":"write","run":run,"ms":ms,"stores":w.stores.len(),"stored_bytes":w.stores[0].1.len(),"phases_ms":{"refresh":refresh_ms,"prepare_sign":prepare_sign_ms,"finish_verify_apply":finish_ms,"store_fsync":store_ms},"uptime":uptime.trim()})
        );
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
        "fixture" => fixture(Path::new(&args[2]), args[3].parse().unwrap()),
        "child" => child(Path::new(&args[2]), &args[3], args[4].parse().unwrap()),
        "all" => all(Path::new(&args[2]), Path::new(&args[3])),
        _ => panic!("fixture ROOT SIZE | child ROOT cold|resumed|catchup RUN"),
    }
}

fn all(root: &Path, output: &Path) {
    assert!(!root.exists(), "choose a fresh benchmark directory");
    let exe = std::env::current_exe().unwrap();
    let command = |args: &[String]| {
        let o = Command::new(&exe).args(args).output().unwrap();
        eprint!("{}", String::from_utf8_lossy(&o.stderr));
        assert!(
            o.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&o.stdout)
        );
        o.stdout
    };
    let shell = |cmd: &str| {
        String::from_utf8(
            Command::new("sh")
                .args(["-c", cmd])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string()
    };
    let mut result = json!({"date":"2026-11-16","commit":shell("git rev-parse HEAD"),"machine":{"model":"MacBook Pro Mac15,9","chip":"Apple M3 Max","cores":16,"performance_cores":12,"memory_gib":64,"os":shell("sw_vers -productVersion"),"rustc":shell("rustc --version")},"profile":"release (workspace LTO=true, opt-level=3)","rss_method":"getrusage(RUSAGE_SELF), Darwin ru_maxrss bytes; fresh child per case/run, sampled before write; includes process setup and simulated home for catchup","measurements":[],"fixtures":[],"stopped_unusable":false});
    result["started_utc"] = json!(shell("date -u +%Y-%m-%dT%H:%M:%SZ"));
    result["pressroom_threads"] = json!(std::env::var("PRESSROOM_THREADS").ok());
    result["cargo_target_dir"] = json!(std::env::var("CARGO_TARGET_DIR").ok());
    result["fixture_shape"] = json!("N immutable operations in reading.saved: 83 required blob manifests followed by N-83 distinct captured items; one writer, 64 authority entries; fixed 83 blobs / 249 chunks / 10,880,387 plaintext bytes at every size. Prefix has N/10 operations, all authority, all blobs; saved before any home pass.");
    result["timing_boundary"] = json!("Cold/resumed: read host inventory manifest, read sealed saved bytes if resumed, Engine::open, software ECDH and finish_unlock_epochs (all disk record reads and judgement). Catchup additionally runs all simulated-home passes and fsyncs received stores. Write after resumed open includes advance/refresh/record_due, prepare/software sign/finish and file+directory fsync. Excludes fixture/saved-state construction, simulator hydration, process launch, key setup, UI, checkpoint saving, network and language ABI. OS filesystem caches uncontrolled/warm; cold means no engine saved state.");
    for n in [2000, 10000, 100000] {
        let dir = root.join(n.to_string());
        let d = dir.to_str().unwrap().to_string();
        command(&["fixture".into(), d.clone(), n.to_string()]);
        let mut meta: Value =
            serde_json::from_slice(&fs::read(dir.join("meta.json")).unwrap()).unwrap();
        meta["saved_bytes"] = json!(fs::metadata(dir.join("saved.bin")).unwrap().len());
        result["fixtures"].as_array_mut().unwrap().push(meta);
        for run in 1..=5 {
            for case in ["cold", "resumed", "catchup"] {
                eprintln!("measure {n} {case} {run}/5");
                let bytes = command(&["child".into(), d.clone(), case.into(), run.to_string()]);
                for line in String::from_utf8(bytes).unwrap().lines() {
                    let v: Value = serde_json::from_str(line).unwrap();
                    println!("{v}");
                    result["measurements"].as_array_mut().unwrap().push(v);
                }
                fs::create_dir_all(output.parent().unwrap()).unwrap();
                fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
            }
        }
        if n == 2000 {
            let unusable = result["measurements"].as_array().unwrap().iter().any(|v| {
                let limit = match v["case"].as_str().unwrap() {
                    "cold" => 10000.,
                    "resumed" => 1000.,
                    "write" => 100.,
                    _ => f64::INFINITY,
                };
                v["ms"].as_f64().unwrap() > limit
                    || v["peak_rss_bytes"].as_u64().unwrap_or(0) > 300_000_000
            });
            if unusable {
                result["stopped_unusable"] = json!(true);
                fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
                eprintln!("STOP: owner-size unusability threshold crossed; no engine changes");
                break;
            }
        }
    }
    eprintln!("saved raw measurements to {}", output.display());
}
