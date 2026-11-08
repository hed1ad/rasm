//! Stable-toolchain smoke run of every fuzz target: N deterministic inputs
//! per target (`DASM_FUZZ_ITERS`, default 100 000; run with `--release`),
//! plus the reproducers in `regressions/`.
//!
//! A panic whose message carries a known finding id
//! (`dasm_fuzz::report::KNOWN`) is counted and printed, not failed: those
//! are filed bugs. Any other panic fails the test with the offending input
//! written to `artifacts/<target>/`.

use std::cell::{Cell, RefCell};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Once;

use dasm_core::testing::MockArch;
use dasm_core::{
    Address, AddressRange, ArchId, BinaryInfo, LoadError, LoadOptions, LoadedImage, Loader,
    MemoryMap, MemoryRegion, Permissions, SharedBytes, sha256,
};
use dasm_fuzz::elf_image::{self, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS, SectionSpec};
use dasm_fuzz::generate::Rng;
use dasm_fuzz::report::KNOWN;

thread_local! {
    static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
}

fn iterations() -> u64 {
    std::env::var("DASM_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

/// Installs (once, process-wide) a hook that records panics of inputs run
/// under [`capture`] instead of printing them; other panics print as usual.
fn quiet_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let default = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !CAPTURING.with(Cell::get) {
                default(info);
                return;
            }
            let msg = info
                .payload()
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    info.payload()
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_owned())
                })
                .unwrap_or_default();
            let at = info
                .location()
                .map(|l| format!(" at {}:{}", l.file(), l.line()))
                .unwrap_or_default();
            LAST_PANIC.with(|p| *p.borrow_mut() = Some(format!("{msg}{at}")));
        }));
    });
}

/// Runs `f` with panics recorded; returns the panic message, if any.
fn capture(f: impl FnOnce()) -> Option<String> {
    quiet_hook();
    CAPTURING.with(|c| c.set(true));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    CAPTURING.with(|c| c.set(false));
    let msg = LAST_PANIC
        .with(|p| p.borrow_mut().take())
        .unwrap_or_default();
    result.err().map(|_| msg)
}

/// A fuzz target entry point.
type Target = fn(&[u8]);

#[derive(Default)]
struct Outcome {
    runs: u64,
    known: Vec<(String, Vec<u8>)>,
}

/// Runs `target` on one input; returns `Err(message)` for an unknown panic.
fn run_one(target: fn(&[u8]), input: &[u8], out: &mut Outcome) -> Result<(), String> {
    out.runs += 1;
    let Some(msg) = capture(|| target(input)) else {
        return Ok(());
    };
    match KNOWN.iter().find(|id| msg.starts_with(&format!("[{id}]"))) {
        Some(_) => {
            if out.known.iter().all(|(m, _)| m.get(..13) != msg.get(..13)) {
                out.known.push((msg, input.to_vec()));
            }
            Ok(())
        }
        None => Err(msg),
    }
}

fn artifacts(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts")
        .join(name)
}

fn drive(name: &str, target: fn(&[u8]), mut next_input: impl FnMut(&mut Rng) -> Vec<u8>) {
    let mut rng = Rng::new(0x5eed ^ name.len() as u64);
    let mut out = Outcome::default();
    for i in 0..iterations() {
        let input = next_input(&mut rng);
        if let Err(msg) = run_one(target, &input, &mut out) {
            let dir = artifacts(name);
            let _ = std::fs::create_dir_all(&dir);
            let file = dir.join(format!("crash-{i}"));
            let _ = std::fs::write(&file, &input);
            panic!("{name}: input #{i} ({}) crashed: {msg}", file.display());
        }
    }
    for (msg, input) in &out.known {
        eprintln!(
            "{name}: known finding hit ({} input bytes): {msg}",
            input.len()
        );
    }
    eprintln!(
        "{name}: {} inputs, {} distinct known findings",
        out.runs,
        out.known.len()
    );
}

fn json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

#[test]
fn smoke_operation_json() {
    drive("operation_json", dasm_fuzz::operation_json::run, |rng| {
        let op = json(&rng.operation(3));
        if rng.one_in(2) { rng.mutate(op) } else { op }
    });
}

#[test]
fn smoke_journal_replay() {
    drive("journal_replay", dasm_fuzz::journal_replay::run, |rng| {
        let j = json(&rng.journal());
        if rng.one_in(3) { rng.mutate(j) } else { j }
    });
}

#[test]
fn smoke_memory_read() {
    drive("memory_read", dasm_fuzz::memory_read::run, |rng| {
        let len = rng.below(400) as usize;
        rng.bytes(len)
    });
}

#[test]
fn smoke_arch_with_mock() {
    fn target(data: &[u8]) {
        dasm_fuzz::arch::run_with(&MockArch, data);
    }
    drive("arch_mock", target, |rng| {
        const FIRST: [u8; 12] = [
            0x55, 0x5d, 0x90, 0xcc, 0xc3, 0x0f, 0x31, 0x48, 0xb8, 0xe8, 0xe9, 0xff,
        ];
        let len = rng.below(24) as usize;
        let mut b = rng.bytes(len);
        if let Some(x) = b.first_mut() {
            *x = FIRST.get(rng.below(12) as usize).copied().unwrap_or(0);
        }
        b
    });
}

/// A stand-in loader until `dasm-elf` lands: maps the file at 0x1000 (and,
/// for files starting with `\x7fELF`, also every alloc section of an
/// [`elf_image`] file as its own region), so the generic loader oracles and
/// the listing run on loader-shaped output.
struct RawLoader;

impl Loader for RawLoader {
    fn name(&self) -> &'static str {
        "raw"
    }
    fn probe(&self, _bytes: &[u8]) -> bool {
        true
    }
    fn load(&self, file: SharedBytes, options: &LoadOptions) -> Result<LoadedImage, LoadError> {
        if file.is_empty() {
            return Err(LoadError::UnknownFormat); // no empty regions (LDR-04)
        }
        let base = options.base.unwrap_or(Address(0x1000));
        let bad = |what: &str| LoadError::Malformed {
            what: what.into(),
            reason: "overflow".into(),
        };
        let range = AddressRange::from_len(base, file.len() as u64).map_err(|_| bad("range"))?;
        let region =
            MemoryRegion::new(range, file.clone(), Permissions::RX).map_err(|_| bad("region"))?;
        Ok(LoadedImage {
            info: BinaryInfo {
                arch: ArchId::X86_64,
                sha256: sha256(file.as_slice()),
                ..Default::default()
            },
            memory: MemoryMap::new(vec![region]).map_err(|_| bad("map"))?,
            ..Default::default()
        })
    }
}

#[test]
fn smoke_loader_contract_with_raw_loader() {
    fn target(data: &[u8]) {
        dasm_fuzz::loader::run_with(&RawLoader, data);
    }
    let iters = iterations() / 20;
    let mut rng = Rng::new(7);
    let mut out = Outcome::default();
    for _ in 0..iters.max(1) {
        let eh_len = rng.below(64) as usize;
        let eh = rng.bytes(eh_len);
        let (file, _) = elf_image::build(&[
            SectionSpec {
                name: ".text",
                sh_type: SHT_PROGBITS,
                flags: SHF_ALLOC | SHF_EXECINSTR,
                data: &[0xc3; 16],
            },
            SectionSpec {
                name: ".eh_frame",
                sh_type: SHT_PROGBITS,
                flags: SHF_ALLOC,
                data: &eh,
            },
        ]);
        let input = rng.mutate(file);
        if let Err(msg) = run_one(target, &input, &mut out) {
            panic!("loader contract: {msg}");
        }
    }
}

/// The ELF writer produces files `readelf` accepts (skipped if binutils is
/// not installed).
#[test]
fn elf_image_is_valid_elf() {
    let (file, placed) = elf_image::build(&[
        SectionSpec {
            name: ".text",
            sh_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            data: &[0xc3; 16],
        },
        SectionSpec {
            name: ".eh_frame",
            sh_type: SHT_PROGBITS,
            flags: SHF_ALLOC,
            data: &[0; 8],
        },
        SectionSpec {
            name: ".debug_info",
            sh_type: SHT_PROGBITS,
            flags: 0,
            data: b"abc",
        },
    ]);
    assert_eq!(placed.first().map(|p| p.addr), Some(0x1000));
    let path = std::env::temp_dir().join(format!("dasm-fuzz-elf-{}", std::process::id()));
    std::fs::write(&path, &file).unwrap_or_default();
    let output = std::process::Command::new("readelf")
        .arg("-SlW")
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    let Ok(output) = output else {
        eprintln!("readelf not found, skipping");
        return;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && err.trim().is_empty(),
        "readelf: {err}"
    );
    for name in [".text", ".eh_frame", ".debug_info", ".shstrtab", "LOAD"] {
        assert!(text.contains(name), "{name} missing in:\n{text}");
    }
}

#[test]
fn dwarf_split_is_total() {
    let empty: Vec<&[u8]> = vec![&[], &[], &[]];
    assert_eq!(elf_image::split(&[], 3), empty);
    let parts = elf_image::split(&[2, 0, 1, 0, 9, 9, 7, 6, 5], 3);
    assert_eq!(parts, vec![&[9, 9][..], &[7][..], &[6, 5][..]]);
}

/// Every file in `regressions/<target>/` is replayed. Files named
/// `known-<ID>-*` must still reproduce finding `<ID>` while it is listed in
/// `KNOWN` (delete the file's prefix once fixed: then it must pass).
#[test]
fn regressions() {
    #[allow(unused_mut)] // the backend targets are behind features
    let mut targets: Vec<(&str, Target)> = vec![
        ("journal_replay", dasm_fuzz::journal_replay::run),
        ("memory_read", dasm_fuzz::memory_read::run),
        ("operation_json", dasm_fuzz::operation_json::run),
    ];
    #[cfg(feature = "elf")]
    targets.extend([
        ("elf_load", dasm_fuzz::elf_load::run as Target),
        ("eh_frame", dasm_fuzz::eh_frame::run as Target),
        ("dwarf", dasm_fuzz::dwarf::run as Target),
    ]);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("regressions");
    let mut failures = Vec::new();
    for (name, target) in targets {
        let Ok(dir) = std::fs::read_dir(root.join(name)) else {
            continue;
        };
        for file in dir.flatten() {
            let path = file.path();
            let Ok(input) = std::fs::read(&path) else {
                continue;
            };
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let panicked = capture(|| target(&input));
            let ok = panicked.is_none();
            let msg = panicked.unwrap_or_default();
            let expected = file_name
                .strip_prefix("known-")
                .and_then(|rest| KNOWN.iter().find(|id| rest.starts_with(*id)));
            match (expected, ok) {
                (None, true) => {}
                (None, false) => failures.push(format!("{name}/{file_name}: {msg}")),
                (Some(id), false) if msg.starts_with(&format!("[{id}]")) => {}
                (Some(id), _) => {
                    failures.push(format!("{name}/{file_name}: expected {id}, got {msg:?}"))
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Hand-written edge cases that must not crash (stack depth, sizes).
#[test]
fn deep_and_large_json_does_not_crash() {
    // 100k nested batches: serde_json's recursion limit must reject it
    // before the stack overflows.
    let mut deep = String::new();
    for _ in 0..100_000 {
        deep.push_str(r#"{"op":"batch","ops":["#);
    }
    dasm_fuzz::operation_json::run(deep.as_bytes());
    // The deepest nesting serde_json accepts, applied and inverted.
    let mut ok = String::new();
    let mut depth = 0;
    loop {
        let mut candidate = String::new();
        for _ in 0..=depth {
            candidate.push_str(r#"{"op":"batch","ops":["#);
        }
        candidate.push_str(r#"{"op":"rename","address":"0x1000","name":"x"}"#);
        for _ in 0..=depth {
            candidate.push_str("]}");
        }
        if serde_json::from_str::<dasm_core::Operation>(&candidate).is_err() {
            break;
        }
        ok = candidate;
        depth += 1;
    }
    assert!(depth > 10, "nesting limit unexpectedly low: {depth}");
    dasm_fuzz::operation_json::run(ok.as_bytes());
    dasm_fuzz::journal_replay::run(format!(r#"[{{"seq":1,"op":{ok},"inverse":{ok},"meta":{{"author":"a","timestamp_ms":0,"source":{{"kind":"ui"}}}},"scope":null,"state":"active"}}]"#).as_bytes());
}

/// SEC-CORE-06 (open): an empty region between two mapped regions makes the
/// linear listing stop before the second one, hiding its contents from the
/// analyst. Correct behaviour asserted; ignored until the fix lands.
#[test]
#[ignore = "SEC-CORE-06: open finding, owner Architect"]
fn sec_core_06_listing_skips_empty_region() {
    use dasm_core::{Program, Snapshot};
    let region = |start: u64, len: u64| {
        MemoryRegion::new(
            AddressRange::from_len(Address(start), len).unwrap_or_default(),
            SharedBytes::from(vec![0x90; usize::try_from(len).unwrap_or(0)]),
            Permissions::RX,
        )
    };
    let regions: Vec<MemoryRegion> = [region(0x1000, 4), region(0x2000, 0), region(0x3000, 4)]
        .into_iter()
        .flatten()
        .collect();
    let Ok(memory) = MemoryMap::new(regions) else {
        return; // rejecting empty regions is a valid fix too
    };
    let image = LoadedImage {
        info: BinaryInfo {
            arch: ArchId::X86_64,
            ..Default::default()
        },
        memory,
        ..Default::default()
    };
    let snap = Snapshot::initial(std::sync::Arc::new(Program::new(
        image,
        std::sync::Arc::new(MockArch),
    )));
    let last = snap
        .listing_from(Address(0x1000))
        .last()
        .map(|i| i.range.start());
    assert_eq!(last, Some(Address(0x3003)), "listing stopped early");
}

/// SEC-CORE-01, fixed on main in 6b0fbf4: a linked source is opened once
/// (`O_NONBLOCK`) and must be a regular file, so a device or a FIFO from a
/// project is refused without being read or blocking.
#[test]
fn sec_core_01_linked_special_files_are_refused() {
    use dasm_core::StoredSource;
    let linked = |path: &Path| {
        StoredSource::linked("x", path, sha256(b""), LoadOptions::default()).read_bytes()
    };
    // Would succeed if devices were read: /dev/null yields the empty input.
    let read = linked(Path::new("/dev/null")).map(|b| b.len());
    assert!(read.is_err(), "/dev/null was read: {read:?}");
    let Ok(dir) = tempfile_dir() else {
        return;
    };
    let fifo = dir.join("fifo");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    if made.is_ok_and(|s| s.success()) {
        let read = linked(&fifo).map(|b| b.len());
        assert!(read.is_err(), "FIFO was read: {read:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn tempfile_dir() -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("dasm-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// SEC-CORE-02, fixed on main in 6b0fbf4: `limits` in a stored project is
/// ignored, the limits of the running build apply.
#[test]
fn sec_core_02_project_cannot_set_limits() {
    let stored = r#"{"base":"0x1000","limits":{"max_file_size":1,"max_symbols":1}}"#;
    let options: Result<LoadOptions, _> = serde_json::from_str(stored);
    let Ok(options) = options else {
        panic!("stored options must parse");
    };
    assert_eq!(options.base, Some(Address(0x1000)));
    assert_eq!(options.limits, dasm_core::Limits::default());
    let json = serde_json::to_string(&options).unwrap_or_default();
    assert!(!json.contains("limits"), "limits persisted: {json}");
}

/// Stable runs of the ELF targets (`cargo test --release --features elf`).
#[cfg(feature = "elf")]
mod elf {
    use super::*;

    fn wrapped(rng: &mut Rng) -> Vec<u8> {
        let len = rng.below(256) as usize;
        rng.bytes(len)
    }

    #[test]
    fn smoke_elf_load() {
        drive("elf_load", dasm_fuzz::elf_load::run, |rng| {
            let eh = wrapped(rng);
            let (file, _) = elf_image::build(&[
                SectionSpec {
                    name: ".text",
                    sh_type: SHT_PROGBITS,
                    flags: SHF_ALLOC | SHF_EXECINSTR,
                    data: &[0xc3; 16],
                },
                SectionSpec {
                    name: ".eh_frame",
                    sh_type: SHT_PROGBITS,
                    flags: SHF_ALLOC,
                    data: &eh,
                },
            ]);
            rng.mutate(file)
        });
    }

    #[test]
    fn smoke_eh_frame() {
        drive("eh_frame", dasm_fuzz::eh_frame::run, wrapped);
    }

    #[test]
    fn smoke_dwarf() {
        drive("dwarf", dasm_fuzz::dwarf::run, wrapped);
    }
}
