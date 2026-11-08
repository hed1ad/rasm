use std::sync::Arc;
use std::time::{Duration, Instant};

use dasm_core::testing::{self, addrs};
use dasm_core::{
    Address, AddressRange, AnalysisDriver, AnalysisResults, AnalysisState, Focus, Operation,
    PassId, Snapshot, SnapshotHub, UndoInfo, Xref,
};

use crate::{Config, Scheduler};

const WAIT: Duration = Duration::from_secs(30);

fn hub() -> Arc<SnapshotHub> {
    let program = testing::synthetic_program().unwrap();
    SnapshotHub::new(Snapshot::initial(Arc::new(program)))
}

fn cfg(threads: usize) -> Config {
    Config {
        threads,
        publish_interval: Duration::from_millis(20),
    }
}

fn run(hub: &Arc<SnapshotHub>, threads: usize) -> Scheduler {
    let s = Scheduler::new(cfg(threads)).unwrap();
    s.start(Arc::clone(hub));
    assert!(s.wait_idle(WAIT), "analysis did not finish");
    s
}

/// Applies a user operation to the hub and tells the driver.
fn apply(hub: &SnapshotHub, s: &Scheduler, op: &Operation) {
    let snap = hub.load();
    let mut user = snap.user().clone();
    user.apply(op).unwrap();
    hub.publish_user(user, UndoInfo::default());
    s.invalidate(&op.changes());
    assert!(s.wait_idle(WAIT), "re-analysis did not finish");
}

/// Everything that must be identical between two analyses.
fn dump(r: &AnalysisResults) -> String {
    let mut out = String::new();
    for f in r.functions() {
        out.push_str(&format!("{f:?}\n"));
    }
    let mut x: Vec<Xref> = r.all_xrefs().copied().collect();
    x.sort_unstable();
    x.dedup();
    for x in x {
        out.push_str(&format!("{x:?}\n"));
    }
    for s in r.strings() {
        out.push_str(&format!("{s:?}\n"));
    }
    out
}

fn count(s: &Scheduler, id: &str) -> u64 {
    s.run_counts()
        .get(&PassId::new(id))
        .copied()
        .unwrap_or_default()
}

#[test]
fn synthetic_matches_reference() {
    let hub = hub();
    let s = run(&hub, 4);
    let snap = hub.load();
    let got = snap.analysis();
    assert_eq!(got.progress.state, AnalysisState::Done);
    let want = testing::reference_analysis(&snap);
    assert_eq!(dump(got), dump(&want));
    assert_eq!(got.function_count(), 4);
    assert_eq!(s.error_count(), 0);
}

#[test]
fn deterministic_across_threads_and_focus() {
    let mut dumps = Vec::new();
    for threads in [1, 2, 12] {
        for focus in [
            Focus::default(),
            Focus {
                cursor: Some(addrs::HELPER),
                visible: None,
            },
            Focus {
                cursor: Some(addrs::MAIN_SKIP),
                visible: AddressRange::from_len(addrs::START, 0x30).ok(),
            },
        ] {
            let hub = hub();
            let s = Scheduler::new(cfg(threads)).unwrap();
            s.set_focus(focus);
            s.start(Arc::clone(&hub));
            assert!(s.wait_idle(WAIT));
            dumps.push(dump(hub.load().analysis()));
        }
    }
    assert!(dumps.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn rename_invalidates_nothing() {
    let hub = hub();
    let s = run(&hub, 2);
    s.reset_run_counts();
    apply(
        &hub,
        &s,
        &Operation::Rename {
            address: addrs::MAIN,
            name: Some("entry_main".into()),
        },
    );
    assert!(s.run_counts().values().all(|n| *n == 0));
}

#[test]
fn delete_function_recomputes_only_what_is_affected() {
    let hub = hub();
    let s = run(&hub, 2);
    s.reset_run_counts();
    apply(
        &hub,
        &s,
        &Operation::DeleteFunction {
            address: addrs::HELPER,
        },
    );
    assert_eq!(count(&s, "strings"), 0);
    assert_eq!(count(&s, "entry_points"), 1);
    // Only the caller is re-analysed.
    assert_eq!(count(&s, "functions"), 1);
    let snap = hub.load();
    assert!(snap.analysis().function_at(addrs::HELPER).is_none());
    assert_eq!(
        dump(snap.analysis()),
        dump(&testing::reference_analysis(&snap))
    );
    // Undo-like: reset brings it back.
    apply(
        &hub,
        &s,
        &Operation::ResetFunction {
            address: addrs::HELPER,
        },
    );
    let snap = hub.load();
    assert!(snap.analysis().function_at(addrs::HELPER).is_some());
    assert_eq!(
        dump(snap.analysis()),
        dump(&testing::reference_analysis(&snap))
    );
}

#[test]
fn create_function_matches_a_fresh_analysis() {
    let hub = hub();
    let s = run(&hub, 3);
    apply(
        &hub,
        &s,
        &Operation::CreateFunction {
            address: addrs::MAIN_SKIP,
        },
    );
    let incremental = dump(hub.load().analysis());
    let fresh_hub = hub.clone();
    let fresh = Scheduler::new(cfg(5)).unwrap();
    fresh.start(fresh_hub);
    assert!(fresh.wait_idle(WAIT));
    assert_eq!(incremental, dump(hub.load().analysis()));
    let snap = hub.load();
    let skip = snap.analysis().function_at(addrs::MAIN_SKIP).unwrap();
    assert_eq!(skip.source, dasm_core::FunctionSource::User);
    // `main` falls into the new function, so it still returns.
    let main = snap.analysis().function_at(addrs::MAIN).unwrap();
    assert!(!main.flags.noreturn);
}

#[test]
fn patch_bytes_recomputes_only_the_patched_function() {
    let hub = hub();
    let s = run(&hub, 2);
    s.reset_run_counts();
    // `mov eax, 0x2a` -> `mov eax, 0x2b` in the helper.
    apply(
        &hub,
        &s,
        &Operation::PatchBytes {
            address: Address(addrs::HELPER.get() + 1),
            bytes: vec![0x2b],
        },
    );
    assert_eq!(count(&s, "entry_points"), 0);
    assert_eq!(count(&s, "functions"), 1);
    assert_eq!(count(&s, "xrefs"), 1);
    let snap = hub.load();
    assert_eq!(
        dump(snap.analysis()),
        dump(&testing::reference_analysis(&snap))
    );
}

#[test]
fn patch_that_kills_the_return_propagates() {
    let hub = big_hub(6);
    let s = run(&hub, 2);
    assert!(hub.load().analysis().functions().all(|f| !f.flags.noreturn));
    // The last function's `ret` becomes `hlt`: the whole chain stops
    // returning.
    apply(
        &hub,
        &s,
        &Operation::PatchBytes {
            address: Address(0x10_0000 + 5 * 8),
            bytes: vec![0xf4],
        },
    );
    let snap = hub.load();
    let r = snap.analysis();
    assert!(r.functions().all(|f| f.flags.noreturn));
    // Same as analysing the patched program from scratch.
    let incremental = dump(r);
    let fresh = Scheduler::new(cfg(2)).unwrap();
    fresh.start(Arc::clone(&hub));
    assert!(fresh.wait_idle(WAIT));
    assert_eq!(incremental, dump(hub.load().analysis()));
}

#[test]
fn cancel_stops_quickly_and_keeps_results_consistent() {
    let hub = big_hub(200_000);
    let s = Scheduler::new(cfg(4)).unwrap();
    s.start(Arc::clone(&hub));
    std::thread::sleep(Duration::from_millis(10));
    let t = Instant::now();
    s.cancel();
    let after_cancel = t.elapsed();
    assert!(s.wait_idle(Duration::from_secs(5)));
    let took = t.elapsed();
    eprintln!("cancel() {after_cancel:?}, idle {took:?}");
    assert!(took < Duration::from_millis(50), "cancel took {took:?}");
    assert_eq!(s.state(), AnalysisState::Cancelled);
    assert_eq!(
        hub.load().analysis().progress.state,
        AnalysisState::Cancelled
    );
}

/// A program of `n` chained functions: `f_i: call f_{i+1}; ret`.
fn big_hub(n: u64) -> Arc<SnapshotHub> {
    use dasm_core::{
        ArchId, BinaryInfo, FunctionHint, FunctionHintSource, LoadedImage, MemoryMap, MemoryRegion,
        Permissions, SharedBytes,
    };
    let base = 0x10_0000u64;
    let mut text = Vec::new();
    for i in 0..n {
        // call rel32 (+0 -> next function), ret, pad to 8 bytes
        if i + 1 == n {
            text.extend_from_slice(&[0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]);
        } else {
            text.extend_from_slice(&[0xe8, 0x03, 0, 0, 0, 0xc3, 0xcc, 0xcc]);
        }
    }
    let region = MemoryRegion::new(
        AddressRange::from_len(Address(base), text.len() as u64).unwrap(),
        SharedBytes::from(text),
        Permissions::RX,
    )
    .unwrap();
    let image = LoadedImage {
        info: BinaryInfo {
            arch: ArchId::Mock,
            ..Default::default()
        },
        memory: MemoryMap::new(vec![region]).unwrap(),
        function_hints: (0..n)
            .map(|i| FunctionHint {
                address: Address(base + i * 8),
                size: None,
                source: FunctionHintSource::EhFrame,
            })
            .collect(),
        ..Default::default()
    };
    let program = dasm_core::Program::new(image, Arc::new(testing::MockArch));
    SnapshotHub::new(Snapshot::initial(Arc::new(program)))
}

/// Uncalled functions are found by the prologue sweep: one round per gap,
/// not one round per function (16k functions used to take ~8.6 s).
#[test]
fn sweep_finds_uncalled_functions_fast() {
    use dasm_core::{
        ArchId, BinaryInfo, LoadedImage, MemoryMap, MemoryRegion, Permissions, SharedBytes,
    };
    let n: u64 = 16_000;
    let base = 0x10_0000u64;
    let mut text = Vec::new();
    for _ in 0..n {
        // push rbp; mov rbp, rsp; xor eax, eax; ret; int3
        text.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0xc3, 0xcc]);
    }
    let region = MemoryRegion::new(
        AddressRange::from_len(Address(base), text.len() as u64).unwrap(),
        SharedBytes::from(text),
        Permissions::RX,
    )
    .unwrap();
    let image = LoadedImage {
        info: BinaryInfo {
            arch: ArchId::X86_64,
            ..Default::default()
        },
        memory: MemoryMap::new(vec![region]).unwrap(),
        ..Default::default()
    };
    let program = dasm_core::Program::new(image, Arc::new(dasm_x86::X86_64));
    let hub = SnapshotHub::new(Snapshot::initial(Arc::new(program)));
    let t = Instant::now();
    let s = Scheduler::new(cfg(4)).unwrap();
    s.start(Arc::clone(&hub));
    assert!(s.wait_idle(WAIT), "analysis did not finish");
    let took = t.elapsed();
    assert_eq!(hub.load().analysis().function_count(), n as usize);
    assert!(count(&s, "linear_sweep") <= 2, "sweep needed many rounds");
    assert!(took < Duration::from_secs(25), "sweep took {took:?}");
}

#[test]
fn long_call_chain_resolves_and_matches_reference() {
    let hub = big_hub(300);
    let s = run(&hub, 4);
    let snap = hub.load();
    let r = snap.analysis();
    assert_eq!(r.function_count(), 300);
    assert!(r.functions().all(|f| !f.flags.noreturn));
    let (a, b) = (dump(r), dump(&testing::reference_analysis(&snap)));
    for (x, y) in a.lines().zip(b.lines()) {
        assert_eq!(x, y);
    }
    assert_eq!(a.lines().count(), b.lines().count());
    drop(s);
}

// ------------------------------------------------- x86-64 mini program

mod x86 {
    use super::*;
    use dasm_core::{
        ArchId, BinaryInfo, EdgeKind, FunctionHint, FunctionHintSource, FunctionSource, Import,
        LoadedImage, MemoryMap, MemoryRegion, Permissions, SharedBytes, StringEncoding, SymbolKind,
        Target, XrefKind,
    };
    use dasm_x86::X86_64;

    pub(super) const F1: u64 = 0x1000;
    pub(super) const F2: u64 = 0x1010;
    pub(super) const F3: u64 = 0x1020;
    pub(super) const F4: u64 = 0x1030;
    pub(super) const F5: u64 = 0x1050;
    pub(super) const PLT: u64 = 0x1100;
    pub(super) const GOT: u64 = 0x2000;

    fn put(buf: &mut [u8], at: u64, bytes: &[u8]) {
        let off = (at - 0x1000) as usize;
        buf[off..off + bytes.len()].copy_from_slice(bytes);
    }

    pub(super) fn hub() -> Arc<SnapshotHub> {
        let mut text = vec![0xccu8; 0x110];
        put(&mut text, F1, &[0xe8, 0xfb, 0, 0, 0, 0xc3]);
        put(&mut text, F2, &[0xe9, 0x0b, 0, 0, 0]);
        put(&mut text, F3, &[0xc3]);
        put(&mut text, F4, &[0xe8, 0xeb, 0xff, 0xff, 0xff]);
        put(&mut text, 0x1035, &[0x48, 0xff, 0x05, 0xd4, 0x0f, 0, 0]);
        put(&mut text, 0x103c, &[0xff, 0x15, 0xbe, 0x0f, 0, 0]);
        put(&mut text, 0x1042, &[0xc3]);
        put(&mut text, F5, &[0x55, 0x48, 0x89, 0xe5, 0xc3]);
        put(&mut text, PLT, &[0xff, 0x25, 0xfa, 0x0e, 0, 0]);
        let mut data = vec![0u8; 0x20];
        data[..8].copy_from_slice(&0x1106u64.to_le_bytes());
        data[8..16].copy_from_slice(&F4.to_le_bytes());
        let mut ro = vec![0u8; 0x80];
        ro[..12].copy_from_slice(b"hello world\0");
        for (i, c) in "ab c".encode_utf16().enumerate() {
            ro[0x10 + i * 2..0x12 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        for (i, c) in "xyz".chars().enumerate() {
            ro[0x20 + i * 4..0x24 + i * 4].copy_from_slice(&u32::from(c).to_le_bytes());
        }
        for (i, c) in "Big".encode_utf16().enumerate() {
            ro[0x40 + i * 2..0x42 + i * 2].copy_from_slice(&c.to_be_bytes());
        }
        let cafe = "caf\u{e9} ok".as_bytes();
        ro[0x50..0x50 + cafe.len()].copy_from_slice(cafe);
        let reg = |start: u64, data: Vec<u8>, perms| {
            MemoryRegion::new(
                AddressRange::from_len(Address(start), data.len() as u64).unwrap(),
                SharedBytes::from(data),
                perms,
            )
            .unwrap()
        };
        let hint = |a: u64, source| FunctionHint {
            address: Address(a),
            size: None,
            source,
        };
        let image = LoadedImage {
            info: BinaryInfo {
                arch: ArchId::X86_64,
                ..Default::default()
            },
            memory: MemoryMap::new(vec![
                reg(0x1000, text, Permissions::RX),
                reg(0x2000, data, Permissions::RW),
                reg(0x3000, ro, Permissions::R),
            ])
            .unwrap(),
            imports: vec![Import {
                name: "exit".into(),
                kind: SymbolKind::Function,
                plt: Some(Address(PLT)),
                got: Some(Address(GOT)),
                ..Default::default()
            }],
            function_hints: vec![
                hint(F1, FunctionHintSource::Symbol),
                hint(F2, FunctionHintSource::Symbol),
                hint(F4, FunctionHintSource::Symbol),
                hint(PLT, FunctionHintSource::Plt),
            ],
            ..Default::default()
        };
        let program = dasm_core::Program::new(image, Arc::new(X86_64));
        SnapshotHub::new(Snapshot::initial(Arc::new(program)))
    }

    #[test]
    fn x86_program_analysis() {
        let hub = hub();
        let s = run(&hub, 3);
        assert_eq!(s.error_count(), 0);
        let snap = hub.load();
        let r = snap.analysis();
        let f = |a: u64| r.function_at(Address(a)).unwrap();

        // exit through the PLT: the call ends the path.
        assert!(f(F1).flags.noreturn);
        assert_eq!(f(F1).insn_count(), 1);
        // PLT stub of a noreturn import.
        assert!(f(PLT).flags.thunk && f(PLT).flags.plt && f(PLT).flags.noreturn);
        // Tail call to a function found through a call.
        assert_eq!(f(F3).source, FunctionSource::CallTarget);
        assert!(!f(F2).flags.noreturn);
        assert_eq!(f(F2).insn_count(), 1);
        let edge = f(F2).blocks[0].successors[0];
        assert_eq!(edge.kind, EdgeKind::TailCall);
        assert_eq!(edge.target, Target::Direct(Address(F3)));
        // `call [rip+GOT]` of exit (-fno-plt): no return.
        assert!(f(F4).flags.noreturn);
        assert_eq!(f(F4).insn_count(), 3);
        // Found by the prologue sweep.
        assert_eq!(f(F5).source, FunctionSource::Prologue);
        assert!(!f(F5).flags.noreturn);

        let xr = |from: u64| -> Vec<(u64, XrefKind)> {
            r.xrefs_from(Address(from))
                .map(|x| (x.to.get(), x.kind))
                .collect()
        };
        assert_eq!(xr(F4), vec![(F3, XrefKind::Call)]);
        assert_eq!(xr(0x1035), vec![(0x2010, XrefKind::ReadWrite)]);
        assert_eq!(xr(0x103c), vec![(GOT, XrefKind::Read)]);
        // Pointer in data; the GOT slot is not one.
        assert_eq!(xr(0x2008), vec![(F4, XrefKind::DataPtr)]);
        assert!(xr(GOT).is_empty());

        let strs: Vec<(u64, StringEncoding, String)> = r
            .strings()
            .map(|s| (s.address.get(), s.encoding, s.value.clone()))
            .collect();
        assert_eq!(
            strs,
            vec![
                (0x3000, StringEncoding::Ascii, "hello world".to_owned()),
                (0x3010, StringEncoding::Utf16Le, "ab c".to_owned()),
                (0x3020, StringEncoding::Utf32Le, "xyz".to_owned()),
                (0x3040, StringEncoding::Utf16Be, "Big".to_owned()),
                (0x3050, StringEncoding::Utf8, "caf\u{e9} ok".to_owned()),
            ]
        );
    }

    #[test]
    fn x86_incremental_equals_fresh() {
        let hub = hub();
        let s = run(&hub, 2);
        apply(
            &hub,
            &s,
            &Operation::DeleteFunction {
                address: Address(F5),
            },
        );
        assert!(hub.load().analysis().function_at(Address(F5)).is_none());
        apply(
            &hub,
            &s,
            &Operation::CreateFunction {
                address: Address(F3 + 0x100),
            },
        );
        apply(
            &hub,
            &s,
            &Operation::ResetFunction {
                address: Address(F5),
            },
        );
        let incremental = dump(hub.load().analysis());
        let fresh = Scheduler::new(cfg(7)).unwrap();
        fresh.start(Arc::clone(&hub));
        assert!(fresh.wait_idle(WAIT));
        assert_eq!(incremental, dump(hub.load().analysis()));
    }
}

#[test]
fn extra_passes_are_ordered_and_validated() {
    use dasm_core::{
        AnalysisDelta, AnalysisPass, ChangeKind, Error, Granularity, PassContext, PassScope,
    };
    struct Late(&'static str, Vec<PassId>);
    impl AnalysisPass for Late {
        fn id(&self) -> PassId {
            PassId::new(self.0)
        }
        fn dependencies(&self) -> Vec<PassId> {
            self.1.clone()
        }
        fn granularity(&self) -> Granularity {
            Granularity::Program
        }
        fn invalidated_by(&self) -> &[ChangeKind] {
            &[ChangeKind::Bytes]
        }
        fn run(&self, _: &PassContext<'_>, _: PassScope) -> Result<AnalysisDelta, Error> {
            Ok(AnalysisDelta::default())
        }
    }
    let bad = Scheduler::with_passes(
        cfg(1),
        vec![Arc::new(Late("x", vec![PassId::new("missing")]))],
    );
    assert!(bad.is_err());
    let cyc = Scheduler::with_passes(
        cfg(1),
        vec![
            Arc::new(Late("a", vec![PassId::new("b")])),
            Arc::new(Late("b", vec![PassId::new("a")])),
        ],
    );
    assert!(cyc.is_err());
    let s = Scheduler::with_passes(
        cfg(2),
        vec![Arc::new(Late(
            "extra",
            vec![dasm_core::pass::passes::XREFS],
        ))],
    )
    .unwrap();
    let hub = hub();
    s.start(Arc::clone(&hub));
    assert!(s.wait_idle(WAIT));
    assert_eq!(count(&s, "extra"), 1);
    apply(
        &hub,
        &s,
        &Operation::PatchBytes {
            address: addrs::HELPER,
            bytes: vec![0x90],
        },
    );
    assert_eq!(count(&s, "extra"), 2);
}

// ------------------------------------------------------ strings scaling

mod strings {
    use super::*;
    use dasm_core::{
        AnalysisPass, ArchId, BinaryInfo, CancelToken, LoadedImage, MemoryMap, MemoryRegion,
        PassContext, PassScope, Permissions, SharedBytes,
    };

    /// A 256 KiB run of text without a terminator used to be O(n * max_len)
    /// (tens of seconds); now the whole run is skipped after one scan.
    #[test]
    fn long_text_run_without_nul_is_scanned_once() {
        let region = MemoryRegion::new(
            AddressRange::from_len(Address(0x3000), 256 * 1024).unwrap(),
            SharedBytes::from(vec![b'A'; 256 * 1024]),
            Permissions::R,
        )
        .unwrap();
        let image = LoadedImage {
            info: BinaryInfo {
                arch: ArchId::X86_64,
                ..Default::default()
            },
            memory: MemoryMap::new(vec![region]).unwrap(),
            ..Default::default()
        };
        let program = dasm_core::Program::new(image, Arc::new(dasm_x86::X86_64));
        let snap = Snapshot::initial(Arc::new(program));
        let cancel = CancelToken::new();
        let ctx = PassContext {
            snapshot: &snap,
            cancel: &cancel,
        };
        let t = Instant::now();
        let delta = crate::strings::StringsPass::default()
            .run(&ctx, PassScope::Program)
            .unwrap();
        let took = t.elapsed();
        // Long runs are cut at `max_len` and reported.
        assert_eq!(delta.upsert_strings.len(), 4);
        assert!(took < Duration::from_secs(2), "strings took {took:?}");
    }
}

// ------------------------------------------------------ real binary

/// Analysis of `/usr/bin/ls`, with the image assembled from `readelf`
/// output (program headers, FDEs as function hints, GOT slots of imports),
/// because the ELF loader is developed separately. Run with
/// `cargo test -p dasm-analysis --release -- --ignored --nocapture`;
/// the wave C integration repeats it through `ElfLoader`.
mod real {
    use super::*;
    use dasm_core::{
        ArchId, BinaryInfo, FunctionHint, FunctionHintSource, Import, LoadedImage, MemoryMap,
        MemoryRegion, Permissions, SharedBytes, SymbolKind,
    };
    use std::collections::BTreeSet;
    use std::process::Command;

    fn readelf(args: &[&str]) -> Option<String> {
        let out = Command::new("readelf")
            .args(args)
            .arg("/usr/bin/ls")
            .output()
            .ok()?;
        // readelf exits with 1 on benign warnings.
        (!out.stdout.is_empty()).then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn hex(s: &str) -> Option<u64> {
        u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
    }

    fn load() -> Option<(Arc<SnapshotHub>, Vec<u64>)> {
        let file = std::fs::read("/usr/bin/ls").ok()?;
        let mut regions = Vec::new();
        for line in readelf(&["-lW"])?.lines() {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.first() != Some(&"LOAD") || t.len() < 8 {
                continue;
            }
            let (off, va, fsz, msz) = (hex(t[1])?, hex(t[2])?, hex(t[4])?, hex(t[5])?);
            let flags: String = t[6..t.len() - 1].concat();
            let mut data = file.get(off as usize..(off + fsz) as usize)?.to_vec();
            data.resize(msz as usize, 0);
            let perms = Permissions {
                read: flags.contains('R'),
                write: flags.contains('W'),
                execute: flags.contains('E'),
            };
            regions.push(
                MemoryRegion::new(
                    AddressRange::from_len(Address(va), msz).ok()?,
                    SharedBytes::from(data),
                    perms,
                )
                .ok()?,
            );
        }
        let mut fdes = Vec::new();
        for line in readelf(&["--debug-dump=frames"])?.lines() {
            if let Some(i) = line.find(" FDE ")
                && let Some(p) = line[i..].find("pc=")
            {
                let lo = line[i + p + 3..].split("..").next()?;
                fdes.push(hex(lo)?);
            }
        }
        fdes.sort_unstable();
        fdes.dedup();
        let mut imports = Vec::new();
        for line in readelf(&["-rW"])?.lines() {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() >= 5 && (t[2] == "R_X86_64_GLOB_DAT" || t[2] == "R_X86_64_JUMP_SLOT") {
                imports.push(Import {
                    name: t[4].split('@').next()?.to_owned(),
                    kind: SymbolKind::Function,
                    got: Some(Address(hex(t[0])?)),
                    ..Default::default()
                });
            }
        }
        let image = LoadedImage {
            info: BinaryInfo {
                arch: ArchId::X86_64,
                ..Default::default()
            },
            memory: MemoryMap::new(regions).ok()?,
            imports,
            function_hints: fdes
                .iter()
                .map(|a| FunctionHint {
                    address: Address(*a),
                    size: None,
                    source: FunctionHintSource::EhFrame,
                })
                .collect(),
            ..Default::default()
        };
        let program = dasm_core::Program::new(image, Arc::new(dasm_x86::X86_64));
        Some((SnapshotHub::new(Snapshot::initial(Arc::new(program))), fdes))
    }

    #[test]
    #[ignore = "needs readelf and /usr/bin/ls; prints timings, run in release"]
    fn usr_bin_ls() {
        let Some((hub, fdes)) = load() else {
            eprintln!("readelf or /usr/bin/ls unavailable: skipped");
            return;
        };
        let threads = Config::default().threads.max(11);
        let s = Scheduler::new(Config {
            threads,
            ..Config::default()
        })
        .unwrap();
        let focus = fdes[fdes.len() / 2];
        s.set_focus(Focus {
            cursor: Some(Address(focus)),
            visible: None,
        });
        let t = Instant::now();
        s.start(Arc::clone(&hub));
        let mut first = None;
        while first.is_none() && t.elapsed() < Duration::from_secs(20) {
            first = hub
                .load()
                .analysis()
                .function_at(Address(focus))
                .filter(|f| !f.blocks.is_empty())
                .map(|_| t.elapsed());
            std::thread::sleep(Duration::from_micros(200));
        }
        assert!(s.wait_idle(Duration::from_secs(60)));
        let total = t.elapsed();
        let snap = hub.load();
        let r = snap.analysis();
        let found: BTreeSet<u64> = r.functions().map(|f| f.entry.get()).collect();
        let hit = fdes.iter().filter(|a| found.contains(a)).count();
        eprintln!(
            "threads {threads}: total {total:?}, first publication of focused function {first:?}, \
             functions {}, FDE starts found {hit}/{} ({:.2}%), xrefs {}, strings {}, errors {}",
            r.function_count(),
            fdes.len(),
            100.0 * hit as f64 / fdes.len() as f64,
            r.all_xrefs().count(),
            r.strings().count(),
            s.error_count()
        );
        eprintln!("{:?}", s.run_counts());
        assert!(hit * 100 >= fdes.len() * 95);

        // Same result with one thread and another focus.
        let (hub1, _) = load().unwrap();
        let s1 = Scheduler::new(Config {
            threads: 1,
            ..Config::default()
        })
        .unwrap();
        s1.set_focus(Focus {
            cursor: Some(Address(fdes[3])),
            visible: AddressRange::from_len(Address(fdes[10]), 0x400).ok(),
        });
        s1.start(Arc::clone(&hub1));
        assert!(s1.wait_idle(Duration::from_secs(120)));
        let (da, db) = (dump(hub1.load().analysis()), dump(r));
        eprintln!("lines {} vs {}", da.lines().count(), db.lines().count());
        let first = da
            .lines()
            .zip(db.lines())
            .enumerate()
            .find(|(_, (x, y))| x != y);
        if let Some((i, (x, y))) = first {
            eprintln!("first difference at line {i}:\n  1 thread: {x}\n  {threads} threads: {y}");
        }
        assert!(da == db, "1 thread differs from {threads}");
    }
}

// ----------------------------------------- invalidation races (review)

/// A one-region x86-64 program with function hints at the given offsets.
fn mini_hub(text: Vec<u8>, hints: &[u64]) -> Arc<SnapshotHub> {
    let sized: Vec<(u64, Option<u64>)> = hints.iter().map(|h| (*h, None)).collect();
    mini_hub_sized(text, &sized)
}

/// Like [`mini_hub`], hints with the size the loader would give (FDE).
fn mini_hub_sized(text: Vec<u8>, hints: &[(u64, Option<u64>)]) -> Arc<SnapshotHub> {
    use dasm_core::{
        ArchId, BinaryInfo, FunctionHint, FunctionHintSource, LoadedImage, MemoryMap, MemoryRegion,
        Permissions, SharedBytes,
    };
    let base = 0x10_0000u64;
    let region = MemoryRegion::new(
        AddressRange::from_len(Address(base), text.len() as u64).unwrap(),
        SharedBytes::from(text),
        Permissions::RX,
    )
    .unwrap();
    let image = LoadedImage {
        info: BinaryInfo {
            arch: ArchId::X86_64,
            ..Default::default()
        },
        memory: MemoryMap::new(vec![region]).unwrap(),
        function_hints: hints
            .iter()
            .map(|(h, size)| FunctionHint {
                address: Address(base + h),
                size: *size,
                source: FunctionHintSource::EhFrame,
            })
            .collect(),
        ..Default::default()
    };
    let program = dasm_core::Program::new(image, Arc::new(dasm_x86::X86_64));
    SnapshotHub::new(Snapshot::initial(Arc::new(program)))
}

fn assert_equals_fresh(hub: &Arc<SnapshotHub>) {
    let incremental = dump(hub.load().analysis());
    let fresh = Scheduler::new(cfg(3)).unwrap();
    fresh.start(Arc::clone(hub));
    assert!(fresh.wait_idle(WAIT));
    assert_eq!(incremental, dump(hub.load().analysis()));
}

/// A patch that arrives while the function is being analysed on the old
/// bytes must not be lost.
#[test]
fn patch_during_a_running_pass_is_not_lost() {
    let n = 400_000usize;
    let mut text = vec![0x90u8; n];
    text.push(0xc3);
    let hub = mini_hub(text, &[0]);
    let s = Scheduler::new(cfg(2)).unwrap();
    s.start(Arc::clone(&hub));
    std::thread::sleep(Duration::from_millis(5));
    apply(
        &hub,
        &s,
        &Operation::PatchBytes {
            address: Address(0x10_0000 + n as u64),
            bytes: vec![0xf4],
        },
    );
    let snap = hub.load();
    let f = snap.analysis().function_at(Address(0x10_0000)).unwrap();
    assert!(f.flags.noreturn, "the stale result was merged");
    assert_equals_fresh(&hub);
}

/// A function that stopped on undecodable bytes right before the patch is
/// recomputed when the bytes become valid.
#[test]
fn function_stopped_on_invalid_bytes_is_recomputed() {
    let hub = mini_hub(vec![0x90, 0x90, 0x06, 0xcc, 0xcc, 0xcc], &[0]);
    let s = run(&hub, 2);
    let f0 = hub
        .load()
        .analysis()
        .function_at(Address(0x10_0000))
        .unwrap()
        .clone();
    assert_eq!(f0.insn_count(), 2);
    apply(
        &hub,
        &s,
        &Operation::PatchBytes {
            address: Address(0x10_0002),
            bytes: vec![0xc3],
        },
    );
    let snap = hub.load();
    let f = snap.analysis().function_at(Address(0x10_0000)).unwrap();
    assert_eq!(f.insn_count(), 3);
    assert!(!f.flags.noreturn);
    assert_equals_fresh(&hub);
}

// ------------------------------------------------ failure reporting

struct Boom(&'static str, bool);

impl dasm_core::AnalysisPass for Boom {
    fn id(&self) -> PassId {
        PassId::new(self.0)
    }
    fn dependencies(&self) -> Vec<PassId> {
        Vec::new()
    }
    fn granularity(&self) -> dasm_core::Granularity {
        dasm_core::Granularity::Program
    }
    fn invalidated_by(&self) -> &[dasm_core::ChangeKind] {
        &[]
    }
    fn run(
        &self,
        _: &dasm_core::PassContext<'_>,
        _: dasm_core::PassScope,
    ) -> Result<dasm_core::AnalysisDelta, dasm_core::Error> {
        if self.1 {
            panic!("kaboom");
        }
        Err(dasm_core::Error::Unsupported("boom".into()))
    }
}

#[test]
fn pass_errors_and_panics_reach_the_progress() {
    for (panics, needle) in [(false, "boom"), (true, "kaboom")] {
        let s = Scheduler::with_passes(cfg(2), vec![Arc::new(Boom("exploder", panics))]).unwrap();
        let hub = hub();
        s.start(Arc::clone(&hub));
        assert!(s.wait_idle(WAIT));
        assert_eq!(s.state(), AnalysisState::Failed);
        let p = hub.load().analysis().progress.clone();
        assert_eq!(p.state, AnalysisState::Failed);
        let msg = p.error.unwrap();
        assert!(msg.contains("exploder") && msg.contains(needle), "{msg}");
        // The other passes still finished.
        assert_eq!(hub.load().analysis().function_count(), 4);
    }
}

#[test]
fn panicking_listener_does_not_hang_the_scheduler() {
    struct Bad;
    impl dasm_core::SnapshotListener for Bad {
        fn snapshot_published(&self, _generation: u64) {
            panic!("listener bug");
        }
    }
    let hub = hub();
    hub.subscribe(Arc::new(Bad));
    let s = Scheduler::new(cfg(2)).unwrap();
    s.start(Arc::clone(&hub));
    assert!(s.wait_idle(WAIT), "scheduler stuck in Running");
    assert_eq!(s.state(), AnalysisState::Done);
    let p = hub.load().analysis().progress.clone();
    assert_eq!(p.state, AnalysisState::Done);
    assert!(p.error.is_none());
    assert!(hub.listener_panics() > 0);
}

/// `DefineData` over a function that starts after the item's address
/// truncates it, and `Undefine` restores it (review: Definition changes
/// carry only the start address).
#[test]
fn definition_covering_a_function_recomputes_it() {
    // 8 padding bytes, then `nop; nop; ret` at +8.
    let mut text = vec![0xccu8; 8];
    text.extend_from_slice(&[0x90, 0x90, 0xc3]);
    let hub = mini_hub(text, &[8]);
    let s = run(&hub, 2);
    let entry = Address(0x10_0008);
    assert_eq!(
        hub.load()
            .analysis()
            .function_at(entry)
            .unwrap()
            .insn_count(),
        3
    );
    apply(
        &hub,
        &s,
        &Operation::DefineData {
            address: Address(0x10_0000),
            ty: dasm_core::DataType::Array {
                element: Box::new(dasm_core::DataType::Byte),
                count: 16,
            },
        },
    );
    assert_eq!(
        hub.load()
            .analysis()
            .function_at(entry)
            .unwrap()
            .insn_count(),
        0
    );
    assert_equals_fresh(&hub);
    apply(
        &hub,
        &s,
        &Operation::Undefine {
            address: Address(0x10_0000),
        },
    );
    assert_eq!(
        hub.load()
            .analysis()
            .function_at(entry)
            .unwrap()
            .insn_count(),
        3
    );
    assert_equals_fresh(&hub);
}

/// A data definition that starts in the middle of a function cuts it;
/// removing it grows the function back.
#[test]
fn definition_inside_a_function_cuts_and_restores_it() {
    let hub = mini_hub(vec![0x90, 0x90, 0x90, 0x90, 0xc3, 0xcc], &[0]);
    let s = run(&hub, 2);
    let entry = Address(0x10_0000);
    apply(
        &hub,
        &s,
        &Operation::DefineData {
            address: Address(0x10_0002),
            ty: dasm_core::DataType::Word,
        },
    );
    assert_eq!(
        hub.load()
            .analysis()
            .function_at(entry)
            .unwrap()
            .insn_count(),
        2
    );
    assert_equals_fresh(&hub);
    apply(
        &hub,
        &s,
        &Operation::Undefine {
            address: Address(0x10_0002),
        },
    );
    assert_eq!(
        hub.load()
            .analysis()
            .function_at(entry)
            .unwrap()
            .insn_count(),
        5
    );
    assert_equals_fresh(&hub);
}

/// Code inside the declared range that the flow does not reach (switch
/// cases behind an indirect jump) belongs to the function.
#[test]
fn unreached_code_inside_the_declared_range_joins_the_function() {
    // xor eax,eax; jmp rax; | nop; nop; ret (never reached) | int3 padding
    let text = vec![0x31, 0xc0, 0xff, 0xe0, 0x90, 0x90, 0xc3, 0xcc, 0xcc, 0xcc];
    let plain = mini_hub_sized(text.clone(), &[(0, None)]);
    let sized = mini_hub_sized(text, &[(0, Some(7))]);
    for (hub, insns) in [(plain, 2), (sized, 5)] {
        let _s = run(&hub, 2);
        let snap = hub.load();
        let f = snap.analysis().function_at(Address(0x10_0000)).unwrap();
        assert_eq!(f.insn_count(), insns);
    }
}

/// A hint inside a padding instruction (glibc's `__restore_rt` FDE starts
/// one byte early) moves to the instruction after it.
#[test]
fn hint_inside_padding_is_realigned() {
    // nop word ptr [rax+rax] (66 0f 1f 44 00 00) then `xor eax,eax; ret`.
    let text = vec![0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x31, 0xc0, 0xc3];
    let hub = mini_hub_sized(text, &[(5, Some(4))]);
    let _s = run(&hub, 2);
    let snap = hub.load();
    let r = snap.analysis();
    assert!(r.function_at(Address(0x10_0005)).is_none());
    assert_eq!(r.function_at(Address(0x10_0006)).unwrap().insn_count(), 2);
}
