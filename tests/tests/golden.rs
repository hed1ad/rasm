#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Golden tests against `readelf` / `objdump` / `nm`.
//!
//! * `oracle_*` / `mutation_*` tests validate the harness itself: a report
//!   synthesised from the reference tools must score 100 %, and every kind
//!   of wrong report must be rejected. They need only fixtures + binutils.
//! * `dasm_*` tests run the real `dasm analyze --json --insns` and compare.
//!   They skip (with a message) until the CLI is implemented; with
//!   `DASM_STRICT=1 DASM_BIN=...` every skip is a failure (wave C).

use std::path::{Path, PathBuf};
use std::process::Command;

use dasm_core::address::Address;
use dasm_core::report::AnalyzeReport;
use dasm_tests::compare::{BODY_THRESHOLD, FDE_THRESHOLD};
use dasm_tests::{cli, compare, fixtures, oracle, schema};
use serde_json::{Value, json};

/// Fixtures that legitimately have no `.eh_frame` (Go uses `.debug_frame`,
/// the hand-written asm has no CFI).
const NO_FDE: &[&str] = &["hello-go", "hello-go-stripped", "tiny-asm-nopie-static"];

fn fname(p: &Path) -> String {
    p.file_name().unwrap().to_string_lossy().into_owned()
}

/// Builds a report whose content is derived from the reference tools only.
fn oracle_report(p: &Path) -> AnalyzeReport {
    let secs = oracle::sections(p).unwrap();
    let segs = oracle::segments(p).unwrap();
    let fdes = oracle::fdes(p).unwrap();
    let ins = oracle::insns(p).unwrap();
    let hdr = oracle::header(p).unwrap();
    let mut syms = oracle::nm_static(p).unwrap();
    syms.extend(oracle::nm_dynamic(p).unwrap());
    let a = |v: u64| format!("{v:#x}");
    let instructions: Vec<Value> = ins
        .iter()
        .map(|(ad, b)| {
            json!({"address": a(*ad), "bytes": dasm_core::report::hex(b), "len": b.len(),
                   "mnemonic": "x", "operands": "", "tokens": []})
        })
        .collect();
    let doc = json!({
        "schema_version": 1,
        "tool": {"name": "dasm", "version": "0"},
        "binary": {"path": p.display().to_string(), "sha256": "0".repeat(64), "format": "elf",
            "kind": hdr.kind, "arch": "x86_64", "endian": "little", "bits": 64,
            "entry": a(hdr.entry), "base": "0x0", "build_id": null, "interpreter": null, "needed": []},
        "segments": segs.iter().filter(|s| s.ty == "LOAD").enumerate().map(|(i, s)| json!({
            "name": format!("LOAD[{i}]"), "kind": "load", "start": a(s.vaddr), "end": a(s.vaddr + s.memsz),
            "file_offset": s.offset, "file_size": s.filesz, "perms": s.perms})).collect::<Vec<_>>(),
        "sections": secs.iter().map(|s| json!({
            "name": s.name, "start": a(s.addr), "end": a(s.addr + s.size), "file_offset": s.offset,
            "file_size": s.size, "kind": "other", "tls": false, "perms": "r--"})).collect::<Vec<_>>(),
        "symbols": syms.iter().map(|s| json!({
            "name": s.name, "demangled": null, "address": a(s.addr), "size": s.size,
            "kind": "unknown", "binding": "global", "source": "static", "undefined": false})).collect::<Vec<_>>(),
        "imports": oracle::import_names(p).unwrap().iter().map(|n| json!({
            "name": n, "version": null, "library": null, "kind": "function", "plt": null, "got": null})).collect::<Vec<_>>(),
        "functions": fdes.iter().map(|(s, e)| json!({
            "entry": a(*s), "name": format!("sub_{s:x}"), "size": e - s, "insn_count": 0,
            "source": {"type": "hint", "hint": "eh_frame"},
            "flags": {"noreturn": false, "thunk": false, "plt": false, "library": false},
            "blocks": []})).collect::<Vec<_>>(),
        "xrefs": [], "strings": [],
        "stats": {"function_count": 0, "insn_count": 0, "xref_count": 0, "string_count": 0,
                  "analysis_ms": 0, "analysis_state": "done"},
    });
    let mut r: AnalyzeReport = serde_json::from_value(doc).unwrap();
    if r.functions.is_empty() {
        // no FDEs (Go, asm): a pseudo-function still carries the instructions
        let mut f = oracle_fn_template();
        f.entry = Address(ins.keys().next().copied().unwrap_or(0));
        r.functions.push(f);
    }
    // One pseudo-function carries every instruction (comparison flattens
    // function[].instructions[]).
    if let Some(f) = r.functions.first_mut() {
        f.instructions = Some(serde_json::from_value(Value::Array(instructions)).unwrap());
    }
    r
}

fn oracle_fn_template() -> dasm_core::report::FunctionReport {
    serde_json::from_value(json!({
        "entry": "0x0", "name": "pseudo", "size": 1, "insn_count": 0,
        "source": {"type": "hint", "hint": "eh_frame"},
        "flags": {"noreturn": false, "thunk": false, "plt": false, "library": false},
        "blocks": []}))
    .unwrap()
}

/// Fixtures that must have FDEs: asserts the oracle really produced some.
fn assert_fde_expectation(p: &Path, fdes: &[(u64, u64)]) {
    let n = fname(p);
    if NO_FDE.contains(&n.as_str()) {
        assert!(fdes.is_empty(), "{n}: unexpectedly has .eh_frame FDEs");
    } else {
        assert!(
            !fdes.is_empty(),
            "{n}: no FDEs parsed - reference tool failed?"
        );
    }
}

#[test]
fn oracle_parsers_agree_with_themselves_on_all_fixtures() {
    for p in fixtures::require_any() {
        let r = oracle_report(&p);
        let name = fname(&p);
        let secs = oracle::sections(&p).unwrap();
        let segs = oracle::segments(&p).unwrap();
        assert!(
            !secs.is_empty() && !segs.is_empty(),
            "{name}: parsers found nothing"
        );
        let fdes = oracle::fdes(&p).unwrap();
        assert_fde_expectation(&p, &fdes);
        let od = oracle::insns(&p).unwrap();
        assert!(!od.is_empty(), "{name}: objdump produced nothing");

        let h = compare::header(&r, &oracle::header(&p).unwrap());
        assert_eq!(h.ratio(), 1.0, "{name}: {:?}", h.problems);
        let s = compare::sections(&r, &secs);
        assert_eq!(s.ratio(), 1.0, "{name}: {:?}", s.problems);
        let l = compare::load_segments(&r, &segs);
        assert_eq!(l.ratio(), 1.0, "{name}: {:?}", l.problems);
        let f = compare::fde_coverage(&r, &fdes);
        assert_eq!((f.total > 0, f.ratio()), (!fdes.is_empty(), 1.0), "{name}");
        let b = compare::fde_bodies(&r, &fdes, &od);
        assert_eq!(b.ratio(), 1.0, "{name}: {:?}", b.problems);
        let i = compare::insns(&r, &od);
        assert_eq!(i.compared.ratio(), 1.0, "{name}: {:?}", i.compared.problems);
        assert_eq!(i.absent, 0);
        let mut nm = oracle::nm_static(&p).unwrap();
        nm.extend(oracle::nm_dynamic(&p).unwrap());
        let y = compare::symbols(&r, &nm);
        assert_eq!(y.ratio(), 1.0, "{name}: {:?}", y.problems);
        let im = compare::imports(&r, &oracle::import_names(&p).unwrap());
        assert_eq!(im.ratio(), 1.0, "{name}: {:?}", im.problems);
        eprintln!(
            "{name}: sections {}, fde {}, body bytes {}, insns {}, symbols {}, imports {}",
            s.total, f.total, b.total, i.total, y.total, im.total
        );
    }
}

// ---- mutation self-tests: every wrong report must be rejected --------------

fn base_case() -> Option<(PathBuf, AnalyzeReport)> {
    let p = fixtures::require("hello-gcc-O2-pie")?;
    let r = oracle_report(&p);
    Some((p, r))
}

#[test]
fn mutation_hollow_functions_are_rejected() {
    // Blocker: one function per FDE with no blocks/size/instructions used to
    // pass everything.
    let Some((p, good)) = base_case() else { return };
    let fdes = oracle::fdes(&p).unwrap();
    let od = oracle::insns(&p).unwrap();
    let mut hollow = good.clone();
    for f in &mut hollow.functions {
        f.size = 0;
        f.insn_count = 0;
        f.blocks.clear();
        f.instructions = Some(Vec::new());
    }
    assert_eq!(compare::fde_coverage(&hollow, &fdes).ratio(), 1.0);
    let b = compare::fde_bodies(&hollow, &fdes, &od);
    assert!(
        b.total > 0 && b.ratio() < BODY_THRESHOLD,
        "{}",
        b.summary("bodies")
    );
    // size 0 alone (instructions present) is also caught
    let mut zero = good.clone();
    zero.functions[0].size = 0;
    assert!(!compare::fde_bodies(&zero, &fdes, &od).problems.is_empty());
    // half of the instructions missing
    let mut half = good.clone();
    let ins = half.functions[0].instructions.as_mut().unwrap();
    ins.truncate(ins.len() / 2);
    assert!(compare::fde_bodies(&half, &fdes, &od).ratio() < BODY_THRESHOLD);
    // wrong instruction length
    let mut wrong = good;
    for i in wrong.functions[0].instructions.as_mut().unwrap() {
        i.len += 1;
    }
    assert!(compare::fde_bodies(&wrong, &fdes, &od).ratio() < BODY_THRESHOLD);
}

#[test]
fn mutation_fde_coverage_threshold() {
    let Some((p, good)) = base_case() else { return };
    let fdes = oracle::fdes(&p).unwrap();
    assert!(fdes.len() >= 5);
    let mut r = good;
    let keep = r.functions.len() / 2;
    r.functions.truncate(keep);
    assert!(compare::fde_coverage(&r, &fdes).ratio() < FDE_THRESHOLD);
}

#[test]
fn mutation_reference_tool_failure_is_an_error() {
    // Major: a failing readelf/objdump/nm must not look like "no data".
    let missing = Path::new("/nonexistent/fixture");
    assert!(oracle::sections(missing).is_err());
    assert!(oracle::segments(missing).is_err());
    assert!(oracle::insns(missing).is_err());
    assert!(oracle::nm_static(missing).is_err());
    assert!(oracle::nm_dynamic(missing).is_err());
    assert!(oracle::fdes(missing).is_err());
    assert!(oracle::header(missing).is_err());
    assert!(oracle::import_names(missing).is_err());
    // and an empty comparison is visibly empty, not a pass
    let Some((_, r)) = base_case() else { return };
    let o = compare::fde_coverage(&r, &[]);
    assert_eq!((o.total, o.ratio()), (0, 1.0));
}

#[test]
fn mutation_instruction_bytes_and_absent() {
    let Some((p, good)) = base_case() else { return };
    let od = oracle::insns(&p).unwrap();
    let mut r = good.clone();
    let insn = &mut r.functions[0].instructions.as_mut().unwrap()[0];
    insn.bytes = "ff".repeat(usize::from(insn.len));
    let o = compare::insns(&r, &od);
    assert_eq!(o.compared.ok + 1, o.compared.total);
    // an instruction at an address objdump does not know is counted
    let mut r = good;
    let insn = &mut r.functions[0].instructions.as_mut().unwrap()[0];
    insn.address = Address(insn.address.get() + 1);
    assert_eq!(compare::insns(&r, &od).absent, 1);
}

#[test]
fn mutation_header_is_checked_against_readelf() {
    let Some((p, good)) = base_case() else { return };
    let h = oracle::header(&p).unwrap();
    assert_eq!(h.kind, "pie_executable");
    let mut r = good.clone();
    r.binary.kind = dasm_core::image::BinaryKind::Executable;
    assert!(compare::header(&r, &h).ratio() < 1.0, "kind");
    let mut r = good.clone();
    r.binary.entry = Some(Address(h.entry + 16));
    assert!(compare::header(&r, &h).ratio() < 1.0, "entry");
    let mut r = good.clone();
    r.binary.entry = None;
    assert!(compare::header(&r, &h).ratio() < 1.0, "null entry");
    let mut r = good;
    r.binary.base = Address(0x400000);
    assert!(
        compare::header(&r, &h).ratio() < 1.0,
        "PIE base must default to 0"
    );
}

#[test]
fn mutation_sections_segments_symbols_imports() {
    let Some((p, good)) = base_case() else { return };
    let secs = oracle::sections(&p).unwrap();
    let segs = oracle::segments(&p).unwrap();
    let mut nm = oracle::nm_static(&p).unwrap();
    nm.extend(oracle::nm_dynamic(&p).unwrap());
    let imps = oracle::import_names(&p).unwrap();
    assert!(!imps.is_empty(), "PIE fixture must import from libc");

    let mut r = good.clone();
    r.sections[0].start = Address(r.sections[0].start.get() + 1);
    assert!(
        compare::sections(&r, &secs).ratio() < 1.0,
        "shifted section"
    );
    let mut r = good.clone();
    let dup = r.sections[3].clone();
    r.sections.push(dup);
    assert!(
        compare::sections(&r, &secs).ratio() < 1.0,
        "duplicate section"
    );
    let mut r = good.clone();
    r.sections.remove(2);
    assert!(
        compare::sections(&r, &secs).ratio() < 1.0,
        "missing section"
    );

    let mut r = good.clone();
    r.segments[0].perms = "rwx".into();
    assert!(compare::load_segments(&r, &segs).ratio() < 1.0, "perms");
    let mut r = good.clone();
    let dup = r.segments[0].clone();
    r.segments.push(dup);
    assert!(
        compare::load_segments(&r, &segs).ratio() < 1.0,
        "duplicate LOAD"
    );

    let mut r = good.clone();
    for s in &mut r.symbols {
        s.size = None;
    }
    let o = compare::symbols(&r, &nm);
    assert!(
        o.ratio() < 1.0,
        "null size must mismatch: {}",
        o.summary("symbols")
    );
    let mut r = good.clone();
    let victim = nm.iter().find(|s| "TtDdBbRr".contains(s.ty)).unwrap();
    r.symbols
        .retain(|x| !(x.name == victim.name && x.address.get() == victim.addr));
    assert!(compare::symbols(&r, &nm).ratio() < 1.0, "missing symbol");

    let mut r = good;
    r.imports.clear();
    assert!(compare::imports(&r, &imps).ratio() < 1.0, "imports");
}

#[test]
fn oracle_fixture_properties() {
    // sanity of the fixture matrix itself, via the reference tools
    let kind = |n: &str| fixtures::require(n).map(|p| oracle::header(&p).unwrap().kind);
    if let Some(p) = fixtures::require("hello-gcc-O2-pie-ibt") {
        assert!(
            oracle::sections(&p)
                .unwrap()
                .iter()
                .any(|s| s.name == ".plt.sec")
        );
    }
    assert!(kind("hello-gcc-O2-nopie").is_none_or(|k| k == "executable"));
    assert!(kind("hello-gcc-O2-pie").is_none_or(|k| k == "pie_executable"));
    assert!(kind("libfoo-gcc.so").is_none_or(|k| k == "shared_library"));
    if let Some(p) = fixtures::require("hello-gcc-O2-pie-stripped") {
        assert!(
            oracle::nm_static(&p).unwrap().is_empty(),
            "stripped has no .symtab"
        );
        assert!(
            !oracle::fdes(&p).unwrap().is_empty(),
            "stripped keeps .eh_frame"
        );
    }
}

// ---- aggregation / strict mode ----------------------------------------------

/// Runs `check` for each path; a skip (`Ok(false)`) never discards errors.
fn aggregate(
    paths: &[PathBuf],
    mut check: impl FnMut(&Path) -> Result<bool, String>,
) -> (usize, usize, Vec<String>) {
    let (mut ran, mut skipped, mut errors) = (0, 0, Vec::new());
    for p in paths {
        match check(p) {
            Ok(true) => ran += 1,
            Ok(false) => skipped += 1,
            Err(e) => errors.push(e),
        }
    }
    (ran, skipped, errors)
}

#[test]
fn mutation_skips_do_not_hide_errors() {
    let paths: Vec<PathBuf> = ["a", "b", "c", "d"].iter().map(PathBuf::from).collect();
    let (ran, skipped, errors) = aggregate(&paths, |p| match p.to_str() {
        Some("a") => Err("boom".into()),
        Some("b") => Ok(false),
        Some("c") => Ok(true),
        _ => Err("bang".into()),
    });
    assert_eq!((ran, skipped), (1, 1));
    assert_eq!(errors, ["boom", "bang"]);
}

/// Child side of [`strict_mode_turns_every_skip_into_a_failure`].
#[test]
fn strict_probe() {
    match std::env::var("DASM_PROBE").as_deref() {
        Ok("no_bin") => {
            let _ = cli::analyze(&["--json"], Path::new("/bin/ls"));
        }
        Ok("bad_bin") => {
            let _ = cli::analyze(&["--json"], Path::new("/bin/ls"));
        }
        Ok("no_fixture") => {
            let _ = fixtures::require("no-such-fixture");
        }
        Ok("stub") => {
            let _ = cli::analyze(&["--json"], Path::new("/bin/ls"));
        }
        _ => {}
    }
}

#[test]
fn strict_mode_turns_every_skip_into_a_failure() {
    let exe = std::env::current_exe().unwrap();
    let run = |strict: bool, probe: &str, bin: Option<&str>| {
        let mut c = Command::new(&exe);
        c.args(["--exact", "strict_probe", "--nocapture"])
            .env("DASM_PROBE", probe)
            .env_remove("DASM_BIN")
            .env_remove("DASM_STRICT");
        if strict {
            c.env("DASM_STRICT", "1");
        }
        if let Some(b) = bin {
            c.env("DASM_BIN", b);
        }
        c.output().unwrap()
    };
    // stub CLI: a script that prints the stub message and exits 2
    let stub = std::env::temp_dir().join(format!("dasm-stub-{}", std::process::id()));
    std::fs::write(
        &stub,
        "#!/bin/sh\necho 'dasm: not implemented yet' >&2\nexit 2\n",
    )
    .unwrap();
    Command::new("chmod").arg("+x").arg(&stub).status().unwrap();
    let stub_s = stub.to_str().unwrap();

    for (probe, bin) in [
        ("no_bin", None),                       // binary not found / not pinned
        ("bad_bin", Some("/nonexistent/dasm")), // DASM_BIN is not a file
        ("no_fixture", None),                   // fixture missing
        ("stub", Some(stub_s)),                 // "not implemented yet"
    ] {
        let lax = run(false, probe, bin);
        assert!(
            lax.status.success(),
            "{probe}: lax mode must skip, not fail"
        );
        let strict = run(true, probe, bin);
        assert!(!strict.status.success(), "{probe}: strict mode must fail");
    }
    // "unrecognised file format" on a real ELF
    let unrec = std::env::temp_dir().join(format!("dasm-unrec-{}", std::process::id()));
    std::fs::write(
        &unrec,
        "#!/bin/sh\necho 'load error: unrecognised file format' >&2\nexit 1\n",
    )
    .unwrap();
    Command::new("chmod")
        .arg("+x")
        .arg(&unrec)
        .status()
        .unwrap();
    let u = unrec.to_str().unwrap();
    assert!(run(false, "stub", Some(u)).status.success());
    assert!(!run(true, "stub", Some(u)).status.success());
    let _ = std::fs::remove_file(stub);
    let _ = std::fs::remove_file(unrec);
}

// ---- tests against the real CLI (skip until implemented) -------------------

fn gate(failures: &mut Vec<String>, name: &str, what: &str, o: &compare::Outcome, min: f64) {
    eprintln!("{name}: {}", o.summary(what));
    if o.ratio() < min {
        failures.push(format!("{}: {:?}", o.summary(what), o.problems));
    }
}

/// Runs the full comparison for one fixture; `Ok(false)` = skipped.
fn check_with_dasm(p: &Path) -> Result<bool, String> {
    let name = fname(p);
    let Some((raw, r)) = cli::analyze_json(p, true)? else {
        return Ok(false);
    };
    let problems = schema::validate(&raw, true);
    if !problems.is_empty() {
        return Err(format!("{name}: schema violations: {problems:#?}"));
    }
    let mut failures = Vec::new();

    gate(
        &mut failures,
        &name,
        "header",
        &compare::header(&r, &oracle::header(p)?),
        1.0,
    );

    let fdes = oracle::fdes(p)?;
    if fdes.is_empty() && !NO_FDE.contains(&name.as_str()) && !name.starts_with("ls") {
        return Err(format!("{name}: no FDEs parsed from the reference"));
    }
    let od = oracle::insns(p)?;
    if od.is_empty() {
        return Err(format!("{name}: objdump produced no instructions"));
    }
    gate(
        &mut failures,
        &name,
        "FDE coverage",
        &compare::fde_coverage(&r, &fdes),
        FDE_THRESHOLD,
    );
    gate(
        &mut failures,
        &name,
        "FDE bodies",
        &compare::fde_bodies(&r, &fdes, &od),
        BODY_THRESHOLD,
    );

    let ins = compare::insns(&r, &od);
    gate(&mut failures, &name, "insn bytes", &ins.compared, 1.0);
    // Contract: every reported instruction coincides with objdump. Only
    // non-gcc/clang/musl code (Go, Rust) gets 2 % slack for data in .text.
    let strict_code = ["gcc", "clang", "musl"].iter().any(|c| name.contains(c));
    let allowed = if strict_code { 0 } else { ins.total / 50 };
    if ins.absent > allowed {
        failures.push(format!(
            "{} of {} instructions absent from objdump (allowed {allowed})",
            ins.absent, ins.total
        ));
    }

    gate(
        &mut failures,
        &name,
        "sections",
        &compare::sections(&r, &oracle::sections(p)?),
        1.0,
    );
    gate(
        &mut failures,
        &name,
        "LOAD segments",
        &compare::load_segments(&r, &oracle::segments(p)?),
        1.0,
    );
    let mut nm = oracle::nm_static(p)?;
    nm.extend(oracle::nm_dynamic(p)?);
    gate(
        &mut failures,
        &name,
        "symbols",
        &compare::symbols(&r, &nm),
        1.0,
    );
    gate(
        &mut failures,
        &name,
        "imports",
        &compare::imports(&r, &oracle::import_names(p)?),
        1.0,
    );
    if failures.is_empty() {
        Ok(true)
    } else {
        Err(format!("{name}: {failures:#?}"))
    }
}

#[test]
fn dasm_matches_reference_tools_on_fixtures() {
    let paths = fixtures::require_any();
    let (ran, skipped, errors) = aggregate(&paths, check_with_dasm);
    eprintln!(
        "dasm golden: {ran} passed, {skipped} skipped, {} failed",
        errors.len()
    );
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn dasm_matches_reference_tools_on_usr_bin_ls() {
    let ls = Path::new("/usr/bin/ls");
    if !ls.is_file() {
        fixtures::skip("/usr/bin/ls missing");
        return;
    }
    if let Err(e) = check_with_dasm(ls) {
        panic!("{e}");
    }
}

#[test]
fn dasm_output_is_deterministic() {
    let Some(p) = fixtures::require("hello-gcc-O2-pie") else {
        return;
    };
    let (Some((a, _)), Some((b, _))) = (
        cli::analyze_json(&p, true).unwrap(),
        cli::analyze_json(&p, true).unwrap(),
    ) else {
        return;
    };
    let (mut a, mut b) = (a, b);
    a["stats"]["analysis_ms"] = 0.into();
    b["stats"]["analysis_ms"] = 0.into();
    assert_eq!(a, b);
}

#[test]
fn dasm_exit_codes() {
    use cli::Run;
    // 1: unreadable / not an ELF; stdout empty
    match cli::analyze(&["--json"], Path::new("/nonexistent/file")) {
        Run::Skipped(why) => eprintln!("SKIPPED: {why}"),
        Run::Done { code, stdout, .. } => {
            assert_eq!(code, 1);
            assert!(stdout.is_empty());
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let junk =
        std::env::temp_dir().join(format!("dasm-qa-junk-{}-{nanos}.bin", std::process::id()));
    std::fs::write(&junk, b"not an elf at all").unwrap();
    match cli::analyze(&["--json"], &junk) {
        Run::Skipped(_) => {}
        Run::Done { code, stdout, .. } => {
            assert_eq!(code, 1);
            assert!(stdout.is_empty());
        }
    }
    let _ = std::fs::remove_file(junk);
}
