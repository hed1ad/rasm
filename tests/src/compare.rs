//! Comparison rules between an `AnalyzeReport` and the reference tools
//! (`docs/api/analyze-json.md`, section "Как QA сверяет").
//!
//! Address rule: report addresses are absolute. `readelf`/`objdump` print
//! link-time addresses; for PIE and shared objects the default base is `0`
//! (checked in [`header`]), so addresses compare directly. The expected
//! values come from the reference tools, never from the report under test.

use std::collections::{BTreeMap, BTreeSet};

use dasm_core::report::AnalyzeReport;

use crate::oracle::{NmSymbol, RHeader, RSection, RSegment};

/// Minimum share of FDE starts that must be found as function entries.
pub const FDE_THRESHOLD: f64 = 0.95;
/// Minimum share of objdump instruction bytes inside FDE ranges that must
/// be reported as instructions (rejects "function per FDE, empty body").
pub const BODY_THRESHOLD: f64 = 0.95;

/// Outcome of one comparison: `total` items checked, `ok` matched.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// Items examined.
    pub total: usize,
    /// Items that matched.
    pub ok: usize,
    /// Human-readable mismatches (capped at 20).
    pub problems: Vec<String>,
}

impl Outcome {
    fn miss(&mut self, msg: String) {
        if self.problems.len() < 20 {
            self.problems.push(msg);
        }
    }
    /// `ok / total`, 1.0 for an empty comparison (callers that need a
    /// non-empty comparison must assert on `total`).
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.ok as f64 / self.total as f64
        }
    }
    /// One-line summary.
    pub fn summary(&self, what: &str) -> String {
        format!(
            "{what}: {}/{} ({:.2}%)",
            self.ok,
            self.total,
            self.ratio() * 100.0
        )
    }
}

/// `kind`, `entry` and default base against `readelf -h`.
pub fn header(r: &AnalyzeReport, h: &RHeader) -> Outcome {
    let mut o = Outcome::default();
    let kind = serde_json::to_value(r.binary.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut check = |ok: bool, msg: String| {
        o.total += 1;
        if ok {
            o.ok += 1;
        } else {
            o.miss(msg);
        }
    };
    check(
        kind == h.kind,
        format!("kind `{kind}` != readelf `{}`", h.kind),
    );
    let entry_ok = if h.entry == 0 {
        // No entry point: both `null` and an explicit 0 are acceptable.
        r.binary.entry.is_none_or(|a| a.get() == 0)
    } else {
        r.binary.entry.map(|a| a.get()) == Some(h.entry)
    };
    check(
        entry_ok,
        format!("entry {:?} != readelf {:#x}", r.binary.entry, h.entry),
    );
    if matches!(h.kind, "pie_executable" | "shared_library") {
        check(
            r.binary.base.get() == 0,
            format!("PIE/so base {} != 0", r.binary.base),
        );
    }
    o
}

/// FDE coverage: every FDE start should be a function entry.
pub fn fde_coverage(r: &AnalyzeReport, fdes: &[(u64, u64)]) -> Outcome {
    let entries: BTreeSet<u64> = r.functions.iter().map(|f| f.entry.get()).collect();
    let mut o = Outcome::default();
    let starts: BTreeSet<u64> = fdes.iter().map(|f| f.0).collect();
    for s in starts {
        o.total += 1;
        if entries.contains(&s) {
            o.ok += 1;
        } else {
            o.miss(format!("FDE start {s:#x} is not a function entry"));
        }
    }
    o
}

/// Function bodies: of the instruction bytes objdump shows inside FDE
/// ranges, the share present in the report as the same instruction
/// (address and length), counted in bytes. Also requires, per matched
/// FDE function, a non-zero `size`.
pub fn fde_bodies(
    r: &AnalyzeReport,
    fdes: &[(u64, u64)],
    objdump: &BTreeMap<u64, Vec<u8>>,
) -> Outcome {
    let mut reported: BTreeMap<u64, usize> = BTreeMap::new();
    for f in &r.functions {
        for i in f.instructions.iter().flatten() {
            reported.insert(i.address.get(), usize::from(i.len));
        }
    }
    let mut o = Outcome::default();
    let ranges: BTreeSet<(u64, u64)> = fdes.iter().copied().collect();
    for (s, e) in ranges {
        for (a, b) in objdump.range(s..e) {
            o.total += b.len();
            if reported.get(a) == Some(&b.len()) {
                o.ok += b.len();
            } else {
                o.miss(format!("insn {a:#x} (FDE {s:#x}..{e:#x}) not reported"));
            }
        }
        if let Some(f) = r.functions.iter().find(|f| f.entry.get() == s)
            && f.size == 0
        {
            o.total += 1;
            o.miss(format!(
                "function {s:#x} has size 0 but FDE covers {:#x}",
                e - s
            ));
        }
    }
    o
}

/// Instruction bytes/lengths versus `objdump -d`. Instructions whose
/// address objdump did not disassemble count as `absent`, not mismatches.
#[derive(Clone, Debug, Default)]
pub struct InsnOutcome {
    /// Byte/length comparison for addresses known to both.
    pub compared: Outcome,
    /// Instructions of the report absent in objdump.
    pub absent: usize,
    /// Report instructions in total.
    pub total: usize,
}

/// Compares `functions[].instructions[]` with objdump output.
pub fn insns(r: &AnalyzeReport, objdump: &BTreeMap<u64, Vec<u8>>) -> InsnOutcome {
    let mut out = InsnOutcome::default();
    for f in &r.functions {
        for i in f.instructions.iter().flatten() {
            out.total += 1;
            let Some(ref_bytes) = objdump.get(&i.address.get()) else {
                out.absent += 1;
                continue;
            };
            out.compared.total += 1;
            let hex = dasm_core::report::hex(ref_bytes);
            if i.bytes == hex && usize::from(i.len) == ref_bytes.len() {
                out.compared.ok += 1;
            } else {
                out.compared.miss(format!(
                    "{}: dasm bytes={} len={} objdump={}",
                    i.address, i.bytes, i.len, hex
                ));
            }
        }
    }
    out
}

/// Sections: the ordered name list equals `readelf -SW`, and every
/// allocated section has the same start and size.
pub fn sections(r: &AnalyzeReport, rs: &[RSection]) -> Outcome {
    let mut o = Outcome::default();
    o.total += 1;
    let want: Vec<&str> = rs.iter().map(|s| s.name.as_str()).collect();
    let got: Vec<&str> = r.sections.iter().map(|s| s.name.as_str()).collect();
    if want == got {
        o.ok += 1;
    } else {
        o.miss(format!(
            "section names differ: readelf {} entries, report {} entries",
            want.len(),
            got.len()
        ));
    }
    for s in rs.iter().filter(|s| s.alloc()) {
        o.total += 1;
        let found = r.sections.iter().any(|x| {
            x.name == s.name
                && x.start.get() == s.addr
                && x.end.get().saturating_sub(x.start.get()) == s.size
        });
        if found {
            o.ok += 1;
        } else {
            o.miss(format!(
                "section {} @{:#x}+{:#x} not matched",
                s.name, s.addr, s.size
            ));
        }
    }
    o
}

/// `PT_LOAD` segments: exact set (no extras, no duplicates) with start,
/// memory size, file offset/size and permissions.
pub fn load_segments(r: &AnalyzeReport, rs: &[RSegment]) -> Outcome {
    let mut o = Outcome::default();
    let want: Vec<&RSegment> = rs.iter().filter(|s| s.ty == "LOAD").collect();
    let got: Vec<_> = r
        .segments
        .iter()
        .filter(|x| x.name.starts_with("LOAD"))
        .collect();
    o.total += 1;
    if got.len() == want.len() {
        o.ok += 1;
    } else {
        o.miss(format!(
            "LOAD count {} != readelf {}",
            got.len(),
            want.len()
        ));
    }
    for s in want {
        o.total += 1;
        let found = got.iter().any(|x| {
            x.start.get() == s.vaddr
                && x.end.get().saturating_sub(x.start.get()) == s.memsz
                && x.file_offset == s.offset
                && x.file_size == s.filesz
                && x.perms == s.perms
        });
        if found {
            o.ok += 1;
        } else {
            o.miss(format!(
                "LOAD @{:#x} memsz {:#x} perms {} not matched",
                s.vaddr, s.memsz, s.perms
            ));
        }
    }
    o
}

/// nm symbols (function/object kinds only, no absolute/special) must appear
/// in `symbols` by (name, address) with the same size (`null` size when nm
/// printed one is a mismatch).
pub fn symbols(r: &AnalyzeReport, nm: &[NmSymbol]) -> Outcome {
    let mut o = Outcome::default();
    for s in nm.iter().filter(|s| "TtDdBbRrWwVvSsGg".contains(s.ty)) {
        o.total += 1;
        let hit = r
            .symbols
            .iter()
            .find(|x| x.name == s.name && x.address.get() == s.addr);
        match hit {
            Some(x) if s.size.is_none_or(|n| x.size == Some(n)) => o.ok += 1,
            Some(x) => o.miss(format!(
                "symbol {} size {:?} != nm {:?}",
                s.name, x.size, s.size
            )),
            None => o.miss(format!("symbol {} @{:#x} missing", s.name, s.addr)),
        }
    }
    o
}

/// Imports: every versioned undefined symbol of the dynamic relocations
/// (`readelf -rW`) is present in `imports`.
pub fn imports(r: &AnalyzeReport, names: &[String]) -> Outcome {
    let have: BTreeSet<&str> = r.imports.iter().map(|i| i.name.as_str()).collect();
    let mut o = Outcome::default();
    for n in names {
        o.total += 1;
        if have.contains(n.as_str()) {
            o.ok += 1;
        } else {
            o.miss(format!("import `{n}` missing"));
        }
    }
    o
}
