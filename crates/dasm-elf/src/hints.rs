//! Function hints: `.eh_frame` FDEs, DWARF subprograms, init/fini arrays.

use gimli::{AttributeValue, EndianSlice, RunTimeEndian, UnwindSection};

use dasm_core::{Address, FunctionHint, FunctionHintSource};

use crate::Ctx;
use crate::dynamic::{DynInfo, vaddr_to_off};
use crate::raw::{Phdr, Res, SHT_FINI_ARRAY, SHT_INIT_ARRAY, Shdr};
use crate::relocs::RelocOut;

fn endian(ctx: &Ctx<'_>) -> RunTimeEndian {
    if ctx.eh.fmt.le {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    }
}

/// One hint per FDE in `.eh_frame`. Parse errors end the walk silently
/// (best effort): hints are advisory.
pub(crate) fn eh_frame_hints(ctx: &Ctx<'_>, sections: &[Shdr]) -> Res<Vec<FunctionHint>> {
    let mut out = Vec::new();
    let Some(sec) = sections.iter().find(|s| s.name == ".eh_frame") else {
        return Ok(out);
    };
    let Some(bytes) = sec.bytes(ctx.data) else {
        return Ok(out);
    };
    let mut eh = gimli::EhFrame::new(bytes, endian(ctx));
    eh.set_address_size(if ctx.eh.fmt.is64 { 8 } else { 4 });
    let mut bases = gimli::BaseAddresses::default().set_eh_frame(sec.addr);
    if let Some(t) = sections.iter().find(|s| s.name == ".text") {
        bases = bases.set_text(t.addr);
    }
    if let Some(g) = sections
        .iter()
        .find(|s| s.name == ".got.plt")
        .or_else(|| sections.iter().find(|s| s.name == ".got"))
    {
        bases = bases.set_got(g.addr);
    }
    let mut it = eh.entries(&bases);
    while let Ok(Some(entry)) = it.next() {
        let gimli::CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(|_, b, o| eh.cie_from_offset(b, o)) else {
            continue;
        };
        let (start, len) = (fde.initial_address(), fde.len());
        if start == 0 || len == 0 {
            continue; // discarded by --gc-sections
        }
        let Ok(address) = ctx.rebase(start) else {
            continue;
        };
        out.push(FunctionHint {
            address,
            size: Some(len),
            source: FunctionHintSource::EhFrame,
            ..Default::default()
        });
    }
    Ok(out)
}

/// A function found in DWARF.
pub(crate) struct DwarfFn {
    pub name: String,
    pub address: Address,
    pub size: u64,
}

type R<'a> = EndianSlice<'a, RunTimeEndian>;

/// A DWARF name longer than this is ignored (never truncated).
const MAX_DWARF_NAME: usize = 64 << 10;

fn skip_leb(b: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        if byte & 0x80 == 0 {
            return Some(());
        }
    }
}

fn read_uleb(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            v |= u64::from(byte & 0x7f) << shift;
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
}

/// Byte length of the abbreviation table starting at `off` (up to and
/// including its terminating zero code). Allocation-free linear scan.
fn abbrev_table_len(b: &[u8], off: usize) -> Option<usize> {
    let mut pos = off;
    loop {
        if read_uleb(b, &mut pos)? == 0 {
            return Some(pos - off);
        }
        skip_leb(b, &mut pos)?; // tag
        pos = pos.checked_add(1)?; // has_children
        loop {
            let name = read_uleb(b, &mut pos)?;
            let form = read_uleb(b, &mut pos)?;
            if form == 0x21 {
                skip_leb(b, &mut pos)?; // DW_FORM_implicit_const value
            }
            if name == 0 && form == 0 {
                break;
            }
        }
    }
}

/// `DW_TAG_subprogram` entries with `low_pc`/`high_pc`.
///
/// Best effort: a DWARF error ends the walk and what was found is returned.
/// Defences against hostile debug info:
/// * abbreviation tables are measured first (each distinct offset once, by
///   a linear scan); if their total exceeds `Limits::max_debug_work` the
///   DWARF is ignored, which rules out quadratic re-parsing by units that
///   point into one big table at many offsets; the tables are then cached
///   so each is parsed once;
/// * names longer than 64 KiB are ignored, and name bytes are charged to
///   the load's string budget (when exhausted the walk ends).
///
/// At most `budget` functions are returned; more is `LimitExceeded`.
pub(crate) fn dwarf_functions(
    ctx: &Ctx<'_>,
    sections: &[Shdr],
    budget: usize,
) -> Res<Vec<DwarfFn>> {
    let mut out = Vec::new();
    if budget == 0 || !sections.iter().any(|s| s.name == ".debug_info") {
        return Ok(out);
    }
    let e = endian(ctx);
    let load = |id: gimli::SectionId| -> Result<R<'_>, std::convert::Infallible> {
        let b = sections
            .iter()
            .find(|s| s.name == id.name())
            .and_then(|s| s.bytes(ctx.data))
            .unwrap_or(&[]);
        Ok(EndianSlice::new(b, e))
    };
    let Ok(mut dwarf) = gimli::Dwarf::load(load);

    // Work bound on abbreviation parsing.
    let abbrev_bytes = sections
        .iter()
        .find(|s| s.name == ".debug_abbrev")
        .and_then(|s| s.bytes(ctx.data))
        .unwrap_or(&[]);
    let cap = ctx.limits.max_debug_work;
    let mut work = 0u64;
    let mut seen = std::collections::HashSet::new();
    let mut headers = dwarf.units();
    while let Ok(Some(h)) = headers.next() {
        let off = h.debug_abbrev_offset().0;
        if !seen.insert(off) {
            continue;
        }
        let Some(len) = abbrev_table_len(abbrev_bytes, off) else {
            continue; // parse error is reported when the unit is used
        };
        work = work.saturating_add(len as u64);
        if work > cap {
            return Ok(out);
        }
    }
    dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::All);

    let section = |name: &str| {
        sections
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.bytes(ctx.data))
            .unwrap_or(&[])
    };
    let strs = Strs {
        debug_str: section(".debug_str"),
        debug_line_str: section(".debug_line_str"),
    };
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let uref = unit.unit_ref(&dwarf);
        let mut cur = uref.entries();
        while let Ok(Some(die)) = cur.next_dfs() {
            if die.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let Some(low_v) = die.attr_value(gimli::DW_AT_low_pc) else {
                continue;
            };
            let Ok(Some(low)) = uref.attr_address(low_v) else {
                continue;
            };
            let Some(high_v) = die.attr_value(gimli::DW_AT_high_pc) else {
                continue;
            };
            let high = match high_v {
                AttributeValue::Addr(a) => Some(a),
                AttributeValue::DebugAddrIndex(_) => uref.attr_address(high_v).ok().flatten(),
                v => v.udata_value().and_then(|o| low.checked_add(o)),
            };
            let Some(high) = high.filter(|h| *h > low) else {
                continue;
            };
            if low == 0 {
                continue;
            }
            let name = match die_name(ctx, &uref, &strs, die, 0) {
                Ok(Some(n)) if !n.is_empty() => n,
                Ok(_) => continue,
                Err(Spent) => return Ok(out), // string budget spent: best effort
            };
            let Ok(address) = ctx.rebase(low) else {
                continue;
            };
            if out.len() >= budget {
                return Err(dasm_core::LoadError::LimitExceeded(
                    "too many DWARF functions for the symbol limit".into(),
                ));
            }
            // The symbol owns a copy of the name.
            if ctx.budget.charge(name.len() as u64).is_err() {
                return Ok(out);
            }
            out.push(DwarfFn {
                name: String::from_utf8_lossy(name).into_owned(),
                address,
                size: high - low,
            });
        }
    }
    Ok(out)
}

/// String sections used to resolve names.
struct Strs<'a> {
    debug_str: &'a [u8],
    debug_line_str: &'a [u8],
}

/// The string budget is spent: end the DWARF walk.
struct Spent;

/// Looks for a NUL within `MAX_DWARF_NAME` bytes at `off`; the scan length
/// is charged to the budget whether or not the name is usable, so shared or
/// overlapping huge strings cannot cause repeated long scans.
fn bounded_cstr<'a>(ctx: &Ctx<'_>, table: &'a [u8], off: usize) -> Result<Option<&'a [u8]>, Spent> {
    let Some(rest) = table.get(off..) else {
        return Ok(None);
    };
    let window = rest
        .get(..rest.len().min(MAX_DWARF_NAME + 1))
        .unwrap_or(rest);
    let found = window.iter().position(|&b| b == 0);
    ctx.budget
        .charge(found.map_or(window.len(), |n| n + 1) as u64)
        .map_err(|_| Spent)?;
    Ok(found.and_then(|n| window.get(..n)))
}

fn attr_name<'a>(
    ctx: &Ctx<'_>,
    uref: &gimli::UnitRef<'_, R<'a>>,
    strs: &Strs<'a>,
    v: AttributeValue<R<'a>>,
) -> Result<Option<&'a [u8]>, Spent> {
    match v {
        AttributeValue::String(s) => Ok(Some(s.slice()).filter(|n| n.len() <= MAX_DWARF_NAME)),
        AttributeValue::DebugStrRef(o) => bounded_cstr(ctx, strs.debug_str, o.0),
        AttributeValue::DebugLineStrRef(o) => bounded_cstr(ctx, strs.debug_line_str, o.0),
        AttributeValue::DebugStrOffsetsIndex(i) => match uref.string_offset(i) {
            Ok(o) => bounded_cstr(ctx, strs.debug_str, o.0),
            Err(_) => Ok(None),
        },
        _ => Ok(None),
    }
}

fn die_name<'a>(
    ctx: &Ctx<'_>,
    uref: &gimli::UnitRef<'_, R<'a>>,
    strs: &Strs<'a>,
    die: &gimli::DebuggingInformationEntry<R<'a>>,
    depth: u8,
) -> Result<Option<&'a [u8]>, Spent> {
    for at in [gimli::DW_AT_name, gimli::DW_AT_linkage_name] {
        if let Some(v) = die.attr_value(at)
            && let Some(n) = attr_name(ctx, uref, strs, v)?
        {
            return Ok(Some(n));
        }
    }
    if depth >= 3 {
        return Ok(None);
    }
    for at in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
        if let Some(AttributeValue::UnitRef(off)) = die.attr_value(at)
            && let Ok(other) = uref.entry(off)
            && let Some(n) = die_name(ctx, uref, strs, &other, depth + 1)?
        {
            return Ok(Some(n));
        }
    }
    Ok(None)
}

/// Entries of `.init_array` / `.fini_array`.
pub(crate) fn array_hints(
    ctx: &Ctx<'_>,
    sections: &[Shdr],
    dynamic: Option<&DynInfo>,
    phdrs: &[Phdr],
    relocs: &RelocOut,
) -> Res<Vec<FunctionHint>> {
    let mut arrays: Vec<(u64, u64, FunctionHintSource)> = Vec::new();
    if sections.is_empty() {
        if let Some(d) = dynamic {
            if let Some((a, s)) = d.init_array {
                arrays.push((a, s, FunctionHintSource::InitArray));
            }
            if let Some((a, s)) = d.fini_array {
                arrays.push((a, s, FunctionHintSource::FiniArray));
            }
        }
    } else {
        for s in sections {
            match s.stype {
                SHT_INIT_ARRAY => arrays.push((s.addr, s.size, FunctionHintSource::InitArray)),
                SHT_FINI_ARRAY => arrays.push((s.addr, s.size, FunctionHintSource::FiniArray)),
                _ => {}
            }
        }
    }
    let fmt = ctx.eh.fmt;
    let ws = fmt.word_size();
    let mut out = Vec::new();
    for (addr, size, source) in arrays {
        let Some(off) = vaddr_to_off(ctx.data, phdrs, addr, size) else {
            continue;
        };
        for i in 0..size / ws {
            let Ok(slot) = ctx.rebase(addr.wrapping_add(i * ws)) else {
                continue;
            };
            let value = if let Some(a) = relocs.relative.get(&slot.0) {
                *a as u64
            } else {
                match fmt
                    .cur(ctx.data, off as u64 + i * ws)
                    .and_then(|mut c| c.word())
                {
                    Some(v) => v,
                    None => break,
                }
            };
            // Skip empty and "-1" sentinel entries.
            if value == 0 || value == u64::MAX || value == u64::from(u32::MAX) {
                continue;
            }
            let Ok(address) = ctx.rebase(value) else {
                continue;
            };
            out.push(FunctionHint {
                address,
                size: None,
                source,
                ..Default::default()
            });
        }
    }
    Ok(out)
}
