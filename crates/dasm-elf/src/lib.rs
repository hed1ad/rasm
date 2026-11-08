//! # dasm-elf
//!
//! ELF loader: implements [`dasm_core::Loader`] ([`ElfLoader`]).
//!
//! Supports ELF32/ELF64, both byte orders. Produces segments, sections,
//! static/dynamic/DWARF symbols, relocations (`DT_RELA`, `DT_REL`,
//! `DT_JMPREL`, `DT_RELR`), imports with PLT/GOT addresses and versions,
//! and function hints (entry, symbols, `.eh_frame` FDEs, DWARF, init/fini
//! arrays, PLT stubs).
//!
//! # Conventions
//!
//! * **Rebase**: for `ET_DYN` every address is shifted by
//!   [`LoadOptions::base`] (default 0); `ET_EXEC` ignores it. Relocation
//!   addends are *not* shifted (they are link-time values).
//!   [`BinaryInfo::base`](dasm_core::BinaryInfo) is the bias for `ET_DYN`
//!   and 0 otherwise.
//! * **Overlapping `PT_LOAD` segments** are rejected as `Malformed`.
//!   `p_filesz > p_memsz` is clamped to `p_memsz`; file data of a `PT_LOAD`
//!   that lies outside the file is `Truncated`.
//! * **Sections** are optional: a section table that does not fit into the
//!   file is ignored. Non-`SHF_ALLOC` sections have an *empty* range at
//!   address 0 (so that they never shadow real addresses); their size is in
//!   `file_size`.
//! * **Imports/relocations** come from the first `PT_DYNAMIC` segment only
//!   (further ones are ignored; more than 65 536 real entries is
//!   `LimitExceeded`; more than 65 536 symbol version records is best
//!   effort: the versions read so far are kept); they work without section headers.
//! * **Demangling** is not done yet (no demangler in the workspace
//!   dependencies); `Symbol::demangled` is `None`.
//! * `ET_REL` is loaded without memory regions (symbol values stay
//!   section-relative).
//! * DWARF and `.eh_frame` are best effort: malformed debug data ends the
//!   walk and yields what was found so far. Advisory records (symbols, FDEs,
//!   relocations, init/fini entries, `DT_*` tables) that are broken are
//!   skipped individually; only resource limits fail the load.
//! * `SHF_COMPRESSED` sections (e.g. compressed DWARF) are ignored.
//!   PLT stubs and `.eh_frame` are found by section name, so they are
//!   absent in binaries without section headers (`PT_GNU_EH_FRAME` is not
//!   used yet).
//! * Strings copied from the file are charged to a per-load budget of
//!   [`Limits::max_string_bytes`](dasm_core::Limits) bytes; exceeding it is
//!   `LimitExceeded` (DWARF names: the DWARF walk just ends). Names are
//!   never truncated.
//! * `STT_TLS` symbol values are offsets in the TLS block and are not
//!   rebased. For `ET_REL`, ALLOC sections have empty ranges and no
//!   function hints are produced.
//!
//! Never panics on any input.

// Struct literals end in `..Default::default()` by project convention, so new
// `dasm-core` fields do not break this crate (ADR 0001).
#![allow(clippy::needless_update)]

mod dynamic;
mod hints;
mod raw;
mod relocs;
mod syms;

#[cfg(test)]
mod tests;

use dasm_core::{
    Address, AddressRange, ArchId, BinaryFormat, BinaryInfo, BinaryKind, Endian, FunctionHint,
    FunctionHintSource, LoadError, LoadOptions, LoadedImage, Loader, MemoryMap, MemoryRegion,
    Permissions, Section, SectionKind, Segment, SegmentKind, SharedBytes, Symbol, SymbolKind,
    SymbolSource, sha256,
};

use crate::dynamic::{DynInfo, parse_verneed};
use crate::raw::*;

/// The ELF loader.
#[derive(Clone, Copy, Debug, Default)]
pub struct ElfLoader;

/// Shared parsing context.
pub(crate) struct Ctx<'a> {
    pub data: &'a [u8],
    pub eh: Ehdr,
    pub bias: u64,
    pub limits: &'a dasm_core::Limits,
    /// Budget for strings copied out of the file.
    pub budget: Budget,
}

impl Ctx<'_> {
    /// Link-time address -> loaded address.
    pub(crate) fn rebase(&self, a: u64) -> Res<Address> {
        a.checked_add(self.bias)
            .map(Address)
            .ok_or_else(|| malformed("address", format!("{a:#x} + base overflows")))
    }
}

impl Loader for ElfLoader {
    fn name(&self) -> &'static str {
        "elf"
    }

    fn probe(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"\x7fELF")
    }

    fn load(&self, file: SharedBytes, options: &LoadOptions) -> Result<LoadedImage, LoadError> {
        load_elf(&file, options)
    }
}

fn perms_of(flags: u32) -> Permissions {
    Permissions {
        read: flags & 4 != 0,
        write: flags & 2 != 0,
        execute: flags & 1 != 0,
    }
}

fn segment_kind(t: u32) -> (SegmentKind, String) {
    match t {
        PT_LOAD => (SegmentKind::Load, "LOAD".into()),
        PT_DYNAMIC => (SegmentKind::Dynamic, "DYNAMIC".into()),
        PT_INTERP => (SegmentKind::Interp, "INTERP".into()),
        PT_NOTE => (SegmentKind::Note, "NOTE".into()),
        PT_PHDR => (SegmentKind::Phdr, "PHDR".into()),
        PT_TLS => (SegmentKind::Tls, "TLS".into()),
        PT_GNU_EH_FRAME => (SegmentKind::GnuEhFrame, "GNU_EH_FRAME".into()),
        PT_GNU_STACK => (SegmentKind::GnuStack, "GNU_STACK".into()),
        PT_GNU_RELRO => (SegmentKind::GnuRelro, "GNU_RELRO".into()),
        PT_GNU_PROPERTY => (SegmentKind::GnuProperty, "GNU_PROPERTY".into()),
        other => (SegmentKind::Other(other), format!("PT_{other:#x}")),
    }
}

fn range_of(ctx: &Ctx<'_>, start: u64, len: u64, what: &str) -> Res<AddressRange> {
    let s = ctx.rebase(start)?;
    AddressRange::from_len(s, len).map_err(|_| malformed(what, "range overflows"))
}

fn build_segments(
    ctx: &Ctx<'_>,
    file: &SharedBytes,
    phdrs: &[Phdr],
) -> Res<(Vec<Segment>, MemoryMap)> {
    let mut segments = Vec::with_capacity(phdrs.len());
    let mut regions = Vec::new();
    let mut mapped: u64 = 0;
    let mut nload = 0usize;
    for p in phdrs {
        let (kind, mut name) = segment_kind(p.ptype);
        let range = range_of(ctx, p.vaddr, p.memsz, "program header")?;
        if kind == SegmentKind::Load {
            name = format!("LOAD[{nload}]");
            nload += 1;
            if p.memsz != 0 {
                mapped = mapped.saturating_add(p.memsz);
                if mapped > ctx.limits.max_mapped_size {
                    return Err(LoadError::LimitExceeded(format!(
                        "mapped size exceeds {} bytes",
                        ctx.limits.max_mapped_size
                    )));
                }
                let flen = p.filesz.min(p.memsz);
                let data = usize::try_from(p.offset)
                    .ok()
                    .zip(usize::try_from(flen).ok())
                    .and_then(|(o, l)| file.slice(o, l))
                    .ok_or_else(|| truncated("PT_LOAD data", p.offset))?;
                let region = MemoryRegion::new(range, data, perms_of(p.flags))
                    .map_err(|e| malformed("PT_LOAD", e.to_string()))?;
                regions.push(region);
            }
        }
        segments.push(Segment {
            name,
            kind,
            range,
            file_offset: p.offset,
            file_size: p.filesz,
            perms: perms_of(p.flags),
            ..Default::default()
        });
    }
    let memory = MemoryMap::new(regions).map_err(|e| malformed("PT_LOAD", e.to_string()))?;
    Ok((segments, memory))
}

fn build_sections(ctx: &Ctx<'_>, shdrs: &[Shdr]) -> Res<Vec<Section>> {
    let mut out = Vec::with_capacity(shdrs.len());
    for s in shdrs.iter().skip(1).filter(|s| s.stype != SHT_NULL) {
        let alloc = s.flags & SHF_ALLOC != 0;
        let nobits = s.stype == SHT_NOBITS;
        // Non-ALLOC sections, and every section of a relocatable object
        // (all at address 0, overlapping), have no address range.
        let range = if alloc && ctx.eh.etype != ET_REL {
            match range_of(ctx, s.addr, s.size, &s.name) {
                Ok(r) => r,
                Err(_) => continue, // advisory: skip a section that overflows
            }
        } else {
            AddressRange::empty_at(Address::ZERO)
        };
        let kind = if !alloc {
            SectionKind::Metadata
        } else if nobits {
            SectionKind::Bss
        } else if s.flags & SHF_EXECINSTR != 0 {
            SectionKind::Code
        } else if s.flags & SHF_WRITE != 0 {
            SectionKind::Data
        } else {
            SectionKind::ReadOnlyData
        };
        out.push(Section {
            name: s.name.clone(),
            range,
            file_offset: (!nobits).then_some(s.offset),
            file_size: if nobits { 0 } else { s.size },
            kind,
            tls: s.flags & SHF_TLS != 0,
            perms: Permissions {
                read: alloc,
                write: s.flags & SHF_WRITE != 0,
                execute: s.flags & SHF_EXECINSTR != 0,
            },
            ..Default::default()
        });
    }
    Ok(out)
}

/// Finds `NT_GNU_BUILD_ID` in `PT_NOTE` segments (or `SHT_NOTE` sections).
fn find_build_id(ctx: &Ctx<'_>, phdrs: &[Phdr], shdrs: &[Shdr]) -> Option<Vec<u8>> {
    let mut blobs: Vec<(&[u8], u64)> = Vec::new();
    for p in phdrs.iter().filter(|p| p.ptype == PT_NOTE) {
        let range = usize::try_from(p.offset).ok().and_then(|s| {
            let e = s.checked_add(usize::try_from(p.filesz).ok()?)?;
            ctx.data.get(s..e)
        });
        if let Some(b) = range {
            blobs.push((b, p.align));
        }
    }
    if blobs.is_empty() {
        for s in shdrs.iter().filter(|s| s.stype == 7) {
            if let Some(b) = s.bytes(ctx.data) {
                blobs.push((b, 4));
            }
        }
    }
    blobs
        .into_iter()
        .find_map(|(blob, align)| build_id_in(ctx, blob, if align == 8 { 8 } else { 4 }))
}

/// Walks the notes in one blob looking for `NT_GNU_BUILD_ID`; a malformed
/// note ends the walk of this blob only.
fn build_id_in(ctx: &Ctx<'_>, blob: &[u8], al: usize) -> Option<Vec<u8>> {
    let pad = |n: usize| n.checked_add(al - 1).map(|v| v & !(al - 1));
    let mut pos = 0usize;
    loop {
        let mut c = ctx.eh.fmt.cur(blob, pos as u64)?;
        let (namesz, descsz, ntype) = (c.u32()?, c.u32()?, c.u32()?);
        let (namesz, descsz) = (namesz as usize, descsz as usize);
        let name_at = pos.checked_add(12)?;
        let desc_at = name_at.checked_add(pad(namesz)?)?;
        let next = desc_at.checked_add(pad(descsz)?)?;
        if ntype == 3
            && blob.get(name_at..name_at.checked_add(namesz)?) == Some(b"GNU\0")
            && descsz <= 1024
            && let Some(d) = blob.get(desc_at..desc_at.checked_add(descsz)?)
        {
            return Some(d.to_vec());
        }
        if next > blob.len() {
            return None;
        }
        pos = next;
    }
}

fn load_elf(file: &SharedBytes, options: &LoadOptions) -> Result<LoadedImage, LoadError> {
    let data = file.as_slice();
    let eh = Ehdr::parse(data)?;
    let limits = &options.limits;
    let bias = if eh.etype == ET_DYN {
        options.base.map_or(0, |a| a.0)
    } else {
        0
    };
    let ctx = Ctx {
        data,
        eh,
        bias,
        limits,
        budget: Budget::new(limits.max_string_bytes),
    };
    let phdrs = parse_phdrs(data, &eh, limits)?;
    let shdrs = parse_shdrs(data, &eh, limits, &ctx.budget)?;

    let (segments, memory) = build_segments(&ctx, file, &phdrs)?;
    let sections = build_sections(&ctx, &shdrs)?;
    let dynamic = DynInfo::parse(data, &eh, &phdrs, &ctx.budget)?;

    // Binary info.
    let interpreter = phdrs.iter().find(|p| p.ptype == PT_INTERP).and_then(|p| {
        let s = usize::try_from(p.offset).ok()?;
        let e = s.checked_add(usize::try_from(p.filesz).ok()?)?;
        let b = data.get(s..e)?;
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        Some(String::from_utf8_lossy(b.get(..end)?).into_owned())
    });
    let kind = match eh.etype {
        ET_REL => BinaryKind::Relocatable,
        ET_EXEC => BinaryKind::Executable,
        ET_CORE => BinaryKind::Core,
        ET_DYN => {
            let pie_flag = dynamic.as_ref().is_some_and(|d| d.is_pie_flag);
            let soname = dynamic.as_ref().is_some_and(|d| d.has_soname);
            if pie_flag || (interpreter.is_some() && !soname) {
                BinaryKind::PieExecutable
            } else {
                BinaryKind::SharedLibrary
            }
        }
        _ => BinaryKind::Other,
    };
    let arch = match eh.machine {
        relocs::EM_X86_64 => ArchId::X86_64,
        relocs::EM_386 => ArchId::X86,
        relocs::EM_AARCH64 => ArchId::Aarch64,
        other => ArchId::Unknown(other),
    };
    let entry = if eh.entry != 0 {
        Some(ctx.rebase(eh.entry)?)
    } else {
        None
    };
    // `base` is the load bias: `LoadOptions::base` for `ET_DYN`, 0 otherwise.
    let base = Address(bias);
    let info = BinaryInfo {
        format: BinaryFormat::Elf,
        kind,
        arch,
        endian: if eh.fmt.le {
            Endian::Little
        } else {
            Endian::Big
        },
        bits: if eh.fmt.is64 { 64 } else { 32 },
        entry,
        base,
        build_id: find_build_id(&ctx, &phdrs, &shdrs),
        interpreter,
        needed_libraries: dynamic
            .as_ref()
            .map(|d| d.needed.clone())
            .unwrap_or_default(),
        sha256: sha256(data),
        ..Default::default()
    };

    // Symbols.
    let mut used = 0usize;
    let mut symbols = syms::read_symbols(&ctx, &shdrs, &mut used)?;

    // Relocations and imports.
    let versions = dynamic
        .as_ref()
        .map(|d| parse_verneed(data, &eh, d, &ctx.budget))
        .transpose()?
        .unwrap_or_default();
    let rel = relocs::read_relocs(&ctx, dynamic.as_ref(), &shdrs, &memory, &versions)?;

    // Relocatable objects have section-relative values only: no DWARF
    // symbols, no function hints.
    let is_rel = eh.etype == ET_REL;

    // DWARF.
    let budget = limits.max_symbols.saturating_sub(used);
    let dwarf_fns = if is_rel {
        Vec::new()
    } else {
        hints::dwarf_functions(&ctx, &shdrs, budget)?
    };

    // Function hints.
    let mut fh: Vec<FunctionHint> = Vec::new();
    if !is_rel {
        if let Some(e) = entry {
            fh.push(FunctionHint {
                address: e,
                size: None,
                source: FunctionHintSource::Entry,
                ..Default::default()
            });
        }
        for s in &symbols {
            if matches!(s.kind, SymbolKind::Function | SymbolKind::Ifunc)
                && !s.undefined
                && s.address != Address::ZERO
            {
                fh.push(FunctionHint {
                    address: s.address,
                    size: s.size,
                    source: FunctionHintSource::Symbol,
                    ..Default::default()
                });
            }
        }
        fh.extend(hints::eh_frame_hints(&ctx, &shdrs)?);
        for f in &dwarf_fns {
            fh.push(FunctionHint {
                address: f.address,
                size: Some(f.size),
                source: FunctionHintSource::Dwarf,
                ..Default::default()
            });
        }
        fh.extend(hints::array_hints(
            &ctx,
            &shdrs,
            dynamic.as_ref(),
            &phdrs,
            &rel,
        )?);
        fh.extend(rel.plt_hints.iter().cloned());
        fh.sort_by_key(|h| h.address);
        fh.dedup_by(|a, b| a.address == b.address && a.source == b.source);
    }

    symbols.extend(dwarf_fns.into_iter().map(|f| Symbol {
        name: f.name,
        address: f.address,
        size: Some(f.size),
        kind: SymbolKind::Function,
        source: SymbolSource::Dwarf,
        ..Default::default()
    }));

    Ok(LoadedImage {
        info,
        memory,
        segments,
        sections,
        symbols,
        imports: rel.imports,
        relocations: rel.relocs,
        function_hints: fh,
        ..Default::default()
    })
}
