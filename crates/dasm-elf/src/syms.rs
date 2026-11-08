//! `.symtab` / `.dynsym` -> [`Symbol`].

use dasm_core::{Address, LoadError, Symbol, SymbolBinding, SymbolKind, SymbolSource};

use crate::Ctx;
use crate::raw::{Res, SHT_DYNSYM, SHT_SYMTAB, Shdr};

const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;

/// A raw symbol table entry.
pub(crate) struct RawSym {
    pub name: u32,
    pub info: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

/// Size of one symbol table entry.
pub(crate) fn sym_size(is64: bool) -> u64 {
    if is64 { 24 } else { 16 }
}

/// Reads the symbol at file offset `off`.
pub(crate) fn read_sym(ctx: &Ctx<'_>, off: u64) -> Option<RawSym> {
    let mut c = ctx.eh.fmt.cur(ctx.data, off)?;
    if ctx.eh.fmt.is64 {
        let name = c.u32()?;
        let info = c.u8()?;
        let _other = c.u8()?;
        let shndx = c.u16()?;
        let value = c.u64()?;
        let size = c.u64()?;
        Some(RawSym {
            name,
            info,
            shndx,
            value,
            size,
        })
    } else {
        let name = c.u32()?;
        let value = u64::from(c.u32()?);
        let size = u64::from(c.u32()?);
        let info = c.u8()?;
        let _other = c.u8()?;
        let shndx = c.u16()?;
        Some(RawSym {
            name,
            info,
            shndx,
            value,
            size,
        })
    }
}

pub(crate) fn kind_of(stt: u8) -> SymbolKind {
    match stt {
        1 => SymbolKind::Object,
        2 => SymbolKind::Function,
        3 => SymbolKind::Section,
        4 => SymbolKind::File,
        6 => SymbolKind::Tls,
        10 => SymbolKind::Ifunc,
        _ => SymbolKind::Unknown,
    }
}

/// Reads all `.symtab`/`.dynsym` tables. `used` counts symbols already
/// produced, to enforce `max_symbols` across all sources.
pub(crate) fn read_symbols(ctx: &Ctx<'_>, sections: &[Shdr], used: &mut usize) -> Res<Vec<Symbol>> {
    let mut out = Vec::new();
    let esz = sym_size(ctx.eh.fmt.is64);
    for sec in sections
        .iter()
        .filter(|s| s.stype == SHT_SYMTAB || s.stype == SHT_DYNSYM)
    {
        let source = if sec.stype == SHT_SYMTAB {
            SymbolSource::Static
        } else {
            SymbolSource::Dynamic
        };
        // Advisory data: an unreadable table is skipped.
        let Some(raw) = sec.bytes(ctx.data) else {
            continue;
        };
        let strtab = usize::try_from(sec.link)
            .ok()
            .and_then(|i| sections.get(i))
            .and_then(|s| s.bytes(ctx.data))
            .unwrap_or(&[]);
        let n = raw.len() as u64 / esz;
        if (*used as u64).saturating_add(n) > ctx.limits.max_symbols as u64 {
            return Err(LoadError::LimitExceeded(format!(
                "more than {} symbols",
                ctx.limits.max_symbols
            )));
        }
        for i in 1..n {
            let Some(rs) = read_sym(ctx, sec.offset + i * esz) else {
                break;
            };
            if let Some(sym) = make_symbol(ctx, &rs, strtab, source)? {
                out.push(sym);
                *used += 1;
            }
        }
    }
    Ok(out)
}

/// `Ok(None)` skips a broken entry (address overflow).
fn make_symbol(
    ctx: &Ctx<'_>,
    rs: &RawSym,
    strtab: &[u8],
    source: SymbolSource,
) -> Res<Option<Symbol>> {
    let undefined = rs.shndx == SHN_UNDEF;
    let kind = kind_of(rs.info & 0xf);
    let address = if undefined {
        Address::ZERO
    } else if rs.shndx < SHN_LORESERVE && kind != SymbolKind::Tls {
        match ctx.rebase(rs.value) {
            Ok(a) => a,
            Err(_) => return Ok(None),
        }
    } else {
        // SHN_ABS / SHN_COMMON, and STT_TLS (an offset into the TLS block):
        // not addresses inside the image, never rebased.
        Address(rs.value)
    };
    let binding = match rs.info >> 4 {
        0 => SymbolBinding::Local,
        2 => SymbolBinding::Weak,
        _ => SymbolBinding::Global,
    };
    Ok(Some(Symbol {
        name: ctx
            .budget
            .string(strtab, u64::from(rs.name))?
            .unwrap_or_default(),
        address,
        size: (rs.size != 0).then_some(rs.size),
        kind,
        binding,
        source,
        undefined,
        ..Default::default()
    }))
}
