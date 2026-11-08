//! Dynamic relocations, imports (PLT/GOT) and PLT stub discovery.

use std::collections::{HashMap, HashSet};

use dasm_core::{
    FunctionHint, FunctionHintSource, Import, LoadError, MemoryMap, Relocation, SymbolKind,
};

use crate::Ctx;
use crate::dynamic::{DynInfo, Table};
use crate::raw::{Res, Shdr};
use crate::syms::{kind_of, read_sym, sym_size};

pub(crate) const EM_386: u16 = 3;
pub(crate) const EM_X86_64: u16 = 62;
pub(crate) const EM_AARCH64: u16 = 183;

/// Machine-specific relocation type numbers.
#[derive(Clone, Copy)]
pub(crate) struct RelocTypes {
    pub jump_slot: u32,
    pub glob_dat: u32,
    pub relative: u32,
}

pub(crate) fn reloc_types(machine: u16) -> Option<RelocTypes> {
    match machine {
        EM_X86_64 | EM_386 => Some(RelocTypes {
            jump_slot: 7,
            glob_dat: 6,
            relative: 8,
        }),
        EM_AARCH64 => Some(RelocTypes {
            jump_slot: 1026,
            glob_dat: 1025,
            relative: 1027,
        }),
        _ => None,
    }
}

/// Everything derived from the relocation tables.
#[derive(Default)]
pub(crate) struct RelocOut {
    pub relocs: Vec<Relocation>,
    pub imports: Vec<Import>,
    pub plt_hints: Vec<FunctionHint>,
    /// Rebased slot address -> link-time addend of relative relocations.
    pub relative: HashMap<u64, i64>,
}

struct Raw {
    offset: u64,
    rtype: u32,
    sym: u32,
    addend: i64,
    /// REL entry: the addend lives in the relocated word itself.
    implicit: bool,
}

fn read_table(ctx: &Ctx<'_>, t: Table, is_rela: bool, out: &mut Vec<Raw>, max: usize) -> Res<()> {
    let fmt = ctx.eh.fmt;
    let esz: u64 = match (fmt.is64, is_rela) {
        (true, true) => 24,
        (true, false) => 16,
        (false, true) => 12,
        (false, false) => 8,
    };
    let n = t.size as u64 / esz;
    if (out.len() as u64).saturating_add(n) > max as u64 {
        return Err(LoadError::LimitExceeded(format!(
            "more than {max} relocations"
        )));
    }
    for i in 0..n {
        let off = t.off as u64 + i * esz;
        let Some(mut c) = fmt.cur(ctx.data, off) else {
            break;
        };
        let (Some(offset), Some(info)) = (c.word(), c.word()) else {
            break;
        };
        let addend = if is_rela { c.sword().unwrap_or(0) } else { 0 };
        let (sym, rtype) = if fmt.is64 {
            ((info >> 32) as u32, info as u32)
        } else {
            ((info >> 8) as u32, (info & 0xff) as u32)
        };
        out.push(Raw {
            offset,
            rtype,
            sym,
            addend,
            implicit: !is_rela,
        });
    }
    Ok(())
}

/// Maps GOT slot (link-time address) -> (PLT stub address, stub size) by
/// decoding the `jmp *disp(%rip)` in each stub. x86-64 only.
fn plt_map(ctx: &Ctx<'_>, sections: &[Shdr]) -> HashMap<u64, (u64, u64)> {
    let mut map = HashMap::new();
    if ctx.eh.machine != EM_X86_64 {
        return map;
    }
    for name in [".plt.sec", ".plt", ".plt.got"] {
        let Some(sec) = sections.iter().find(|s| s.name == name) else {
            continue;
        };
        let Some(bytes) = sec.bytes(ctx.data) else {
            continue;
        };
        let endbr = bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]);
        let stride: usize = if name == ".plt.got" && !endbr { 8 } else { 16 };
        for (i, stub) in bytes.chunks(stride).enumerate() {
            if stub.len() < stride {
                break;
            }
            for pos in 0..=6usize {
                if stub.get(pos) == Some(&0xff) && stub.get(pos + 1) == Some(&0x25) {
                    let Some(d) = stub.get(pos + 2..pos + 6) else {
                        break;
                    };
                    let Ok(d4) = <[u8; 4]>::try_from(d) else {
                        break;
                    };
                    let disp = i64::from(i32::from_le_bytes(d4));
                    let stub_addr = sec.addr.wrapping_add((i * stride) as u64);
                    let target = stub_addr
                        .wrapping_add(pos as u64 + 6)
                        .wrapping_add_signed(disp);
                    map.entry(target).or_insert((stub_addr, stride as u64));
                    break;
                }
            }
        }
    }
    map
}

/// Reads relocations, builds imports and PLT hints.
pub(crate) fn read_relocs(
    ctx: &Ctx<'_>,
    dynamic: Option<&DynInfo>,
    sections: &[Shdr],
    memory: &MemoryMap,
    versions: &HashMap<u16, (String, String)>,
) -> Res<RelocOut> {
    let mut out = RelocOut::default();
    let Some(dy) = dynamic else {
        return Ok(out);
    };
    let fmt = ctx.eh.fmt;
    let max = ctx.limits.max_relocations;
    let mut raws: Vec<Raw> = Vec::new();
    if let Some(t) = dy.rela {
        read_table(ctx, t, true, &mut raws, max)?;
    }
    if let Some(t) = dy.rel {
        read_table(ctx, t, false, &mut raws, max)?;
    }
    if let Some(j) = dy.jmprel {
        let inside = |outer: Option<Table>| {
            outer.is_some_and(|o| j.off >= o.off && j.off + j.size <= o.off + o.size)
        };
        if !(inside(dy.rela) || inside(dy.rel)) {
            read_table(ctx, j, dy.jmprel_is_rela, &mut raws, max)?;
        }
    }
    let types = reloc_types(ctx.eh.machine);
    // RELR (packed relative relocations).
    if let (Some(t), Some(ty)) = (dy.relr, types) {
        let ws = fmt.word_size();
        let n = t.size as u64 / ws;
        let mut next: u64 = 0;
        for i in 0..n {
            let Some(mut c) = fmt.cur(ctx.data, t.off as u64 + i * ws) else {
                break;
            };
            let Some(e) = c.word() else { break };
            let mut addrs: Vec<u64> = Vec::new();
            if e & 1 == 0 {
                addrs.push(e);
                next = e.wrapping_add(ws);
            } else {
                let mut bits = e >> 1;
                let mut k = 0u64;
                while bits != 0 {
                    if bits & 1 != 0 {
                        addrs.push(next.wrapping_add(k * ws));
                    }
                    bits >>= 1;
                    k += 1;
                }
                next = next.wrapping_add((8 * ws - 1) * ws);
            }
            if raws.len() + addrs.len() + out.relocs.len() > max {
                return Err(LoadError::LimitExceeded(format!(
                    "more than {max} relocations"
                )));
            }
            for a in addrs {
                let Ok(rebased) = ctx.rebase(a) else {
                    continue;
                };
                let addend = memory
                    .read(rebased, ws as usize)
                    .and_then(|b| {
                        let mut c = fmt.cur(&b, 0)?;
                        c.sword()
                    })
                    .unwrap_or(0);
                out.relative.insert(rebased.0, addend);
                out.relocs.push(Relocation {
                    address: rebased,
                    kind: ty.relative,
                    symbol: None,
                    addend,
                    ..Default::default()
                });
            }
        }
        if raws.len() + out.relocs.len() > max {
            return Err(LoadError::LimitExceeded(format!(
                "more than {max} relocations"
            )));
        }
    }

    let plt = plt_map(ctx, sections);
    let esz = sym_size(fmt.is64);
    let mut seen_stubs: HashSet<u64> = HashSet::new();
    for r in raws {
        // Advisory data: a relocation whose address overflows is skipped.
        let Ok(address) = ctx.rebase(r.offset) else {
            continue;
        };
        let addend = if r.implicit {
            memory
                .read(address, fmt.word_size() as usize)
                .and_then(|b| fmt.cur(&b, 0)?.sword())
                .unwrap_or(0)
        } else {
            r.addend
        };
        let sym = if r.sym != 0 {
            dy.symtab_off
                .and_then(|so| read_sym(ctx, so as u64 + u64::from(r.sym) * esz))
        } else {
            None
        };
        let name = match &sym {
            Some(s) => dy
                .dynstr(ctx.data, &ctx.budget, u64::from(s.name))?
                .filter(|n| !n.is_empty()),
            None => None,
        };
        if let Some(ty) = types {
            if ty.relative == r.rtype {
                out.relative.insert(address.0, addend);
            }
            let is_slot = r.rtype == ty.jump_slot;
            let is_got = r.rtype == ty.glob_dat;
            if let (true, Some(n), Some(s)) = ((is_slot || is_got), name.as_ref(), sym.as_ref())
                && (is_slot || s.shndx == 0)
            {
                let (version, library) = version_of(ctx, dy, versions, r.sym);
                // The import owns copies of these strings.
                let copied = n.len()
                    + version.as_ref().map_or(0, String::len)
                    + library.as_ref().map_or(0, String::len);
                ctx.budget.charge(copied as u64)?;
                let stub = plt.get(&r.offset).copied();
                let plt_addr = stub.and_then(|(a, _)| ctx.rebase(a).ok());
                if let Some((a, size)) = stub
                    && let Some(address) = plt_addr
                    && seen_stubs.insert(a)
                {
                    out.plt_hints.push(FunctionHint {
                        address,
                        size: Some(size),
                        source: FunctionHintSource::Plt,
                        ..Default::default()
                    });
                }
                out.imports.push(Import {
                    name: n.clone(),
                    version,
                    library,
                    kind: if is_slot {
                        SymbolKind::Function
                    } else {
                        kind_of(s.info & 0xf)
                    },
                    plt: plt_addr,
                    got: Some(address),
                    ..Default::default()
                });
            }
        }
        out.relocs.push(Relocation {
            address,
            kind: r.rtype,
            symbol: name,
            addend,
            ..Default::default()
        });
    }
    Ok(out)
}

fn version_of(
    ctx: &Ctx<'_>,
    dy: &DynInfo,
    versions: &HashMap<u16, (String, String)>,
    sym: u32,
) -> (Option<String>, Option<String>) {
    let ver = dy.versym_off.and_then(|vo| {
        let mut c = ctx.eh.fmt.cur(ctx.data, vo as u64 + u64::from(sym) * 2)?;
        c.u16()
    });
    if let Some(idx) = ver.map(|v| v & 0x7fff)
        && let Some((v, lib)) = versions.get(&idx)
    {
        return (Some(v.clone()), Some(lib.clone()));
    }
    let lib = (dy.needed.len() == 1)
        .then(|| dy.needed.first().cloned())
        .flatten();
    (None, lib)
}
