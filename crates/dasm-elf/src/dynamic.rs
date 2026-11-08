//! `PT_DYNAMIC` contents and GNU symbol versioning.

use std::collections::HashMap;

use dasm_core::LoadError;

use crate::raw::{Budget, Ehdr, PT_DYNAMIC, PT_LOAD, Phdr, Res};

/// Upper bound on dynamic section entries; more is `LimitExceeded`.
const MAX_DYNAMIC_TAGS: u64 = 1 << 16;

const DT_NEEDED: u64 = 1;
const DT_PLTRELSZ: u64 = 2;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_VERSYM: u64 = 0x6fff_fff0;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DT_VERNEED: u64 = 0x6fff_fffe;
const DT_VERNEEDNUM: u64 = 0x6fff_ffff;
const DF_1_PIE: u64 = 0x0800_0000;

/// A byte range inside the file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Table {
    pub off: usize,
    pub size: usize,
}

/// Information from the dynamic section; offsets are file offsets.
#[derive(Debug, Default)]
pub(crate) struct DynInfo {
    pub needed: Vec<String>,
    pub has_soname: bool,
    pub is_pie_flag: bool,
    pub strtab: Option<Table>,
    pub symtab_off: Option<usize>,
    pub rela: Option<Table>,
    pub rel: Option<Table>,
    pub jmprel: Option<Table>,
    pub jmprel_is_rela: bool,
    pub relr: Option<Table>,
    pub versym_off: Option<usize>,
    pub verneed: Option<(usize, u64)>,
    /// (vaddr, size) of `DT_INIT_ARRAY` / `DT_FINI_ARRAY`, link-time.
    pub init_array: Option<(u64, u64)>,
    pub fini_array: Option<(u64, u64)>,
}

/// Translates a link-time virtual range to a file offset through `PT_LOAD`.
pub(crate) fn vaddr_to_off(data: &[u8], phdrs: &[Phdr], vaddr: u64, len: u64) -> Option<usize> {
    let end = vaddr.checked_add(len)?;
    for p in phdrs.iter().filter(|p| p.ptype == PT_LOAD) {
        let pend = p.vaddr.checked_add(p.filesz)?;
        if vaddr >= p.vaddr && end <= pend {
            let off = p.offset.checked_add(vaddr - p.vaddr)?;
            if off.checked_add(len)? <= data.len() as u64 {
                return usize::try_from(off).ok();
            }
        }
    }
    None
}

impl DynInfo {
    /// Reads the dynamic section, if any. Only the first `PT_DYNAMIC`
    /// segment is used; further ones are ignored. More than 65 536 real
    /// (non-terminator) entries is `LimitExceeded`.
    pub(crate) fn parse(
        data: &[u8],
        eh: &Ehdr,
        phdrs: &[Phdr],
        budget: &Budget,
    ) -> Res<Option<DynInfo>> {
        let Some(dynp) = phdrs.iter().find(|p| p.ptype == PT_DYNAMIC) else {
            return Ok(None);
        };
        let esz = eh.fmt.word_size() * 2;
        let Some(mut cur) = eh.fmt.cur(data, dynp.offset) else {
            return Ok(None);
        };
        // Entries actually present in the file (the header may claim more).
        let avail = (data.len() as u64).saturating_sub(dynp.offset);
        let count = dynp.filesz.min(avail) / esz;
        let mut tags: Vec<(u64, u64)> = Vec::new();
        let mut terminated = false;
        for _ in 0..count.min(MAX_DYNAMIC_TAGS) {
            let (Some(tag), Some(val)) = (cur.word(), cur.word()) else {
                break;
            };
            if tag == 0 {
                terminated = true;
                break;
            }
            tags.push((tag, val));
        }
        // The limit is exceeded only by MAX_DYNAMIC_TAGS real entries that
        // are followed by yet another non-terminator entry; the declared
        // `p_filesz` alone is never a reason to fail.
        if !terminated
            && count > MAX_DYNAMIC_TAGS
            && let (Some(tag), Some(_)) = (cur.word(), cur.word())
            && tag != 0
        {
            return Err(LoadError::LimitExceeded(format!(
                "dynamic section has more than {MAX_DYNAMIC_TAGS} entries"
            )));
        }
        let get = |t: u64| tags.iter().find(|e| e.0 == t).map(|e| e.1);
        let mut info = DynInfo::default();
        let strsz = get(DT_STRSZ);
        if let (Some(addr), Some(sz)) = (get(DT_STRTAB), strsz)
            && let Some(off) = vaddr_to_off(data, phdrs, addr, sz)
            && let Ok(size) = usize::try_from(sz)
        {
            info.strtab = Some(Table { off, size });
        }
        // Advisory data: a table outside the file is skipped, not an error.
        let table = |addr_tag: u64, size_tag: u64| -> Option<Table> {
            let (addr, size) = (get(addr_tag)?, get(size_tag)?);
            if size == 0 {
                return None;
            }
            let off = vaddr_to_off(data, phdrs, addr, size)?;
            Some(Table {
                off,
                size: usize::try_from(size).ok()?,
            })
        };
        info.rela = table(DT_RELA, DT_RELASZ);
        info.rel = table(DT_REL, DT_RELSZ);
        info.jmprel = table(DT_JMPREL, DT_PLTRELSZ);
        info.relr = table(DT_RELR, DT_RELRSZ);
        info.jmprel_is_rela = match get(DT_PLTREL) {
            Some(7) => true,
            Some(_) => false,
            None => eh.fmt.is64,
        };
        info.symtab_off = get(DT_SYMTAB).and_then(|a| vaddr_to_off(data, phdrs, a, 0));
        info.versym_off = get(DT_VERSYM).and_then(|a| vaddr_to_off(data, phdrs, a, 0));
        if let (Some(a), Some(n)) = (get(DT_VERNEED), get(DT_VERNEEDNUM))
            && let Some(off) = vaddr_to_off(data, phdrs, a, 0)
        {
            info.verneed = Some((off, n));
        }
        info.init_array = get(DT_INIT_ARRAY).zip(get(DT_INIT_ARRAYSZ));
        info.fini_array = get(DT_FINI_ARRAY).zip(get(DT_FINI_ARRAYSZ));
        info.is_pie_flag = get(DT_FLAGS_1).is_some_and(|f| f & DF_1_PIE != 0);
        info.has_soname = get(DT_SONAME).is_some();
        if info.strtab.is_some() {
            for (_, v) in tags.iter().filter(|e| e.0 == DT_NEEDED) {
                if let Some(n) = info.dynstr(data, budget, *v)? {
                    info.needed.push(n);
                }
            }
        }
        Ok(Some(info))
    }

    /// String from the dynamic string table (charged to `budget`).
    pub(crate) fn dynstr(&self, data: &[u8], budget: &Budget, off: u64) -> Res<Option<String>> {
        let Some(st) = self.strtab else {
            return Ok(None);
        };
        let Some(tab) = st
            .off
            .checked_add(st.size)
            .and_then(|e| data.get(st.off..e))
        else {
            return Ok(None);
        };
        budget.string(tab, off)
    }
}

/// Upper bound on `Verneed` + `Vernaux` records visited. Version data is
/// advisory: when the bound is hit the walk stops and the versions read so
/// far are kept (the load does not fail; the remaining imports simply have
/// no version).
const MAX_VERSION_RECORDS: u32 = 1 << 16;

/// `(version name, library file)` per `vna_other` index.
pub(crate) fn parse_verneed(
    data: &[u8],
    eh: &Ehdr,
    info: &DynInfo,
    budget: &Budget,
) -> Res<HashMap<u16, (String, String)>> {
    let mut out = HashMap::new();
    let Some((start, num)) = info.verneed else {
        return Ok(out);
    };
    let mut visits = 0u32;
    let mut off = start as u64;
    for _ in 0..num {
        let Some(mut c) = eh.fmt.cur(data, off) else {
            break;
        };
        let (Some(_ver), Some(cnt), Some(file), Some(aux), Some(next)) =
            (c.u16(), c.u16(), c.u32(), c.u32(), c.u32())
        else {
            break;
        };
        let lib = info
            .dynstr(data, budget, u64::from(file))?
            .unwrap_or_default();
        let mut aoff = off.saturating_add(u64::from(aux));
        for _ in 0..cnt {
            visits += 1;
            if visits > MAX_VERSION_RECORDS {
                return Ok(out);
            }
            let Some(mut a) = eh.fmt.cur(data, aoff) else {
                break;
            };
            let (Some(_hash), Some(_flags), Some(other), Some(name), Some(anext)) =
                (a.u32(), a.u16(), a.u16(), a.u32(), a.u32())
            else {
                break;
            };
            if let std::collections::hash_map::Entry::Vacant(v) = out.entry(other)
                && let Some(n) = info.dynstr(data, budget, u64::from(name))?
            {
                v.insert((n, lib.clone()));
            }
            if anext == 0 {
                break;
            }
            aoff = aoff.saturating_add(u64::from(anext));
        }
        visits += 1;
        if visits > MAX_VERSION_RECORDS {
            return Ok(out);
        }
        if next == 0 {
            break;
        }
        off = off.saturating_add(u64::from(next));
    }
    Ok(out)
}
