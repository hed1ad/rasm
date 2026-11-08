//! Bounds-checked reading of raw ELF structures (32/64-bit, both endians).

use dasm_core::{Limits, LoadError};

pub(crate) type Res<T> = Result<T, LoadError>;

pub(crate) fn malformed(what: &str, reason: impl Into<String>) -> LoadError {
    LoadError::Malformed {
        what: what.to_string(),
        reason: reason.into(),
    }
}

pub(crate) fn truncated(what: &str, offset: u64) -> LoadError {
    LoadError::Truncated {
        what: what.to_string(),
        offset,
    }
}

/// ELF class and byte order.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fmt {
    pub is64: bool,
    pub le: bool,
}

/// Sequential reader over a byte slice; every read is bounds-checked.
pub(crate) struct Cur<'a> {
    data: &'a [u8],
    off: usize,
    fmt: Fmt,
}

impl<'a> Cur<'a> {
    pub(crate) fn new(data: &'a [u8], off: usize, fmt: Fmt) -> Self {
        Cur { data, off, fmt }
    }

    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.off.checked_add(N)?;
        let b: [u8; N] = self.data.get(self.off..end)?.try_into().ok()?;
        self.off = end;
        Some(b)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|b| b[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let b = self.take::<2>()?;
        Some(if self.fmt.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let b = self.take::<4>()?;
        Some(if self.fmt.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        let b = self.take::<8>()?;
        Some(if self.fmt.le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    /// Pointer-sized unsigned word (4 or 8 bytes).
    pub(crate) fn word(&mut self) -> Option<u64> {
        if self.fmt.is64 {
            self.u64()
        } else {
            self.u32().map(u64::from)
        }
    }

    /// Pointer-sized signed word.
    pub(crate) fn sword(&mut self) -> Option<i64> {
        if self.fmt.is64 {
            self.u64().map(|v| v as i64)
        } else {
            self.u32().map(|v| i64::from(v as i32))
        }
    }
}

impl Fmt {
    pub(crate) fn cur<'a>(self, data: &'a [u8], off: u64) -> Option<Cur<'a>> {
        Some(Cur::new(data, usize::try_from(off).ok()?, self))
    }

    pub(crate) fn word_size(self) -> u64 {
        if self.is64 { 8 } else { 4 }
    }
}

pub(crate) const ET_REL: u16 = 1;
pub(crate) const ET_EXEC: u16 = 2;
pub(crate) const ET_DYN: u16 = 3;
pub(crate) const ET_CORE: u16 = 4;

/// Parsed ELF header.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ehdr {
    pub fmt: Fmt,
    pub etype: u16,
    pub machine: u16,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

impl Ehdr {
    pub(crate) fn parse(d: &[u8]) -> Res<Ehdr> {
        if d.get(..4) != Some(b"\x7fELF") {
            return Err(LoadError::UnknownFormat);
        }
        let is64 = match d.get(4) {
            Some(1) => false,
            Some(2) => true,
            other => return Err(malformed("ELF header", format!("bad class {other:?}"))),
        };
        let le = match d.get(5) {
            Some(1) => true,
            Some(2) => false,
            other => {
                return Err(malformed(
                    "ELF header",
                    format!("bad data encoding {other:?}"),
                ));
            }
        };
        let fmt = Fmt { is64, le };
        let min = if is64 { 64 } else { 52 };
        if d.len() < min {
            return Err(truncated("ELF header", d.len() as u64));
        }
        let t = || truncated("ELF header", 0);
        let mut c = Cur::new(d, 16, fmt);
        let etype = c.u16().ok_or_else(t)?;
        let machine = c.u16().ok_or_else(t)?;
        let _version = c.u32().ok_or_else(t)?;
        let entry = c.word().ok_or_else(t)?;
        let phoff = c.word().ok_or_else(t)?;
        let shoff = c.word().ok_or_else(t)?;
        let _flags = c.u32().ok_or_else(t)?;
        let _ehsize = c.u16().ok_or_else(t)?;
        let phentsize = c.u16().ok_or_else(t)?;
        let phnum = c.u16().ok_or_else(t)?;
        let shentsize = c.u16().ok_or_else(t)?;
        let shnum = c.u16().ok_or_else(t)?;
        let shstrndx = c.u16().ok_or_else(t)?;
        Ok(Ehdr {
            fmt,
            etype,
            machine,
            entry,
            phoff,
            shoff,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        })
    }
}

pub(crate) const PT_LOAD: u32 = 1;
pub(crate) const PT_DYNAMIC: u32 = 2;
pub(crate) const PT_INTERP: u32 = 3;
pub(crate) const PT_NOTE: u32 = 4;
pub(crate) const PT_PHDR: u32 = 6;
pub(crate) const PT_TLS: u32 = 7;
pub(crate) const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub(crate) const PT_GNU_STACK: u32 = 0x6474_e551;
pub(crate) const PT_GNU_RELRO: u32 = 0x6474_e552;
pub(crate) const PT_GNU_PROPERTY: u32 = 0x6474_e553;

/// Program header.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Phdr {
    pub ptype: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

pub(crate) fn parse_phdrs(d: &[u8], eh: &Ehdr, limits: &Limits) -> Res<Vec<Phdr>> {
    let n = usize::from(eh.phnum);
    if n == 0 || eh.phoff == 0 {
        return Ok(Vec::new());
    }
    if n > limits.max_sections {
        return Err(LoadError::LimitExceeded(format!(
            "{n} program headers, limit is {}",
            limits.max_sections
        )));
    }
    let min = if eh.fmt.is64 { 56 } else { 32 };
    let ent = u64::from(eh.phentsize);
    if ent < min {
        return Err(malformed(
            "program header table",
            format!("entry size {ent} is too small"),
        ));
    }
    let end = ent
        .checked_mul(n as u64)
        .and_then(|s| s.checked_add(eh.phoff))
        .ok_or_else(|| malformed("program header table", "offset overflows"))?;
    if end > d.len() as u64 {
        return Err(truncated("program header table", eh.phoff));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n as u64 {
        let off = eh.phoff + i * ent;
        let t = || truncated("program header", off);
        let mut c = eh.fmt.cur(d, off).ok_or_else(t)?;
        let ptype = c.u32().ok_or_else(t)?;
        let ph = if eh.fmt.is64 {
            let flags = c.u32().ok_or_else(t)?;
            let offset = c.u64().ok_or_else(t)?;
            let vaddr = c.u64().ok_or_else(t)?;
            let _paddr = c.u64().ok_or_else(t)?;
            let filesz = c.u64().ok_or_else(t)?;
            let memsz = c.u64().ok_or_else(t)?;
            let align = c.u64().ok_or_else(t)?;
            Phdr {
                ptype,
                flags,
                offset,
                vaddr,
                filesz,
                memsz,
                align,
            }
        } else {
            let offset = u64::from(c.u32().ok_or_else(t)?);
            let vaddr = u64::from(c.u32().ok_or_else(t)?);
            let _paddr = c.u32().ok_or_else(t)?;
            let filesz = u64::from(c.u32().ok_or_else(t)?);
            let memsz = u64::from(c.u32().ok_or_else(t)?);
            let flags = c.u32().ok_or_else(t)?;
            let align = u64::from(c.u32().ok_or_else(t)?);
            Phdr {
                ptype,
                flags,
                offset,
                vaddr,
                filesz,
                memsz,
                align,
            }
        };
        out.push(ph);
    }
    Ok(out)
}

pub(crate) const SHT_NULL: u32 = 0;
pub(crate) const SHT_SYMTAB: u32 = 2;
pub(crate) const SHT_NOBITS: u32 = 8;
pub(crate) const SHT_INIT_ARRAY: u32 = 14;
pub(crate) const SHT_FINI_ARRAY: u32 = 15;
pub(crate) const SHT_DYNSYM: u32 = 11;
pub(crate) const SHF_WRITE: u64 = 1;
pub(crate) const SHF_ALLOC: u64 = 2;
pub(crate) const SHF_EXECINSTR: u64 = 4;
pub(crate) const SHF_TLS: u64 = 0x400;
pub(crate) const SHF_COMPRESSED: u64 = 0x800;

/// Section header with its resolved name.
#[derive(Clone, Debug)]
pub(crate) struct Shdr {
    pub name: String,
    pub stype: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
}

impl Shdr {
    /// File bytes of the section; `None` for NOBITS, compressed or
    /// out-of-file sections.
    pub(crate) fn bytes<'a>(&self, d: &'a [u8]) -> Option<&'a [u8]> {
        if self.stype == SHT_NOBITS || self.flags & SHF_COMPRESSED != 0 {
            return None;
        }
        let start = usize::try_from(self.offset).ok()?;
        let end = start.checked_add(usize::try_from(self.size).ok()?)?;
        d.get(start..end)
    }
}

/// Total budget for string data copied out of the file during one load.
///
/// Many table entries may point at the same (possibly huge) string, so
/// copying strings amplifies memory use. Every copied byte is charged here;
/// the budget is [`Limits::max_string_bytes`](dasm_core::Limits).
pub(crate) struct Budget(std::cell::Cell<u64>);

impl Budget {
    pub(crate) fn new(max_bytes: u64) -> Self {
        Budget(std::cell::Cell::new(max_bytes))
    }

    /// Charges `n` bytes; fails with `LimitExceeded` when exhausted.
    pub(crate) fn charge(&self, n: u64) -> Res<()> {
        match self.0.get().checked_sub(n) {
            Some(left) => {
                self.0.set(left);
                Ok(())
            }
            None => Err(LoadError::LimitExceeded(
                "string data copied from the file exceeds the load budget".into(),
            )),
        }
    }

    /// Copies the NUL-terminated string at `off` in `table` (lossy UTF-8,
    /// never truncated). `Ok(None)` if `off` is outside the table.
    pub(crate) fn string(&self, table: &[u8], off: u64) -> Res<Option<String>> {
        let Some(rest) = usize::try_from(off).ok().and_then(|o| table.get(o..)) else {
            return Ok(None);
        };
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        self.charge(end as u64)?;
        Ok(Some(
            String::from_utf8_lossy(rest.get(..end).unwrap_or(&[])).into_owned(),
        ))
    }
}

/// Raw section header fields.
struct RawSh {
    name: u32,
    stype: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
}

/// Parses the section header table.
///
/// A table that does not fit in the file (or has a bad entry size) is
/// treated as absent: sections are optional metadata, segments suffice to
/// load. Exceeding `max_sections` is an error.
pub(crate) fn parse_shdrs(d: &[u8], eh: &Ehdr, limits: &Limits, budget: &Budget) -> Res<Vec<Shdr>> {
    if eh.shoff == 0 {
        return Ok(Vec::new());
    }
    let min = if eh.fmt.is64 { 64 } else { 40 };
    let ent = u64::from(eh.shentsize);
    if ent < min {
        return Ok(Vec::new());
    }
    let raw_at = |i: u64| -> Option<RawSh> {
        let off = eh.shoff.checked_add(i.checked_mul(ent)?)?;
        let mut c = eh.fmt.cur(d, off)?;
        let name = c.u32()?;
        let stype = c.u32()?;
        let flags = c.word()?;
        let addr = c.word()?;
        let offset = c.word()?;
        let size = c.word()?;
        let link = c.u32()?;
        Some(RawSh {
            name,
            stype,
            flags,
            addr,
            offset,
            size,
            link,
        })
    };
    let Some(first) = raw_at(0) else {
        return Ok(Vec::new());
    };
    let mut n = u64::from(eh.shnum);
    if n == 0 {
        n = first.size; // extended numbering: size of section 0
    }
    let mut strndx = u64::from(eh.shstrndx);
    if eh.shstrndx == 0xffff {
        strndx = u64::from(first.link);
    }
    if n > limits.max_sections as u64 {
        return Err(LoadError::LimitExceeded(format!(
            "{n} sections, limit is {}",
            limits.max_sections
        )));
    }
    let fits = ent
        .checked_mul(n)
        .and_then(|s| s.checked_add(eh.shoff))
        .is_some_and(|e| e <= d.len() as u64);
    if !fits {
        return Ok(Vec::new());
    }
    let strtab: &[u8] = raw_at(strndx)
        .filter(|r| r.stype != SHT_NOBITS)
        .and_then(|r| {
            let s = usize::try_from(r.offset).ok()?;
            d.get(s..s.checked_add(usize::try_from(r.size).ok()?)?)
        })
        .unwrap_or(&[]);
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let Some(r) = raw_at(i) else {
            return Ok(Vec::new());
        };
        out.push(Shdr {
            name: budget
                .string(strtab, u64::from(r.name))?
                .unwrap_or_default(),
            stype: r.stype,
            flags: r.flags,
            addr: r.addr,
            offset: r.offset,
            size: r.size,
            link: r.link,
        });
    }
    Ok(out)
}
