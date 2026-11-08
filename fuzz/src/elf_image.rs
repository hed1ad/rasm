//! A minimal ELF64 (x86-64, little-endian, `ET_DYN`) writer, used to wrap
//! fuzzer bytes into a well-formed container: the `eh_frame` and `dwarf`
//! targets put the input into `.eh_frame` / `.debug_*` sections so that
//! the fuzzer spends its time in those parsers, not in the ELF header.
//!
//! Layout: headers, then each section at file offset == virtual address
//! (16-aligned, from 0x1000), covered by one `PT_LOAD` (R+X); then
//! `.shstrtab` and the section header table.

/// `SHT_PROGBITS`.
pub const SHT_PROGBITS: u32 = 1;
/// `SHF_ALLOC`.
pub const SHF_ALLOC: u64 = 2;
/// `SHF_EXECINSTR`.
pub const SHF_EXECINSTR: u64 = 4;

/// One section to emit.
#[derive(Debug, Clone)]
pub struct SectionSpec<'a> {
    /// Name (`.text`, `.eh_frame`, ...).
    pub name: &'a str,
    /// `sh_type`.
    pub sh_type: u32,
    /// `sh_flags`.
    pub flags: u64,
    /// Contents.
    pub data: &'a [u8],
}

/// Where a section ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    /// Virtual address (== file offset).
    pub addr: u64,
    /// Size.
    pub size: u64,
}

const EHDR: usize = 64;
const PHDR: usize = 56;
const SHDR: usize = 64;
const FIRST: usize = 0x1000;

fn align(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}

/// Builds the image. Returns the file and where each section was placed.
#[must_use]
pub fn build(sections: &[SectionSpec<'_>]) -> (Vec<u8>, Vec<Placed>) {
    let mut placed = Vec::with_capacity(sections.len());
    let mut body: Vec<u8> = vec![0; FIRST];
    for s in sections {
        let at = align(body.len(), 16);
        body.resize(at, 0);
        body.extend_from_slice(s.data);
        placed.push(Placed {
            addr: at as u64,
            size: s.data.len() as u64,
        });
    }
    let load_end = body.len() as u64;

    let mut shstrtab = vec![0u8];
    let mut name_offsets = Vec::with_capacity(sections.len());
    for s in sections {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(s.name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");
    let shstrtab_off = body.len();
    body.extend_from_slice(&shstrtab);
    let shoff = align(body.len(), 8);
    body.resize(shoff, 0);

    let entry = sections
        .iter()
        .zip(&placed)
        .find(|(s, _)| s.flags & SHF_EXECINSTR != 0)
        .map_or(0, |(_, p)| p.addr);
    let shnum = sections.len() + 2; // null + sections + .shstrtab

    // ELF header.
    let mut h = Vec::with_capacity(EHDR + PHDR);
    put(&mut h, b"\x7fELF");
    put(&mut h, &[2, 1, 1, 0]); // ELFCLASS64, LSB, EV_CURRENT, SYSV
    put(&mut h, &[0; 8]);
    put(&mut h, &3u16.to_le_bytes()); // ET_DYN
    put(&mut h, &62u16.to_le_bytes()); // EM_X86_64
    put(&mut h, &1u32.to_le_bytes());
    put(&mut h, &entry.to_le_bytes());
    put(&mut h, &(EHDR as u64).to_le_bytes()); // e_phoff
    put(&mut h, &(shoff as u64).to_le_bytes());
    put(&mut h, &0u32.to_le_bytes()); // e_flags
    put(&mut h, &(EHDR as u16).to_le_bytes());
    put(&mut h, &(PHDR as u16).to_le_bytes());
    put(&mut h, &1u16.to_le_bytes()); // e_phnum
    put(&mut h, &(SHDR as u16).to_le_bytes());
    put(&mut h, &(shnum as u16).to_le_bytes());
    put(&mut h, &((shnum - 1) as u16).to_le_bytes()); // e_shstrndx
    // PT_LOAD covering [0, load_end).
    put(&mut h, &1u32.to_le_bytes());
    put(&mut h, &5u32.to_le_bytes()); // PF_R | PF_X
    put(&mut h, &0u64.to_le_bytes()); // p_offset
    put(&mut h, &0u64.to_le_bytes()); // p_vaddr
    put(&mut h, &0u64.to_le_bytes()); // p_paddr
    put(&mut h, &load_end.to_le_bytes()); // p_filesz
    put(&mut h, &load_end.to_le_bytes()); // p_memsz
    put(&mut h, &0x1000u64.to_le_bytes()); // p_align
    for (dst, src) in body.iter_mut().zip(&h) {
        *dst = *src;
    }

    // Section headers.
    let shdr =
        |out: &mut Vec<u8>, name: u32, ty: u32, flags: u64, addr: u64, off: u64, size: u64| {
            put(out, &name.to_le_bytes());
            put(out, &ty.to_le_bytes());
            put(out, &flags.to_le_bytes());
            put(out, &addr.to_le_bytes());
            put(out, &off.to_le_bytes());
            put(out, &size.to_le_bytes());
            put(out, &0u32.to_le_bytes()); // link
            put(out, &0u32.to_le_bytes()); // info
            put(out, &1u64.to_le_bytes()); // addralign
            put(out, &0u64.to_le_bytes()); // entsize
        };
    body.extend_from_slice(&[0; SHDR]);
    for ((s, p), name) in sections.iter().zip(&placed).zip(&name_offsets) {
        let addr = if s.flags & SHF_ALLOC != 0 { p.addr } else { 0 };
        shdr(&mut body, *name, s.sh_type, s.flags, addr, p.addr, p.size);
    }
    shdr(
        &mut body,
        shstrtab_name,
        3,
        0,
        0,
        shstrtab_off as u64,
        shstrtab.len() as u64,
    );
    (body, placed)
}

/// Splits fuzzer input into `n` chunks: the first `2 * (n - 1)` bytes are
/// little-endian `u16` lengths of the first `n - 1` chunks, the rest is the
/// last chunk.
#[must_use]
pub fn split(data: &[u8], n: usize) -> Vec<&[u8]> {
    let mut r = crate::input::Reader::new(data);
    let lens: Vec<usize> = (1..n).map(|_| usize::from(r.u16())).collect();
    let mut out: Vec<&[u8]> = lens.into_iter().map(|l| r.bytes(l)).collect();
    out.push(r.bytes(usize::MAX));
    out
}
