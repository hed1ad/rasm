//! Unit tests: generated ELF images, comparison with `readelf` on system
//! binaries (skipped when unavailable) and robustness on mutated input.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use super::*;
use dasm_core::SymbolBinding;

// ---------------------------------------------------------------- builder

#[derive(Clone, Copy)]
struct Enc {
    is64: bool,
    le: bool,
}

#[derive(Default)]
struct Out(Vec<u8>, Option<Enc>);

impl Out {
    fn new(enc: Enc) -> Self {
        Out(Vec::new(), Some(enc))
    }
    fn enc(&self) -> Enc {
        self.1.unwrap()
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        let b = if self.enc().le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.0.extend(b);
    }
    fn u32(&mut self, v: u32) {
        let b = if self.enc().le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.0.extend(b);
    }
    fn u64(&mut self, v: u64) {
        let b = if self.enc().le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.0.extend(b);
    }
    fn word(&mut self, v: u64) {
        if self.enc().is64 {
            self.u64(v);
        } else {
            self.u32(v as u32);
        }
    }
    fn pad_to(&mut self, n: usize) {
        self.0.resize(n, 0);
    }
}

struct Ph {
    ptype: u32,
    flags: u32,
    off: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

struct Sh {
    name: u32,
    stype: u32,
    flags: u64,
    addr: u64,
    off: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

#[allow(clippy::too_many_arguments)]
/// Header + program headers at 64/52, section headers right after (if
/// any), file padded to `len`; `body` is written at `body_off`.
fn build(
    enc: Enc,
    etype: u16,
    machine: u16,
    entry: u64,
    phs: &[Ph],
    shs: &[Sh],
    shstrndx: u16,
    body_off: usize,
    body: &[u8],
) -> Vec<u8> {
    let mut o = Out::new(enc);
    o.0.extend(b"\x7fELF");
    o.u8(if enc.is64 { 2 } else { 1 });
    o.u8(if enc.le { 1 } else { 2 });
    o.u8(1);
    o.pad_to(16);
    let ehsize = if enc.is64 { 64 } else { 52 };
    let phsize = if enc.is64 { 56 } else { 32 };
    let shsize = if enc.is64 { 64 } else { 40 };
    let shoff = if shs.is_empty() {
        0
    } else {
        ehsize + phsize * phs.len()
    };
    o.u16(etype);
    o.u16(machine);
    o.u32(1);
    o.word(entry);
    o.word(if phs.is_empty() { 0 } else { ehsize as u64 });
    o.word(shoff as u64);
    o.u32(0);
    o.u16(ehsize as u16);
    o.u16(phsize as u16);
    o.u16(phs.len() as u16);
    o.u16(shsize as u16);
    o.u16(shs.len() as u16);
    o.u16(shstrndx);
    for p in phs {
        o.u32(p.ptype);
        if enc.is64 {
            o.u32(p.flags);
            o.u64(p.off);
            o.u64(p.vaddr);
            o.u64(p.vaddr);
            o.u64(p.filesz);
            o.u64(p.memsz);
            o.u64(0x1000);
        } else {
            o.u32(p.off as u32);
            o.u32(p.vaddr as u32);
            o.u32(p.vaddr as u32);
            o.u32(p.filesz as u32);
            o.u32(p.memsz as u32);
            o.u32(p.flags);
            o.u32(0x1000);
        }
    }
    for s in shs {
        o.u32(s.name);
        o.u32(s.stype);
        o.word(s.flags);
        o.word(s.addr);
        o.word(s.off);
        o.word(s.size);
        o.u32(s.link);
        o.u32(0);
        o.word(1);
        o.word(s.entsize);
    }
    assert!(o.0.len() <= body_off);
    o.pad_to(body_off);
    o.0.extend(body);
    o.0
}

const LE64: Enc = Enc {
    is64: true,
    le: true,
};

fn load(bytes: Vec<u8>) -> Result<LoadedImage, LoadError> {
    ElfLoader.load(SharedBytes::from(bytes), &LoadOptions::default())
}

fn load_with(bytes: Vec<u8>, o: &LoadOptions) -> Result<LoadedImage, LoadError> {
    ElfLoader.load(SharedBytes::from(bytes), o)
}

fn simple_exec(etype: u16) -> Vec<u8> {
    let body: Vec<u8> = (0..0x40u8).collect();
    build(
        LE64,
        etype,
        62,
        0x401010,
        &[
            Ph {
                ptype: 1,
                flags: 5,
                off: 0x200,
                vaddr: 0x401000,
                filesz: 0x40,
                memsz: 0x100,
            },
            Ph {
                ptype: 0x6474_e551,
                flags: 6,
                off: 0,
                vaddr: 0,
                filesz: 0,
                memsz: 0,
            },
            Ph {
                ptype: 0x1234_5678,
                flags: 4,
                off: 0,
                vaddr: 0,
                filesz: 0,
                memsz: 0,
            },
        ],
        &[],
        0,
        0x200,
        &body,
    )
}

// ------------------------------------------------------- generated images

#[test]
fn probe_and_name() {
    assert_eq!(ElfLoader.name(), "elf");
    assert!(ElfLoader.probe(b"\x7fELF...."));
    assert!(!ElfLoader.probe(b"MZ"));
    assert!(!ElfLoader.probe(b""));
}

#[test]
fn rejects_garbage_without_panicking() {
    assert_eq!(load(vec![]).unwrap_err(), LoadError::UnknownFormat);
    assert_eq!(
        load(b"MZ\x90\0".to_vec()).unwrap_err(),
        LoadError::UnknownFormat
    );
    assert!(load(b"\x7fELF".to_vec()).is_err());
    assert!(load(b"\x7fELF\x02\x01\x01".to_vec()).is_err());
    assert!(load(b"\x7fELF\x09\x01\x01".repeat(30)).is_err());
    assert!(
        load(vec![
            0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff
        ])
        .is_err()
    );
}

#[test]
fn exec_segments_and_memory() {
    let img = load(simple_exec(2)).unwrap();
    assert_eq!(img.info.kind, BinaryKind::Executable);
    assert_eq!(img.info.arch, ArchId::X86_64);
    assert_eq!(img.info.endian, Endian::Little);
    assert_eq!(img.info.bits, 64);
    assert_eq!(img.info.entry, Some(Address(0x401010)));
    assert_eq!(img.info.base, Address::ZERO);
    assert_eq!(img.segments.len(), 3);
    assert_eq!(img.segments[0].name, "LOAD[0]");
    assert_eq!(img.segments[0].perms, Permissions::RX);
    assert_eq!(img.segments[1].kind, SegmentKind::GnuStack);
    assert_eq!(img.segments[2].kind, SegmentKind::Other(0x1234_5678));
    let region = img.memory.region_at(Address(0x401000)).unwrap();
    assert_eq!(region.range().len(), 0x100);
    assert_eq!(region.data().len(), 0x40);
    // File bytes, then zero fill (.bss-like tail).
    assert_eq!(&*img.memory.read(Address(0x401002), 3).unwrap(), &[2, 3, 4]);
    assert_eq!(&*img.memory.read(Address(0x401040), 4).unwrap(), &[0; 4]);
    assert!(img.memory.read(Address(0x401100), 1).is_none());
    assert_eq!(img.info.sha256, sha256(&simple_exec(2)));
    // entry is a hint
    assert!(
        img.function_hints
            .iter()
            .any(|h| h.address == Address(0x401010) && h.source == FunctionHintSource::Entry)
    );
}

#[test]
fn exec_ignores_base_dyn_applies_it() {
    let opts = LoadOptions {
        base: Some(Address(0x1000_0000)),
        ..Default::default()
    };
    let exec = load_with(simple_exec(2), &opts).unwrap();
    assert_eq!(exec.info.entry, Some(Address(0x401010)));
    let dynimg = load_with(simple_exec(3), &opts).unwrap();
    assert_eq!(dynimg.info.entry, Some(Address(0x1040_1010)));
    assert_eq!(dynimg.info.base, Address(0x1000_0000));
    assert_eq!(dynimg.segments[0].range.start(), Address(0x1040_1000));
    assert!(dynimg.memory.read(Address(0x1040_1000), 4).is_some());
    assert!(dynimg.memory.read(Address(0x401000), 4).is_none());
    // address overflow is an error, not a panic
    let opts = LoadOptions {
        base: Some(Address(u64::MAX - 5)),
        ..Default::default()
    };
    assert!(matches!(
        load_with(simple_exec(3), &opts),
        Err(LoadError::Malformed { .. })
    ));
}

#[test]
fn overlapping_loads_are_malformed() {
    let img = build(
        LE64,
        2,
        62,
        0,
        &[
            Ph {
                ptype: 1,
                flags: 5,
                off: 0x200,
                vaddr: 0x1000,
                filesz: 0x10,
                memsz: 0x100,
            },
            Ph {
                ptype: 1,
                flags: 6,
                off: 0x200,
                vaddr: 0x1080,
                filesz: 0x10,
                memsz: 0x100,
            },
        ],
        &[],
        0,
        0x200,
        &[0; 0x20],
    );
    assert!(matches!(load(img), Err(LoadError::Malformed { .. })));
}

#[test]
fn load_data_outside_file_is_truncated() {
    let img = build(
        LE64,
        2,
        62,
        0,
        &[Ph {
            ptype: 1,
            flags: 5,
            off: 0x200,
            vaddr: 0x1000,
            filesz: 0x1000,
            memsz: 0x1000,
        }],
        &[],
        0,
        0x200,
        &[0; 0x20],
    );
    assert!(matches!(load(img), Err(LoadError::Truncated { .. })));
}

#[test]
fn filesz_larger_than_memsz_is_clamped() {
    let img = build(
        LE64,
        2,
        62,
        0,
        &[Ph {
            ptype: 1,
            flags: 4,
            off: 0x200,
            vaddr: 0x1000,
            filesz: 0x20,
            memsz: 0x8,
        }],
        &[],
        0,
        0x200,
        &[7; 0x20],
    );
    let img = load(img).unwrap();
    assert_eq!(img.memory.regions()[0].data().len(), 8);
}

#[test]
fn limits_are_enforced() {
    let mut o = LoadOptions::default();
    o.limits.max_sections = 2;
    assert!(matches!(
        load_with(simple_exec(2), &o),
        Err(LoadError::LimitExceeded(_))
    ));
    let mut o = LoadOptions::default();
    o.limits.max_mapped_size = 0x80;
    assert!(matches!(
        load_with(simple_exec(2), &o),
        Err(LoadError::LimitExceeded(_))
    ));
}

#[test]
fn elf32_big_endian_and_arch_mapping() {
    for (machine, arch) in [
        (3u16, ArchId::X86),
        (183, ArchId::Aarch64),
        (40, ArchId::Unknown(40)),
        (0xabcd, ArchId::Unknown(0xabcd)),
    ] {
        for enc in [
            Enc {
                is64: false,
                le: true,
            },
            Enc {
                is64: false,
                le: false,
            },
            Enc {
                is64: true,
                le: false,
            },
        ] {
            let img = build(
                enc,
                2,
                machine,
                0x8000,
                &[Ph {
                    ptype: 1,
                    flags: 7,
                    off: 0x100,
                    vaddr: 0x8000,
                    filesz: 4,
                    memsz: 4,
                }],
                &[],
                0,
                0x100,
                &[1, 2, 3, 4],
            );
            let img = load(img).unwrap();
            assert_eq!(img.info.arch, arch);
            assert_eq!(img.info.bits, if enc.is64 { 64 } else { 32 });
            assert_eq!(
                img.info.endian,
                if enc.le { Endian::Little } else { Endian::Big }
            );
            assert_eq!(img.info.entry, Some(Address(0x8000)));
            assert_eq!(
                &*img.memory.read(Address(0x8000), 4).unwrap(),
                &[1, 2, 3, 4]
            );
            assert_eq!(
                img.segments[0].perms,
                Permissions {
                    read: true,
                    write: true,
                    execute: true
                }
            );
        }
    }
}

/// An ELF with `.text`, `.bss`, `.tbss`, `.comment`, `.symtab`, `.strtab`.
fn with_sections() -> Vec<u8> {
    // body layout (file offset 0x300 + i): text 0x10 bytes, then strtab,
    // symtab, shstrtab
    let text = [0x90u8; 0x10];
    let strtab = b"\0main\0_start\0puts\0ifn\0";
    let mut sym = Out::new(LE64);
    let mut push = |name: u32, info: u8, shndx: u16, value: u64, size: u64| {
        sym.u32(name);
        sym.u8(info);
        sym.u8(0);
        sym.u16(shndx);
        sym.u64(value);
        sym.u64(size);
    };
    push(0, 0, 0, 0, 0);
    push(1, 0x12, 1, 0x401000, 8); // GLOBAL FUNC main
    push(6, 0x02, 1, 0x401008, 0); // LOCAL FUNC _start
    push(13, 0x12, 0, 0, 0); // GLOBAL FUNC undefined puts
    push(18, 0x1a, 1, 0x401004, 4); // GLOBAL IFUNC ifn
    push(0, 0x03, 1, 0x401000, 0); // SECTION
    push(0, 0x16, 1, 0x10, 8); // GLOBAL TLS (offset in the TLS block)
    let sym = sym.0;
    let shstr = b"\0.text\0.bss\0.tbss\0.comment\0.symtab\0.strtab\0.shstrtab\0";
    let mut body = Vec::new();
    let text_off = 0x300usize;
    body.extend(text);
    let str_off = text_off + body.len();
    body.extend(strtab);
    while body.len() % 8 != 0 {
        body.push(0);
    }
    let sym_off = text_off + body.len();
    body.extend(&sym);
    let shs_off = text_off + body.len();
    body.extend(shstr);
    let sh = |name: &str, stype, flags, addr, off, size, link, entsize| Sh {
        name: shs_name(shstr, name),
        stype,
        flags,
        addr,
        off,
        size,
        link,
        entsize,
    };
    let shs = [
        sh("", 0, 0, 0, 0, 0, 0, 0),
        sh(".text", 1, 6, 0x401000, text_off as u64, 0x10, 0, 0),
        sh(".bss", 8, 3, 0x402000, 0, 0x20, 0, 0),
        sh(".tbss", 8, 0x403, 0x403000, 0, 0x8, 0, 0),
        sh(".comment", 1, 0, 0, str_off as u64, 5, 0, 1),
        sh(".symtab", 2, 0, 0, sym_off as u64, sym.len() as u64, 6, 24),
        sh(
            ".strtab",
            3,
            0,
            0,
            str_off as u64,
            strtab.len() as u64,
            0,
            0,
        ),
        sh(
            ".shstrtab",
            3,
            0,
            0,
            shs_off as u64,
            shstr.len() as u64,
            0,
            0,
        ),
    ];
    build(
        LE64,
        2,
        62,
        0x401000,
        &[Ph {
            ptype: 1,
            flags: 5,
            off: 0x300,
            vaddr: 0x401000,
            filesz: 0x10,
            memsz: 0x10,
        }],
        &shs,
        7,
        0x300,
        &body,
    )
}

fn shs_name(tab: &[u8], name: &str) -> u32 {
    if name.is_empty() {
        return 0;
    }
    let pos = tab
        .windows(name.len() + 1)
        .position(|w| &w[..name.len()] == name.as_bytes() && w[name.len()] == 0);
    pos.unwrap() as u32
}

#[test]
fn sections_and_symbols() {
    let img = load(with_sections()).unwrap();
    let names: Vec<_> = img.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        [
            ".text",
            ".bss",
            ".tbss",
            ".comment",
            ".symtab",
            ".strtab",
            ".shstrtab"
        ]
    );
    let text = &img.sections[0];
    assert_eq!(text.kind, SectionKind::Code);
    assert_eq!(text.range.start(), Address(0x401000));
    assert_eq!(text.file_size, 0x10);
    assert!(text.perms.execute);
    let bss = &img.sections[1];
    assert_eq!(
        (bss.kind, bss.file_offset, bss.file_size),
        (SectionKind::Bss, None, 0)
    );
    assert_eq!(bss.range.len(), 0x20);
    let tbss = &img.sections[2];
    assert!(tbss.tls && tbss.kind == SectionKind::Bss);
    let comment = &img.sections[3];
    assert_eq!(comment.kind, SectionKind::Metadata);
    assert!(comment.range.is_empty());
    assert_eq!(comment.file_size, 5);

    let by_name: BTreeMap<_, _> = img.symbols.iter().map(|s| (s.name.as_str(), s)).collect();
    let main = by_name["main"];
    assert_eq!(
        (
            main.address,
            main.size,
            main.kind,
            main.binding,
            main.source,
            main.undefined
        ),
        (
            Address(0x401000),
            Some(8),
            SymbolKind::Function,
            SymbolBinding::Global,
            SymbolSource::Static,
            false
        )
    );
    assert_eq!(by_name["_start"].binding, SymbolBinding::Local);
    assert_eq!(by_name["_start"].size, None);
    assert!(by_name["puts"].undefined);
    assert!(!by_name["puts"].names_address());
    assert_eq!(by_name["ifn"].kind, SymbolKind::Ifunc);
    assert_eq!(img.symbols.len(), 6);
    // hints: entry, main, _start, ifn (not the undefined puts)
    let hint_addrs: BTreeSet<_> = img
        .function_hints
        .iter()
        .filter(|h| h.source == FunctionHintSource::Symbol)
        .map(|h| h.address.0)
        .collect();
    assert_eq!(hint_addrs, BTreeSet::from([0x401000, 0x401004, 0x401008]));
}

#[test]
fn symbol_limit() {
    let mut o = LoadOptions::default();
    o.limits.max_symbols = 3;
    assert!(matches!(
        load_with(with_sections(), &o),
        Err(LoadError::LimitExceeded(_))
    ));
}

#[test]
fn section_limit() {
    let mut o = LoadOptions::default();
    o.limits.max_sections = 4;
    assert!(matches!(
        load_with(with_sections(), &o),
        Err(LoadError::LimitExceeded(_))
    ));
}

#[test]
fn bad_section_table_is_ignored() {
    let mut b = with_sections();
    b.truncate(0x200); // cuts section headers (and PT_LOAD data!)
    // PT_LOAD data is now outside the file -> Truncated, not a panic.
    assert!(load(b).is_err());
    // Section table beyond EOF but segments intact:
    let mut b = simple_exec(2);
    let n = b.len();
    b[40..48].copy_from_slice(&((n as u64) + 100).to_le_bytes());
    b[60..62].copy_from_slice(&5u16.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    let img = load(b).unwrap();
    assert!(img.sections.is_empty());
}

// ------------------------------------------------------ system binary tests

/// Explicit skip: only for a missing file or tool, never for a load error.
fn skip(why: &str) {
    eprintln!("SKIPPED: {why}");
}

fn tool(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

fn ls_image() -> Option<(LoadedImage, String)> {
    let path = "/usr/bin/ls";
    let bytes = std::fs::read(path).ok()?;
    let img = ElfLoader
        .load(SharedBytes::from(bytes), &LoadOptions::default())
        .expect("loading /usr/bin/ls must succeed");
    Some((img, path.to_string()))
}

#[test]
fn ls_sections_match_readelf() {
    let Some((img, path)) = ls_image() else {
        return skip("required file or tool is unavailable");
    };
    let Some(txt) = tool("readelf", &["-SW", &path]) else {
        return skip("required file or tool is unavailable");
    };
    let mut expect = Vec::new();
    for line in txt.lines() {
        let Some(rest) = line.trim_start().strip_prefix('[') else {
            continue;
        };
        let Some((idx, rest)) = rest.split_once(']') else {
            continue;
        };
        if idx.trim() == "Nr" || idx.trim() == "0" {
            continue;
        }
        let t: Vec<_> = rest.split_whitespace().collect();
        expect.push((t[0].to_string(), hex(t[2]), hex(t[4])));
    }
    assert!(expect.len() > 10);
    assert_eq!(img.sections.len(), expect.len());
    for (s, (name, addr, size)) in img.sections.iter().zip(&expect) {
        assert_eq!(&s.name, name);
        if s.kind == SectionKind::Metadata {
            assert_eq!(s.file_size, *size, "{name}");
        } else {
            assert_eq!((s.range.start().0, s.range.len()), (*addr, *size), "{name}");
        }
    }
}

#[test]
fn ls_segments_match_readelf() {
    let Some((img, path)) = ls_image() else {
        return skip("required file or tool is unavailable");
    };
    let Some(txt) = tool("readelf", &["-lW", &path]) else {
        return skip("required file or tool is unavailable");
    };
    let mut expect = Vec::new();
    let mut in_ph = false;
    for line in txt.lines() {
        if line.starts_with("Program Headers") {
            in_ph = true;
            continue;
        }
        if !in_ph {
            continue;
        }
        let t: Vec<_> = line.split_whitespace().collect();
        if t.len() >= 6 && t[1].starts_with("0x") && t[0] != "Type" {
            expect.push((hex(t[1]), hex(t[2]), hex(t[4]), hex(t[5])));
        }
    }
    assert_eq!(img.segments.len(), expect.len());
    for (s, (off, va, fsz, msz)) in img.segments.iter().zip(expect) {
        assert_eq!(
            (s.file_offset, s.range.start().0, s.file_size, s.range.len()),
            (off, va, fsz, msz)
        );
    }
    assert!(img.segments.iter().any(|s| s.kind == SegmentKind::GnuRelro));
}

#[test]
fn ls_dynsym_matches_readelf() {
    let Some((img, path)) = ls_image() else {
        return skip("required file or tool is unavailable");
    };
    let Some(txt) = tool("readelf", &["-sW", "--dyn-syms", &path]) else {
        return skip("required file or tool is unavailable");
    };
    let mut expect = Vec::new();
    for line in txt.lines() {
        let t: Vec<_> = line.split_whitespace().collect();
        if t.len() >= 7 && t[0].ends_with(':') && t[0] != "Num:" && t[0] != "0:" {
            let name = t.get(7).map_or("", |n| n.split('@').next().unwrap());
            expect.push((
                hex(t[1]),
                t[2].parse::<u64>().unwrap(),
                name.to_string(),
                t[6] == "UND",
            ));
        }
    }
    let got: Vec<_> = img
        .symbols
        .iter()
        .filter(|s| s.source == SymbolSource::Dynamic)
        .collect();
    assert!(expect.len() > 50);
    assert_eq!(got.len(), expect.len());
    for (g, (v, sz, name, und)) in got.iter().zip(expect) {
        assert_eq!(g.name, name);
        assert_eq!(g.undefined, und);
        if !und {
            assert_eq!(g.address.0, v);
        }
        assert_eq!(g.size.unwrap_or(0), sz);
    }
}

#[test]
fn ls_fde_starts_match_readelf() {
    let Some((img, path)) = ls_image() else {
        return skip("required file or tool is unavailable");
    };
    let Some(txt) = tool("readelf", &["--debug-dump=frames", &path]) else {
        return skip("required file or tool is unavailable");
    };
    let mut expect = BTreeSet::new();
    for line in txt.lines() {
        if let Some(i) = line.find(" FDE ") {
            let _ = i;
            if let Some(p) = line.split("pc=").nth(1) {
                let start = p.split("..").next().unwrap();
                expect.insert(hex(start));
            }
        }
    }
    let got: BTreeSet<_> = img
        .function_hints
        .iter()
        .filter(|h| h.source == FunctionHintSource::EhFrame)
        .map(|h| h.address.0)
        .collect();
    assert!(expect.len() > 100);
    assert_eq!(got, expect, "FDE starts differ");
}

#[test]
fn ls_imports_match_readelf() {
    let Some((img, path)) = ls_image() else {
        return skip("required file or tool is unavailable");
    };
    let Some(txt) = tool("readelf", &["-rW", &path]) else {
        return skip("required file or tool is unavailable");
    };
    let mut expect = BTreeMap::new();
    let mut total = 0;
    for line in txt.lines() {
        let t: Vec<_> = line.split_whitespace().collect();
        if t.len() >= 5 && t[0].len() == 16 && t[2].starts_with("R_X86_64_") {
            total += 1;
            if (t[2] == "R_X86_64_GLOB_DAT" || t[2] == "R_X86_64_JUMP_SLOT")
                && hex(t[3]) == 0
                && !t[4].starts_with('+')
            {
                expect.insert(hex(t[0]), t[4].split('@').next().unwrap().to_string());
            }
        }
    }
    let got: BTreeMap<_, _> = img
        .imports
        .iter()
        .map(|i| (i.got.unwrap().0, i.name.clone()))
        .collect();
    assert_eq!(got.len(), img.imports.len());
    // readelf truncates long names with "[...]"; compare by prefix.
    assert_eq!(got.len(), expect.len());
    for (a, n) in &expect {
        let g = got
            .get(a)
            .unwrap_or_else(|| panic!("missing import at {a:#x}"));
        let prefix = n.trim_end_matches("[...]");
        assert!(g.starts_with(prefix), "{g} vs {n}");
    }
    // relocation list: RELA entries + RELR expansion >= readelf non-RELR count
    assert!(img.relocations.len() >= total);
    let getenv = img.imports.iter().find(|i| i.name == "getenv").unwrap();
    assert_eq!(getenv.version.as_deref(), Some("GLIBC_2.2.5"));
    assert_eq!(getenv.library.as_deref(), Some("libc.so.6"));
    assert_eq!(getenv.plt, None);
}

#[test]
fn ls_info() {
    let Some((img, _)) = ls_image() else { return };
    assert_eq!(img.info.kind, BinaryKind::PieExecutable);
    assert_eq!(img.info.arch, ArchId::X86_64);
    assert!(
        img.info
            .interpreter
            .as_deref()
            .unwrap()
            .contains("ld-linux")
    );
    assert!(img.info.needed_libraries.iter().any(|l| l == "libc.so.6"));
    assert_eq!(img.info.build_id.as_ref().map(Vec::len), Some(20));
    let init: Vec<_> = img
        .function_hints
        .iter()
        .filter(|h| h.source == FunctionHintSource::InitArray)
        .collect();
    assert!(!init.is_empty());
}

#[test]
fn ls_rebase_shifts_everything() {
    let Some((a, _)) = ls_image() else { return };
    let bytes = std::fs::read("/usr/bin/ls").unwrap();
    let base = 0x5555_0000_0000u64;
    let opts = LoadOptions {
        base: Some(Address(base)),
        ..Default::default()
    };
    let b = ElfLoader.load(SharedBytes::from(bytes), &opts).unwrap();
    assert_eq!(b.info.entry.unwrap().0, a.info.entry.unwrap().0 + base);
    let hints = |i: &LoadedImage| {
        i.function_hints
            .iter()
            .map(|h| h.address.0)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        hints(&b),
        hints(&a).iter().map(|x| x + base).collect::<Vec<_>>()
    );
    for (x, y) in a.imports.iter().zip(&b.imports) {
        assert_eq!(x.got.unwrap().0 + base, y.got.unwrap().0);
    }
    for (x, y) in a.sections.iter().zip(&b.sections) {
        if !x.range.is_empty() {
            assert_eq!(x.range.start().0 + base, y.range.start().0);
        }
    }
    for (x, y) in a.relocations.iter().zip(&b.relocations) {
        assert_eq!((x.address.0 + base, x.addend), (y.address.0, y.addend));
    }
    // memory content is identical
    let t = a.sections.iter().find(|s| s.name == ".text").unwrap().range;
    let t2 = b.sections.iter().find(|s| s.name == ".text").unwrap().range;
    assert_eq!(a.memory.read(t.start(), 64), b.memory.read(t2.start(), 64));
}

#[test]
fn ls_load_time_is_reported() {
    let Ok(bytes) = std::fs::read("/usr/bin/ls") else {
        return skip("required file or tool is unavailable");
    };
    let shared = SharedBytes::from(bytes);
    let t = std::time::Instant::now();
    ElfLoader.load(shared, &LoadOptions::default()).unwrap();
    let el = t.elapsed();
    eprintln!("ls load: {el:?}");
    // Generous: debug build under load; release target is < 50 ms.
    assert!(el.as_secs() < 30, "{el:?}");
}

/// Compiles a small C program with gcc and checks PLT/GOT handling.
fn gcc_image(flags: &[&str]) -> Option<LoadedImage> {
    let dir = std::env::temp_dir().join(format!(
        "dasm-elf-test-{}-{}",
        std::process::id(),
        flags.join("")
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join("t.c");
    let exe = dir.join("t");
    std::fs::write(
        &src,
        "#include <stdio.h>\n#include <stdlib.h>\nint main(int c,char**v){ puts(\"x\"); if(c>3) exit(1); printf(\"%d\", c); return 0; }\n",
    )
    .ok()?;
    // gcc missing -> skip; gcc present but failing -> test failure.
    let status = Command::new("gcc")
        .args(flags)
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .status()
        .ok()?;
    assert!(status.success(), "gcc {flags:?} failed");
    let bytes = std::fs::read(&exe).expect("gcc output");
    let _ = std::fs::remove_dir_all(&dir);
    Some(
        ElfLoader
            .load(SharedBytes::from(bytes), &LoadOptions::default())
            .expect("loading a gcc-built binary must succeed"),
    )
}

#[test]
fn gcc_plt_imports_have_stub_addresses() {
    for flags in [
        &["-O1", "-no-pie", "-Wl,-z,lazy", "-fcf-protection=none"][..],
        &[
            "-O1",
            "-fPIE",
            "-pie",
            "-Wl,-z,lazy",
            "-fcf-protection=full",
        ][..],
        &[
            "-O1",
            "-fPIE",
            "-pie",
            "-Wl,-z,lazy",
            "-fcf-protection=none",
        ][..],
    ] {
        let Some(img) = gcc_image(flags) else { return };
        let puts = img
            .imports
            .iter()
            .find(|i| i.name == "puts")
            .expect("puts import");
        let plt = puts
            .plt
            .unwrap_or_else(|| panic!("{flags:?}: puts has no PLT address"));
        let got = puts.got.unwrap();
        // The stub is inside .plt / .plt.sec / .plt.got.
        let sec = img.section_at(plt).unwrap();
        assert!(sec.name.starts_with(".plt"), "{flags:?}: {}", sec.name);
        // The stub jumps through the GOT slot of the import.
        let bytes = img.memory.read(plt, 16).unwrap();
        let pos = bytes.windows(2).position(|w| w == [0xff, 0x25]).unwrap();
        let disp = i32::from_le_bytes(bytes[pos + 2..pos + 6].try_into().unwrap());
        assert_eq!(
            plt.0
                .wrapping_add(pos as u64 + 6)
                .wrapping_add_signed(i64::from(disp)),
            got.0
        );
        assert!(
            img.function_hints
                .iter()
                .any(|h| h.address == plt && h.source == FunctionHintSource::Plt)
        );
        let exit = img.imports.iter().find(|i| i.name == "exit").unwrap();
        assert!(exit.plt.is_some() && exit.plt != puts.plt);
        assert_eq!(puts.library.as_deref(), Some("libc.so.6"));
    }
}

#[test]
fn gcc_no_plt_gives_got_only_imports() {
    let Some(img) = gcc_image(&["-O1", "-fPIE", "-pie", "-fno-plt", "-Wl,-z,now"]) else {
        return skip("required file or tool is unavailable");
    };
    let puts = img
        .imports
        .iter()
        .find(|i| i.name == "puts")
        .expect("puts import");
    assert!(puts.got.is_some());
    assert_eq!(puts.kind, SymbolKind::Function);
}

#[test]
fn gcc_debug_info_gives_dwarf_functions() {
    let Some(img) = gcc_image(&["-O0", "-g", "-no-pie"]) else {
        return skip("required file or tool is unavailable");
    };
    let f = img
        .symbols
        .iter()
        .find(|s| s.source == SymbolSource::Dwarf && s.name == "main")
        .expect("DWARF main");
    let sym = img
        .symbols
        .iter()
        .find(|s| s.source == SymbolSource::Static && s.name == "main")
        .unwrap();
    assert_eq!(f.address, sym.address);
    assert_eq!(f.size, sym.size);
    assert!(
        img.function_hints
            .iter()
            .any(|h| h.address == f.address && h.source == FunctionHintSource::Dwarf)
    );
}

#[test]
fn gcc_symtab_matches_readelf() {
    let dir = std::env::temp_dir().join(format!("dasm-elf-symtab-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let src = dir.join("t.c");
    let exe = dir.join("t");
    let _ = std::fs::write(
        &src,
        "int g; static int f(int x){return x+g;} int main(int c,char**v){return f(c);}\n",
    );
    let built = Command::new("gcc")
        .args(["-O1", "-g", "-o"])
        .arg(&exe)
        .arg(&src)
        .status();
    let path = exe.to_string_lossy().into_owned();
    let (Ok(st), Some(txt), Ok(bytes)) =
        (built, tool("readelf", &["-sW", &path]), std::fs::read(&exe))
    else {
        return skip("required file or tool is unavailable");
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(st.success());
    let img = load(bytes).unwrap();
    let mut expect = Vec::new();
    let mut in_symtab = false;
    for line in txt.lines() {
        if line.starts_with("Symbol table") {
            in_symtab = line.contains("'.symtab'");
            continue;
        }
        let t: Vec<_> = line.split_whitespace().collect();
        if in_symtab && t.len() >= 7 && t[0].ends_with(':') && t[0] != "Num:" && t[0] != "0:" {
            let name = t.get(7).map_or("", |n| *n);
            expect.push((
                hex(t[1]),
                t[2].parse::<u64>().unwrap(),
                name.to_string(),
                t[3].to_string(),
            ));
        }
    }
    let got: Vec<_> = img
        .symbols
        .iter()
        .filter(|s| s.source == SymbolSource::Static)
        .collect();
    assert!(expect.len() > 20);
    assert_eq!(got.len(), expect.len());
    for (g, (v, sz, name, ty)) in got.iter().zip(expect) {
        assert_eq!(g.name, name);
        assert_eq!(g.size.unwrap_or(0), sz);
        if !g.undefined {
            assert_eq!(g.address.0, v, "{name}");
        }
        match ty.as_str() {
            "FUNC" => assert_eq!(g.kind, SymbolKind::Function),
            "OBJECT" => assert_eq!(g.kind, SymbolKind::Object),
            "FILE" => assert_eq!(g.kind, SymbolKind::File),
            "SECTION" => assert_eq!(g.kind, SymbolKind::Section),
            "TLS" => assert_eq!(g.kind, SymbolKind::Tls),
            "IFUNC" => assert_eq!(g.kind, SymbolKind::Ifunc),
            _ => assert_eq!(g.kind, SymbolKind::Unknown),
        }
    }
}

/// Smoke test over system shared libraries: no panics, no errors for
/// well-formed files.
#[test]
fn system_libraries_load() {
    let Ok(rd) = std::fs::read_dir("/usr/lib") else {
        return skip("required file or tool is unavailable");
    };
    let mut n = 0;
    for e in rd.flatten().take(400) {
        let p = e.path();
        let Ok(md) = std::fs::metadata(&p) else {
            continue;
        };
        if !md.is_file() || md.len() > 64 << 20 || !p.to_string_lossy().contains(".so") {
            continue;
        }
        let Ok(b) = std::fs::read(&p) else { continue };
        if !b.starts_with(b"\x7fELF") {
            continue;
        }
        let r = load(b);
        assert!(r.is_ok(), "{}: {:?}", p.display(), r.err());
        n += 1;
        if n >= 60 {
            break;
        }
    }
}

// ------------------------------------------------- review regressions

struct Sec {
    name: &'static str,
    stype: u32,
    flags: u64,
    addr: u64,
    data: Vec<u8>,
    link: u32,
    entsize: u64,
}

fn sec(name: &'static str, stype: u32, data: Vec<u8>) -> Sec {
    Sec {
        name,
        stype,
        flags: 0,
        addr: 0,
        data,
        link: 0,
        entsize: 0,
    }
}

/// An ELF64 file consisting of header, section headers and section data
/// (a `.shstrtab` is appended).
fn sections_elf(etype: u16, secs: &[Sec]) -> Vec<u8> {
    let mut shstr = vec![0u8];
    let mut name_offs = Vec::new();
    for s in secs.iter().map(|s| s.name).chain([".shstrtab"]) {
        name_offs.push(shstr.len() as u32);
        shstr.extend(s.as_bytes());
        shstr.push(0);
    }
    let n = secs.len() + 2;
    let body_off = 64 + 64 * n;
    let mut body = Vec::new();
    let mut shs = vec![Sh {
        name: 0,
        stype: 0,
        flags: 0,
        addr: 0,
        off: 0,
        size: 0,
        link: 0,
        entsize: 0,
    }];
    for (s, no) in secs.iter().zip(&name_offs) {
        shs.push(Sh {
            name: *no,
            stype: s.stype,
            flags: s.flags,
            addr: s.addr,
            off: (body_off + body.len()) as u64,
            size: s.data.len() as u64,
            link: s.link,
            entsize: s.entsize,
        });
        body.extend(&s.data);
    }
    shs.push(Sh {
        name: *name_offs.last().unwrap(),
        stype: 3,
        flags: 0,
        addr: 0,
        off: (body_off + body.len()) as u64,
        size: shstr.len() as u64,
        link: 0,
        entsize: 0,
    });
    body.extend(&shstr);
    build(
        LE64,
        etype,
        62,
        0,
        &[],
        &shs,
        (n - 1) as u16,
        body_off,
        &body,
    )
}

fn uleb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Abbreviations: 1 = compile unit (children), 2 = subprogram(name strp,
/// low_pc addr, high_pc data1).
const FN_ABBREV: &[u8] = &[
    1, 0x11, 1, 0, 0, 2, 0x2e, 0, 3, 0x0e, 0x11, 1, 0x12, 0x0b, 0, 0, 0,
];

/// One unit with `n` subprograms, all naming the string at `.debug_str` 0.
fn fn_unit(n: usize) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(4u16.to_le_bytes());
    body.extend(0u32.to_le_bytes());
    body.push(8);
    body.push(1);
    for _ in 0..n {
        body.push(2);
        body.extend(0u32.to_le_bytes());
        body.extend(0x401000u64.to_le_bytes());
        body.push(0x10);
    }
    body.push(0);
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend(body);
    out
}

fn dwarf_elf(abbrev: Vec<u8>, info: Vec<u8>, strings: Vec<u8>) -> Vec<u8> {
    sections_elf(
        2,
        &[
            sec(".debug_abbrev", 1, abbrev),
            sec(".debug_str", 1, strings),
            sec(".debug_info", 1, info),
        ],
    )
}

#[test]
fn dwarf_normal_functions_are_found() {
    let mut strings = b"my_function".to_vec();
    strings.push(0);
    let img = load(dwarf_elf(FN_ABBREV.to_vec(), fn_unit(3), strings)).unwrap();
    let f: Vec<_> = img
        .symbols
        .iter()
        .filter(|s| s.source == SymbolSource::Dwarf)
        .collect();
    assert_eq!(f.len(), 3);
    assert_eq!(f[0].name, "my_function");
    assert_eq!((f[0].address, f[0].size), (Address(0x401000), Some(0x10)));
}

/// PoC dw.s: 2000 DIEs sharing one 1 MiB name. Must neither blow up memory
/// nor take long: over-long names are ignored.
#[test]
fn dwarf_string_bomb_is_bounded() {
    let mut strings = vec![b'A'; 1 << 20];
    strings.push(0);
    let t = std::time::Instant::now();
    let img = load(dwarf_elf(FN_ABBREV.to_vec(), fn_unit(2000), strings)).unwrap();
    assert!(t.elapsed().as_secs() < 30, "{:?}", t.elapsed());
    let bytes: usize = img.symbols.iter().map(|s| s.name.len()).sum();
    assert!(bytes <= 5 << 20, "{bytes} name bytes");
}

/// Names below the per-name cap are limited by the shared budget instead.
#[test]
fn dwarf_medium_names_hit_the_string_budget() {
    let mut strings = vec![b'B'; 40_000];
    strings.push(0);
    let o = LoadOptions {
        limits: dasm_core::Limits {
            max_string_bytes: 1 << 20,
            ..Default::default()
        },
        ..Default::default()
    };
    let img = load_with(dwarf_elf(FN_ABBREV.to_vec(), fn_unit(2000), strings), &o).unwrap();
    let n = img
        .symbols
        .iter()
        .filter(|s| s.source == SymbolSource::Dwarf)
        .count();
    assert!(n > 0 && n < 100, "{n} DWARF functions kept");
    // Not truncated: kept names are complete.
    assert!(img.symbols.iter().all(|s| s.name.len() == 40_000));
}

/// Abbreviations table: `FN_ABBREV` at offset 0, then 10 000 trivial
/// entries. Returns the table and the offsets of those entries.
fn abbrev_bomb_table() -> (Vec<u8>, Vec<u32>) {
    let mut abbrev = FN_ABBREV.to_vec();
    let mut starts = Vec::new();
    for i in 1..=10_000u64 {
        starts.push(abbrev.len() as u32);
        uleb(i, &mut abbrev);
        abbrev.extend([0x11, 0, 0, 0]);
    }
    abbrev.push(0);
    (abbrev, starts)
}

/// Units at the given abbrev offsets (no DIEs), then one real unit with a
/// function at abbrev offset 0.
fn bomb_info(offsets: &[u32]) -> Vec<u8> {
    let mut info = Vec::new();
    for off in offsets {
        info.extend(8u32.to_le_bytes());
        info.extend(4u16.to_le_bytes());
        info.extend(off.to_le_bytes());
        info.extend([8, 0]);
    }
    info.extend(fn_unit(1));
    info
}

fn dwarf_count(img: &LoadedImage) -> usize {
    img.symbols
        .iter()
        .filter(|s| s.source == SymbolSource::Dwarf)
        .count()
}

/// Work (bytes of abbreviation tables measured) for units at `offsets`
/// followed by the real unit at abbrev offset 0 (`FN_ABBREV`, 17 bytes).
fn bomb_work(abbrev: &[u8], offsets: &[u32]) -> u64 {
    let mut seen = std::collections::BTreeSet::new();
    let mut work = FN_ABBREV.len() as u64;
    for &o in offsets {
        if seen.insert(o) {
            work += (abbrev.len() - o as usize) as u64;
        }
    }
    work
}

fn with_debug_work(work: u64) -> LoadOptions {
    let mut o = LoadOptions::default();
    o.limits.max_debug_work = work;
    o
}

/// Quadratic abbreviation parsing is cut off by `Limits::max_debug_work`,
/// independent of wall-clock time. The boundary is exact: with the budget
/// equal to the measured work the trailing real function is read, one less
/// and the DWARF is ignored. The full bomb exceeds the default budget too.
#[test]
fn abbrev_table_bomb_is_bounded() {
    let (abbrev, starts) = abbrev_bomb_table();
    let strings = b"f\0".to_vec();
    let small = &starts[..100];
    let elf = dwarf_elf(abbrev.clone(), bomb_info(small), strings.clone());
    let work = bomb_work(&abbrev, small);
    assert_eq!(
        dwarf_count(&load_with(elf.clone(), &with_debug_work(work)).unwrap()),
        1
    );
    assert_eq!(
        dwarf_count(&load_with(elf, &with_debug_work(work - 1)).unwrap()),
        0
    );
    // The whole bomb is far above the default budget.
    assert!(bomb_work(&abbrev, &starts) > dasm_core::Limits::default().max_debug_work);
    let bomb = dwarf_elf(abbrev, bomb_info(&starts), strings);
    assert_eq!(dwarf_count(&load(bomb).unwrap()), 0);
}

/// PoC ab.s as written: many units at one offset parse that table once.
/// With a budget of a few table sizes the DWARF is still read; without
/// the `seen` dedup the work would be 20 000 table sizes.
#[test]
fn many_units_sharing_a_table_are_cheap() {
    let (abbrev, starts) = abbrev_bomb_table();
    let shared = vec![starts[0]; 20_000];
    let elf = dwarf_elf(abbrev.clone(), bomb_info(&shared), b"f\0".to_vec());
    let work = bomb_work(&abbrev, &shared);
    assert!(work < 2 * abbrev.len() as u64);
    let img = load_with(elf, &with_debug_work(work)).unwrap();
    assert_eq!(dwarf_count(&img), 1);
}

fn symtab_elf(strtab: Vec<u8>, syms: &[(u32, u8, u16, u64)]) -> Vec<u8> {
    let mut o = Out::new(LE64);
    o.0.extend([0u8; 24]);
    for &(name, info, shndx, value) in syms {
        o.u32(name);
        o.u8(info);
        o.u8(0);
        o.u16(shndx);
        o.u64(value);
        o.u64(0);
    }
    sections_elf(
        2,
        &[
            sec(".strtab", 3, strtab),
            Sec {
                link: 1,
                entsize: 24,
                ..sec(".symtab", 2, o.0)
            },
        ],
    )
}

#[test]
fn long_symbol_names_are_not_truncated() {
    let mut strtab = vec![0u8];
    strtab.extend(vec![b'x'; 10_000]);
    strtab.push(0);
    let img = load(symtab_elf(strtab, &[(1, 0x12, 1, 0x1000)])).unwrap();
    assert_eq!(img.symbols[0].name.len(), 10_000);
}

/// Many symbols sharing one huge name: amplification is stopped.
#[test]
fn symbol_string_amplification_is_limited() {
    let mut strtab = vec![0u8];
    strtab.extend(vec![b'y'; 1 << 20]);
    strtab.push(0);
    let syms: Vec<_> = (0..3000).map(|_| (1u32, 0x12u8, 1u16, 0x1000u64)).collect();
    let err = load(symtab_elf(strtab, &syms)).unwrap_err();
    assert!(matches!(err, LoadError::LimitExceeded(_)), "{err:?}");
}

#[test]
fn tls_symbols_are_not_rebased() {
    let mut b = with_sections();
    b[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    // keep the PT_LOAD addresses sane: base only shifts, never breaks
    let opts = LoadOptions {
        base: Some(Address(0x1000_0000)),
        ..Default::default()
    };
    let img = load_with(b, &opts).unwrap();
    let tls = img
        .symbols
        .iter()
        .find(|s| s.kind == SymbolKind::Tls)
        .unwrap();
    assert_eq!(tls.address, Address(0x10));
    let main = img.symbols.iter().find(|s| s.name == "main").unwrap();
    assert_eq!(main.address, Address(0x1040_1000));
}

#[test]
fn relocatable_objects_have_no_ranges_or_hints() {
    let mut b = with_sections();
    b[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    let img = load(b).unwrap();
    assert_eq!(img.info.kind, BinaryKind::Relocatable);
    assert!(img.sections.iter().all(|s| s.range.is_empty()));
    assert!(img.function_hints.is_empty());
}

/// i386 `DT_REL`: the init_array entry is the implicit addend in memory.
#[test]
fn rel_implicit_addend_feeds_init_array_hints() {
    let enc = Enc {
        is64: false,
        le: true,
    };
    let mut o = Out::new(enc);
    let dynamic = [
        (17u32, 0xb0u32), // DT_REL
        (18, 8),          // DT_RELSZ
        (25, 0xc0),       // DT_INIT_ARRAY
        (27, 4),          // DT_INIT_ARRAYSZ
        (0, 0),
    ];
    for (t, v) in dynamic {
        o.u32(t);
        o.u32(v);
    }
    o.pad_to(0x30); // -> file offset 0xb0
    o.u32(0xc0); // r_offset
    o.u32(8); // R_386_RELATIVE, no symbol
    o.pad_to(0x40);
    o.u32(0x1234); // implicit addend
    let body = o.0;
    let img = build(
        enc,
        3,
        3,
        0,
        &[
            Ph {
                ptype: 1,
                flags: 6,
                off: 0,
                vaddr: 0,
                filesz: 0xc4,
                memsz: 0xc4,
            },
            Ph {
                ptype: 2,
                flags: 6,
                off: 0x80,
                vaddr: 0x80,
                filesz: 40,
                memsz: 40,
            },
        ],
        &[],
        0,
        0x80,
        &body,
    );
    let img = load(img).unwrap();
    assert!(
        img.function_hints
            .iter()
            .any(|h| { h.source == FunctionHintSource::InitArray && h.address == Address(0x1234) })
    );
    assert_eq!(img.relocations[0].addend, 0x1234);
}

// ------------------------------------------------------- verneed / dynamic

mod version_records {
    use super::*;
    use crate::dynamic::{DynInfo, Table, parse_verneed};
    use crate::raw::{Budget, Ehdr, Fmt};

    const STRTAB: &[u8] = b"\0libc.so.6\0GLIBC_2.2\0";
    const VN_AT: usize = 0x40;

    fn run(
        blob: Vec<u8>,
        num: u64,
    ) -> Result<std::collections::HashMap<u16, (String, String)>, LoadError> {
        let mut data = vec![0u8; VN_AT];
        data[..STRTAB.len()].copy_from_slice(STRTAB);
        data.extend(blob);
        let eh = Ehdr {
            fmt: Fmt {
                is64: true,
                le: true,
            },
            etype: 3,
            machine: 62,
            entry: 0,
            phoff: 0,
            shoff: 0,
            phentsize: 0,
            phnum: 0,
            shentsize: 0,
            shnum: 0,
            shstrndx: 0,
        };
        let info = DynInfo {
            strtab: Some(Table {
                off: 0,
                size: STRTAB.len(),
            }),
            verneed: Some((VN_AT, num)),
            ..Default::default()
        };
        parse_verneed(&data, &eh, &info, &Budget::new(1 << 30))
    }

    /// `Verneed` record: version, cnt, file, aux, next.
    fn vn(cnt: u16, aux: u32, next: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(1u16.to_le_bytes());
        b.extend(cnt.to_le_bytes());
        b.extend(1u32.to_le_bytes()); // "libc.so.6"
        b.extend(aux.to_le_bytes());
        b.extend(next.to_le_bytes());
        b
    }

    /// `Vernaux` record: hash, flags, other, name, next.
    fn aux(other: u16, next: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(0u32.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend(other.to_le_bytes());
        b.extend(11u32.to_le_bytes()); // "GLIBC_2.2"
        b.extend(next.to_le_bytes());
        b
    }

    /// One Verneed followed by `n` chained Vernaux.
    fn chain(n: u16, vn_next: u32) -> Vec<u8> {
        let mut b = vn(n, 16, vn_next);
        for i in 0..n {
            b.extend(aux(i + 1, if i + 1 == n { 0 } else { 16 }));
        }
        b
    }

    #[test]
    fn valid_records() {
        let m = run(chain(2, 0), 1).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[&2], ("GLIBC_2.2".to_string(), "libc.so.6".to_string()));
    }

    #[test]
    fn exactly_the_record_limit_is_accepted() {
        // 65 535 Vernaux + 1 Verneed = 65 536 records.
        let m = run(chain(65_535, 0), 1).unwrap();
        assert_eq!(m.len(), 65_535);
    }

    #[test]
    fn exceeding_the_record_limit_keeps_what_was_read() {
        // 2 Verneed + 65 536 Vernaux = 65 538 records: over the limit, but
        // the load must not fail and the versions read so far are kept.
        let mut b = chain(40_000, 16 + 40_000 * 16);
        b.extend(chain(25_536, 0));
        let m = run(b, 2).unwrap();
        assert_eq!(m.len(), 40_000);
    }

    #[test]
    fn shared_chains_cannot_fail_the_load() {
        // Many Verneed sharing one Vernaux chain (vn_aux is relative, so
        // each record points at the chain after the last record).
        let n_vn = 300u32;
        let n_aux = 300u16;
        let mut b = Vec::new();
        for i in 0..n_vn {
            let to_aux = (n_vn - i) * 16;
            b.extend(vn(n_aux, to_aux, if i + 1 == n_vn { 0 } else { 16 }));
        }
        for i in 0..n_aux {
            b.extend(aux(i + 1, if i + 1 == n_aux { 0 } else { 16 }));
        }
        let m = run(b, u64::from(n_vn)).unwrap();
        assert_eq!(m.len(), usize::from(n_aux));
    }

    #[test]
    fn broken_offsets_do_not_panic_or_loop() {
        // vn_aux far outside the data, vn_next huge, absurd counts.
        assert!(
            run(vn(5, 0xffff_ff00, 0x7fff_ffff), u64::from(u32::MAX))
                .unwrap()
                .is_empty()
        );
        // vna_next leaves the data after the first aux.
        let mut b = vn(3, 16, 0);
        b.extend(aux(7, 0xffff_fff0));
        let m = run(b, 1).unwrap();
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), [7]);
        // Truncated record.
        assert!(run(vec![1, 0, 2], 1).unwrap().is_empty());
        // vna_next of 0 with cnt > 1 stops cleanly.
        let mut b = vn(9, 16, 0);
        b.extend(aux(4, 0));
        assert_eq!(run(b, 1).unwrap().len(), 1);
    }

    fn dyn_elf(tags: &[u8], filesz: u64) -> Vec<u8> {
        build(
            LE64,
            3,
            62,
            0,
            &[Ph {
                ptype: 2,
                flags: 6,
                off: 0x100,
                vaddr: 0x100,
                filesz,
                memsz: filesz,
            }],
            &[],
            0,
            0x100,
            tags,
        )
    }

    fn nulls(n: usize, terminate: bool) -> Vec<u8> {
        let mut tags = Vec::new();
        for _ in 0..n {
            tags.extend(0x7000_0000u64.to_le_bytes());
            tags.extend(0u64.to_le_bytes());
        }
        if terminate {
            tags.extend([0u8; 16]);
        }
        tags
    }

    #[test]
    fn short_table_with_huge_declared_size_loads() {
        // p_filesz claims 4 MiB; the real table is 2 entries + DT_NULL and
        // there is more than 1 MiB of file after it.
        let mut tags = nulls(2, true);
        tags.resize(2 << 20, 0xaa);
        assert!(load(dyn_elf(&tags, 4 << 20)).is_ok());
    }

    #[test]
    fn exactly_the_tag_limit_is_accepted() {
        assert!(load(dyn_elf(&nulls(1 << 16, true), (65_537) * 16)).is_ok());
        // ... also without a terminator when the table ends there.
        assert!(load(dyn_elf(&nulls(1 << 16, false), (1 << 16) * 16)).is_ok());
    }

    #[test]
    fn more_than_the_tag_limit_is_reported() {
        let tags = nulls((1 << 16) + 1, false);
        let n = tags.len() as u64;
        let err = load(dyn_elf(&tags, n)).unwrap_err();
        assert!(matches!(err, LoadError::LimitExceeded(_)), "{err:?}");
    }

    #[test]
    fn only_the_first_dynamic_segment_is_used() {
        // First PT_DYNAMIC: DT_NULL only. Second: DT_NEEDED "libx.so".
        let mut body = b"\0libx.so\0".to_vec();
        body.resize(0x10, 0); // strtab at 0x100
        body.extend([0u8; 16]); // dynamic #1 at 0x110
        for (tag, val) in [(1u64, 1u64), (5, 0x100), (10, 0x10), (0, 0)] {
            body.extend(tag.to_le_bytes());
            body.extend(val.to_le_bytes());
        }
        let ph = |ptype, off, size| Ph {
            ptype,
            flags: 6,
            off,
            vaddr: off,
            filesz: size,
            memsz: size,
        };
        let img = build(
            LE64,
            3,
            62,
            0,
            &[ph(1, 0, 0x160), ph(2, 0x110, 16), ph(2, 0x120, 64)],
            &[],
            0,
            0x100,
            &body,
        );
        let img = load(img).unwrap();
        assert!(img.info.needed_libraries.is_empty());
        // Control: with the segments swapped the library is found.
        let img = build(
            LE64,
            3,
            62,
            0,
            &[ph(1, 0, 0x160), ph(2, 0x120, 64), ph(2, 0x110, 16)],
            &[],
            0,
            0x100,
            &body,
        );
        assert_eq!(load(img).unwrap().info.needed_libraries, ["libx.so"]);
    }
}

// ------------------------------------------------------------ robustness

mod fuzzish {
    use super::*;
    use proptest::prelude::*;

    fn corpus() -> Vec<Vec<u8>> {
        let mut v = vec![with_sections(), simple_exec(3)];
        if let Ok(b) = std::fs::read("/usr/bin/ls") {
            v.push(b);
        }
        v
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300))]

        #[test]
        fn truncation_never_panics(which in 0usize..3, frac in 0.0f64..1.0) {
            let c = corpus();
            let b = &c[which % c.len()];
            let n = (b.len() as f64 * frac) as usize;
            let _ = load(b[..n].to_vec());
        }

        #[test]
        fn mutation_never_panics(
            which in 0usize..3,
            edits in proptest::collection::vec((0usize..4096, any::<u8>()), 1..8),
            tail in proptest::collection::vec((0.0f64..1.0, any::<u8>()), 0..4),
        ) {
            let c = corpus();
            let mut b = c[which % c.len()].clone();
            for (pos, v) in edits {
                let i = pos % b.len();
                b[i] = v;
            }
            for (f, v) in tail {
                let i = ((b.len() - 1) as f64 * f) as usize;
                b[i] = v;
            }
            let mut o = LoadOptions::default();
            o.limits.max_relocations = 1 << 16;
            let _ = load_with(b, &o);
        }

        #[test]
        fn random_bytes_after_magic(rest in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut b = b"\x7fELF".to_vec();
            b.extend(rest);
            let _ = load(b);
        }
    }
}

#[test]
fn big_library_loads() {
    let found = std::fs::read_dir("/usr/lib").ok().and_then(|rd| {
        rd.flatten().map(|e| e.path()).find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("libLLVM"))
        })
    });
    let Some(path) = found else {
        return skip("no libLLVM in /usr/lib");
    };
    let b = std::fs::read(&path).expect("read libLLVM");
    let t = std::time::Instant::now();
    let img = load(b).expect("libLLVM must load");
    eprintln!(
        "{}: {:?}, {} syms, {} hints",
        path.display(),
        t.elapsed(),
        img.symbols.len(),
        img.function_hints.len()
    );
    assert!(!img.symbols.is_empty() && !img.function_hints.is_empty());
}
