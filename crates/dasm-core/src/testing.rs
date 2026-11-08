//! Mock implementations for parallel development (feature `mock`).
//!
//! - [`MockArch`]: decoder for a small x86-64 subset (enough for the
//!   synthetic program, with real-looking bytes and tokens).
//! - [`synthetic_image`]: a tiny ELF-like program with `_start`, `main`, a
//!   stripped helper, a PLT stub, strings and globals.
//! - [`reference_analysis`]: a naive single-threaded recursive descent that
//!   produces consistent functions/blocks/xrefs/strings for any [`Arch`].
//! - [`InMemoryStore`], [`StaticDriver`] and [`mock_session`]: a fully
//!   working [`Session`] (rename, undo/redo, create function) with no
//!   SQLite, no ELF parser and no scheduler.
//!
//! The Frontend develops against [`mock_session`]; QA and backends use the
//! pieces as test doubles. Layout of the synthetic program is documented on
//! [`synthetic_image`] and is stable (tests may rely on the addresses).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use crate::address::{Address, AddressRange};
use crate::arch::Arch;
use crate::error::{DecodeError, Error};
use crate::image::{
    ArchId, BinaryFormat, BinaryInfo, BinaryKind, Endian, FunctionHint, FunctionHintSource, Import,
    LoadedImage, Section, SectionKind, Segment, Symbol, SymbolBinding, SymbolKind, SymbolSource,
};
use crate::insn::{
    DecodedInsn, Flow, InsnRef, RenderedInsn, SymbolLookup, Target, Token, TokenKind,
};
use crate::journal::{EntryState, JournalEntry, JournalEvent};
use crate::loader::{Limits, LoadOptions, sha256};
use crate::memory::{MemoryMap, MemoryRegion, Permissions, SharedBytes};
use crate::model::{
    AnalysisDelta, AnalysisProgress, AnalysisResults, AnalysisState, BasicBlock, Edge, EdgeKind,
    Function, FunctionFlags, FunctionSource, StringEncoding, StringLiteral, Xref, XrefKind,
    XrefOwner,
};
use crate::ops::{Change, FunctionOverride};
use crate::pass::{AnalysisDriver, Focus};
use crate::session::Session;
use crate::snapshot::{Program, Snapshot, SnapshotHub};
use crate::store::{ProjectStore, StoredSource};

// ---------------------------------------------------------------- MockArch

/// Decoder for a small x86-64 subset. Encodings are real x86-64, so the
/// synthetic bytes look right in a hex view:
///
/// | bytes | text |
/// |---|---|
/// | `55` / `5d` | `push rbp` / `pop rbp` |
/// | `90`, `cc`, `f4`, `c3` | `nop`, `int3`, `hlt`, `ret` |
/// | `0f 05` | `syscall` |
/// | `31 c0` | `xor eax, eax` |
/// | `48 89 e5` | `mov rbp, rsp` |
/// | `b8 imm32` | `mov eax, imm32` |
/// | `e8 rel32` / `e9 rel32` / `eb rel8` | `call` / `jmp` / `jmp` |
/// | `74 rel8` / `75 rel8` | `je` / `jne` |
/// | `48 8d 3d rel32` | `lea rdi, [rip+rel32]` (data pointer) |
/// | `48 8b 05 rel32` | `mov rax, qword ptr [rip+rel32]` (read) |
/// | `48 89 05 rel32` | `mov qword ptr [rip+rel32], rax` (write) |
/// | `ff 25 rel32` | `jmp qword ptr [rip+rel32]` (PLT stub) |
/// | `ff d0` | `call rax` |
///
/// Anything else is [`DecodeError::Invalid`].
#[derive(Clone, Copy, Debug, Default)]
pub struct MockArch;

#[derive(Clone, Copy)]
enum Op {
    Plain(&'static str, &'static str),
    MovEaxImm(u32),
    Branch(&'static str, Address),
    RipMem(&'static str, &'static str, Address, XrefKind),
}

fn rel32(b: &[u8], at: usize) -> Option<i64> {
    let raw: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    Some(i64::from(i32::from_le_bytes(raw)))
}

fn rel8(b: &[u8], at: usize) -> Option<i64> {
    b.get(at).map(|&x| i64::from(x as i8))
}

impl MockArch {
    fn parse(bytes: &[u8], address: Address) -> Result<(DecodedInsn, Op), DecodeError> {
        let trunc = DecodeError::Truncated(address);
        let first = *bytes.first().ok_or(trunc.clone())?;
        let target = |len: u8, disp: Option<i64>| -> Result<Address, DecodeError> {
            address
                .checked_add(u64::from(len))
                .and_then(|n| n.checked_offset(disp?))
                .ok_or(DecodeError::Truncated(address))
        };
        let simple = |len: u8, flow: Flow, op: Op| Ok((DecodedInsn::new(address, len, flow), op));
        match (first, bytes.get(1).copied(), bytes.get(2).copied()) {
            (0x55, ..) => simple(1, Flow::Sequential, Op::Plain("push", "rbp")),
            (0x5d, ..) => simple(1, Flow::Sequential, Op::Plain("pop", "rbp")),
            (0x90, ..) => simple(1, Flow::Sequential, Op::Plain("nop", "")),
            (0xcc, ..) => simple(1, Flow::Halt, Op::Plain("int3", "")),
            (0xf4, ..) => simple(1, Flow::Halt, Op::Plain("hlt", "")),
            (0xc3, ..) => simple(1, Flow::Return, Op::Plain("ret", "")),
            (0x0f, Some(0x05), _) => simple(2, Flow::Syscall, Op::Plain("syscall", "")),
            (0x31, Some(0xc0), _) => simple(2, Flow::Sequential, Op::Plain("xor", "eax, eax")),
            (0x48, Some(0x89), Some(0xe5)) => {
                simple(3, Flow::Sequential, Op::Plain("mov", "rbp, rsp"))
            }
            (0xb8, ..) => {
                let raw: [u8; 4] = bytes
                    .get(1..5)
                    .ok_or(trunc)?
                    .try_into()
                    .map_err(|_| DecodeError::Truncated(address))?;
                simple(5, Flow::Sequential, Op::MovEaxImm(u32::from_le_bytes(raw)))
            }
            (0xe8, ..) => {
                let t = target(5, rel32(bytes, 1))?;
                simple(
                    5,
                    Flow::Call {
                        target: Target::Direct(t),
                    },
                    Op::Branch("call", t),
                )
            }
            (0xe9, ..) => {
                let t = target(5, rel32(bytes, 1))?;
                simple(
                    5,
                    Flow::Jump {
                        target: Target::Direct(t),
                    },
                    Op::Branch("jmp", t),
                )
            }
            (0xeb, ..) => {
                let t = target(2, rel8(bytes, 1))?;
                simple(
                    2,
                    Flow::Jump {
                        target: Target::Direct(t),
                    },
                    Op::Branch("jmp", t),
                )
            }
            (0x74 | 0x75, ..) => {
                let t = target(2, rel8(bytes, 1))?;
                let m = if first == 0x74 { "je" } else { "jne" };
                simple(
                    2,
                    Flow::ConditionalJump {
                        target: Target::Direct(t),
                    },
                    Op::Branch(m, t),
                )
            }
            (0x48, Some(b1 @ (0x8d | 0x8b | 0x89)), Some(b2 @ (0x3d | 0x05))) => {
                let t = target(7, rel32(bytes, 3))?;
                let (m, reg, kind) = match (b1, b2) {
                    (0x8d, 0x3d) => ("lea", "rdi", XrefKind::DataPtr),
                    (0x8b, 0x05) => ("mov", "rax", XrefKind::Read),
                    (0x89, 0x05) => ("mov", "rax", XrefKind::Write),
                    _ => return Err(DecodeError::Invalid(address)),
                };
                let mut d = DecodedInsn::new(address, 7, Flow::Sequential);
                d.push_ref(InsnRef { target: t, kind });
                Ok((d, Op::RipMem(m, reg, t, kind)))
            }
            (0xff, Some(0x25), _) => {
                let t = target(6, rel32(bytes, 2))?;
                let mut d = DecodedInsn::new(
                    address,
                    6,
                    Flow::Jump {
                        target: Target::Indirect,
                    },
                );
                d.push_ref(InsnRef {
                    target: t,
                    kind: XrefKind::Read,
                });
                Ok((d, Op::RipMem("jmp", "", t, XrefKind::Read)))
            }
            (0xff, Some(0xd0), _) => simple(
                2,
                Flow::Call {
                    target: Target::Indirect,
                },
                Op::Plain("call", "rax"),
            ),
            (_, None, _) if matches!(first, 0x0f | 0x31 | 0x48 | 0xff) => Err(trunc),
            // A REX.W prefix followed by a known opcode but no ModRM byte.
            (0x48, Some(0x89 | 0x8b | 0x8d), None) => Err(trunc),
            _ => Err(DecodeError::Invalid(address)),
        }
    }
}

fn addr_token(target: Address, symbols: &dyn SymbolLookup) -> Token {
    match symbols.name_at(target) {
        Some(name) => Token::linked(TokenKind::Symbol, name, target),
        None => Token::linked(TokenKind::Address, target.to_string(), target),
    }
}

impl Arch for MockArch {
    fn id(&self) -> ArchId {
        ArchId::Mock
    }

    fn max_insn_len(&self) -> usize {
        15
    }

    fn decode(&self, bytes: &[u8], address: Address) -> Result<DecodedInsn, DecodeError> {
        MockArch::parse(bytes, address).map(|(d, _)| d)
    }

    fn render(
        &self,
        bytes: &[u8],
        address: Address,
        symbols: &dyn SymbolLookup,
    ) -> Result<RenderedInsn, DecodeError> {
        let (d, op) = MockArch::parse(bytes, address)?;
        let comma = || Token::new(TokenKind::Punctuation, ", ");
        let (mnemonic, operands) = match op {
            Op::Plain(m, ops) => {
                let mut toks = Vec::new();
                for (i, part) in ops.split(", ").filter(|p| !p.is_empty()).enumerate() {
                    if i > 0 {
                        toks.push(comma());
                    }
                    toks.push(Token::new(TokenKind::Register, part));
                }
                (m, toks)
            }
            Op::MovEaxImm(v) => (
                "mov",
                vec![
                    Token::new(TokenKind::Register, "eax"),
                    comma(),
                    Token::new(TokenKind::Immediate, format!("{v:#x}")),
                ],
            ),
            Op::Branch(m, t) => (m, vec![addr_token(t, symbols)]),
            Op::RipMem(m, reg, t, kind) => {
                let mut mem = Vec::new();
                if kind != XrefKind::DataPtr {
                    mem.push(Token::new(TokenKind::Keyword, "qword ptr "));
                }
                mem.push(Token::new(TokenKind::Punctuation, "["));
                mem.push(addr_token(t, symbols));
                mem.push(Token::new(TokenKind::Punctuation, "]"));
                let r = Token::new(TokenKind::Register, reg);
                let toks = match kind {
                    _ if reg.is_empty() => mem,
                    XrefKind::Write => mem.into_iter().chain([comma(), r]).collect(),
                    _ => [r, comma()].into_iter().chain(mem).collect(),
                };
                (m, toks)
            }
        };
        let raw = bytes
            .get(..usize::from(d.len))
            .ok_or(DecodeError::Truncated(address))?;
        Ok(RenderedInsn {
            address,
            bytes: raw.to_vec(),
            mnemonic: mnemonic.to_owned(),
            operands,
        })
    }

    fn is_prologue(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&[0x55, 0x48, 0x89, 0xe5])
    }

    fn is_padding(&self, bytes: &[u8]) -> bool {
        matches!(bytes.first(), Some(0x90 | 0xcc))
    }
}

// ------------------------------------------------------- synthetic program

/// Well-known addresses of the synthetic program.
pub mod addrs {
    use crate::address::Address;
    /// `_start` (entry point).
    pub const START: Address = Address(0x401000);
    /// `main`.
    pub const MAIN: Address = Address(0x401010);
    /// Branch target inside `main` (`.Lskip`).
    pub const MAIN_SKIP: Address = Address(0x40102e);
    /// Stripped helper (`sub_401040`), known only from `.eh_frame`.
    pub const HELPER: Address = Address(0x401040);
    /// `puts@plt`.
    pub const PUTS_PLT: Address = Address(0x401050);
    /// `"Hello, dasm!"`.
    pub const STR_HELLO: Address = Address(0x402000);
    /// `"/etc/passwd"` (never referenced).
    pub const STR_PASSWD: Address = Address(0x40200d);
    /// UTF-16LE `"Hi!"`.
    pub const STR_UTF16: Address = Address(0x402020);
    /// GOT slot of `puts`.
    pub const GOT_PUTS: Address = Address(0x404000);
    /// Global `g_counter`.
    pub const G_COUNTER: Address = Address(0x404008);
}

struct Asm {
    base: u64,
    bytes: Vec<u8>,
}

impl Asm {
    fn pc(&self) -> u64 {
        self.base + self.bytes.len() as u64
    }
    fn raw(&mut self, b: &[u8]) {
        self.bytes.extend_from_slice(b);
    }
    fn rel32(&mut self, opcode: &[u8], target: Address) {
        let end = self.pc() + opcode.len() as u64 + 4;
        let disp = (target.get() as i64 - end as i64) as i32;
        self.raw(opcode);
        self.raw(&disp.to_le_bytes());
    }
    fn rel8(&mut self, opcode: u8, target: Address) {
        let disp = (target.get() as i64 - (self.pc() + 2) as i64) as i8;
        self.raw(&[opcode, disp as u8]);
    }
    fn pad_to(&mut self, addr: Address) {
        while self.pc() < addr.get() {
            self.raw(&[0xcc]);
        }
    }
}

fn text_bytes() -> Vec<u8> {
    use addrs::*;
    let mut a = Asm {
        base: START.get(),
        bytes: Vec::new(),
    };
    // _start
    a.raw(&[0x31, 0xc0]);
    a.rel32(&[0xe8], MAIN);
    a.raw(&[0xf4]);
    a.pad_to(MAIN);
    // main
    a.raw(&[0x55, 0x48, 0x89, 0xe5]);
    a.rel32(&[0x48, 0x8d, 0x3d], STR_HELLO);
    a.rel32(&[0xe8], PUTS_PLT);
    a.rel32(&[0x48, 0x8b, 0x05], G_COUNTER);
    a.rel8(0x74, MAIN_SKIP);
    a.rel32(&[0xe8], HELPER);
    a.rel32(&[0x48, 0x89, 0x05], G_COUNTER);
    a.raw(&[0x31, 0xc0, 0x5d, 0xc3]);
    a.pad_to(HELPER);
    // helper
    a.raw(&[0xb8, 0x2a, 0, 0, 0, 0xc3]);
    a.pad_to(PUTS_PLT);
    // puts@plt
    a.rel32(&[0xff, 0x25], GOT_PUTS);
    a.pad_to(Address(0x401060));
    a.bytes
}

fn rodata_bytes() -> Vec<u8> {
    let mut v = b"Hello, dasm!\0/etc/passwd\0".to_vec();
    v.resize(0x20, 0);
    for c in "Hi!\0".encode_utf16() {
        v.extend_from_slice(&c.to_le_bytes());
    }
    v
}

fn data_bytes() -> Vec<u8> {
    let mut data = vec![0u8; 0x10];
    if let Some(slot) = data.get_mut(..8) {
        slot.copy_from_slice(&(addrs::PUTS_PLT.get() + 6).to_le_bytes());
    }
    data
}

/// The "file" the synthetic image is loaded from (its SHA-256 is
/// `BinaryInfo::sha256`).
#[must_use]
pub fn synthetic_file() -> Vec<u8> {
    let mut file = text_bytes();
    file.extend_from_slice(&rodata_bytes());
    file.extend_from_slice(&data_bytes());
    file
}

/// The [`StoredSource`] matching [`synthetic_program`].
#[must_use]
pub fn synthetic_source() -> StoredSource {
    StoredSource::embedded(
        "synthetic",
        SharedBytes::from(synthetic_file()),
        LoadOptions::default(),
    )
}

fn region(start: u64, size: u64, data: Vec<u8>, perms: Permissions) -> Result<MemoryRegion, Error> {
    MemoryRegion::new(
        AddressRange::from_len(Address(start), size)?,
        SharedBytes::from(data),
        perms,
    )
}

fn range(start: u64, size: u64) -> Result<AddressRange, Error> {
    AddressRange::from_len(Address(start), size)
}

/// Builds the synthetic program.
///
/// ```text
/// 0x401000 .text   r-x  _start, main, sub_401040 (stripped), puts@plt
/// 0x402000 .rodata r--  "Hello, dasm!", "/etc/passwd", u"Hi!"
/// 0x404000 .data   rw-  GOT[puts], g_counter
/// 0x404010 .bss    rw-  16 zero bytes
/// ```
///
/// `main` calls `puts@plt` and the helper, reads and writes `g_counter`
/// and loads the address of `"Hello, dasm!"`; it has a conditional branch,
/// so it has three basic blocks.
pub fn synthetic_image() -> Result<LoadedImage, Error> {
    use addrs::*;
    let text = text_bytes();
    let rodata = rodata_bytes();
    let data = data_bytes();
    let file = synthetic_file();

    let memory = MemoryMap::new(vec![
        region(0x401000, 0x60, text, Permissions::RX)?,
        region(0x402000, 0x28, rodata, Permissions::R)?,
        region(0x404000, 0x20, data, Permissions::RW)?,
    ])?;
    let sym = |name: &str, a: Address, size: u64, kind: SymbolKind| Symbol {
        name: name.into(),
        demangled: None,
        address: a,
        size: Some(size),
        kind,
        binding: SymbolBinding::Global,
        source: SymbolSource::Static,
        ..Default::default()
    };
    let hint = |a: Address, size: Option<u64>, source: FunctionHintSource| FunctionHint {
        address: a,
        size,
        source,
    };
    Ok(LoadedImage {
        info: BinaryInfo {
            format: BinaryFormat::Elf,
            kind: BinaryKind::Executable,
            arch: ArchId::Mock,
            endian: Endian::Little,
            bits: 64,
            entry: Some(START),
            base: Address::ZERO,
            build_id: Some(vec![0xd4, 0x5a, 0x00, 0x01]),
            interpreter: Some("/lib64/ld-linux-x86-64.so.2".into()),
            needed_libraries: vec!["libc.so.6".into()],
            sha256: sha256(&file),
        },
        memory,
        segments: vec![
            Segment {
                name: "LOAD[0]".into(),
                range: range(0x401000, 0x60)?,
                file_offset: 0x1000,
                file_size: 0x60,
                perms: Permissions::RX,
                ..Default::default()
            },
            Segment {
                name: "LOAD[1]".into(),
                range: range(0x402000, 0x28)?,
                file_offset: 0x2000,
                file_size: 0x28,
                perms: Permissions::R,
                ..Default::default()
            },
            Segment {
                name: "LOAD[2]".into(),
                range: range(0x404000, 0x20)?,
                file_offset: 0x3000,
                file_size: 0x10,
                perms: Permissions::RW,
                ..Default::default()
            },
        ],
        sections: vec![
            Section {
                name: ".text".into(),
                range: range(0x401000, 0x60)?,
                file_offset: Some(0x1000),
                file_size: 0x60,
                kind: SectionKind::Code,
                perms: Permissions::RX,
                ..Default::default()
            },
            Section {
                name: ".rodata".into(),
                range: range(0x402000, 0x28)?,
                file_offset: Some(0x2000),
                file_size: 0x28,
                kind: SectionKind::ReadOnlyData,
                perms: Permissions::R,
                ..Default::default()
            },
            Section {
                name: ".data".into(),
                range: range(0x404000, 0x10)?,
                file_offset: Some(0x3000),
                file_size: 0x10,
                kind: SectionKind::Data,
                perms: Permissions::RW,
                ..Default::default()
            },
            Section {
                name: ".bss".into(),
                range: range(0x404010, 0x10)?,
                file_offset: None,
                file_size: 0,
                kind: SectionKind::Bss,
                perms: Permissions::RW,
                ..Default::default()
            },
        ],
        symbols: vec![
            sym("_start", START, 8, SymbolKind::Function),
            sym("main", MAIN, 0x29, SymbolKind::Function),
            sym("g_counter", G_COUNTER, 8, SymbolKind::Object),
        ],
        imports: vec![Import {
            name: "puts".into(),
            version: Some("GLIBC_2.2.5".into()),
            library: Some("libc.so.6".into()),
            kind: SymbolKind::Function,
            plt: Some(PUTS_PLT),
            got: Some(GOT_PUTS),
        }],
        relocations: Vec::new(),
        function_hints: vec![
            hint(START, None, FunctionHintSource::Entry),
            hint(START, Some(8), FunctionHintSource::Symbol),
            hint(MAIN, Some(0x29), FunctionHintSource::Symbol),
            hint(HELPER, Some(6), FunctionHintSource::EhFrame),
            hint(PUTS_PLT, Some(6), FunctionHintSource::Plt),
        ],
    })
}

/// [`synthetic_image`] wrapped in a [`Program`] with [`MockArch`].
pub fn synthetic_program() -> Result<Program, Error> {
    Ok(Program::new(synthetic_image()?, Arc::new(MockArch)))
}

// ------------------------------------------------------ reference analysis

/// A naive, single-threaded recursive descent over any [`Arch`]: seeds from
/// hints and user overrides, follows direct calls, splits blocks at branch
/// targets, records xrefs, and finds ASCII/UTF-16LE strings in non-code
/// regions. It is a test oracle and mock, not the real analysis (no
/// incrementality, no jump tables, no noreturn propagation).
#[must_use]
pub fn reference_analysis(snap: &Snapshot) -> AnalysisResults {
    let user = snap.user();
    let mut seeds: BTreeMap<Address, FunctionSource> = BTreeMap::new();
    for h in &snap.image().function_hints {
        seeds
            .entry(h.address)
            .or_insert(FunctionSource::Hint(h.source));
    }
    for (a, d) in user.definitions() {
        let executable = snap
            .memory()
            .region_at(a)
            .is_some_and(|r| r.perms().execute);
        if *d == crate::ops::Definition::Code && executable {
            seeds.entry(a).or_insert(FunctionSource::UserCode);
        }
    }
    for (a, o) in user.function_overrides() {
        match o {
            FunctionOverride::Create => {
                seeds.insert(a, FunctionSource::User);
            }
            FunctionOverride::Delete => {
                seeds.remove(&a);
            }
        }
    }
    let plt_seeds: BTreeSet<Address> = snap
        .image()
        .function_hints
        .iter()
        .filter(|h| h.source == FunctionHintSource::Plt)
        .map(|h| h.address)
        .collect();

    let mut delta = AnalysisDelta::default();
    let mut done: BTreeSet<Address> = BTreeSet::new();
    let mut queue: Vec<(Address, FunctionSource)> =
        seeds.iter().rev().map(|(a, s)| (*a, *s)).collect();
    while let Some((entry, source)) = queue.pop() {
        if !done.insert(entry) {
            continue;
        }
        let (func, xrefs, callees) = descend(snap, entry, source, plt_seeds.contains(&entry));
        for c in callees {
            if !done.contains(&c) && user.function_override(c) != Some(FunctionOverride::Delete) {
                let src = seeds.get(&c).copied().unwrap_or(FunctionSource::CallTarget);
                queue.push((c, src));
            }
        }
        delta.set_xrefs.push((XrefOwner::Function(entry), xrefs));
        delta.upsert_functions.push(func);
    }
    delta.upsert_strings = find_strings(snap);
    let mut results = AnalysisResults::default();
    results.apply(delta);
    results.progress = AnalysisProgress {
        state: AnalysisState::Done,
        current_pass: None,
        done: 1,
        total: 1,
        ..Default::default()
    };
    results
}

fn descend(
    snap: &Snapshot,
    entry: Address,
    source: FunctionSource,
    plt: bool,
) -> (Function, Vec<Xref>, Vec<Address>) {
    let arch = snap.arch();
    let mut insns: BTreeMap<Address, DecodedInsn> = BTreeMap::new();
    let mut leaders: BTreeSet<Address> = BTreeSet::from([entry]);
    let mut work = vec![entry];
    let mut xrefs = Vec::new();
    let mut callees = Vec::new();
    while let Some(mut pc) = work.pop() {
        loop {
            if insns.contains_key(&pc) {
                break;
            }
            let Some(region) = snap.memory().region_at(pc) else {
                break;
            };
            if !region.perms().execute {
                break;
            }
            let Some(bytes) = snap.memory().read_up_to(pc, arch.max_insn_len()) else {
                break;
            };
            let Ok(d) = arch.decode(&bytes, pc) else {
                break;
            };
            insns.insert(pc, d);
            for r in d.refs() {
                xrefs.push(Xref {
                    from: pc,
                    to: r.target,
                    kind: r.kind,
                });
            }
            match d.flow {
                Flow::Call {
                    target: Target::Direct(t),
                } => {
                    xrefs.push(Xref {
                        from: pc,
                        to: t,
                        kind: XrefKind::Call,
                    });
                    callees.push(t);
                }
                Flow::Jump {
                    target: Target::Direct(t),
                }
                | Flow::ConditionalJump {
                    target: Target::Direct(t),
                } => {
                    xrefs.push(Xref {
                        from: pc,
                        to: t,
                        kind: XrefKind::Jump,
                    });
                    leaders.insert(t);
                    work.push(t);
                }
                _ => {}
            }
            let Some(next) = d.next_address() else {
                break;
            };
            if d.flow.ends_block() {
                if d.flow.falls_through() {
                    leaders.insert(next);
                    work.push(next);
                }
                break;
            }
            pc = next;
        }
    }

    let mut blocks = Vec::new();
    let mut cur: Vec<DecodedInsn> = Vec::new();
    let flush =
        |cur: &mut Vec<DecodedInsn>, blocks: &mut Vec<BasicBlock>, next: Option<Address>| {
            let (Some(first), Some(last)) = (cur.first(), cur.last()) else {
                return;
            };
            let mut succ = Vec::new();
            match last.flow {
                Flow::Jump { target } => succ.push(Edge {
                    target,
                    kind: EdgeKind::Jump,
                }),
                Flow::ConditionalJump { target } => {
                    succ.push(Edge {
                        target,
                        kind: EdgeKind::ConditionalTaken,
                    });
                    if let Some(n) = last.next_address() {
                        succ.push(Edge {
                            target: Target::Direct(n),
                            kind: EdgeKind::ConditionalNotTaken,
                        });
                    }
                }
                f if f.falls_through() => {
                    if let Some(n) = next {
                        succ.push(Edge {
                            target: Target::Direct(n),
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
                _ => {}
            }
            let lens = cur.iter().map(|i| i.len).collect();
            if let Ok(b) = BasicBlock::new(first.address, lens, succ) {
                blocks.push(b);
            }
            cur.clear();
        };
    for (addr, d) in &insns {
        let contiguous = cur.last().and_then(DecodedInsn::next_address) == Some(*addr);
        if !cur.is_empty() && (!contiguous || leaders.contains(addr)) {
            let next = contiguous.then_some(*addr);
            flush(&mut cur, &mut blocks, next);
        }
        cur.push(*d);
        if d.flow.ends_block() {
            flush(&mut cur, &mut blocks, None);
        }
    }
    flush(&mut cur, &mut blocks, None);

    let thunk = insns.len() == 1 && insns.values().all(|d| matches!(d.flow, Flow::Jump { .. }));
    let noreturn = !insns.values().any(|d| d.flow == Flow::Return) && !thunk;
    let f = Function {
        entry,
        blocks,
        flags: FunctionFlags {
            noreturn,
            thunk,
            plt,
            library: false,
        },
        source,
    };
    (f, xrefs, callees)
}

fn find_strings(snap: &Snapshot) -> Vec<StringLiteral> {
    let mut out = Vec::new();
    for r in snap.memory().regions() {
        if r.perms().execute {
            continue;
        }
        let Some(bytes) = snap.memory().read(
            r.range().start(),
            usize::try_from(r.range().len()).unwrap_or(0),
        ) else {
            continue;
        };
        let base = r.range().start();
        let mut i = 0usize;
        while i < bytes.len() {
            let ascii_len = bytes
                .get(i..)
                .unwrap_or(&[])
                .iter()
                .take_while(|b| b.is_ascii_graphic() || **b == b' ')
                .count();
            if ascii_len >= 4 && bytes.get(i + ascii_len) == Some(&0) {
                let text = String::from_utf8_lossy(bytes.get(i..i + ascii_len).unwrap_or(&[]));
                if let Some(a) = base.checked_add(i as u64) {
                    out.push(StringLiteral {
                        address: a,
                        encoding: StringEncoding::Ascii,
                        byte_len: ascii_len as u64 + 1,
                        value: text.into_owned(),
                    });
                }
                i += ascii_len + 1;
                continue;
            }
            let units: Vec<u16> = bytes
                .get(i..)
                .unwrap_or(&[])
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|u| (0x20..0x7f).contains(u))
                .collect();
            let term = bytes.get(i + units.len() * 2..i + units.len() * 2 + 2) == Some(&[0, 0][..]);
            if units.len() >= 3 && term {
                if let Some(a) = base.checked_add(i as u64) {
                    out.push(StringLiteral {
                        address: a,
                        encoding: StringEncoding::Utf16Le,
                        byte_len: (units.len() as u64 + 1) * 2,
                        value: String::from_utf16_lossy(&units),
                    });
                }
                i += (units.len() + 1) * 2;
                continue;
            }
            i += 1;
        }
    }
    out
}

// ------------------------------------------------------------------ store

#[derive(Debug, Default)]
struct StoreData {
    source: Option<StoredSource>,
    entries: BTreeMap<u64, JournalEntry>,
    settings: BTreeMap<String, String>,
    format_version: Option<u32>,
}

/// A [`ProjectStore`] in memory. Clones share the same data, so a test can
/// keep a handle, drop the session and reopen it to check persistence.
#[derive(Clone, Debug, Default)]
pub struct InMemoryStore(Arc<Mutex<StoreData>>);

impl InMemoryStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        InMemoryStore::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut StoreData) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl ProjectStore for InMemoryStore {
    fn load_source(&mut self) -> Result<Option<StoredSource>, Error> {
        Ok(self.with(|d| d.source.clone()))
    }

    fn save_source(&mut self, source: &StoredSource) -> Result<(), Error> {
        self.with(|d| match &d.source {
            Some(s) if s.sha256 != source.sha256 => Err(Error::Store(
                "project already holds a different binary".into(),
            )),
            _ => {
                // Limits are runtime-only: persistent stores drop them.
                let mut stored = source.clone();
                stored.options.limits = Limits::default();
                d.source = Some(stored);
                Ok(())
            }
        })
    }

    fn load_journal(&mut self) -> Result<Vec<JournalEntry>, Error> {
        Ok(self.with(|d| d.entries.values().cloned().collect()))
    }

    fn record(&mut self, events: &[JournalEvent]) -> Result<(), Error> {
        self.with(|d| {
            // Validate the whole batch first, then apply: all or nothing,
            // without copying the stored journal.
            let mut appended = BTreeSet::new();
            for e in events {
                match e {
                    JournalEvent::Appended(entry) => {
                        if d.entries.contains_key(&entry.seq) || !appended.insert(entry.seq) {
                            return Err(Error::Store(format!("duplicate seq {}", entry.seq)));
                        }
                    }
                    JournalEvent::StateChanged { seq, .. } => {
                        if !d.entries.contains_key(seq) && !appended.contains(seq) {
                            return Err(Error::Store(format!("unknown seq {seq}")));
                        }
                    }
                }
            }
            for e in events {
                match e {
                    JournalEvent::Appended(entry) => {
                        d.entries.insert(entry.seq, entry.clone());
                    }
                    JournalEvent::StateChanged {
                        seq,
                        state,
                        inverse,
                    } => {
                        if let Some(entry) = d.entries.get_mut(seq) {
                            entry.state = *state;
                            entry.inverse = inverse.clone();
                        }
                    }
                }
            }
            Ok(())
        })
    }

    fn format_version(&mut self) -> Result<Option<u32>, Error> {
        Ok(self.with(|d| d.format_version))
    }

    fn set_format_version(&mut self, version: u32) -> Result<(), Error> {
        self.with(|d| d.format_version = Some(version));
        Ok(())
    }

    fn setting(&mut self, key: &str) -> Result<Option<String>, Error> {
        Ok(self.with(|d| d.settings.get(key).cloned()))
    }

    fn set_setting(&mut self, key: &str, value: &str) -> Result<(), Error> {
        self.with(|d| {
            d.settings.insert(key.to_owned(), value.to_owned());
        });
        Ok(())
    }
}

impl InMemoryStore {
    /// Number of entries in a given state (for tests).
    #[must_use]
    pub fn count(&self, state: EntryState) -> usize {
        self.with(|d| d.entries.values().filter(|e| e.state == state).count())
    }
}

// ----------------------------------------------------------------- driver

/// An [`AnalysisDriver`] that runs [`reference_analysis`] synchronously on
/// start and after every invalidation. Good enough for UI development on
/// small inputs; the real scheduler lives in `dasm-analysis`.
#[derive(Debug, Default)]
pub struct StaticDriver {
    hub: Mutex<Option<Arc<SnapshotHub>>>,
}

impl StaticDriver {
    fn rerun(&self) {
        let hub = self
            .hub
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(hub) = hub {
            hub.update(|s| {
                let results = reference_analysis(s);
                s.with_analysis(results)
            });
        }
    }
}

impl AnalysisDriver for StaticDriver {
    fn start(&self, hub: Arc<SnapshotHub>) {
        *self.hub.lock().unwrap_or_else(PoisonError::into_inner) = Some(hub);
        self.rerun();
    }

    fn invalidate(&self, _changes: &[Change]) {
        self.rerun();
    }

    fn set_focus(&self, _focus: Focus) {}

    fn cancel(&self) {}
}

/// A ready session over the synthetic program, analysed, with an
/// in-memory store.
pub fn mock_session() -> Result<Session, Error> {
    mock_session_with_store(InMemoryStore::new())
}

/// Like [`mock_session`] but with a given store (to test reopening).
pub fn mock_session_with_store(store: InMemoryStore) -> Result<Session, Error> {
    Session::open(
        synthetic_program()?,
        synthetic_source(),
        Box::new(store),
        Arc::new(StaticDriver::default()),
        "tester",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::NoSymbols;
    use crate::journal::{OpSource, UndoScope};
    use crate::ops::Operation;
    use crate::report::{AnalyzeReport, ReportOptions};
    use crate::snapshot::{ItemKind, SnapshotListener};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn mock_arch_reports_truncation_not_invalid() {
        let arch = MockArch;
        for bytes in [
            &[0x48][..],
            &[0x48, 0x89],
            &[0x48, 0x8b],
            &[0x48, 0x8d, 0x3d, 0],
        ] {
            assert_eq!(
                arch.decode(bytes, Address(0x10)),
                Err(DecodeError::Truncated(Address(0x10))),
                "{bytes:02x?}"
            );
        }
        assert_eq!(
            arch.decode(&[0x48, 0x00, 0x00], Address(0x10)),
            Err(DecodeError::Invalid(Address(0x10)))
        );
    }

    #[test]
    fn session_exposes_scoped_undo_state_and_history() {
        let session = mock_session().unwrap();
        session
            .apply(
                Operation::Comment {
                    address: Address(0x401011),
                    text: Some("in main".into()),
                },
                OpSource::Ui,
            )
            .unwrap();
        session
            .apply(
                Operation::Rename {
                    address: addrs::HELPER,
                    name: Some("helper".into()),
                },
                OpSource::Ui,
            )
            .unwrap();
        assert!(session.can_undo(UndoScope::Function(addrs::MAIN)));
        assert!(!session.can_redo(UndoScope::Function(addrs::MAIN)));
        assert_eq!(session.history(UndoScope::Global).len(), 2);
        let in_main = session.history(UndoScope::Function(addrs::MAIN));
        assert_eq!(in_main.len(), 1);
        assert!(matches!(in_main[0].op, Operation::Comment { .. }));
        session.undo(UndoScope::Function(addrs::MAIN)).unwrap();
        assert!(session.can_redo(UndoScope::Function(addrs::MAIN)));
        assert!(!session.can_undo(UndoScope::Function(addrs::MAIN)));
    }

    #[test]
    fn mock_arch_never_panics_on_any_prefix() {
        let arch = MockArch;
        let text = text_bytes();
        for start in 0..text.len() {
            for end in start..=text.len().min(start + 16) {
                let _ = arch.decode(&text[start..end], Address(start as u64));
                let _ = arch.render(&text[start..end], Address(start as u64), &NoSymbols);
            }
        }
        for b in 0..=255u8 {
            let _ = arch.decode(&[b], Address(u64::MAX));
            let _ = arch.decode(&[b, 0xff, 0xff, 0xff, 0x7f, 0, 0], Address(u64::MAX - 3));
        }
    }

    #[test]
    fn synthetic_program_analyses_as_documented() {
        let session = mock_session().unwrap();
        let snap = session.snapshot();
        let a = snap.analysis();
        let entries: Vec<Address> = a.functions().map(|f| f.entry).collect();
        assert_eq!(
            entries,
            vec![addrs::START, addrs::MAIN, addrs::HELPER, addrs::PUTS_PLT]
        );
        let main = a.function_at(addrs::MAIN).unwrap();
        assert_eq!(main.blocks.len(), 3);
        assert_eq!(snap.function_name(main), "main");
        assert_eq!(
            snap.display_name(addrs::HELPER).as_deref(),
            Some("sub_401040")
        );
        assert_eq!(
            snap.display_name(addrs::PUTS_PLT).as_deref(),
            Some("puts@plt")
        );
        assert!(a.function_at(addrs::START).unwrap().flags.noreturn);
        let plt = a.function_at(addrs::PUTS_PLT).unwrap();
        assert!(plt.flags.plt && plt.flags.thunk);

        let kinds: Vec<XrefKind> = a.xrefs_to(addrs::G_COUNTER).map(|x| x.kind).collect();
        assert_eq!(kinds, vec![XrefKind::Read, XrefKind::Write]);
        assert_eq!(a.xrefs_to(addrs::STR_HELLO).count(), 1);
        assert_eq!(
            a.xrefs_to(addrs::HELPER).next().map(|x| x.kind),
            Some(XrefKind::Call)
        );

        let strings: Vec<(Address, StringEncoding)> =
            a.strings().map(|s| (s.address, s.encoding)).collect();
        assert_eq!(
            strings,
            vec![
                (addrs::STR_HELLO, StringEncoding::Ascii),
                (addrs::STR_PASSWD, StringEncoding::Ascii),
                (addrs::STR_UTF16, StringEncoding::Utf16Le),
            ]
        );
    }

    #[test]
    fn got_slots_are_named_after_imports() {
        // -fno-plt binaries call through the GOT: `call [rip+puts@got]`.
        let session = mock_session().unwrap();
        let snap = session.snapshot();
        assert_eq!(
            snap.display_name(addrs::GOT_PUTS).as_deref(),
            Some("puts@got")
        );
        let program = snap.program();
        assert_eq!(
            program.import_at(addrs::GOT_PUTS).map(|i| i.name.as_str()),
            Some("puts")
        );
        assert_eq!(
            program.import_at(addrs::PUTS_PLT).map(|i| i.name.as_str()),
            Some("puts")
        );
        let stub = snap.render_insn(addrs::PUTS_PLT).unwrap();
        assert_eq!(stub.operands_text(), "qword ptr [puts@got]");
    }

    #[test]
    fn untrusted_symbol_names_are_sanitized_for_display() {
        let mut image = synthetic_image().unwrap();
        image.symbols.push(Symbol {
            name: "evil\u{1b}[2J\u{202e}".into(),
            address: addrs::HELPER,
            kind: SymbolKind::Function,
            ..Default::default()
        });
        image.imports[0].name = "pu\u{7}ts".into();
        let snap = Snapshot::initial(Arc::new(Program::new(image, Arc::new(MockArch))));
        assert_eq!(
            snap.display_name(addrs::HELPER).as_deref(),
            Some("evil\\u{1b}[2J\\u{202e}")
        );
        assert_eq!(
            snap.display_name(addrs::PUTS_PLT).as_deref(),
            Some("pu\\u{7}ts@plt")
        );
    }

    #[test]
    fn rendering_links_operands_to_names() {
        let session = mock_session().unwrap();
        let snap = session.snapshot();
        let call = snap.render_insn(Address(0x40101b)).unwrap();
        assert_eq!(call.mnemonic, "call");
        assert_eq!(call.operands_text(), "puts@plt");
        assert_eq!(
            call.operands.first().and_then(|t| t.target),
            Some(addrs::PUTS_PLT)
        );
        let rd = snap.render_insn(Address(0x401020)).unwrap();
        assert_eq!(rd.operands_text(), "rax, qword ptr [g_counter]");
        assert_eq!(rd.bytes.len(), 7);
    }

    #[test]
    fn rename_undo_redo_flow_through_snapshots() {
        struct Count(AtomicU64);
        impl SnapshotListener for Count {
            fn snapshot_published(&self, g: u64) {
                self.0.store(g, Ordering::SeqCst);
            }
        }
        let store = InMemoryStore::new();
        let session = mock_session_with_store(store.clone()).unwrap();
        let counter = Arc::new(Count(AtomicU64::new(0)));
        session.hub().subscribe(counter.clone());
        let before = session.snapshot();

        session
            .apply(
                Operation::Rename {
                    address: addrs::HELPER,
                    name: Some("compute".into()),
                },
                OpSource::Ui,
            )
            .unwrap();
        let after = session.snapshot();
        assert!(after.generation() > before.generation());
        assert_eq!(counter.0.load(Ordering::SeqCst), after.generation());
        // Old snapshot is untouched; new one shows the name in operands.
        assert_eq!(
            before.display_name(addrs::HELPER).as_deref(),
            Some("sub_401040")
        );
        assert_eq!(
            after
                .render_insn(Address(0x401029))
                .unwrap()
                .operands_text(),
            "compute"
        );
        assert!(after.undo_info().can_undo);

        assert!(session.undo(UndoScope::Global).unwrap());
        assert_eq!(
            session.snapshot().display_name(addrs::HELPER).as_deref(),
            Some("sub_401040")
        );
        assert!(session.redo(UndoScope::Global).unwrap());
        drop(session);

        // Reopen from the same store: the rename survived.
        let reopened = mock_session_with_store(store.clone()).unwrap();
        assert_eq!(
            reopened.snapshot().display_name(addrs::HELPER).as_deref(),
            Some("compute")
        );
        assert_eq!(store.count(EntryState::Active), 1);
    }

    #[test]
    fn open_checks_the_stored_source() {
        let store = InMemoryStore::new();
        drop(mock_session_with_store(store.clone()).unwrap());
        assert!(store.clone().load_source().unwrap().is_some(), "created");
        let open = |source: StoredSource| {
            Session::open(
                synthetic_program().unwrap(),
                source,
                Box::new(store.clone()),
                Arc::new(StaticDriver::default()),
                "t",
            )
        };
        // Same binary, different base: refused.
        let mut rebased = synthetic_source();
        rebased.options.base = Some(Address(0x1000));
        assert!(matches!(open(rebased), Err(Error::ProjectMismatch(_))));
        // Source that does not match the program: refused.
        let mut other = synthetic_source();
        other.sha256 = [7; 32];
        assert!(matches!(open(other), Err(Error::InvalidArgument(_))));
        // A project holding another binary: refused.
        let foreign = InMemoryStore::new();
        let mut s = foreign.clone();
        s.save_source(&StoredSource {
            sha256: [9; 32],
            ..synthetic_source()
        })
        .unwrap();
        let err = Session::open(
            synthetic_program().unwrap(),
            synthetic_source(),
            Box::new(foreign),
            Arc::new(StaticDriver::default()),
            "t",
        )
        .unwrap_err();
        assert!(matches!(err, Error::ProjectMismatch(_)), "{err}");
        // Matching source reopens fine.
        assert!(open(synthetic_source()).is_ok());
    }

    /// Delegates to an [`InMemoryStore`] but fails the first
    /// `set_format_version` call, after `save_source` already succeeded
    /// (worst-case order for a non-transactional store).
    struct CrashOnVersion {
        inner: InMemoryStore,
        crashed: bool,
    }

    impl ProjectStore for CrashOnVersion {
        fn load_source(&mut self) -> Result<Option<StoredSource>, Error> {
            self.inner.load_source()
        }
        fn save_source(&mut self, s: &StoredSource) -> Result<(), Error> {
            self.inner.save_source(s)
        }
        fn load_journal(&mut self) -> Result<Vec<JournalEntry>, Error> {
            self.inner.load_journal()
        }
        fn record(&mut self, e: &[JournalEvent]) -> Result<(), Error> {
            self.inner.record(e)
        }
        fn format_version(&mut self) -> Result<Option<u32>, Error> {
            self.inner.format_version()
        }
        fn set_format_version(&mut self, v: u32) -> Result<(), Error> {
            if !self.crashed {
                self.crashed = true;
                // Simulate: source written, then the process dies.
                self.inner.save_source(&synthetic_source())?;
                return Err(Error::Store("simulated crash".into()));
            }
            self.inner.set_format_version(v)
        }
        fn setting(&mut self, k: &str) -> Result<Option<String>, Error> {
            self.inner.setting(k)
        }
        fn set_setting(&mut self, k: &str, v: &str) -> Result<(), Error> {
            self.inner.set_setting(k, v)
        }
    }

    #[test]
    fn interrupted_project_creation_can_be_reopened() {
        let store = InMemoryStore::new();
        let first = Session::open(
            synthetic_program().unwrap(),
            synthetic_source(),
            Box::new(CrashOnVersion {
                inner: store.clone(),
                crashed: false,
            }),
            Arc::new(StaticDriver::default()),
            "t",
        );
        assert!(first.is_err());
        assert!(store.clone().load_source().unwrap().is_some());
        assert_eq!(store.clone().format_version().unwrap(), None);
        let reopened = mock_session_with_store(store.clone());
        assert!(reopened.is_ok(), "{:?}", reopened.err());
        assert_eq!(
            store.clone().format_version().unwrap(),
            Some(crate::journal::JOURNAL_FORMAT_VERSION)
        );
    }

    #[test]
    fn newer_project_format_is_refused() {
        let store = InMemoryStore::new();
        drop(mock_session_with_store(store.clone()).unwrap());
        let mut s = store.clone();
        assert_eq!(
            s.format_version().unwrap(),
            Some(crate::journal::JOURNAL_FORMAT_VERSION)
        );
        s.set_format_version(crate::journal::JOURNAL_FORMAT_VERSION + 1)
            .unwrap();
        let err = mock_session_with_store(store).unwrap_err();
        assert!(matches!(err, Error::NewerProjectFormat { .. }), "{err}");
    }

    /// Regression for the O(n) journal clone per operation (Backend #3
    /// measured ~2.2 ms/op at 10k ops). Budget: < 1 s in release; debug
    /// gets a generous bound so the test is not flaky on loaded CI.
    #[test]
    fn ten_thousand_applies_are_fast() {
        const N: u64 = 10_000;
        let session = mock_session().unwrap();
        let start = std::time::Instant::now();
        for i in 0..N {
            session
                .apply(
                    Operation::Rename {
                        address: Address(addrs::MAIN.get() + (i % 7)),
                        name: Some(format!("n{i}")),
                    },
                    OpSource::Script,
                )
                .unwrap();
        }
        let elapsed = start.elapsed();
        eprintln!(
            "{N} Session::apply: {elapsed:?} ({:?}/op)",
            elapsed / N as u32
        );
        let budget = if cfg!(debug_assertions) {
            std::time::Duration::from_secs(10)
        } else {
            std::time::Duration::from_secs(1)
        };
        assert!(elapsed < budget, "{N} applies took {elapsed:?}");
        assert_eq!(session.history(UndoScope::Global).len(), N as usize);
    }

    #[test]
    fn define_code_roots_a_function_only_while_defined() {
        let session = mock_session().unwrap();
        // The padding at 0x401008 is not reachable from any seed.
        let a = Address(0x401008);
        assert!(session.snapshot().analysis().function_at(a).is_none());
        session
            .apply(Operation::DefineCode { address: a }, OpSource::Ui)
            .unwrap();
        let source = session
            .snapshot()
            .analysis()
            .function_at(a)
            .map(|f| f.source);
        assert_eq!(source, Some(FunctionSource::UserCode));

        // Precedence: an explicit create_function names the stronger intent...
        session
            .apply(Operation::CreateFunction { address: a }, OpSource::Ui)
            .unwrap();
        let source = session
            .snapshot()
            .analysis()
            .function_at(a)
            .map(|f| f.source);
        assert_eq!(source, Some(FunctionSource::User));
        // ...and delete_function wins over the definition.
        session
            .apply(Operation::DeleteFunction { address: a }, OpSource::Ui)
            .unwrap();
        assert!(session.snapshot().analysis().function_at(a).is_none());

        // Called code keeps its function when the definition goes.
        session
            .apply(
                Operation::DefineCode {
                    address: addrs::HELPER,
                },
                OpSource::Ui,
            )
            .unwrap();
        session
            .apply(
                Operation::Undefine {
                    address: addrs::HELPER,
                },
                OpSource::Ui,
            )
            .unwrap();
        assert!(
            session
                .snapshot()
                .analysis()
                .function_at(addrs::HELPER)
                .is_some()
        );

        // Outside executable memory a definition roots nothing.
        for data in [Address(0x10), addrs::STR_HELLO] {
            session
                .apply(Operation::DefineCode { address: data }, OpSource::Ui)
                .unwrap();
            assert!(session.snapshot().analysis().function_at(data).is_none());
        }

        // Back to the definition alone, then gone with it.
        session
            .apply(Operation::ResetFunction { address: a }, OpSource::Ui)
            .unwrap();
        let source = session
            .snapshot()
            .analysis()
            .function_at(a)
            .map(|f| f.source);
        assert_eq!(source, Some(FunctionSource::UserCode));
        session
            .apply(Operation::Undefine { address: a }, OpSource::Ui)
            .unwrap();
        assert!(session.snapshot().analysis().function_at(a).is_none());
    }

    #[test]
    fn extremely_deep_batch_is_rejected_without_overflowing() {
        // Deep enough to overflow the stack if anything recursed over it,
        // including the drop of the rejected operation.
        let session = mock_session().unwrap();
        let mut deep = Operation::Batch { ops: Vec::new() };
        for _ in 0..200_000 {
            deep = Operation::Batch { ops: vec![deep] };
        }
        let err = session.apply(deep, OpSource::Script).unwrap_err();
        assert!(matches!(err, Error::InvalidOperation(_)), "{err}");
    }

    #[test]
    fn author_is_checked_when_opening() {
        let opened = Session::open(
            synthetic_program().unwrap(),
            synthetic_source(),
            Box::new(InMemoryStore::new()),
            Arc::new(StaticDriver::default()),
            "bad\u{1b}author",
        );
        assert!(matches!(opened, Err(Error::InvalidArgument(_))));
    }

    #[test]
    fn delete_and_create_function_reanalyse() {
        let session = mock_session().unwrap();
        session
            .apply(
                Operation::DeleteFunction {
                    address: addrs::HELPER,
                },
                OpSource::Ui,
            )
            .unwrap();
        // Still found as a call target from main.
        assert!(
            session
                .snapshot()
                .analysis()
                .function_at(addrs::HELPER)
                .is_none()
        );
        session
            .apply(
                Operation::CreateFunction {
                    address: addrs::HELPER,
                },
                OpSource::Ui,
            )
            .unwrap();
        let s = session.snapshot();
        let f = s.analysis().function_at(addrs::HELPER).unwrap();
        assert_eq!(f.source, FunctionSource::User);
    }

    #[test]
    fn listing_walks_items_across_regions() {
        let session = mock_session().unwrap();
        let snap = session.snapshot();
        let items: Vec<_> = snap.listing_from(Address(0x401050)).take(20).collect();
        let first = items.first().unwrap();
        assert_eq!(first.kind, ItemKind::Code);
        assert_eq!(first.range.len(), 6);
        assert!(
            items
                .iter()
                .any(|i| i.range.start() == addrs::STR_HELLO && i.kind == ItemKind::String)
        );
        // Starting in a gap jumps to the next region.
        let gap = snap.listing_from(Address(0x403000)).next().unwrap();
        assert_eq!(gap.range.start(), Address(0x404000));
        assert!(snap.listing_from(Address(0x500000)).next().is_none());
    }

    #[test]
    fn item_containing_aligns_to_instruction_start() {
        let session = mock_session().unwrap();
        let snap = session.snapshot();
        // 0x401022 is inside `mov rax, [g_counter]` at 0x401020 (7 bytes).
        let item = snap.item_containing(Address(0x401022)).unwrap();
        assert_eq!(item.kind, ItemKind::Code);
        assert_eq!(item.range.start(), Address(0x401020));
        assert_eq!(item.range.len(), 7);
        // Inside a string.
        let s = snap.item_containing(Address(0x402003)).unwrap();
        assert_eq!(
            (s.range.start(), s.kind),
            (addrs::STR_HELLO, ItemKind::String)
        );
        // Inside user-defined data.
        session
            .apply(
                Operation::DefineData {
                    address: addrs::G_COUNTER,
                    ty: crate::model::DataType::Qword,
                },
                OpSource::Ui,
            )
            .unwrap();
        let d = session
            .snapshot()
            .item_containing(Address(0x40400c))
            .unwrap();
        assert_eq!(d.range.start(), addrs::G_COUNTER);
        assert_eq!(d.range.len(), 8);
    }

    #[test]
    fn user_defined_string_covers_up_to_terminator() {
        let session = mock_session().unwrap();
        // "/etc/passwd\0" at STR_PASSWD is found by analysis; define a
        // string one byte later, where analysis has none.
        let a = Address(addrs::STR_PASSWD.get() + 1);
        session
            .apply(
                Operation::DefineData {
                    address: a,
                    ty: crate::model::DataType::String {
                        encoding: StringEncoding::Ascii,
                    },
                },
                OpSource::Ui,
            )
            .unwrap();
        let item = session
            .snapshot()
            .item_containing(Address(a.get() + 3))
            .unwrap();
        assert_eq!(item.range.start(), a);
        assert_eq!(item.range.len(), "etc/passwd".len() as u64 + 1);
    }

    #[test]
    fn empty_region_does_not_end_the_listing() {
        // SEC-CORE-06: `PT_LOAD` with `p_memsz == 0` hid all later code.
        let mut image = synthetic_image().unwrap();
        let mut regions: Vec<MemoryRegion> = image.memory.regions().to_vec();
        regions.push(region(0x401800, 0, Vec::new(), Permissions::R).unwrap());
        image.memory = MemoryMap::new(regions).unwrap();
        let snap = Snapshot::initial(Arc::new(Program::new(image, Arc::new(MockArch))));
        let last = snap.listing_from(Address(0)).last().unwrap();
        assert_eq!(last.range.end(), Address(0x404020));
    }

    #[test]
    fn listing_backward_mirrors_forward() {
        let session = mock_session().unwrap();
        let snap = session.snapshot();
        let forward: Vec<_> = snap.listing_from(Address(0)).collect();
        let mut backward: Vec<_> = snap.listing_before(Address(u64::MAX)).collect();
        backward.reverse();
        assert_eq!(forward, backward);
        // Starting backward from the middle of an instruction yields the
        // previous one first.
        let prev = snap.listing_before(Address(0x401022)).next().unwrap();
        assert_eq!(prev.range.start(), Address(0x40101b));
        assert!(snap.listing_before(Address(0x401000)).next().is_none());
    }

    #[test]
    fn report_roundtrips_through_json() {
        let session = mock_session().unwrap();
        let snap = session.snapshot();
        let report = AnalyzeReport::from_snapshot(
            &snap,
            &ReportOptions {
                path: "synthetic".into(),
                include_instructions: true,
                analysis_ms: 1,
            },
        );
        assert_eq!(report.stats.function_count, 4);
        let main = report.functions.iter().find(|f| f.name == "main").unwrap();
        let insns = main.instructions.as_ref().unwrap();
        assert_eq!(insns.first().map(|i| i.bytes.as_str()), Some("55"));
        let json = serde_json::to_string_pretty(&report).unwrap();
        let back: AnalyzeReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }
}
