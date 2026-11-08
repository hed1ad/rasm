//! What a [`crate::Loader`] produces: the immutable description of a binary.

use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressRange};
use crate::memory::{MemoryMap, Permissions};

/// File format of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BinaryFormat {
    /// ELF (stage 1).
    Elf,
    /// Raw bytes mapped at a user-chosen base.
    Raw,
}

/// ELF-style object kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BinaryKind {
    /// Fixed-address executable (`ET_EXEC`).
    Executable,
    /// Position-independent executable (`ET_DYN` with an entry/interpreter).
    PieExecutable,
    /// Shared library (`ET_DYN`).
    SharedLibrary,
    /// Relocatable object (`ET_REL`).
    Relocatable,
    /// Core dump.
    Core,
    /// Anything else.
    Other,
}

/// Instruction-set architecture identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchId {
    /// AMD64.
    X86_64,
    /// IA-32.
    X86,
    /// ARMv8-A 64-bit.
    Aarch64,
    /// ARM / Thumb 32-bit.
    Arm,
    /// RISC-V 64-bit.
    Riscv64,
    /// MIPS 32-bit.
    Mips,
    /// The synthetic ISA of [`crate::testing`] (feature `mock`).
    Mock,
    /// Recognised format, unsupported architecture (raw ELF `e_machine`).
    Unknown(u16),
}

/// Byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endian {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

/// Summary of the binary. `Default` is a placeholder (ELF, little-endian,
/// 64-bit, unknown architecture) for `..Default::default()` literals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// File format.
    pub format: BinaryFormat,
    /// Object kind.
    pub kind: BinaryKind,
    /// Architecture.
    pub arch: ArchId,
    /// Byte order.
    pub endian: Endian,
    /// Pointer size in bits (32 or 64).
    pub bits: u8,
    /// Entry point, already relocated to `base`.
    pub entry: Option<Address>,
    /// Load bias actually applied: the value added to every file virtual
    /// address (`p_vaddr`, `sh_addr`, `st_value`) to get the addresses in
    /// this image. Always 0 for fixed-address executables (`ET_EXEC`):
    /// their addresses are absolute. For position-independent images it
    /// is [`crate::LoadOptions::base`] (default 0, so addresses match
    /// `readelf`/`objdump`). This is *not* the lowest mapped address; use
    /// the first `Load` segment for that.
    pub base: Address,
    /// GNU build-id, if present.
    pub build_id: Option<Vec<u8>>,
    /// Program interpreter (`PT_INTERP`), if present.
    pub interpreter: Option<String>,
    /// `DT_NEEDED` libraries in order.
    pub needed_libraries: Vec<String>,
    /// SHA-256 of the original file bytes.
    pub sha256: [u8; 32],
}

// Construction convention for the plain-data structs in this module
// (`BinaryInfo`, `LoadedImage`, `Segment`, `Section`, `Symbol`, `Import`,
// `Relocation`, `FunctionHint`; also `StringLiteral` in `model`): fields are
// public so loaders can write struct literals, and every struct implements
// `Default` (`Function` has `Function::new` instead). Loaders MUST end literals with `..Default::default()`; new
// fields are then added without breaking them (ADR 0001).

/// Kind of a program header (ELF `p_type`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SegmentKind {
    /// `PT_LOAD`: mapped into memory. The only kind [`LoadedImage::segment_at`] considers.
    #[default]
    Load,
    /// `PT_DYNAMIC`.
    Dynamic,
    /// `PT_INTERP`.
    Interp,
    /// `PT_NOTE`.
    Note,
    /// `PT_PHDR`.
    Phdr,
    /// `PT_TLS`: TLS initialisation image (overlaps a `Load` segment).
    Tls,
    /// `PT_GNU_EH_FRAME`.
    GnuEhFrame,
    /// `PT_GNU_STACK`.
    GnuStack,
    /// `PT_GNU_RELRO`: read-only-after-relocation part of a `Load` segment.
    GnuRelro,
    /// `PT_GNU_PROPERTY`.
    GnuProperty,
    /// Any other `p_type` (raw value).
    Other(u32),
}

/// A program header (ELF `PT_LOAD` and friends).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// Display name (`LOAD[0]`, `GNU_STACK`, ...).
    pub name: String,
    /// Program header type.
    pub kind: SegmentKind,
    /// Virtual range (`p_vaddr .. p_vaddr + p_memsz`, relocated).
    pub range: AddressRange,
    /// File offset of the first byte.
    pub file_offset: u64,
    /// Bytes present in the file (`p_filesz`).
    pub file_size: u64,
    /// Permissions.
    pub perms: Permissions,
}

/// Coarse classification of a section, used by analysis and UI colouring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SectionKind {
    /// Executable code.
    Code,
    /// Initialised writable data.
    Data,
    /// Read-only data.
    ReadOnlyData,
    /// Zero-initialised (`SHT_NOBITS`).
    Bss,
    /// Metadata not mapped at run time (symbols, debug info, notes...).
    Metadata,
    /// Anything else.
    #[default]
    Other,
}

/// A section (ELF section header).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    /// Section name (`.text`).
    pub name: String,
    /// Virtual range; empty for non-allocated sections.
    pub range: AddressRange,
    /// File offset, `None` for `SHT_NOBITS`.
    pub file_offset: Option<u64>,
    /// Size in the file.
    pub file_size: u64,
    /// Classification.
    pub kind: SectionKind,
    /// Thread-local template (`SHF_TLS`: `.tdata`, `.tbss`). A TLS `Bss`
    /// section's range overlaps the sections after it and is skipped by
    /// [`LoadedImage::section_at`].
    pub tls: bool,
    /// Permissions derived from flags.
    pub perms: Permissions,
}

/// What a symbol names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SymbolKind {
    /// Code.
    Function,
    /// GNU indirect function (`STT_GNU_IFUNC`): the address is a resolver
    /// that returns the real implementation.
    Ifunc,
    /// Data object.
    Object,
    /// Thread-local object (address is an offset in the TLS block).
    Tls,
    /// Section symbol.
    Section,
    /// Source file symbol.
    File,
    /// Untyped / other.
    #[default]
    Unknown,
}

/// Symbol visibility to the linker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolBinding {
    /// File-local.
    Local,
    /// Global.
    #[default]
    Global,
    /// Weak.
    Weak,
}

/// Where a symbol came from. Higher in this list wins when names conflict
/// (user renames always win; they live in the journal, not here).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SymbolSource {
    /// Synthesised by analysis (e.g. `sub_401000` is *not* stored; this is
    /// for names derived from signatures, strings, ...).
    #[default]
    Analysis,
    /// PLT stub name derived from a relocation (`printf@plt`).
    Plt,
    /// `.dynsym`.
    Dynamic,
    /// `.symtab`.
    Static,
    /// DWARF debug info.
    Dwarf,
}

/// A named address.
///
/// Contract for loaders: undefined symbols (`SHN_UNDEF`, e.g. `printf` in
/// `.dynsym`) MAY be listed with `undefined = true` (for `nm -u` parity);
/// they never name an address in the program. Imports are described by
/// [`Import`], not by undefined symbols.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// Raw (possibly mangled) name.
    pub name: String,
    /// Demangled name, if the loader or analysis could demangle it.
    pub demangled: Option<String>,
    /// Address, relocated (0 for undefined symbols; TLS offset for `Tls`).
    pub address: Address,
    /// Size in bytes, if known.
    pub size: Option<u64>,
    /// Kind.
    pub kind: SymbolKind,
    /// Binding.
    pub binding: SymbolBinding,
    /// Origin.
    pub source: SymbolSource,
    /// Not defined in this file (`SHN_UNDEF`).
    pub undefined: bool,
}

impl Symbol {
    /// True if the symbol names an address in this image (defined, not a
    /// TLS offset, not a section/file marker).
    #[must_use]
    pub fn names_address(&self) -> bool {
        !self.undefined
            && !self.name.is_empty()
            && !matches!(
                self.kind,
                SymbolKind::File | SymbolKind::Section | SymbolKind::Tls
            )
    }
}

/// An imported function or object resolved through the dynamic linker.
///
/// Contract for loaders: fill `got` for every import that has a GOT slot,
/// including binaries linked with `-fno-plt` / `-z now` where calls go
/// through `call [rip+GOT]` and `plt` is `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    /// Symbol name (`printf`).
    pub name: String,
    /// Symbol version (`GLIBC_2.2.5`), if versioned.
    pub version: Option<String>,
    /// Providing library, if it can be determined.
    pub library: Option<String>,
    /// Function or object.
    pub kind: SymbolKind,
    /// Address of the PLT stub that calls it, if any.
    pub plt: Option<Address>,
    /// Address of the GOT slot the dynamic linker fills.
    pub got: Option<Address>,
}

/// A relocation entry (kept raw; interpretation is arch-specific).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relocation {
    /// Address being patched.
    pub address: Address,
    /// Raw `r_type`.
    pub kind: u32,
    /// Referenced symbol name, if any.
    pub symbol: Option<String>,
    /// Addend.
    pub addend: i64,
}

/// Why the loader believes a function starts here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FunctionHintSource {
    /// ELF entry point.
    Entry,
    /// A function symbol.
    #[default]
    Symbol,
    /// An FDE in `.eh_frame` (works on stripped binaries).
    EhFrame,
    /// DWARF `DW_TAG_subprogram`.
    Dwarf,
    /// `.init_array` / `.preinit_array` entry.
    InitArray,
    /// `.fini_array` entry.
    FiniArray,
    /// PLT stub.
    Plt,
}

/// A seed for function discovery.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionHint {
    /// Start address.
    pub address: Address,
    /// Size, if the source knows it (FDE, symbol, DWARF).
    pub size: Option<u64>,
    /// Source of the hint.
    pub source: FunctionHintSource,
}

impl Default for BinaryInfo {
    fn default() -> Self {
        BinaryInfo {
            format: BinaryFormat::Elf,
            kind: BinaryKind::Other,
            arch: ArchId::Unknown(0),
            endian: Endian::Little,
            bits: 64,
            entry: None,
            base: Address::ZERO,
            build_id: None,
            interpreter: None,
            needed_libraries: Vec::new(),
            sha256: [0; 32],
        }
    }
}

/// The immutable result of loading a binary. Shared by all snapshots.
#[derive(Clone, Debug, Default)]
pub struct LoadedImage {
    /// Summary.
    pub info: BinaryInfo,
    /// Virtual memory.
    pub memory: MemoryMap,
    /// Program headers of all kinds.
    pub segments: Vec<Segment>,
    /// Sections.
    pub sections: Vec<Section>,
    /// Symbols from all sources (static, dynamic, DWARF, PLT).
    pub symbols: Vec<Symbol>,
    /// Imports.
    pub imports: Vec<Import>,
    /// Relocations.
    pub relocations: Vec<Relocation>,
    /// Function-start seeds.
    pub function_hints: Vec<FunctionHint>,
}

impl LoadedImage {
    /// The section containing `addr`, if any. TLS `Bss` sections (`.tbss`)
    /// are skipped: their range is a template, not real memory.
    #[must_use]
    pub fn section_at(&self, addr: Address) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| !(s.tls && s.kind == SectionKind::Bss))
            .find(|s| s.range.contains(addr))
    }

    /// The `Load` segment containing `addr`, if any.
    #[must_use]
    pub fn segment_at(&self, addr: Address) -> Option<&Segment> {
        self.segments
            .iter()
            .filter(|s| s.kind == SegmentKind::Load)
            .find(|s| s.range.contains(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, len: u64) -> AddressRange {
        AddressRange::from_len(Address(start), len).unwrap()
    }

    fn image(segments: Vec<Segment>, sections: Vec<Section>) -> LoadedImage {
        LoadedImage {
            info: BinaryInfo {
                format: BinaryFormat::Elf,
                kind: BinaryKind::Executable,
                arch: ArchId::X86_64,
                endian: Endian::Little,
                bits: 64,
                entry: None,
                base: Address(0),
                build_id: None,
                interpreter: None,
                needed_libraries: Vec::new(),
                sha256: [0; 32],
            },
            memory: MemoryMap::default(),
            segments,
            sections,
            symbols: Vec::new(),
            imports: Vec::new(),
            relocations: Vec::new(),
            function_hints: Vec::new(),
        }
    }

    #[test]
    fn segment_at_only_considers_load() {
        let img = image(
            vec![
                Segment {
                    name: "TLS".into(),
                    kind: SegmentKind::Tls,
                    range: range(0x3000, 0x10),
                    ..Default::default()
                },
                Segment {
                    name: "LOAD[1]".into(),
                    range: range(0x3000, 0x1000),
                    ..Default::default()
                },
            ],
            Vec::new(),
        );
        assert_eq!(
            img.segment_at(Address(0x3008)).map(|s| s.name.as_str()),
            Some("LOAD[1]")
        );
    }

    #[test]
    fn section_at_skips_tbss() {
        let img = image(
            Vec::new(),
            vec![
                Section {
                    name: ".tbss".into(),
                    range: range(0x3df0, 0x10),
                    kind: SectionKind::Bss,
                    tls: true,
                    ..Default::default()
                },
                Section {
                    name: ".init_array".into(),
                    range: range(0x3df0, 0x8),
                    kind: SectionKind::Data,
                    ..Default::default()
                },
            ],
        );
        assert_eq!(
            img.section_at(Address(0x3df0)).map(|s| s.name.as_str()),
            Some(".init_array")
        );
    }

    #[test]
    fn undefined_and_marker_symbols_do_not_name_addresses() {
        let undef = Symbol {
            name: "printf".into(),
            kind: SymbolKind::Function,
            undefined: true,
            ..Default::default()
        };
        assert!(!undef.names_address());
        let ifunc = Symbol {
            name: "memcpy".into(),
            kind: SymbolKind::Ifunc,
            address: Address(0x1000),
            ..Default::default()
        };
        assert!(ifunc.names_address());
    }
}
