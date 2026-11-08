//! The `dasm analyze --json` report: the machine-readable contract between
//! the CLI and QA (documented in `docs/api/analyze-json.md`, ADR 0004).
//!
//! The types are both `Serialize` and `Deserialize`, so tests parse the
//! CLI output with the very same structs. Changes follow the versioning
//! rules in the ADR: adding a field is a minor change; removing or
//! renaming one bumps [`SCHEMA_VERSION`].

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::image::{
    ArchId, BinaryFormat, BinaryKind, Endian, SectionKind, SegmentKind, SymbolBinding, SymbolKind,
    SymbolSource,
};
use crate::insn::{Target, Token};
use crate::memory::Permissions;
use crate::model::{
    AnalysisState, EdgeKind, FunctionFlags, FunctionSource, StringEncoding, XrefKind,
};
use crate::snapshot::Snapshot;

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// What to include in the report.
#[derive(Clone, Debug, Default)]
pub struct ReportOptions {
    /// Path of the input as given on the command line.
    pub path: String,
    /// Include every instruction of every function (`--insns`).
    pub include_instructions: bool,
    /// Wall time of the analysis in milliseconds.
    pub analysis_ms: u64,
}

/// Top-level report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzeReport {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Producer.
    pub tool: ToolInfo,
    /// Binary summary.
    pub binary: BinaryReport,
    /// Segments in address order.
    pub segments: Vec<SegmentReport>,
    /// Sections in header order.
    pub sections: Vec<SectionReport>,
    /// Symbols, sorted by (address, name).
    pub symbols: Vec<SymbolReport>,
    /// Imports in loader order.
    pub imports: Vec<ImportReport>,
    /// Functions in address order.
    pub functions: Vec<FunctionReport>,
    /// Xrefs sorted by (from, to, kind).
    pub xrefs: Vec<XrefReport>,
    /// Strings in address order.
    pub strings: Vec<StringReport>,
    /// Totals.
    pub stats: StatsReport,
}

/// Producer info.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Always `"dasm"`.
    pub name: String,
    /// Crate version.
    pub version: String,
}

/// Binary summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryReport {
    /// Path as given.
    pub path: String,
    /// Lower-case hex SHA-256.
    pub sha256: String,
    /// Format.
    pub format: BinaryFormat,
    /// Kind.
    pub kind: BinaryKind,
    /// Architecture.
    pub arch: ArchId,
    /// Byte order.
    pub endian: Endian,
    /// 32 or 64.
    pub bits: u8,
    /// Entry point.
    pub entry: Option<Address>,
    /// Load base.
    pub base: Address,
    /// Lower-case hex build-id.
    pub build_id: Option<String>,
    /// `PT_INTERP`.
    pub interpreter: Option<String>,
    /// `DT_NEEDED`.
    pub needed: Vec<String>,
}

/// A segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentReport {
    /// Name.
    pub name: String,
    /// Program header type.
    pub kind: SegmentKind,
    /// Start (inclusive).
    pub start: Address,
    /// End (exclusive).
    pub end: Address,
    /// File offset.
    pub file_offset: u64,
    /// File size.
    pub file_size: u64,
    /// `"r-x"` style.
    pub perms: String,
}

/// A section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionReport {
    /// Name.
    pub name: String,
    /// Start (inclusive).
    pub start: Address,
    /// End (exclusive).
    pub end: Address,
    /// File offset (`null` for NOBITS).
    pub file_offset: Option<u64>,
    /// File size.
    pub file_size: u64,
    /// Kind.
    pub kind: SectionKind,
    /// `SHF_TLS`.
    pub tls: bool,
    /// `"r-x"` style.
    pub perms: String,
}

/// A symbol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolReport {
    /// Raw name.
    pub name: String,
    /// Demangled name.
    pub demangled: Option<String>,
    /// Address.
    pub address: Address,
    /// Size.
    pub size: Option<u64>,
    /// Kind.
    pub kind: SymbolKind,
    /// Binding.
    pub binding: SymbolBinding,
    /// Source.
    pub source: SymbolSource,
    /// `SHN_UNDEF`.
    pub undefined: bool,
}

/// An import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    /// Name.
    pub name: String,
    /// Version.
    pub version: Option<String>,
    /// Library.
    pub library: Option<String>,
    /// Kind.
    pub kind: SymbolKind,
    /// PLT stub.
    pub plt: Option<Address>,
    /// GOT slot.
    pub got: Option<Address>,
}

/// A function.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionReport {
    /// Entry.
    pub entry: Address,
    /// Display name (user > symbol > `sub_<hex>`).
    pub name: String,
    /// Sum of block sizes.
    pub size: u64,
    /// Instruction count.
    pub insn_count: usize,
    /// Why it exists.
    pub source: FunctionSource,
    /// Attributes.
    pub flags: FunctionFlags,
    /// Blocks in address order.
    pub blocks: Vec<BlockReport>,
    /// Instructions, only with `--insns`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<Vec<InsnReport>>,
}

/// A basic block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockReport {
    /// Start (inclusive).
    pub start: Address,
    /// End (exclusive).
    pub end: Address,
    /// Instruction count.
    pub insn_count: usize,
    /// Outgoing edges.
    pub successors: Vec<EdgeReport>,
}

/// A CFG edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeReport {
    /// Kind.
    pub kind: EdgeKind,
    /// Destination (`null` if indirect).
    pub target: Option<Address>,
}

/// An instruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsnReport {
    /// Address.
    pub address: Address,
    /// Lower-case hex bytes without separators (`"4889e5"`).
    pub bytes: String,
    /// Length in bytes.
    pub len: u8,
    /// Mnemonic.
    pub mnemonic: String,
    /// Operands as plain text.
    pub operands: String,
    /// Operand tokens (for clients that want links).
    pub tokens: Vec<Token>,
}

/// A cross-reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefReport {
    /// Source.
    pub from: Address,
    /// Destination.
    pub to: Address,
    /// Kind.
    pub kind: XrefKind,
}

/// A string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringReport {
    /// Address.
    pub address: Address,
    /// Encoding.
    pub encoding: StringEncoding,
    /// Size in bytes.
    pub byte_len: u64,
    /// Text.
    pub value: String,
}

/// Totals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsReport {
    /// Functions.
    pub function_count: usize,
    /// Instructions in functions.
    pub insn_count: usize,
    /// Xrefs.
    pub xref_count: usize,
    /// Strings.
    pub string_count: usize,
    /// Analysis wall time.
    pub analysis_ms: u64,
    /// Final analysis state (`done` unless interrupted).
    pub analysis_state: AnalysisState,
}

/// `"r-x"` notation.
#[must_use]
pub fn perms_string(p: Permissions) -> String {
    let mut s = String::with_capacity(3);
    s.push(if p.read { 'r' } else { '-' });
    s.push(if p.write { 'w' } else { '-' });
    s.push(if p.execute { 'x' } else { '-' });
    s
}

/// Lower-case hex without separators.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl AnalyzeReport {
    /// Builds the report from a snapshot (normally after analysis finished).
    #[must_use]
    pub fn from_snapshot(snap: &Snapshot, opts: &ReportOptions) -> Self {
        let image = snap.image();
        let info = &image.info;
        let analysis = snap.analysis();

        let mut symbols: Vec<SymbolReport> = image
            .symbols
            .iter()
            .map(|s| SymbolReport {
                name: s.name.clone(),
                demangled: s.demangled.clone(),
                address: s.address,
                size: s.size,
                kind: s.kind,
                binding: s.binding,
                source: s.source,
                undefined: s.undefined,
            })
            .collect();
        symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));

        let mut insn_total = 0usize;
        let functions = analysis
            .functions()
            .map(|f| {
                insn_total = insn_total.saturating_add(f.insn_count());
                let instructions = opts.include_instructions.then(|| {
                    f.blocks
                        .iter()
                        .flat_map(|b| b.insn_addresses().zip(b.insn_lens().iter().copied()))
                        .map(|(addr, len)| insn_report(snap, addr, len))
                        .collect()
                });
                FunctionReport {
                    entry: f.entry,
                    name: snap.function_name(f),
                    size: f.size(),
                    insn_count: f.insn_count(),
                    source: f.source,
                    flags: f.flags,
                    blocks: f
                        .blocks
                        .iter()
                        .map(|b| BlockReport {
                            start: b.range().start(),
                            end: b.range().end(),
                            insn_count: b.insn_count(),
                            successors: b
                                .successors
                                .iter()
                                .map(|e| EdgeReport {
                                    kind: e.kind,
                                    target: match e.target {
                                        Target::Direct(a) => Some(a),
                                        Target::Indirect => None,
                                    },
                                })
                                .collect(),
                        })
                        .collect(),
                    instructions,
                }
            })
            .collect::<Vec<_>>();

        let mut xrefs: Vec<XrefReport> = analysis
            .all_xrefs()
            .map(|x| XrefReport {
                from: x.from,
                to: x.to,
                kind: x.kind,
            })
            .collect();
        xrefs.sort_by_key(|x| (x.from, x.to, x.kind));
        xrefs.dedup();

        let strings: Vec<StringReport> = analysis
            .strings()
            .map(|s| StringReport {
                address: s.address,
                encoding: s.encoding,
                byte_len: s.byte_len,
                value: s.value.clone(),
            })
            .collect();

        AnalyzeReport {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo {
                name: "dasm".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            binary: BinaryReport {
                path: opts.path.clone(),
                sha256: hex(&info.sha256),
                format: info.format,
                kind: info.kind,
                arch: info.arch,
                endian: info.endian,
                bits: info.bits,
                entry: info.entry,
                base: info.base,
                build_id: info.build_id.as_deref().map(hex),
                interpreter: info.interpreter.clone(),
                needed: info.needed_libraries.clone(),
            },
            // The loader keeps program-header order; the JSON schema
            // requires segments sorted by address.
            segments: {
                let mut v: Vec<SegmentReport> = image
                    .segments
                    .iter()
                    .map(|s| SegmentReport {
                        name: s.name.clone(),
                        kind: s.kind,
                        start: s.range.start(),
                        end: s.range.end(),
                        file_offset: s.file_offset,
                        file_size: s.file_size,
                        perms: perms_string(s.perms),
                    })
                    .collect();
                v.sort_by_key(|s| (s.start, s.end));
                v
            },
            sections: image
                .sections
                .iter()
                .map(|s| SectionReport {
                    name: s.name.clone(),
                    start: s.range.start(),
                    end: s.range.end(),
                    file_offset: s.file_offset,
                    file_size: s.file_size,
                    kind: s.kind,
                    tls: s.tls,
                    perms: perms_string(s.perms),
                })
                .collect(),
            symbols,
            imports: image
                .imports
                .iter()
                .map(|i| ImportReport {
                    name: i.name.clone(),
                    version: i.version.clone(),
                    library: i.library.clone(),
                    kind: i.kind,
                    plt: i.plt,
                    got: i.got,
                })
                .collect(),
            stats: StatsReport {
                function_count: functions.len(),
                insn_count: insn_total,
                xref_count: xrefs.len(),
                string_count: strings.len(),
                analysis_ms: opts.analysis_ms,
                analysis_state: analysis.progress.state,
            },
            functions,
            xrefs,
            strings,
        }
    }
}

fn insn_report(snap: &Snapshot, addr: Address, len: u8) -> InsnReport {
    let bytes = snap
        .memory()
        .read(addr, usize::from(len))
        .map(|b| hex(&b))
        .unwrap_or_default();
    match snap.render_insn(addr) {
        Ok(r) => InsnReport {
            address: addr,
            bytes,
            len,
            operands: r.operands_text(),
            mnemonic: r.mnemonic,
            tokens: r.operands,
        },
        Err(_) => InsnReport {
            address: addr,
            bytes,
            len,
            mnemonic: "(bad)".into(),
            operands: String::new(),
            tokens: Vec::new(),
        },
    }
}
