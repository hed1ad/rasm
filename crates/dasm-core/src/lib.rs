//! # dasm-core
//!
//! The public data model and extension traits of the dasm disassembler.
//! Every other crate depends on this one; it depends on no other dasm
//! crate (ADR 0001).
//!
//! ## Map
//!
//! | Concept | Types |
//! |---|---|
//! | Addresses | [`Address`], [`AddressRange`] |
//! | Loaded binary (immutable) | [`LoadedImage`], [`BinaryInfo`], [`Segment`], [`Section`], [`Symbol`], [`Import`], [`MemoryMap`] |
//! | Instructions | [`DecodedInsn`] (analysis), [`RenderedInsn`] + [`Token`] (display) |
//! | Analysis cache | [`AnalysisResults`], [`Function`], [`BasicBlock`], [`Xref`], [`StringLiteral`] |
//! | User layer | [`Operation`], [`UserState`], [`Journal`] |
//! | Read side | [`Snapshot`], [`SnapshotHub`], [`SnapshotListener`] |
//! | Write side | [`Session`] |
//! | Extension points | [`Loader`], [`Arch`], [`AnalysisPass`], [`AnalysisDriver`], [`ProjectStore`] |
//! | CLI JSON contract | [`report::AnalyzeReport`] |
//!
//! ## Rules
//!
//! - Parsing untrusted input never panics; errors are [`Error`] values.
//! - The UI reads only [`Snapshot`]s and never waits for analysis.
//! - The model changes only through [`Operation`]s applied by a [`Session`].
//!
//! With the `mock` feature, the [`testing`] module provides a synthetic
//! program and a working session for UI and test development.

pub mod address;
pub mod arch;
pub mod error;
pub mod image;
pub mod insn;
pub mod journal;
pub mod loader;
pub mod memory;
pub mod model;
pub mod ops;
pub mod pass;
pub mod report;
pub mod session;
pub mod snapshot;
pub mod store;
pub mod text;

#[cfg(any(test, feature = "mock"))]
pub mod testing;

pub use address::{Address, AddressRange};
pub use arch::Arch;
pub use error::{DecodeError, Error, LoadError, Result};
pub use image::{
    ArchId, BinaryFormat, BinaryInfo, BinaryKind, Endian, FunctionHint, FunctionHintSource, Import,
    LoadedImage, Relocation, Section, SectionKind, Segment, SegmentKind, Symbol, SymbolBinding,
    SymbolKind, SymbolSource,
};
pub use insn::{
    DecodedInsn, Flow, InsnRef, NoSymbols, RenderedInsn, SymbolLookup, Target, Token, TokenKind,
};
pub use journal::{
    EntryState, JOURNAL_FORMAT_VERSION, Journal, JournalEntry, JournalEvent, MAX_JOURNAL_ENTRIES,
    MAX_SEQ, OpMeta, OpSource, UndoScope, resolve_author,
};
pub use loader::{Limits, LoadOptions, Loader, Registry, sha256};
pub use memory::{MemoryMap, MemoryRegion, Permissions, SharedBytes};
pub use model::{
    AnalysisDelta, AnalysisProgress, AnalysisResults, AnalysisState, BasicBlock, DataType, Edge,
    EdgeKind, Function, FunctionFlags, FunctionSource, StringEncoding, StringLiteral, TypeExpr,
    Xref, XrefKind, XrefOwner,
};
pub use ops::{Change, ChangeKind, Definition, FunctionOverride, Operation, UserState};
pub use ops::{
    MAX_BATCH_DEPTH, MAX_BATCH_OPS, MAX_OPERATION_JSON_BYTES, MAX_PATCHED_BYTES,
    MAX_REPLAY_PATCHED_BYTES,
};
pub use pass::{
    AnalysisDriver, AnalysisPass, CancelToken, Focus, Granularity, NoAnalysis, PassContext, PassId,
    PassScope,
};
pub use session::Session;
pub use snapshot::{
    ItemKind, ListingItem, Program, Snapshot, SnapshotHub, SnapshotListener, SubscriptionId,
    UndoInfo,
};
pub use store::{ProjectStore, SourceContent, StoredSource};
pub use text::sanitize_for_display;

/// Version of the public API (`major.minor`), checked by plugins.
pub const API_VERSION: (u16, u16) = (0, 1);
