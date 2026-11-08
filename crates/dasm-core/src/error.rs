//! Error types shared by all dasm crates.
//!
//! Parsing untrusted input must never panic: every failure is one of these
//! values. Backends wrap their library errors (gimli, rusqlite, ...)
//! into the matching variant with a human-readable message; the library error
//! types never leak into the public API of `dasm-core`.

use crate::address::Address;

/// Result alias used across the workspace.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Top-level error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The binary could not be loaded.
    #[error("load error: {0}")]
    Load(#[from] LoadError),
    /// An instruction could not be decoded.
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),
    /// The project store failed (I/O, SQLite, corrupt project).
    #[error("project store error: {0}")]
    Store(String),
    /// An operation is not valid in the current state (e.g. renaming to an
    /// empty name, patching unmapped bytes).
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
    /// Undo in a scope would discard a later change to the same item.
    #[error("cannot undo: entry #{seq} is overridden by later entry #{blocked_by}")]
    UndoConflict {
        /// Journal entry that the caller tried to undo.
        seq: u64,
        /// Later active entry touching the same item.
        blocked_by: u64,
    },
    /// The project was written by a newer dasm (journal format version
    /// `found` > `supported`). Not corruption: the user must upgrade.
    #[error("project format {found} is newer than supported {supported}; upgrade dasm")]
    NewerProjectFormat {
        /// Version stored in the project.
        found: u32,
        /// [`crate::JOURNAL_FORMAT_VERSION`] of this build.
        supported: u32,
    },
    /// The project file's storage schema (e.g. SQLite `PRAGMA user_version`
    /// of `dasm-db`) is newer than this build supports. Distinct from
    /// [`Error::NewerProjectFormat`] (the journal JSON format).
    #[error("project storage schema {found} is newer than supported {supported}; upgrade dasm")]
    NewerProjectSchema {
        /// Schema version found in the file.
        found: u32,
        /// Highest schema version this build understands.
        supported: u32,
    },
    /// The project belongs to another binary or other load options (base).
    #[error("project mismatch: {0}")]
    ProjectMismatch(String),
    /// The requested work was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// A caller passed a malformed argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The feature exists in the API but is not implemented yet.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Errors produced by a [`crate::Loader`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// No registered loader recognises the file.
    #[error("unrecognised file format")]
    UnknownFormat,
    /// A structure extends past the end of the file.
    #[error("truncated {what} at file offset {offset:#x}")]
    Truncated {
        /// What was being read.
        what: String,
        /// File offset where data ran out.
        offset: u64,
    },
    /// A structure is internally inconsistent.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// What was being parsed.
        what: String,
        /// Why it is invalid.
        reason: String,
    },
    /// A resource limit (count of symbols, section size, ...) was exceeded.
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    /// Valid file, but a feature dasm does not support (e.g. big-endian MIPS
    /// at stage 1).
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Errors produced by an [`crate::Arch`] decoder.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The bytes do not form a valid instruction.
    #[error("invalid instruction at {0}")]
    Invalid(Address),
    /// The instruction would extend past the available bytes.
    #[error("truncated instruction at {0}")]
    Truncated(Address),
    /// The address is not backed by bytes in the image.
    #[error("unmapped address {0}")]
    Unmapped(Address),
}
