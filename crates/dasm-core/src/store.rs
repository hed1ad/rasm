//! The project store extension point (persistence of the journal).

use std::path::{Path, PathBuf};

use crate::error::{Error, LoadError};
use crate::journal::{JournalEntry, JournalEvent};
use crate::loader::{Limits, LoadOptions, sha256};
use crate::memory::SharedBytes;
use crate::text::sanitize_for_display;

/// How a project keeps its input file (customer decision, ADR 0002).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceContent {
    /// A copy inside the project (default): the project is self-contained.
    Embedded(SharedBytes),
    /// Only a reference: the file stays on disk at `path` and is verified
    /// against [`StoredSource::sha256`] every time it is read.
    Linked {
        /// Absolute path recorded when the project was created.
        path: PathBuf,
    },
}

/// The original input file as kept in a project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSource {
    /// Original file name (no directories).
    pub file_name: String,
    /// SHA-256 of the file contents.
    pub sha256: [u8; 32],
    /// Copy or link.
    pub content: SourceContent,
    /// Options it was loaded with (the base address matters: journal
    /// addresses are relative to it).
    pub options: LoadOptions,
}

impl StoredSource {
    /// A source kept as a copy in the project (SHA-256 computed here).
    #[must_use]
    pub fn embedded(
        file_name: impl Into<String>,
        bytes: SharedBytes,
        options: LoadOptions,
    ) -> Self {
        StoredSource {
            file_name: file_name.into(),
            sha256: sha256(bytes.as_slice()),
            content: SourceContent::Embedded(bytes),
            options,
        }
    }

    /// A source kept only as a path + SHA-256.
    #[must_use]
    pub fn linked(
        file_name: impl Into<String>,
        path: impl Into<PathBuf>,
        sha256: [u8; 32],
        options: LoadOptions,
    ) -> Self {
        StoredSource {
            file_name: file_name.into(),
            sha256,
            content: SourceContent::Linked { path: path.into() },
            options,
        }
    }

    /// The file contents: the embedded copy, or the linked file read from
    /// disk and checked against `sha256` ([`Error::ProjectMismatch`] if it
    /// changed or is not a regular file).
    ///
    /// The linked path comes from an untrusted project file, so it is
    /// opened non-blocking (a FIFO cannot hang the open), checked to be a
    /// regular file on the *opened descriptor* (no TOCTOU), and read
    /// through `take(limit + 1)` with `limit` = the build's default
    /// `max_file_size` (never a limit from the project, ADR 0002).
    pub fn read_bytes(&self) -> Result<SharedBytes, Error> {
        match &self.content {
            SourceContent::Embedded(b) => Ok(b.clone()),
            SourceContent::Linked { path } => {
                read_linked(path, &self.sha256, Limits::default().max_file_size)
            }
        }
    }
}

fn read_linked(path: &Path, expected: &[u8; 32], limit: u64) -> Result<SharedBytes, Error> {
    use std::io::Read;
    let lossy = path.to_string_lossy();
    let shown = sanitize_for_display(&lossy);
    let io_err = |e: std::io::Error| Error::ProjectMismatch(format!("linked file {shown}: {e}"));
    // Cheap early rejection; the fstat after open below is the real check
    // (the path can change in between).
    if !std::fs::metadata(path).map_err(io_err)?.is_file() {
        return Err(Error::ProjectMismatch(format!(
            "linked file {shown} is not a regular file"
        )));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Never block on a FIFO swapped in after the check above, and never
        // acquire a controlling terminal.
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = opts.open(path).map_err(io_err)?;
    let meta = file.metadata().map_err(io_err)?;
    if !meta.is_file() {
        return Err(Error::ProjectMismatch(format!(
            "linked file {shown} is not a regular file"
        )));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_err)?;
    if bytes.len() as u64 > limit {
        return Err(LoadError::LimitExceeded(format!(
            "linked file {shown} is larger than {limit} bytes"
        ))
        .into());
    }
    if sha256(&bytes) != *expected {
        return Err(Error::ProjectMismatch(format!(
            "linked file {shown} changed since the project was created"
        )));
    }
    Ok(SharedBytes::from(bytes))
}

/// Durable storage of a project: source bytes + journal + settings.
///
/// Stage 1 implementation: `dasm-db` (SQLite, WAL). [`crate::testing`]
/// provides an in-memory one.
///
/// Contract:
/// - Project creation is two calls (`set_format_version`, then
///   `save_source`); a store need not make them one transaction:
///   [`crate::Session::open`] recovers from a crash between them (and
///   from the reverse order) as long as the journal is empty. A store
///   that can do both in one transaction (SQLite) should.
/// - Both [`SourceContent`] modes must round-trip through
///   `save_source`/`load_source` (copy: bytes; link: path, no bytes).
/// - [`ProjectStore::record`] is atomic: all events or none.
/// - After `record` returns `Ok`, the events survive a crash.
/// - `load_journal` returns every entry ever appended, with its latest
///   state and inverse, in any order.
pub trait ProjectStore: Send {
    /// The stored source file, if the project has one yet.
    fn load_source(&mut self) -> Result<Option<StoredSource>, Error>;

    /// Stores the source file. Fails if a *different* source (other
    /// SHA-256) is already stored.
    fn save_source(&mut self, source: &StoredSource) -> Result<(), Error>;

    /// All journal entries. The file is untrusted: check the entry count
    /// against [`crate::MAX_JOURNAL_ENTRIES`] and bound the size of each
    /// record *before* materialising them, allowing at least
    /// [`crate::MAX_OPERATION_JSON_BYTES`] per stored operation or inverse.
    fn load_journal(&mut self) -> Result<Vec<JournalEntry>, Error>;

    /// Persists journal events atomically.
    fn record(&mut self, events: &[JournalEvent]) -> Result<(), Error>;

    /// The journal format version the project was created with, `None`
    /// for a new, empty project.
    fn format_version(&mut self) -> Result<Option<u32>, Error>;

    /// Records the journal format version (once, at creation).
    fn set_format_version(&mut self, version: u32) -> Result<(), Error>;

    /// Reads a project setting (UI layout, last position, ...).
    fn setting(&mut self, key: &str) -> Result<Option<String>, Error>;

    /// Writes a project setting.
    fn set_setting(&mut self, key: &str, value: &str) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_source_is_verified_on_read() {
        let dir = std::env::temp_dir().join(format!("dasm-core-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("linked.bin");
        std::fs::write(&path, b"hello").unwrap();
        let src = StoredSource::linked(
            "linked.bin",
            &path,
            sha256(b"hello"),
            LoadOptions::default(),
        );
        assert_eq!(src.read_bytes().unwrap().as_slice(), b"hello");
        std::fs::write(&path, b"HELLO").unwrap();
        assert!(matches!(src.read_bytes(), Err(Error::ProjectMismatch(_))));
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(src.read_bytes(), Err(Error::ProjectMismatch(_))));

        // Larger than the limit: refused without reading it all.
        std::fs::write(&path, vec![1u8; 64]).unwrap();
        let err = read_linked(&path, &sha256(&[1u8; 64]), 16).unwrap_err();
        assert!(
            matches!(err, Error::Load(LoadError::LimitExceeded(_))),
            "{err}"
        );
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_dir(&dir);

        let emb = StoredSource::embedded(
            "e",
            SharedBytes::from(b"abc".to_vec()),
            LoadOptions::default(),
        );
        assert_eq!(emb.sha256, sha256(b"abc"));
        assert_eq!(emb.read_bytes().unwrap().as_slice(), b"abc");
    }

    #[cfg(unix)]
    #[test]
    fn linked_special_files_are_refused_quickly() {
        // /dev/zero is endless; a FIFO without a writer would block a
        // plain open. Both must fail fast as "not a regular file".
        let zero = StoredSource::linked("zero", "/dev/zero", [0; 32], LoadOptions::default());
        assert!(matches!(zero.read_bytes(), Err(Error::ProjectMismatch(_))));

        let dir = std::env::temp_dir().join(format!("dasm-core-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if made.is_ok_and(|s| s.success()) {
            let src = StoredSource::linked("pipe", &fifo, [0; 32], LoadOptions::default());
            let t = std::time::Instant::now();
            assert!(matches!(src.read_bytes(), Err(Error::ProjectMismatch(_))));
            assert!(t.elapsed() < std::time::Duration::from_secs(1));
            std::fs::remove_file(&fifo).unwrap();
        }
        let _ = std::fs::remove_dir(&dir);
    }
}
