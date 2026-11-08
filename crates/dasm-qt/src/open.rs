//! The single place where a [`Session`] is assembled for the UI.

use std::sync::Arc;

use dasm_core::Session;

/// What to open.
#[derive(Debug, Clone)]
pub(crate) enum Source {
    /// The synthetic program of `dasm_core::testing` (`--mock`).
    Mock,
    /// The synthetic program after a delay (tests of overlapping opens).
    MockDelayed(u64),
    /// A file on disk.
    Path(String),
}

/// Builds a session; runs on a background thread.
///
/// The returned message is shown in the status bar, never in a dialog.
pub(crate) fn build_session(source: &Source) -> Result<Arc<Session>, String> {
    match source {
        Source::Mock => dasm_core::testing::mock_session()
            .map(Arc::new)
            .map_err(|e| e.to_string()),
        Source::MockDelayed(ms) => {
            std::thread::sleep(std::time::Duration::from_millis(*ms));
            build_session(&Source::Mock)
        }
        Source::Path(path) => open_path(path)
            .map(Arc::new)
            .map_err(|e| format!("cannot open {path}: {e}")),
    }
}

/// Opens `path` with the real backends. The project lives in the user's data
/// directory, keyed by the file's SHA-256, so edits survive a restart.
fn open_path(path: &str) -> Result<Session, dasm_core::Error> {
    use dasm_core::{Error, LoadOptions, Program, Registry, SharedBytes, StoredSource, sha256};
    let bytes =
        SharedBytes::from(std::fs::read(path).map_err(|e| Error::InvalidArgument(e.to_string()))?);
    let options = LoadOptions::default();
    let registry = Registry::new()
        .with_loader(Arc::new(dasm_elf::ElfLoader))
        .with_arch(Arc::new(dasm_x86::X86_64));
    let (image, arch) = registry.load(bytes.clone(), &options)?;
    let program = Program::new(image, arch);
    let name = std::path::Path::new(path)
        .file_name()
        .map_or_else(|| path.to_owned(), |n| n.to_string_lossy().into_owned());
    let project = project_path(&sha256(bytes.as_slice()))?;
    let store = if project.exists() {
        dasm_db::SqliteStore::open(&project)?
    } else {
        dasm_db::SqliteStore::create(&project)?
    };
    let source = StoredSource::embedded(name, bytes, options);
    let driver = dasm_analysis::Scheduler::new(dasm_analysis::Config::default())?;
    Session::open(
        program,
        source,
        Box::new(store),
        Arc::new(driver),
        dasm_core::resolve_author(None),
    )
}

/// `$XDG_DATA_HOME/dasm/projects/<sha256>.dasm`, falling back to
/// `~/.local/share`; creates the directory.
fn project_path(sha: &[u8; 32]) -> Result<std::path::PathBuf, dasm_core::Error> {
    use std::fmt::Write as _;
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".local/share")))
        .ok_or_else(|| dasm_core::Error::InvalidArgument("HOME is not set".into()))?;
    let dir = base.join("dasm/projects");
    std::fs::create_dir_all(&dir).map_err(|e| dasm_core::Error::InvalidArgument(e.to_string()))?;
    let mut file = String::new();
    for b in sha {
        let _ = write!(file, "{b:02x}");
    }
    Ok(dir.join(format!("{file}.dasm")))
}
