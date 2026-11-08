//! `dasm analyze`: open or create the project, wait for the analysis,
//! build the report.

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use dasm_core::report::{AnalyzeReport, ReportOptions};
use dasm_core::{
    Address, AnalysisState, Error, LoadOptions, Program, ProjectStore, Session, SharedBytes,
    SnapshotHub, SnapshotListener, SourceContent, StoredSource, sha256,
};
use dasm_db::SqliteStore;

use crate::args::AnalyzeArgs;
use crate::services::Services;

/// A project store plus whether this call created the file.
struct Opened {
    store: Option<Box<dyn ProjectStore>>,
    created_file: Option<std::path::PathBuf>,
    existing: bool,
}

fn open_store(project: Option<&Path>) -> Result<Opened> {
    match project {
        None => Ok(Opened {
            store: Some(Box::new(SqliteStore::in_memory()?)),
            created_file: None,
            existing: false,
        }),
        Some(p) => {
            // `symlink_metadata`: a symlink is never "an existing empty file".
            let non_empty = std::fs::symlink_metadata(p).is_ok_and(|m| m.len() > 0);
            if non_empty {
                let store = SqliteStore::open(p)
                    .with_context(|| format!("cannot open project {}", p.display()))?;
                Ok(Opened {
                    store: Some(Box::new(store)),
                    created_file: None,
                    existing: true,
                })
            } else {
                // Only a file this call brings into existence may be
                // removed again on failure.
                let created_new = std::fs::symlink_metadata(p).is_err();
                let store = match SqliteStore::create(p) {
                    Ok(store) => store,
                    Err(e) => {
                        if created_new {
                            remove_project_files(p);
                        }
                        return Err(anyhow::Error::from(e)
                            .context(format!("cannot create project {}", p.display())));
                    }
                };
                Ok(Opened {
                    store: Some(Box::new(store)),
                    created_file: created_new.then(|| p.to_path_buf()),
                    existing: false,
                })
            }
        }
    }
}

/// `O_NONBLOCK` on Linux (0o4000 on every architecture except MIPS/Alpha/
/// SPARC/PA-RISC, none of which dasm targets).
#[cfg(target_os = "linux")]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o4000)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn read_input(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let ctx = || format!("cannot read {}", path.display());
    // Checked before opening: opening a FIFO would block.
    let before = std::fs::metadata(path).with_context(ctx)?;
    if !before.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    // O_NONBLOCK: if the path was swapped for a FIFO after the check above,
    // opening must not block waiting for a writer.
    let file = open_nonblocking(path).with_context(ctx)?;
    // And again on the open handle: the path may have been swapped.
    let meta = file.metadata().with_context(ctx)?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > limit {
        bail!(
            "{} is {} bytes, over the {limit}-byte limit",
            path.display(),
            meta.len()
        );
    }
    // Never read more than the limit, whatever the file grows to.
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(ctx)?;
    if bytes.len() as u64 > limit {
        bail!("{} is over the {limit}-byte limit", path.display());
    }
    Ok(bytes)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| "input".to_owned(), |n| n.to_string_lossy().into_owned())
}

/// The source for a brand-new project (or in-memory run).
fn new_source(args: &AnalyzeArgs, options: LoadOptions) -> Result<(StoredSource, SharedBytes)> {
    let bytes = read_input(&args.bin, options.limits.max_file_size)?;
    let name = file_name(&args.bin);
    if args.link {
        let abs = std::fs::canonicalize(&args.bin)
            .with_context(|| format!("cannot resolve {}", args.bin.display()))?;
        let sha = sha256(&bytes);
        Ok((
            StoredSource::linked(name, abs, sha, options),
            SharedBytes::from(bytes),
        ))
    } else {
        let bytes = SharedBytes::from(bytes);
        Ok((StoredSource::embedded(name, bytes.clone(), options), bytes))
    }
}

/// The source of an existing project, checked against the `bin` argument
/// and `--base`.
fn existing_source(
    args: &AnalyzeArgs,
    stored: StoredSource,
) -> Result<(StoredSource, SharedBytes)> {
    let bytes = read_input(&args.bin, dasm_core::Limits::default().max_file_size)?;
    if sha256(&bytes) != stored.sha256 {
        return Err(Error::ProjectMismatch(format!(
            "the project holds {}, which is not {}",
            stored.file_name,
            args.bin.display()
        ))
        .into());
    }
    if let Some(base) = args.base
        && stored.options.base != Some(Address(base))
    {
        return Err(Error::ProjectMismatch(format!(
            "the project was created with load base {:?}, not {base:#x}",
            stored.options.base
        ))
        .into());
    }
    // The bytes the SHA-256 was checked on are the bytes that get analysed.
    // The path stored in the project is untrusted and never opened here.
    Ok((stored, SharedBytes::from(bytes)))
}

/// Wakes the waiting thread on every published snapshot.
struct Wake {
    pair: Arc<(Mutex<()>, Condvar)>,
}

impl SnapshotListener for Wake {
    fn snapshot_published(&self, _generation: u64) {
        let (lock, cv) = &*self.pair;
        let _g = lock.lock().unwrap_or_else(PoisonError::into_inner);
        cv.notify_all();
    }
}

/// Blocks (no polling) until the analysis is in a terminal state.
fn wait_for_analysis(hub: &Arc<SnapshotHub>) -> AnalysisState {
    let pair = Arc::new((Mutex::new(()), Condvar::new()));
    let id = hub.subscribe(Arc::new(Wake {
        pair: Arc::clone(&pair),
    }));
    let (lock, cv) = &*pair;
    let mut guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
    let state = loop {
        // Checked under the lock the listener takes to notify: no lost
        // wake-up between the check and the wait.
        let state = hub.load().analysis().progress.state;
        if state.is_terminal() {
            break state;
        }
        guard = cv.wait(guard).unwrap_or_else(PoisonError::into_inner);
    };
    drop(guard);
    hub.unsubscribe(id);
    state
}

/// The report plus non-fatal remarks for stderr.
pub(crate) struct Analysis {
    pub(crate) report: AnalyzeReport,
    pub(crate) warnings: Vec<String>,
}

/// Runs the whole analysis and returns the report.
pub(crate) fn analyze(args: &AnalyzeArgs, services: &Services, author: String) -> Result<Analysis> {
    let mut opened = open_store(args.project.as_deref())?;
    let result = open_session(args, services, author, &mut opened).and_then(|o| finish(args, o));
    if result.is_err()
        && let Some(path) = &opened.created_file
    {
        // Do not leave an empty shell behind after a failed first run.
        remove_project_files(path);
    }
    result
}

fn remove_project_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for ext in ["-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(ext);
        let _ = std::fs::remove_file(name);
    }
}

fn open_session(
    args: &AnalyzeArgs,
    services: &Services,
    author: String,
    opened: &mut Opened,
) -> Result<OpenSession> {
    let mut store = opened
        .store
        .take()
        .ok_or_else(|| anyhow::anyhow!("project store already in use"))?;
    let stored = if opened.existing {
        store.load_source()?
    } else {
        None
    };
    let mut warnings = Vec::new();
    let (source, bytes) = match stored {
        Some(stored) => {
            if args.link && matches!(stored.content, SourceContent::Embedded(_)) {
                warnings.push(
                    "--link ignored: the project already keeps a copy of the binary".to_owned(),
                );
            }
            existing_source(args, stored)?
        }
        None => {
            let options = LoadOptions {
                base: args.base.map(Address),
                ..LoadOptions::default()
            };
            new_source(args, options)?
        }
    };

    let (image, arch) = services.registry.load(bytes, &source.options)?;
    let program = Program::new(image, arch);

    let started = Instant::now();
    let session = Session::open(program, source, store, (services.driver)(), author)?;
    Ok(OpenSession {
        session,
        warnings,
        started,
    })
}

/// A session whose analysis has been started.
struct OpenSession {
    session: Session,
    warnings: Vec<String>,
    started: Instant,
}

fn finish(args: &AnalyzeArgs, o: OpenSession) -> Result<Analysis> {
    let OpenSession {
        session,
        warnings,
        started,
    } = o;
    let state = wait_for_analysis(session.hub());
    let analysis_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match state {
        AnalysisState::Done => {}
        AnalysisState::Cancelled => bail!("analysis was cancelled before it finished"),
        AnalysisState::Failed => {
            let snapshot = session.snapshot();
            let why = snapshot
                .analysis()
                .progress
                .error
                .as_deref()
                .unwrap_or("no details");
            bail!("analysis failed: {why}");
        }
        other => bail!("analysis stopped in unexpected state {other:?}"),
    }
    let opts = ReportOptions {
        path: args.bin.display().to_string(),
        include_instructions: args.insns,
        analysis_ms,
    };
    Ok(Analysis {
        report: AnalyzeReport::from_snapshot(&session.snapshot(), &opts),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dasm_core::testing::{MockArch, StaticDriver, addrs, synthetic_file, synthetic_image};
    use dasm_core::{LoadError, Loader, OpSource, Operation, Registry};

    struct MockLoader;
    impl Loader for MockLoader {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn probe(&self, _: &[u8]) -> bool {
            true
        }
        fn load(
            &self,
            _: SharedBytes,
            _: &LoadOptions,
        ) -> Result<dasm_core::LoadedImage, LoadError> {
            synthetic_image().map_err(|e| LoadError::Unsupported(e.to_string()))
        }
    }

    #[test]
    fn profile_author_reaches_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::write(&bin, synthetic_file()).unwrap();
        let proj = dir.path().join("p.dasm");
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "[user]\nname = \"Grace\"\n").unwrap();
        let env = crate::Env {
            config_path: Some(cfg),
        };
        let author = dasm_core::resolve_author(env.user_name().as_deref());
        let services = Services {
            registry: Registry::new()
                .with_loader(Arc::new(MockLoader))
                .with_arch(Arc::new(MockArch)),
            driver: Box::new(|| Arc::new(StaticDriver::default())),
        };
        let args = AnalyzeArgs {
            bin,
            json: true,
            insns: false,
            project: Some(proj.clone()),
            link: false,
            base: None,
        };
        let mut opened = open_store(args.project.as_deref()).unwrap();
        let o = open_session(&args, &services, author, &mut opened).unwrap();
        o.session
            .apply(
                Operation::Rename {
                    address: addrs::MAIN,
                    name: Some("m".into()),
                },
                OpSource::Cli,
            )
            .unwrap();
        drop(o);
        let entries = SqliteStore::open(&proj).unwrap().load_journal().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].meta.author, "Grace");
    }
}
