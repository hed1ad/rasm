//! A session: one open project. The single entry point the UI, CLI and
//! scripts use to read the model and change it.

use std::sync::{Arc, Mutex, PoisonError};

use crate::address::Address;
use crate::error::Error;
use crate::journal::{JOURNAL_FORMAT_VERSION, Journal, JournalEntry, OpMeta, OpSource, UndoScope};
use crate::ops::{Operation, UserState};
use crate::pass::{AnalysisDriver, Focus};
use crate::snapshot::{Program, Snapshot, SnapshotHub, UndoInfo};
use crate::store::{ProjectStore, StoredSource};

struct Inner {
    journal: Journal,
    store: Box<dyn ProjectStore>,
}

/// One open project.
///
/// Thread-safe: reads go through lock-free snapshots; writes
/// ([`Session::apply`], undo/redo) are serialised by an internal mutex and
/// persisted *before* the new snapshot is published, so what the UI shows
/// is always durable.
pub struct Session {
    hub: Arc<SnapshotHub>,
    inner: Mutex<Inner>,
    driver: Arc<dyn AnalysisDriver>,
    author: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("hub", &self.hub)
            .field("author", &self.author)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Opens (or creates) a project session.
    ///
    /// `source` is the file `program` was loaded from, with the options
    /// used. If the store is empty, the source and the current
    /// [`JOURNAL_FORMAT_VERSION`] are saved (project creation). Otherwise
    /// the stored source must have the same SHA-256 and load base
    /// ([`Error::ProjectMismatch`]) and a format version this build
    /// understands ([`Error::NewerProjectFormat`]). Then the journal is
    /// replayed over `program`, the first snapshot is published and the
    /// analysis driver started.
    pub fn open(
        program: Program,
        source: StoredSource,
        mut store: Box<dyn ProjectStore>,
        driver: Arc<dyn AnalysisDriver>,
        author: impl Into<String>,
    ) -> Result<Self, Error> {
        // Before anything is written to the store.
        let author = author.into();
        OpMeta::now(author.clone(), OpSource::Ui)
            .validate()
            .map_err(|e| Error::InvalidArgument(format!("author: {e}")))?;
        if source.sha256 != program.info().sha256 {
            return Err(Error::InvalidArgument(
                "source SHA-256 does not match the loaded program".into(),
            ));
        }
        if let Some(found) = store.format_version()?
            && found > JOURNAL_FORMAT_VERSION
        {
            return Err(Error::NewerProjectFormat {
                found,
                supported: JOURNAL_FORMAT_VERSION,
            });
        }
        let entries = store.load_journal()?;
        match store.load_source()? {
            Some(stored) => {
                if stored.sha256 != source.sha256 {
                    return Err(Error::ProjectMismatch(format!(
                        "project holds {} ({}), not this file",
                        crate::text::sanitize_for_display(&stored.file_name),
                        crate::report::hex(&stored.sha256)
                    )));
                }
                if stored.options.base != source.options.base {
                    return Err(Error::ProjectMismatch(format!(
                        "project was created with load base {:?}, not {:?}",
                        stored.options.base, source.options.base
                    )));
                }
                if store.format_version()?.is_none() {
                    // Creation was interrupted after the source was saved.
                    // With an empty journal nothing can be misread: finish it.
                    if !entries.is_empty() {
                        return Err(Error::Store("project has no format version".into()));
                    }
                    store.set_format_version(JOURNAL_FORMAT_VERSION)?;
                }
            }
            None => {
                if !entries.is_empty() {
                    return Err(Error::Store("journal without a source file".into()));
                }
                // Version first: a crash after it leaves a project that is
                // still "empty" (no source) and is simply created again.
                store.set_format_version(JOURNAL_FORMAT_VERSION)?;
                store.save_source(&source)?;
            }
        }
        let program = Arc::new(program);
        let journal = Journal::replay(UserState::new(program.image().memory.clone()), entries)?;
        let initial = Snapshot::initial(Arc::clone(&program))
            .with_user(journal.user_state().clone(), undo_info(&journal));
        let hub = SnapshotHub::new(initial);
        driver.start(Arc::clone(&hub));
        Ok(Session {
            hub,
            inner: Mutex::new(Inner { journal, store }),
            driver,
            author,
        })
    }

    /// The current snapshot (lock-free).
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.hub.load()
    }

    /// The hub, for subscribing to updates.
    #[must_use]
    pub fn hub(&self) -> &Arc<SnapshotHub> {
        &self.hub
    }

    /// Applies an operation: validate, journal, persist, publish, then
    /// notify analysis. Returns the journal sequence number.
    pub fn apply(&self, op: Operation, source: OpSource) -> Result<u64, Error> {
        // First: `changes` recurses over batches, whose depth this bounds.
        let op = op.validated()?;
        let changes = op.changes();
        let scope = self.scope_of(&op);
        let meta = OpMeta::now(self.author.clone(), source);
        let seq = {
            let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            let mut next = inner.journal.clone();
            let events = next.apply(op, meta, scope)?;
            inner.store.record(&events)?;
            inner.journal = next;
            self.hub.publish_user(
                inner.journal.user_state().clone(),
                undo_info(&inner.journal),
            );
            inner.journal.next_seq().saturating_sub(1)
        };
        if changes.iter().any(|c| c.kind.affects_analysis()) {
            self.driver.invalidate(&changes);
        }
        Ok(seq)
    }

    /// Undoes the latest change in `scope`. `Ok(false)` if nothing to undo.
    pub fn undo(&self, scope: UndoScope) -> Result<bool, Error> {
        self.step(scope, true)
    }

    /// Redoes the latest undone change in `scope`. `Ok(false)` if nothing to
    /// redo.
    pub fn redo(&self, scope: UndoScope) -> Result<bool, Error> {
        self.step(scope, false)
    }

    fn step(&self, scope: UndoScope, undo: bool) -> Result<bool, Error> {
        let changes = {
            let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            let mut next = inner.journal.clone();
            let event = if undo {
                next.undo(scope)?
            } else {
                next.redo(scope)?
            };
            let Some(event) = event else {
                return Ok(false);
            };
            inner.store.record(std::slice::from_ref(&event))?;
            inner.journal = next;
            self.hub.publish_user(
                inner.journal.user_state().clone(),
                undo_info(&inner.journal),
            );
            match event {
                crate::journal::JournalEvent::StateChanged { inverse, .. } => inverse.changes(),
                crate::journal::JournalEvent::Appended(e) => e.op.changes(),
            }
        };
        if changes.iter().any(|c| c.kind.affects_analysis()) {
            self.driver.invalidate(&changes);
        }
        Ok(true)
    }

    /// True if [`Session::undo`] would do something in `scope` (it may
    /// still fail with [`Error::UndoConflict`] in a function scope).
    #[must_use]
    pub fn can_undo(&self, scope: UndoScope) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .journal
            .can_undo(scope)
    }

    /// True if [`Session::redo`] would do something in `scope`.
    #[must_use]
    pub fn can_redo(&self, scope: UndoScope) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .journal
            .can_redo(scope)
    }

    /// The journal entries (history panel), oldest first, optionally only
    /// those scoped to one function. A copy: cheap enough for a UI panel,
    /// not meant for per-frame calls.
    #[must_use]
    pub fn history(&self, scope: UndoScope) -> Vec<JournalEntry> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .journal
            .entries()
            .filter(|e| match scope {
                UndoScope::Global => true,
                UndoScope::Function(f) => e.scope == Some(f),
            })
            .cloned()
            .collect()
    }

    /// Tells analysis what the user is looking at.
    pub fn set_focus(&self, focus: Focus) {
        self.driver.set_focus(focus);
    }

    /// Stops background analysis.
    pub fn cancel_analysis(&self) {
        self.driver.cancel();
    }

    /// Reads a project setting.
    pub fn setting(&self, key: &str) -> Result<Option<String>, Error> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .store
            .setting(key)
    }

    /// Writes a project setting (not journaled, not undoable).
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .store
            .set_setting(key, value)
    }

    fn scope_of(&self, op: &Operation) -> Option<Address> {
        let addr = op.primary_address()?;
        self.snapshot()
            .analysis()
            .function_containing(addr)
            .map(|f| f.entry)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver.cancel();
    }
}

fn undo_info(j: &Journal) -> UndoInfo {
    UndoInfo {
        can_undo: j.can_undo(UndoScope::Global),
        can_redo: j.can_redo(UndoScope::Global),
        last_seq: j.next_seq().saturating_sub(1),
    }
}
