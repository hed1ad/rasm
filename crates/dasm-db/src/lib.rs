//! # dasm-db
//!
//! Project file (`*.dasm`, SQLite in WAL mode): implements
//! [`dasm_core::ProjectStore`] - original bytes + SHA-256 (or only a link
//! to the file), the operation journal with entry states, project
//! settings. Schema migrations are versioned (ADR 0002).
//!
//! Durability: WAL + `synchronous=NORMAL`. A committed `record` survives
//! a crash of the process (`kill -9`); only a power loss may lose the
//! last few transactions, never corrupt the file.
//!
//! Owner: Backend #3.

mod schema;

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dasm_core::{
    Address, EntryState, Error, JournalEntry, JournalEvent, LoadOptions, OpMeta, Operation,
    ProjectStore, SharedBytes, SourceContent, StoredSource,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use schema::{
    APPLICATION_ID, MAX_FIELD_BYTES, MAX_JOURNAL_BYTES, MAX_JOURNAL_ENTRIES, MAX_VALUE_LEN,
    META_FORMAT_VERSION, MIGRATIONS, PROGRESS_STEP, STEP_BUDGET, current_version,
    reference_objects, schema_objects,
};

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}

fn db_err(e: rusqlite::Error) -> Error {
    Error::Store(format!("sqlite: {e}"))
}

fn json_err(what: &str, e: serde_json::Error) -> Error {
    Error::Store(format!("corrupt {what}: {e}"))
}

/// A project stored in a SQLite file (or in memory).
#[derive(Debug)]
pub struct SqliteStore {
    conn: Connection,
    /// Work budget of the current store call (see [`Budget`]).
    budget: Arc<Budget>,
    /// Most journal entries loaded (a field so tests can lower it).
    max_entries: usize,
    /// Format version set before the source was saved: written together
    /// with the source in one transaction (project creation is atomic).
    pending_format: Option<u32>,
}

/// Caps the SQLite virtual-machine work of one store call: a project file
/// is untrusted, and a crafted schema (a recursive view, a trigger loop)
/// must not be able to spin forever. The progress handler counts steps
/// and interrupts the statement once `limit` is exceeded; every store
/// method starts by resetting `used`.
#[derive(Debug)]
struct Budget {
    used: AtomicU64,
    limit: AtomicU64,
}

impl Budget {
    fn new() -> Arc<Self> {
        Arc::new(Budget {
            used: AtomicU64::new(0),
            limit: AtomicU64::new(STEP_BUDGET),
        })
    }
}

impl SqliteStore {
    /// Starts the work budget of a new store call.
    fn arm(&self) {
        self.budget.used.store(0, Ordering::Relaxed);
    }

    /// Creates a new, empty project at `path`. Fails if a non-empty file
    /// already exists there.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        // `create_new` never touches an existing project; an existing
        // *empty* file (an interrupted creation) is reused.
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Never reuse a symlink or special file, only an empty regular one.
                let meta = std::fs::symlink_metadata(path).map_err(store_err)?;
                if !meta.is_file() || meta.len() != 0 {
                    return Err(Error::Store(format!(
                        "{} already exists; open it instead",
                        path.display()
                    )));
                }
            }
            Err(e) => return Err(Error::Store(format!("{}: {e}", path.display()))),
        }
        let conn = Connection::open_with_flags(path, file_flags()).map_err(db_err)?;
        Self::init(conn)
    }

    /// Opens an existing project. Older schemas are migrated; a project
    /// written by a newer dasm gives [`Error::NewerProjectFormat`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let is_file = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file());
        if !is_file {
            return Err(Error::Store(format!(
                "{}: no such project file",
                path.display()
            )));
        }
        let conn = Connection::open_with_flags(path, file_flags()).map_err(db_err)?;
        Self::init(conn)
    }

    /// A new project kept in memory (no file; used by `dasm analyze`
    /// without `--project`).
    pub fn in_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        Self::init(conn)
    }

    fn init(mut conn: Connection) -> Result<Self, Error> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db_err)?;
        let budget = Budget::new();
        harden(&mut conn, &budget)?;
        // Look before touching anything: a foreign database must be left
        // exactly as it was (no WAL switch, no -wal/-shm files).
        let app_id: i64 = conn
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(db_err)?;
        if app_id != APPLICATION_ID {
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(db_err)?;
            let objects: i64 = conn
                .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
                .map_err(db_err)?;
            // Only a completely fresh database is ours to claim; this also
            // recovers a creation that died before the id was written.
            if app_id != 0 || version != 0 || objects != 0 {
                return Err(Error::Store("not a dasm project file".into()));
            }
            conn.pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(db_err)?;
        }
        // The file is untrusted: before any other statement runs, its
        // schema must be exactly what this build's migrations produce for
        // its version - no views, no triggers, no extra tables or indexes.
        verify_schema(&conn)?;
        // `journal_mode` returns the resulting mode ("memory" for :memory:).
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .map_err(db_err)?;
        if !mode.eq_ignore_ascii_case("wal") && !mode.eq_ignore_ascii_case("memory") {
            return Err(Error::Store(format!("cannot enable WAL (mode is {mode})")));
        }
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(db_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db_err)?;
        let mut store = SqliteStore {
            conn,
            budget,
            max_entries: MAX_JOURNAL_ENTRIES,
            pending_format: None,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<(), Error> {
        let found: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db_err)?;
        let supported = current_version();
        if found > supported {
            return Err(newer_schema(found, supported));
        }
        if found < 0 {
            return Err(Error::Store(format!("invalid schema version {found}")));
        }
        self.arm();
        let tx = self.conn.transaction().map_err(db_err)?;
        let from = usize::try_from(found).unwrap_or(0);
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(from) {
            tx.execute_batch(sql).map_err(db_err)?;
            tx.pragma_update(None, "user_version", i as i64 + 1)
                .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    fn has_source(&self) -> Result<bool, Error> {
        self.conn
            .query_row("SELECT 1 FROM source WHERE id = 1", [], |_| Ok(()))
            .optional()
            .map(|r| r.is_some())
            .map_err(db_err)
    }

    fn stored_format(&self) -> Result<Option<u32>, Error> {
        let v: Option<i64> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_FORMAT_VERSION],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        v.map(|v| u32::try_from(v).map_err(|_| Error::Store(format!("invalid format version {v}"))))
            .transpose()
    }
}

fn newer_schema(found: i64, supported: i64) -> Error {
    Error::NewerProjectSchema {
        found: u32::try_from(found).unwrap_or(u32::MAX),
        supported: u32::try_from(supported).unwrap_or(u32::MAX),
    }
}

/// Open flags for a project file. Only the last path component is checked
/// for symlinks (`symlink_metadata` in `open`/`create`); SQLite itself
/// refuses a symlinked `-wal`/`-shm`. `SQLITE_OPEN_NOFOLLOW` is not used:
/// it rejects a symlink in *any* component and so breaks ordinary paths
/// such as `/home/user/...` where `/home` is a link.
fn file_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

/// Connection settings for an untrusted file.
fn harden(conn: &mut Connection, budget: &Arc<Budget>) -> Result<(), Error> {
    // No unsafe functions from views or triggers.
    conn.pragma_update(None, "trusted_schema", "OFF")
        .map_err(db_err)?;
    // No writes to the schema through SQL.
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(db_err)?;
    // Validate b-tree cells while reading: corrupt pages give errors.
    conn.pragma_update(None, "cell_size_check", "ON")
        .map_err(db_err)?;
    // No memory-mapped I/O: a file truncated under us must not SIGBUS.
    conn.pragma_update(None, "mmap_size", 0).map_err(db_err)?;
    // No string or blob (or row) beyond this size is ever built.
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, MAX_VALUE_LEN)
        .map_err(db_err)?;
    let b = Arc::clone(budget);
    conn.progress_handler(
        PROGRESS_STEP,
        Some(move || b.used.fetch_add(1, Ordering::Relaxed) >= b.limit.load(Ordering::Relaxed)),
    )
    .map_err(db_err)
}

/// Compares `sqlite_master` with the reference for the file's
/// `user_version`.
fn verify_schema(conn: &Connection) -> Result<(), Error> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(db_err)?;
    let supported = current_version();
    if version > supported {
        return Err(newer_schema(version, supported));
    }
    let version = usize::try_from(version)
        .map_err(|_| Error::Store(format!("invalid schema version {version}")))?;
    if schema_objects(conn)? != reference_objects(version)? {
        return Err(Error::Store(
            "project schema is not what dasm created (unexpected tables, views, \
             triggers or modified definitions); refusing to open"
                .into(),
        ));
    }
    Ok(())
}

fn too_big(what: &str, len: i64) -> Error {
    Error::Store(format!("corrupt project: {what} is {len} bytes"))
}

/// Rejects a stored value over `max` bytes (`None` = NULL passes).
fn check_len(what: &str, len: Option<i64>, max: i64) -> Result<(), Error> {
    match len {
        Some(l) if l > max => Err(too_big(what, l)),
        _ => Ok(()),
    }
}

fn state_to_str(state: EntryState) -> Result<&'static str, Error> {
    match state {
        EntryState::Active => Ok("active"),
        EntryState::Undone => Ok("undone"),
        EntryState::Discarded => Ok("discarded"),
    }
}

fn state_from_str(s: &str) -> Result<EntryState, Error> {
    match s {
        "active" => Ok(EntryState::Active),
        "undone" => Ok(EntryState::Undone),
        "discarded" => Ok(EntryState::Discarded),
        other => Err(Error::Store(format!("unknown entry state {other:?}"))),
    }
}

fn seq_to_db(seq: u64) -> Result<i64, Error> {
    i64::try_from(seq).map_err(|_| Error::Store(format!("sequence number {seq} out of range")))
}

fn to_json<T: serde::Serialize>(what: &str, v: &T) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|e| json_err(what, e))
}

fn path_str(path: &Path) -> Result<&str, Error> {
    path.to_str()
        .ok_or_else(|| Error::Store("linked path is not valid UTF-8".into()))
}

type SourceRow = (
    String,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<String>,
    String,
);

impl ProjectStore for SqliteStore {
    fn load_source(&mut self) -> Result<Option<StoredSource>, Error> {
        self.arm();
        // One read transaction: the size check and the read see the same row.
        let tx = self.conn.transaction().map_err(db_err)?;
        // Sizes first: nothing is read into memory before it is bounded.
        let lens: Option<[Option<i64>; 4]> = tx
            .query_row(
                "SELECT length(CAST(file_name AS BLOB)), length(CAST(path AS BLOB)), \
                 length(CAST(load_options AS BLOB)), length(bytes) FROM source WHERE id = 1",
                [],
                |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
            )
            .optional()
            .map_err(db_err)?;
        if let Some([name, path, options, bytes]) = lens {
            check_len("source file name", name, MAX_FIELD_BYTES)?;
            check_len("source path", path, MAX_FIELD_BYTES)?;
            check_len("source load options", options, MAX_FIELD_BYTES)?;
            check_len("source bytes", bytes, i64::from(MAX_VALUE_LEN))?;
        }
        let row: Option<SourceRow> = tx
            .query_row(
                "SELECT file_name, sha256, mode, bytes, path, load_options \
                 FROM source WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(db_err)?;
        let Some((file_name, sha, mode, bytes, path, options)) = row else {
            return Ok(None);
        };
        let sha256: [u8; 32] = sha
            .try_into()
            .map_err(|_| Error::Store("corrupt source: bad SHA-256 length".into()))?;
        // Serde defaults make options from older projects load.
        let options: LoadOptions =
            serde_json::from_str(&options).map_err(|e| json_err("load options", e))?;
        let content = match (mode.as_str(), bytes, path) {
            ("embedded", Some(b), None) => SourceContent::Embedded(SharedBytes::from(b)),
            ("linked", None, Some(p)) => SourceContent::Linked {
                path: PathBuf::from(p),
            },
            _ => return Err(Error::Store(format!("corrupt source row (mode {mode:?})"))),
        };
        Ok(Some(StoredSource {
            file_name,
            sha256,
            content,
            options,
        }))
    }

    fn save_source(&mut self, source: &StoredSource) -> Result<(), Error> {
        self.arm();
        let options = to_json("load options", &source.options)?;
        let (mode, bytes, path): (&str, Option<&[u8]>, Option<&str>) = match &source.content {
            SourceContent::Embedded(b) => ("embedded", Some(b.as_slice()), None),
            SourceContent::Linked { path } => ("linked", None, Some(path_str(path)?)),
        };
        let pending = self.pending_format;
        let tx = self.conn.transaction().map_err(db_err)?;
        let existing: Option<Vec<u8>> = tx
            .query_row("SELECT sha256 FROM source WHERE id = 1", [], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        if let Some(sha) = existing
            && sha != source.sha256
        {
            return Err(Error::Store(
                "project already holds a different binary".into(),
            ));
        }
        tx.execute(
            "INSERT OR REPLACE INTO source \
             (id, file_name, sha256, mode, bytes, path, load_options) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                source.file_name,
                source.sha256.as_slice(),
                mode,
                bytes,
                path,
                options
            ],
        )
        .map_err(db_err)?;
        if let Some(v) = pending {
            tx.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![META_FORMAT_VERSION, i64::from(v)],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        self.pending_format = None;
        Ok(())
    }

    fn load_journal(&mut self) -> Result<Vec<JournalEntry>, Error> {
        self.arm();
        // No `SELECT count(*)`: SQLite runs it as one opcode that neither the
        // progress handler nor an interrupt can stop inside a crafted
        // b-tree. Rows are counted while reading instead, each one costing
        // budgeted steps.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, scope, state, length(CAST(op AS BLOB)), \
                 length(CAST(inverse AS BLOB)), length(CAST(meta AS BLOB)), op, inverse, meta \
                 FROM journal ORDER BY seq",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query([]).map_err(db_err)?;
        let mut out: Vec<JournalEntry> = Vec::new();
        let mut total_bytes: i64 = 0;
        while let Some(r) = rows.next().map_err(db_err)? {
            if out.len() >= self.max_entries {
                return Err(Error::Store(format!(
                    "the journal has more than {} entries, \
                     more than this version of dasm loads",
                    self.max_entries
                )));
            }
            let seq: i64 = r.get(0).map_err(db_err)?;
            let scope: Option<i64> = r.get(1).map_err(db_err)?;
            let state: String = r.get(2).map_err(db_err)?;
            // Bound the JSON before it is copied into Rust and parsed: per
            // field, and for the whole journal (shared or overflow pages in
            // a crafted file can make a small file expand enormously).
            for (col, what) in [(3, "op"), (4, "inverse"), (5, "meta")] {
                let len: Option<i64> = r.get(col).map_err(db_err)?;
                check_len(what, len, MAX_FIELD_BYTES)?;
                total_bytes = total_bytes.saturating_add(len.unwrap_or(0));
            }
            if total_bytes > MAX_JOURNAL_BYTES {
                return Err(Error::Store(format!(
                    "the journal holds more than {MAX_JOURNAL_BYTES} bytes of operations"
                )));
            }
            let op: String = r.get(6).map_err(db_err)?;
            let inverse: String = r.get(7).map_err(db_err)?;
            let meta: String = r.get(8).map_err(db_err)?;
            let seq = u64::try_from(seq).map_err(|_| Error::Store("negative seq".into()))?;
            // ORDER BY seq on the primary key: anything but strictly
            // increasing means a crafted b-tree that repeats rows.
            if out.last().is_some_and(|prev| prev.seq >= seq) {
                return Err(Error::Store(format!("corrupt journal: repeated seq {seq}")));
            }
            out.push(JournalEntry {
                seq,
                op: serde_json::from_str::<Operation>(&op).map_err(|e| json_err("op", e))?,
                inverse: serde_json::from_str::<Operation>(&inverse)
                    .map_err(|e| json_err("inverse", e))?,
                meta: serde_json::from_str::<OpMeta>(&meta).map_err(|e| json_err("meta", e))?,
                // Addresses are stored as the two's-complement i64 of the u64.
                scope: scope.map(|s| Address(u64::from_ne_bytes(s.to_ne_bytes()))),
                state: state_from_str(&state)?,
            });
        }
        Ok(out)
    }

    fn record(&mut self, events: &[JournalEvent]) -> Result<(), Error> {
        self.arm();
        if events.is_empty() {
            return Ok(());
        }
        // Dropping `tx` on an early return rolls everything back.
        let tx = self.conn.transaction().map_err(db_err)?;
        {
            let mut insert = tx
                .prepare_cached(
                    "INSERT INTO journal (seq, op, inverse, meta, scope, state) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(db_err)?;
            let mut update = tx
                .prepare_cached("UPDATE journal SET state = ?2, inverse = ?3 WHERE seq = ?1")
                .map_err(db_err)?;
            for event in events {
                match event {
                    JournalEvent::Appended(e) => {
                        let scope = e.scope.map(|a| i64::from_ne_bytes(a.0.to_ne_bytes()));
                        insert
                            .execute(params![
                                seq_to_db(e.seq)?,
                                to_json("op", &e.op)?,
                                to_json("inverse", &e.inverse)?,
                                to_json("meta", &e.meta)?,
                                scope,
                                state_to_str(e.state)?,
                            ])
                            .map_err(db_err)?;
                    }
                    JournalEvent::StateChanged {
                        seq,
                        state,
                        inverse,
                    } => {
                        let n = update
                            .execute(params![
                                seq_to_db(*seq)?,
                                state_to_str(*state)?,
                                to_json("inverse", inverse)?,
                            ])
                            .map_err(db_err)?;
                        if n != 1 {
                            return Err(Error::Store(format!("unknown seq {seq}")));
                        }
                    }
                }
            }
        }
        tx.commit().map_err(db_err)
    }

    fn format_version(&mut self) -> Result<Option<u32>, Error> {
        self.arm();
        if let Some(v) = self.pending_format {
            return Ok(Some(v));
        }
        self.stored_format()
    }

    /// Before the source is saved the version is held back and written
    /// together with the source in one transaction (`save_source`), so
    /// project creation is atomic. A store dropped in between is still an
    /// empty project.
    fn set_format_version(&mut self, version: u32) -> Result<(), Error> {
        self.arm();
        if !self.has_source()? {
            self.pending_format = Some(version);
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![META_FORMAT_VERSION, i64::from(version)],
            )
            .map_err(db_err)?;
        Ok(())
    }

    fn setting(&mut self, key: &str) -> Result<Option<String>, Error> {
        self.arm();
        self.conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)
    }

    fn set_setting(&mut self, key: &str, value: &str) -> Result<(), Error> {
        self.arm();
        self.conn
            .execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(db_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_foreign_sqlite_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("other.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE t(x);").unwrap();
        drop(c);
        let err = SqliteStore::open(&path).unwrap_err();
        assert!(err.to_string().contains("not a dasm project"), "{err}");
    }

    #[test]
    fn foreign_database_is_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("other.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1);")
            .unwrap();
        drop(c);
        assert!(SqliteStore::open(&path).is_err());
        let c = Connection::open(&path).unwrap();
        let mode: String = c
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
        drop(c);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["other.db"], "stray files: {names:?}");
    }

    #[test]
    fn creation_interrupted_before_the_application_id_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        // A valid but blank database: create_new succeeded, nothing else did.
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE t(x); DROP TABLE t;").unwrap();
        drop(c);
        assert!(std::fs::metadata(&path).unwrap().len() > 0);
        assert!(SqliteStore::open(&path).is_ok());
        assert!(SqliteStore::open(&path).is_ok());
    }

    #[test]
    fn rejects_newer_schema_and_migrates_interrupted_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        let c = Connection::open(&path).unwrap();
        c.pragma_update(None, "user_version", 99).unwrap();
        drop(c);
        assert!(matches!(
            SqliteStore::open(&path),
            Err(Error::NewerProjectSchema { found: 99, .. })
        ));
        // Schema 0 with the application id = creation died before migration.
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "DROP TABLE meta; DROP TABLE source; DROP TABLE journal; DROP TABLE settings; \
             PRAGMA user_version = 0;",
        )
        .unwrap();
        drop(c);
        let mut s = SqliteStore::open(&path).unwrap();
        assert_eq!(s.format_version().unwrap(), None);
    }

    #[test]
    fn create_refuses_existing_project_but_reuses_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        std::fs::write(&path, b"").unwrap();
        drop(SqliteStore::create(&path).unwrap());
        assert!(SqliteStore::create(&path).is_err());
        assert!(SqliteStore::open(dir.path().join("none.dasm")).is_err());
    }

    #[test]
    fn corrupt_rows_are_errors_not_panics() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        let c = Connection::open(&path).unwrap();
        c.execute(
            "INSERT INTO journal VALUES (0, '{', '{}', '{}', NULL, 'active')",
            [],
        )
        .unwrap();
        drop(c);
        let mut s = SqliteStore::open(&path).unwrap();
        assert!(matches!(s.load_journal(), Err(Error::Store(_))));
    }

    #[test]
    fn pragmas_are_applied() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::create(dir.path().join("p.dasm")).unwrap();
        let mode: String = s
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let fk: i64 = s
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
        let sync: i64 = s
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 1);
        let trusted: i64 = s
            .conn
            .query_row("PRAGMA trusted_schema", [], |r| r.get(0))
            .unwrap();
        assert_eq!(trusted, 0);
        let cell_check: i64 = s
            .conn
            .query_row("PRAGMA cell_size_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cell_check, 1);
        let mmap: i64 = s
            .conn
            .query_row("PRAGMA mmap_size", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mmap, 0);
        assert!(
            s.conn
                .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
                .unwrap()
        );
    }

    /// Creates a real project, lets `tamper` change it with a plain
    /// (non-hardened) connection, and returns the path.
    fn tampered(tamper: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        let c = Connection::open(&path).unwrap();
        c.execute_batch(tamper).unwrap();
        drop(c);
        (dir, path)
    }

    fn assert_refused(path: &std::path::Path) {
        let started = std::time::Instant::now();
        let err = SqliteStore::open(path).unwrap_err();
        assert!(err.to_string().contains("project schema"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn source_replaced_by_an_endless_view_is_refused() {
        let (_d, path) = tampered(
            "DROP TABLE source; \
             CREATE VIEW source AS WITH RECURSIVE c(x) AS \
             (SELECT 1 UNION ALL SELECT x + 1 FROM c) \
             SELECT 1 AS id, 'f' AS file_name, zeroblob(32) AS sha256, 'embedded' AS mode, \
             zeroblob(1) AS bytes, NULL AS path, '{}' AS load_options FROM c;",
        );
        assert_refused(&path);
    }

    #[test]
    fn triggers_extra_objects_and_edited_definitions_are_refused() {
        for sql in [
            "CREATE TRIGGER t AFTER INSERT ON journal BEGIN SELECT 1; END;",
            "CREATE TABLE extra(x);",
            "CREATE INDEX i ON journal(state);",
            "CREATE VIEW v AS SELECT * FROM settings;",
            "DROP TABLE settings; CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);",
        ] {
            let (_d, path) = tampered(sql);
            assert_refused(&path);
        }
    }

    #[test]
    fn untampered_project_still_opens_after_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        assert!(SqliteStore::open(&path).is_ok());
    }

    #[test]
    fn runaway_statements_are_interrupted_by_the_budget() {
        let mut s = SqliteStore::in_memory().unwrap();
        s.budget.limit.store(50, Ordering::Relaxed);
        s.arm();
        let r: Result<i64, _> = s.conn.query_row(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) \
             SELECT count(*) FROM c",
            [],
            |r| r.get(0),
        );
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("interrupt"), "{msg}");
        // The next call gets a fresh budget.
        s.budget.limit.store(STEP_BUDGET, Ordering::Relaxed);
        assert_eq!(s.format_version().unwrap(), None);
    }

    #[test]
    fn oversized_journal_and_fields_are_refused_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        let c = Connection::open(&path).unwrap();
        let op = serde_json::to_string(&Operation::Bookmark {
            address: Address(1),
            note: None,
        })
        .unwrap();
        let meta = serde_json::to_string(&OpMeta::now("t", dasm_core::OpSource::Cli)).unwrap();
        c.execute(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 1001) \
             INSERT INTO journal SELECT x, ?1, ?1, ?2, NULL, 'active' FROM c",
            params![op, meta],
        )
        .unwrap();
        drop(c);
        let mut s = SqliteStore::open(&path).unwrap();
        s.max_entries = 1000;
        let err = s.load_journal().unwrap_err().to_string();
        assert!(err.contains("more than 1000 entries"), "{err}");
        s.max_entries = 1001;
        assert_eq!(s.load_journal().unwrap().len(), 1001);
        drop(s);

        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "DELETE FROM journal; \
             INSERT INTO journal VALUES (1, replace(hex(zeroblob(35000000)), '0', 'a'), \
             '{}', '{}', NULL, 'active');",
        )
        .unwrap();
        drop(c);
        let mut s = SqliteStore::open(&path).unwrap();
        let err = s.load_journal().unwrap_err().to_string();
        assert!(err.contains("op is"), "{err}");
    }

    #[test]
    fn oversized_source_fields_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        let c = Connection::open(&path).unwrap();
        c.execute(
            "INSERT INTO source VALUES (1, replace(hex(zeroblob(35000000)), '0', 'a'), \
             zeroblob(32), 'embedded', zeroblob(1), NULL, '{}')",
            [],
        )
        .unwrap();
        drop(c);
        let mut s = SqliteStore::open(&path).unwrap();
        let err = s.load_source().unwrap_err().to_string();
        assert!(err.contains("source file name"), "{err}");
    }

    #[test]
    fn every_store_call_starts_with_a_fresh_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        let op = serde_json::to_string(&Operation::Bookmark {
            address: Address(1),
            note: None,
        })
        .unwrap();
        let meta = serde_json::to_string(&OpMeta::now("t", dasm_core::OpSource::Cli)).unwrap();
        let c = Connection::open(&path).unwrap();
        {
            let mut ins = c
                .prepare("INSERT INTO journal VALUES (?1, ?2, ?2, ?3, NULL, 'active')")
                .unwrap();
            c.execute_batch("BEGIN").unwrap();
            for seq in 1..=20_000i64 {
                ins.execute(params![seq, op, meta]).unwrap();
            }
            c.execute_batch("COMMIT").unwrap();
        }
        drop(c);
        let mut s = SqliteStore::open(&path).unwrap();
        s.budget.limit.store(1_000, Ordering::Relaxed);
        // A budget exhausted by an earlier call must not leak into this one.
        s.budget.used.store(1_000, Ordering::Relaxed);
        assert_eq!(s.load_journal().unwrap().len(), 20_000);
        // And the budget does cut a call short once it is really spent.
        s.budget.limit.store(2, Ordering::Relaxed);
        s.arm();
        assert!(s.load_journal().is_err());
    }

    #[test]
    fn project_paths_through_symlinked_directories_work() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let lnk = dir.path().join("lnk");
        std::os::unix::fs::symlink(&real, &lnk).unwrap();
        let path = lnk.join("p.dasm");
        drop(SqliteStore::create(&path).unwrap());
        assert!(SqliteStore::open(&path).is_ok());
        assert!(real.join("p.dasm").is_file());
    }

    #[test]
    fn symlinked_wal_and_shm_are_not_followed() {
        for suffix in ["-wal", "-shm"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.dasm");
            drop(SqliteStore::create(&path).unwrap());
            let target = dir.path().join("victim");
            let mut side = path.as_os_str().to_owned();
            side.push(suffix);
            std::os::unix::fs::symlink(&target, &side).unwrap();
            let _ = SqliteStore::open(&path);
            assert!(!target.exists(), "{suffix} symlink was followed");
        }
    }

    #[test]
    fn symlinked_project_path_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.dasm");
        drop(SqliteStore::create(&real).unwrap());
        let link = dir.path().join("link.dasm");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(SqliteStore::open(&link).is_err());
        assert!(SqliteStore::create(&link).is_err());
    }
}
