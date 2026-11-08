//! SQLite schema and migrations.
//!
//! `PRAGMA user_version` is the version of the *SQLite schema* (this file).
//! It is unrelated to the journal format version
//! (`dasm_core::JOURNAL_FORMAT_VERSION`), which is stored in `meta`.
//! Migrations only append: entry `i` upgrades schema `i` to `i + 1`.

/// `PRAGMA application_id` of a dasm project ("dasm" in ASCII).
pub(crate) const APPLICATION_ID: i64 = 0x6461_736d;

/// Key of the journal format version in the `meta` table.
pub(crate) const META_FORMAT_VERSION: &str = "format_version";

/// Migrations; `MIGRATIONS.len()` is the current schema version.
///
/// FROZEN: an opened project's `sqlite_master` is compared byte for byte
/// with what these statements produce, so the text of a published
/// migration (whitespace included) must never change - add a new entry
/// instead. `frozen_v1_text` pins the hash of version 1.
pub(crate) const MIGRATIONS: &[&str] = &[
    // 0 -> 1
    "
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY NOT NULL,
        value
    ) WITHOUT ROWID;
    CREATE TABLE source (
        id           INTEGER PRIMARY KEY CHECK (id = 1),
        file_name    TEXT NOT NULL,
        sha256       BLOB NOT NULL CHECK (length(sha256) = 32),
        mode         TEXT NOT NULL CHECK (mode IN ('embedded', 'linked')),
        bytes        BLOB,
        path         TEXT,
        load_options TEXT NOT NULL,
        CHECK ((mode = 'embedded' AND bytes IS NOT NULL AND path IS NULL)
            OR (mode = 'linked' AND bytes IS NULL AND path IS NOT NULL))
    );
    CREATE TABLE journal (
        seq     INTEGER PRIMARY KEY NOT NULL,
        op      TEXT NOT NULL,
        inverse TEXT NOT NULL,
        meta    TEXT NOT NULL,
        scope   INTEGER,
        state   TEXT NOT NULL CHECK (state IN ('active', 'undone', 'discarded'))
    );
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) WITHOUT ROWID;
    ",
];

/// Current schema version.
pub(crate) fn current_version() -> i64 {
    MIGRATIONS.len() as i64
}

/// Largest journal accepted from a project file.
pub(crate) const MAX_JOURNAL_ENTRIES: usize = dasm_core::MAX_JOURNAL_ENTRIES;

/// Largest single JSON/text field read from a project file (64 MiB).
pub(crate) const MAX_FIELD_BYTES: i64 = 64 << 20;

/// Largest operation text (op + inverse + meta) loaded from a journal in
/// total, 256 MiB.
pub(crate) const MAX_JOURNAL_BYTES: i64 = 256 << 20;

/// `SQLITE_LIMIT_LENGTH`: no string, blob or row beyond 10^9 bytes (also
/// SQLite's own compile-time ceiling).
pub(crate) const MAX_VALUE_LEN: i32 = 1_000_000_000;

/// The progress handler runs every this many virtual-machine steps.
pub(crate) const PROGRESS_STEP: std::os::raw::c_int = 10_000;

/// Handler calls allowed per store call (about 2e8 steps: a few seconds even unoptimised;
/// a million-entry journal needs far less).
pub(crate) const STEP_BUDGET: u64 = 20_000;

/// One `sqlite_master` row: (type, name, table name, SQL).
pub(crate) type SchemaObject = (String, String, String, Option<String>);

/// Everything in `sqlite_master`, in a fixed order.
pub(crate) fn schema_objects(
    conn: &rusqlite::Connection,
) -> Result<Vec<SchemaObject>, dasm_core::Error> {
    let db = |e: rusqlite::Error| dasm_core::Error::Store(format!("sqlite: {e}"));
    let mut stmt = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        .map_err(db)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(db)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(db)
}

/// The schema objects a database at `version` must have: built by running
/// this build's own migrations into a scratch in-memory database.
pub(crate) fn reference_objects(version: usize) -> Result<Vec<SchemaObject>, dasm_core::Error> {
    let db = |e: rusqlite::Error| dasm_core::Error::Store(format!("sqlite: {e}"));
    let scratch = rusqlite::Connection::open_in_memory().map_err(db)?;
    for sql in MIGRATIONS.iter().take(version) {
        scratch.execute_batch(sql).map_err(db)?;
    }
    schema_objects(&scratch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_v1_text() {
        let hex: String = dasm_core::sha256(MIGRATIONS[0].as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex, "f9c09b9eaed11b49d7077f8a6655c21054f7381aaef20b9abaaa59fa031843d7",
            "migration 1 changed: every existing project would stop opening"
        );
    }
}
