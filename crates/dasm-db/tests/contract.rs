//! Contract tests shared by `InMemoryStore` and `SqliteStore`: both must
//! behave identically through `Session`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::sync::Arc;

use dasm_core::testing::{InMemoryStore, StaticDriver, addrs, synthetic_program, synthetic_source};
use dasm_core::{
    Address, EntryState, Error, JOURNAL_FORMAT_VERSION, LoadOptions, NoAnalysis, OpSource,
    Operation, ProjectStore, Session, SharedBytes, SourceContent, StoredSource, UndoScope, sha256,
};
use dasm_db::SqliteStore;

/// Makes a store and reopens "the same project" later.
trait Backend {
    fn fresh() -> Self;
    fn open(&self) -> Box<dyn ProjectStore>;
}

struct Mem(InMemoryStore);
impl Backend for Mem {
    fn fresh() -> Self {
        Mem(InMemoryStore::new())
    }
    fn open(&self) -> Box<dyn ProjectStore> {
        Box::new(self.0.clone())
    }
}

struct Sql {
    _dir: tempfile::TempDir,
    path: PathBuf,
}
impl Backend for Sql {
    fn fresh() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.dasm");
        Sql { _dir: dir, path }
    }
    fn open(&self) -> Box<dyn ProjectStore> {
        if self.path.exists() {
            Box::new(SqliteStore::open(&self.path).unwrap())
        } else {
            Box::new(SqliteStore::create(&self.path).unwrap())
        }
    }
}

fn session(b: &impl Backend) -> Result<Session, Error> {
    Session::open(
        synthetic_program()?,
        synthetic_source(),
        b.open(),
        Arc::new(NoAnalysis),
        "tester",
    )
}

fn rename(a: Address, n: &str) -> Operation {
    Operation::Rename {
        address: a,
        name: Some(n.into()),
    }
}

fn name_at(s: &Session, a: Address) -> Option<String> {
    s.snapshot().user().name(a).map(str::to_owned)
}

fn replay_and_undo_redo_survive_reopen<B: Backend>() {
    let b = B::fresh();
    {
        let s = session(&b).unwrap();
        s.apply(rename(addrs::MAIN, "first"), OpSource::Cli)
            .unwrap();
        s.apply(rename(addrs::MAIN, "second"), OpSource::Cli)
            .unwrap();
        s.apply(rename(addrs::START, "boot"), OpSource::Cli)
            .unwrap();
        assert!(s.undo(UndoScope::Global).unwrap());
    }
    let s = session(&b).unwrap();
    assert_eq!(name_at(&s, addrs::MAIN).as_deref(), Some("second"));
    assert_eq!(name_at(&s, addrs::START), None);
    assert!(s.can_redo(UndoScope::Global));
    assert!(s.redo(UndoScope::Global).unwrap());
    assert!(s.undo(UndoScope::Global).unwrap());
    assert!(s.undo(UndoScope::Global).unwrap());
    drop(s);
    let s = session(&b).unwrap();
    assert_eq!(name_at(&s, addrs::MAIN).as_deref(), Some("first"));
    assert!(s.redo(UndoScope::Global).unwrap());
    let hist = s.history(UndoScope::Global);
    assert_eq!(hist.len(), 3);
    assert!(hist.iter().all(|e| e.meta.author == "tester"));
    assert!(hist.iter().any(|e| e.state == EntryState::Active));
}

fn discarded_entries_survive_reopen<B: Backend>() {
    let b = B::fresh();
    {
        let s = session(&b).unwrap();
        s.apply(rename(addrs::MAIN, "a"), OpSource::Cli).unwrap();
        s.undo(UndoScope::Global).unwrap();
        s.apply(rename(addrs::MAIN, "b"), OpSource::Cli).unwrap();
    }
    let s = session(&b).unwrap();
    let states: Vec<_> = s
        .history(UndoScope::Global)
        .iter()
        .map(|e| e.state)
        .collect();
    assert_eq!(states, [EntryState::Discarded, EntryState::Active]);
    assert_eq!(name_at(&s, addrs::MAIN).as_deref(), Some("b"));
}

fn save_source_rejects_other_sha<B: Backend>() {
    let b = B::fresh();
    let mut st = b.open();
    st.set_format_version(JOURNAL_FORMAT_VERSION).unwrap();
    let src = synthetic_source();
    st.save_source(&src).unwrap();
    st.save_source(&src).unwrap(); // same binary again is fine
    let other = StoredSource::embedded(
        "other",
        SharedBytes::from(vec![1, 2, 3]),
        LoadOptions::default(),
    );
    assert!(st.save_source(&other).is_err());
    drop(st);
    let loaded = b.open().load_source().unwrap().unwrap();
    assert_eq!(loaded.sha256, src.sha256);
    // A different binary opened over the project is a mismatch.
    let mut st = b.open();
    assert!(st.save_source(&other).is_err());
}

fn both_source_modes_survive_reopen<B: Backend>() {
    let embedded = synthetic_source();
    let limits = dasm_core::Limits {
        max_symbols: 77,
        ..dasm_core::Limits::default()
    };
    let options = LoadOptions {
        base: Some(Address(0x1000)),
        limits,
    };
    let linked = StoredSource::linked(
        "linked.bin",
        "/some/where/linked.bin",
        sha256(b"abc"),
        options,
    );
    for src in [embedded, linked] {
        let b = B::fresh();
        let mut st = b.open();
        st.set_format_version(JOURNAL_FORMAT_VERSION).unwrap();
        st.save_source(&src).unwrap();
        drop(st);
        let got = b.open().load_source().unwrap().unwrap();
        // Limits are runtime-only and are not stored in the project.
        assert_eq!(got.options.limits, dasm_core::Limits::default());
        let want = StoredSource {
            options: LoadOptions {
                limits: dasm_core::Limits::default(),
                ..src.options.clone()
            },
            ..src.clone()
        };
        assert_eq!(got, want);
        match (&got.content, &src.content) {
            (SourceContent::Embedded(a), SourceContent::Embedded(b)) => {
                assert_eq!(a.as_slice(), b.as_slice());
            }
            (SourceContent::Linked { path: a }, SourceContent::Linked { path: b }) => {
                assert_eq!(a, b);
            }
            _ => panic!("mode changed"),
        }
    }
}

fn format_version_and_settings_persist<B: Backend>() {
    let b = B::fresh();
    let mut st = b.open();
    assert_eq!(st.format_version().unwrap(), None);
    assert!(st.load_source().unwrap().is_none());
    assert!(st.load_journal().unwrap().is_empty());
    st.set_format_version(JOURNAL_FORMAT_VERSION).unwrap();
    st.save_source(&synthetic_source()).unwrap();
    st.set_setting("layout", "a").unwrap();
    st.set_setting("layout", "b").unwrap();
    drop(st);
    let mut st = b.open();
    assert_eq!(st.format_version().unwrap(), Some(JOURNAL_FORMAT_VERSION));
    assert_eq!(st.setting("layout").unwrap().as_deref(), Some("b"));
    assert_eq!(st.setting("missing").unwrap(), None);
}

fn newer_format_is_rejected<B: Backend>() {
    let b = B::fresh();
    let mut st = b.open();
    st.set_format_version(JOURNAL_FORMAT_VERSION + 1).unwrap();
    st.save_source(&synthetic_source()).unwrap();
    drop(st);
    assert!(matches!(session(&b), Err(Error::NewerProjectFormat { .. })));
}

fn linked_project_reopens_and_detects_change<B: Backend>() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("bin");
    let bytes = dasm_core::testing::synthetic_file();
    std::fs::write(&file, &bytes).unwrap();
    let src = StoredSource::linked(
        "bin",
        &file,
        sha256(&bytes),
        LoadOptions {
            base: Some(Address(0x400000)),
            ..LoadOptions::default()
        },
    );
    let b = B::fresh();
    let open = |b: &B| {
        Session::open(
            synthetic_program().unwrap(),
            src.clone(),
            b.open(),
            Arc::new(StaticDriver::default()),
            "t",
        )
    };
    open(&b)
        .unwrap()
        .apply(rename(addrs::MAIN, "x"), OpSource::Cli)
        .unwrap();
    let s = open(&b).unwrap();
    assert_eq!(name_at(&s, addrs::MAIN).as_deref(), Some("x"));
    let stored = b.open().load_source().unwrap().unwrap();
    assert!(stored.read_bytes().is_ok());
    std::fs::write(&file, b"changed").unwrap();
    assert!(matches!(
        stored.read_bytes(),
        Err(Error::ProjectMismatch(_))
    ));
}

macro_rules! contract {
    ($($name:ident),* $(,)?) => {
        mod memory { use super::*; $( #[test] fn $name() { super::$name::<Mem>(); } )* }
        mod sqlite { use super::*; $( #[test] fn $name() { super::$name::<Sql>(); } )* }
    };
}

contract!(
    replay_and_undo_redo_survive_reopen,
    discarded_entries_survive_reopen,
    save_source_rejects_other_sha,
    both_source_modes_survive_reopen,
    format_version_and_settings_persist,
    newer_format_is_rejected,
    linked_project_reopens_and_detects_change,
);
