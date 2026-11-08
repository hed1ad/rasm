//! Crash safety (`kill -9` in the middle of writing) and write speed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dasm_core::testing::{addrs, synthetic_program, synthetic_source};
use dasm_core::{
    Address, EntryState, Journal, NoAnalysis, OpMeta, OpSource, Operation, ProjectStore, Session,
    UndoScope, UserState,
};
use dasm_db::SqliteStore;

const CHILD_ENV: &str = "DASM_DB_CRASH_CHILD";

fn open_session(path: &std::path::Path, create: bool) -> Session {
    let store = if create {
        SqliteStore::create(path).unwrap()
    } else {
        SqliteStore::open(path).unwrap()
    };
    Session::open(
        synthetic_program().unwrap(),
        synthetic_source(),
        Box::new(store),
        Arc::new(NoAnalysis),
        "child",
    )
    .unwrap()
}

/// Parses a child line: `ACK <i> <seq>` or `UNDO <seq>`.
fn record(line: &str, acked: &mut u64, confirmed: &mut Vec<(u64, u64)>, undone: &mut Vec<u64>) {
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("ACK"), Some(i), Some(seq)) => {
            if let (Ok(i), Ok(seq)) = (i.parse(), seq.parse()) {
                *acked += 1;
                confirmed.push((i, seq));
            }
        }
        (Some("UNDO"), Some(seq), None) => {
            if let Ok(seq) = seq.parse() {
                undone.push(seq);
            }
        }
        _ => {}
    }
}

/// Not a real test: the child process body, run only when spawned by
/// `kill_9_in_the_middle_of_writing_keeps_the_project_intact`.
#[test]
fn crash_child() {
    let Ok(path) = std::env::var(CHILD_ENV) else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let s = open_session(&path, !path.exists());
    for i in 0..u64::MAX {
        let op = Operation::Rename {
            address: Address(addrs::MAIN.0 + (i % 64)),
            name: Some(format!("name_{i}")),
        };
        let seq = s.apply(op, OpSource::Cli).unwrap();
        // Acknowledged only after `apply` returned: must be durable.
        println!("ACK {i} {seq}");
        if i % 7 == 3 {
            s.undo(UndoScope::Global).unwrap();
            println!("UNDO {seq}");
        }
    }
}

#[test]
fn kill_9_in_the_middle_of_writing_keeps_the_project_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.dasm");
    let exe = std::env::current_exe().unwrap();
    let mut acked_total = 0u64;
    for round in 0..5u64 {
        let mut child = Command::new(&exe)
            .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap());
        let mut acked = 0u64;
        let mut confirmed: Vec<(u64, u64)> = Vec::new();
        let mut undone: Vec<u64> = Vec::new();
        let mut line = String::new();
        let started = Instant::now();
        // Let the child write a varying amount, then SIGKILL it.
        while acked < 150 + round * 111 {
            line.clear();
            assert!(
                lines.read_line(&mut line).unwrap() > 0,
                "child exited early"
            );
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "child too slow"
            );
            record(&line, &mut acked, &mut confirmed, &mut undone);
        }
        child.kill().unwrap(); // SIGKILL on Unix
        // Everything the child already printed is still in the pipe.
        let mut rest = String::new();
        loop {
            line.clear();
            if lines.read_line(&mut line).unwrap() == 0 {
                break;
            }
            record(&line, &mut acked, &mut confirmed, &mut undone);
            rest.push_str(&line);
        }
        child.wait().unwrap();
        acked_total += acked;

        // The project opens, passes SQLite's own check, and replays.
        let mut store = SqliteStore::open(&path).unwrap();
        let entries = store.load_journal().unwrap();
        assert!(
            entries.len() as u64 >= acked_total,
            "lost acknowledged entries: {} < {acked_total}",
            entries.len()
        );
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq, i as u64 + 1, "journal has a gap");
        }
        drop(store);
        let conn = rusqlite_check(&path);
        assert_eq!(conn, "ok");
        // Content, not just counts: every acknowledged entry is the exact
        // operation the child applied, and confirmed undos are not active.
        for &(i, seq) in &confirmed {
            let e = entries.iter().find(|e| e.seq == seq).unwrap();
            let want = Operation::Rename {
                address: Address(addrs::MAIN.0 + (i % 64)),
                name: Some(format!("name_{i}")),
            };
            assert_eq!(e.op, want, "entry {seq} differs");
            assert_eq!(e.meta.author, "child");
        }
        for &seq in &undone {
            let e = entries.iter().find(|e| e.seq == seq).unwrap();
            assert_ne!(e.state, EntryState::Active, "undo of {seq} was lost");
        }
        let s = open_session(&path, false);
        assert!(s.history(UndoScope::Global).len() as u64 >= acked_total);
    }
}

/// SQLite's own consistency check on the file.
fn rusqlite_check(path: &std::path::Path) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap()
}

/// 10 000 operations through `ProjectStore::record`, one transaction each
/// (what `Session::apply` does). The journal is built outside the timed
/// section: `Session::apply` clones the in-memory journal on every call
/// (O(n) per operation, a `dasm-core` cost reported to the Architect), which
/// is not what this crate is measured on.
#[test]
fn ten_thousand_operations_are_recorded_in_under_a_second() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.dasm");
    let mut store = SqliteStore::create(&path).unwrap();
    store
        .set_format_version(dasm_core::JOURNAL_FORMAT_VERSION)
        .unwrap();
    store.save_source(&synthetic_source()).unwrap();

    let program = synthetic_program().unwrap();
    let mut journal = Journal::new(UserState::new(program.image().memory.clone()));
    let mut batches = Vec::new();
    for i in 0..10_000u64 {
        let op = Operation::Rename {
            address: Address(addrs::MAIN.0 + (i % 256)),
            name: Some(format!("name_{i}")),
        };
        let meta = OpMeta::now("bench", OpSource::Cli);
        batches.push(journal.apply(op, meta, None).unwrap());
    }

    let t = Instant::now();
    for events in &batches {
        store.record(events).unwrap();
    }
    let took = t.elapsed();
    eprintln!("10000 record() calls: {took:?}");
    // The 1 s target is for optimised builds (measured: ~0.1-0.25 s even in
    // debug on an idle machine); an unoptimised build on a loaded CI box
    // only has to stay within the same order of magnitude.
    let limit = if cfg!(debug_assertions) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(1)
    };
    assert!(took < limit, "too slow: {took:?} (limit {limit:?})");
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    assert_eq!(store.load_journal().unwrap().len(), 10_000);
}
