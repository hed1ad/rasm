//! A project file whose b-tree is crafted: the schema is exactly what dasm
//! writes, but the `journal` table's root is an interior page whose
//! children all point at the next level (a DAG). Visiting it is
//! astronomically long (and `count(*)` would run it inside one opcode that
//! no progress handler can interrupt).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use dasm_core::{Address, OpMeta, OpSource, Operation, ProjectStore};
use dasm_db::SqliteStore;
use rusqlite::Connection;

const PAGE: usize = 4096;
const FANOUT: usize = 300;
const LEVELS: usize = 4;

/// A table-interior page whose `FANOUT` cells and right pointer all lead to `child`.
fn interior_page(child: u32) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    let cell_len = 4 + 2; // child pointer + 2-byte varint key
    let content_start = PAGE - FANOUT * cell_len;
    page[0] = 0x05;
    page[3..5].copy_from_slice(&(FANOUT as u16).to_be_bytes());
    page[5..7].copy_from_slice(&(content_start as u16).to_be_bytes());
    page[8..12].copy_from_slice(&child.to_be_bytes());
    for i in 0..FANOUT {
        let at = content_start + i * cell_len;
        page[12 + 2 * i..14 + 2 * i].copy_from_slice(&(at as u16).to_be_bytes());
        page[at..at + 4].copy_from_slice(&child.to_be_bytes());
        // Strictly increasing 2-byte varint keys: 0x81 0x00 + i  (128 + i).
        page[at + 4] = 0x81;
        page[at + 5] = i as u8;
    }
    page
}

#[test]
fn crafted_interior_page_dag_does_not_hang_load_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dag.dasm");
    drop(SqliteStore::create(&path).unwrap());

    // One real row so every visit of the (shared) leaf yields a row.
    let op = serde_json::to_string(&Operation::Bookmark {
        address: Address(1),
        note: None,
    })
    .unwrap();
    let meta = serde_json::to_string(&OpMeta::now("t", OpSource::Cli)).unwrap();
    let c = Connection::open(&path).unwrap();
    c.execute(
        "INSERT INTO journal VALUES (1, ?1, ?1, ?2, NULL, 'active')",
        rusqlite::params![op, meta],
    )
    .unwrap();
    let leaf: u32 = c
        .query_row(
            "SELECT rootpage FROM sqlite_master WHERE name = 'journal'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let pages: u32 = c.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
    let page_size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
    assert_eq!(page_size, PAGE as i64);
    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    drop(c);

    // Append LEVELS interior pages: root -> ... -> level LEVELS -> leaf.
    let mut bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), pages as usize * PAGE);
    let first_new = pages + 1;
    for level in 0..LEVELS as u32 {
        let child = if level + 1 == LEVELS as u32 {
            leaf
        } else {
            first_new + level + 1
        };
        bytes.extend_from_slice(&interior_page(child));
    }
    // Header: database size in pages (+ the version-valid-for field that
    // makes SQLite trust it).
    let total = pages + LEVELS as u32;
    bytes[28..32].copy_from_slice(&total.to_be_bytes());
    let counter: [u8; 4] = bytes[24..28].try_into().unwrap();
    bytes[92..96].copy_from_slice(&counter);
    std::fs::write(&path, &bytes).unwrap();

    let c = Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA writable_schema = ON").unwrap();
    c.execute(
        "UPDATE sqlite_master SET rootpage = ?1 WHERE name = 'journal'",
        [first_new],
    )
    .unwrap();
    drop(c);

    let started = Instant::now();
    let mut store = SqliteStore::open(&path).unwrap();
    // The schema check passes; reading must fail fast, not walk the DAG.
    let result = store.load_journal();
    let err = result
        .expect_err("crafted journal was accepted")
        .to_string();
    assert!(err.contains("repeated seq"), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
}
