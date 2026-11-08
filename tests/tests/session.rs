#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Session scenarios on the mock session: rename/undo/redo, reopening,
//! scoped undo conflicts, listener notifications.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dasm_core::address::Address;
use dasm_core::error::Error;
use dasm_core::journal::{OpSource, UndoScope};
use dasm_core::ops::Operation;
use dasm_core::snapshot::SnapshotListener;
use dasm_core::testing::{InMemoryStore, addrs, mock_session, mock_session_with_store};

fn rename(a: Address, n: Option<&str>) -> Operation {
    Operation::Rename {
        address: a,
        name: n.map(Into::into),
    }
}

fn name_of(s: &dasm_core::Session, a: Address) -> Option<String> {
    s.snapshot().display_name(a)
}

#[test]
fn rename_changes_listing_and_report() {
    let s = mock_session().unwrap();
    s.apply(rename(addrs::HELPER, Some("compute")), OpSource::Ui)
        .unwrap();
    assert_eq!(name_of(&s, addrs::HELPER).as_deref(), Some("compute"));
    let snap = s.snapshot();
    let f = snap.analysis().function_at(addrs::HELPER).unwrap();
    assert_eq!(snap.function_name(f), "compute");
    // call site operand follows the rename
    assert_eq!(
        snap.render_insn(Address(0x401029)).unwrap().operands_text(),
        "compute"
    );
}

#[test]
fn undo_redo_cycle_is_exact() {
    let s = mock_session().unwrap();
    let original = name_of(&s, addrs::MAIN);
    s.apply(rename(addrs::MAIN, Some("entry_point")), OpSource::Ui)
        .unwrap();
    s.apply(rename(addrs::MAIN, Some("entry_point2")), OpSource::Ui)
        .unwrap();
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("entry_point2"));
    assert!(s.undo(UndoScope::Global).unwrap());
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("entry_point"));
    assert!(s.undo(UndoScope::Global).unwrap());
    assert_eq!(name_of(&s, addrs::MAIN), original);
    assert!(!s.undo(UndoScope::Global).unwrap(), "nothing left to undo");
    assert!(!s.can_undo(UndoScope::Global));
    assert!(s.redo(UndoScope::Global).unwrap());
    assert!(s.redo(UndoScope::Global).unwrap());
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("entry_point2"));
    assert!(!s.redo(UndoScope::Global).unwrap());
}

#[test]
fn new_operation_discards_redo_stack() {
    let s = mock_session().unwrap();
    s.apply(rename(addrs::HELPER, Some("a")), OpSource::Ui)
        .unwrap();
    s.undo(UndoScope::Global).unwrap();
    assert!(s.can_redo(UndoScope::Global));
    s.apply(rename(addrs::HELPER, Some("b")), OpSource::Ui)
        .unwrap();
    assert!(!s.can_redo(UndoScope::Global));
    assert_eq!(name_of(&s, addrs::HELPER).as_deref(), Some("b"));
}

#[test]
fn reopen_restores_names_and_undo_state() {
    let store = InMemoryStore::new();
    {
        let s = mock_session_with_store(store.clone()).unwrap();
        s.apply(rename(addrs::HELPER, Some("kept")), OpSource::Ui)
            .unwrap();
        s.apply(rename(addrs::MAIN, Some("undone")), OpSource::Ui)
            .unwrap();
        s.undo(UndoScope::Global).unwrap();
    }
    let s = mock_session_with_store(store.clone()).unwrap();
    assert_eq!(name_of(&s, addrs::HELPER).as_deref(), Some("kept"));
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("main"));
    // The undone entry survives the restart and can be redone.
    assert!(s.can_redo(UndoScope::Global));
    assert!(s.redo(UndoScope::Global).unwrap());
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("undone"));
    drop(s);
    let s = mock_session_with_store(store).unwrap();
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("undone"));
}

#[test]
fn rename_to_none_resets_and_empty_name_is_rejected() {
    let s = mock_session().unwrap();
    s.apply(rename(addrs::HELPER, Some("x")), OpSource::Ui)
        .unwrap();
    s.apply(rename(addrs::HELPER, None), OpSource::Ui).unwrap();
    assert_eq!(name_of(&s, addrs::HELPER).as_deref(), Some("sub_401040"));
    let err = s
        .apply(rename(addrs::HELPER, Some("")), OpSource::Ui)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidOperation(_)), "{err}");
    let err = s
        .apply(rename(addrs::HELPER, Some("   ")), OpSource::Ui)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidOperation(_)), "{err}");
    assert_eq!(name_of(&s, addrs::HELPER).as_deref(), Some("sub_401040"));
}

#[test]
fn scoped_undo_skips_unrelated_functions() {
    let s = mock_session().unwrap();
    s.apply(rename(addrs::HELPER, Some("h")), OpSource::Ui)
        .unwrap();
    s.apply(rename(addrs::MAIN, Some("m")), OpSource::Ui)
        .unwrap();
    let helper = UndoScope::Function(addrs::HELPER);
    assert!(s.can_undo(helper));
    assert!(s.undo(helper).unwrap());
    assert_eq!(name_of(&s, addrs::HELPER).as_deref(), Some("sub_401040"));
    assert_eq!(
        name_of(&s, addrs::MAIN).as_deref(),
        Some("m"),
        "other function untouched"
    );
    assert!(!s.can_undo(helper));
    assert_eq!(s.history(UndoScope::Function(addrs::MAIN)).len(), 1);
    assert_eq!(s.history(UndoScope::Global).len(), 2);
}

#[test]
fn scoped_undo_conflict_is_reported_and_state_unchanged() {
    // seq1: rename main (scope main); seq2: delete main (scope main);
    // seq3: rename main again - the function is gone, so no function scope.
    // Undoing in main's scope first reverts the delete; the second undo
    // would revert seq1 under a later entry on the same item (seq3).
    let s = mock_session().unwrap();
    s.apply(rename(addrs::MAIN, Some("first")), OpSource::Ui)
        .unwrap();
    s.apply(
        Operation::DeleteFunction {
            address: addrs::MAIN,
        },
        OpSource::Ui,
    )
    .unwrap();
    s.apply(rename(addrs::MAIN, Some("second")), OpSource::Ui)
        .unwrap();
    let scope = UndoScope::Function(addrs::MAIN);
    let h = s.history(scope);
    eprintln!(
        "scope history: {:?}",
        h.iter().map(|e| (e.seq, e.scope)).collect::<Vec<_>>()
    );
    assert!(
        s.undo(scope).unwrap(),
        "first scoped undo reverts the delete"
    );
    let before = s.snapshot().generation();
    match s.undo(scope) {
        Err(Error::UndoConflict { seq, blocked_by }) => assert!(blocked_by > seq),
        other => panic!("expected UndoConflict, got {other:?}"),
    }
    assert_eq!(
        s.snapshot().generation(),
        before,
        "failed undo must not publish"
    );
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("second"));
    // Global undo walks back in order and always succeeds.
    while s.can_undo(UndoScope::Global) {
        assert!(s.undo(UndoScope::Global).unwrap());
    }
    assert_eq!(name_of(&s, addrs::MAIN).as_deref(), Some("main"));
}

/// Publications for apply + undo + redo of a rename on the mock session:
/// one per user-state change; the static driver publishes nothing extra
/// synchronously (documented here so a change is a conscious one).
const EXPECTED_NOTIFICATIONS: u64 = 3;

#[test]
fn listener_is_notified_with_increasing_generations() {
    struct L(AtomicU64, AtomicU64);
    impl SnapshotListener for L {
        fn snapshot_published(&self, g: u64) {
            assert!(
                g >= self.0.load(Ordering::SeqCst),
                "generation went backwards"
            );
            self.0.store(g, Ordering::SeqCst);
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }
    let s = mock_session().unwrap();
    let l = Arc::new(L(AtomicU64::new(0), AtomicU64::new(0)));
    let id = s.hub().subscribe(l.clone());
    s.apply(rename(addrs::HELPER, Some("a")), OpSource::Ui)
        .unwrap();
    s.undo(UndoScope::Global).unwrap();
    s.redo(UndoScope::Global).unwrap();
    eprintln!("notifications: {}", l.1.load(Ordering::SeqCst));
    assert_eq!(l.1.load(Ordering::SeqCst), EXPECTED_NOTIFICATIONS);
    assert_eq!(l.0.load(Ordering::SeqCst), s.snapshot().generation());
    s.hub().unsubscribe(id);
    let n = l.1.load(Ordering::SeqCst);
    s.apply(rename(addrs::MAIN, Some("z")), OpSource::Ui)
        .unwrap();
    assert_eq!(
        l.1.load(Ordering::SeqCst),
        n,
        "no notifications after unsubscribe"
    );
}

#[test]
fn old_snapshots_stay_immutable() {
    let s = mock_session().unwrap();
    let before = s.snapshot();
    s.apply(rename(addrs::MAIN, Some("changed")), OpSource::Ui)
        .unwrap();
    assert_eq!(before.display_name(addrs::MAIN).as_deref(), Some("main"));
    assert_ne!(before.generation(), s.snapshot().generation());
}

#[test]
fn comments_and_patches_are_journaled() {
    let s = mock_session().unwrap();
    s.apply(
        Operation::Comment {
            address: Address(0x401011),
            text: Some("note".into()),
        },
        OpSource::Ui,
    )
    .unwrap();
    let h = s.history(UndoScope::Global);
    assert_eq!(h.len(), 1);
    assert!(matches!(h[0].op, Operation::Comment { .. }));
    let at = Address(0x401011);
    assert_eq!(s.snapshot().user().comment(at), Some("note"));
    s.undo(UndoScope::Global).unwrap();
    assert!(s.can_redo(UndoScope::Global));
    assert_eq!(s.snapshot().user().comment(at), None, "undo removes it");
    s.redo(UndoScope::Global).unwrap();
    assert_eq!(s.snapshot().user().comment(at), Some("note"));
}
