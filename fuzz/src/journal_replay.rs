//! `Journal::replay` of an untrusted journal, then undo/redo/apply steps
//! persisted into a model store.
//!
//! Oracle (ADR 0002): after every step the live user state equals a fresh
//! replay of what the store holds — "what the UI shows is what reopening
//! the project shows".
//!
//! Input: a JSON array of `JournalEntry` (as `ProjectStore::load_journal`
//! would return it). The bytes after the JSON, if any, are not used; the
//! steps are derived from a hash of the input.

use std::collections::BTreeMap;

use dasm_core::{
    Address, Journal, JournalEntry, JournalEvent, OpMeta, OpSource, Operation, UndoScope,
};

use crate::check;
use crate::fixtures::{CODE, DATA, base_state, fingerprint};

/// Larger journals are valid but only slow the fuzzer down (replay is
/// linear, undo is linear per step).
const MAX_ENTRIES: usize = 512;
const STEPS: usize = 24;

/// The target.
pub fn run(data: &[u8]) {
    let Ok(entries) = serde_json::from_slice::<Vec<JournalEntry>>(data) else {
        return;
    };
    if entries.len() > MAX_ENTRIES {
        return;
    }
    let Ok(mut journal) = Journal::replay(base_state(), entries.clone()) else {
        return;
    };
    // Duplicate seqs were rejected by replay, so this is lossless.
    let mut store: BTreeMap<u64, JournalEntry> = entries.into_iter().map(|e| (e.seq, e)).collect();
    check_consistent(&journal, &store, "after replay");

    let mut h = data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3)
    });
    for step in 0..STEPS {
        h ^= h >> 29;
        h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        let scope = match (h >> 8) % 3 {
            0 => UndoScope::Global,
            _ => {
                // Scope of some existing entry, so function-scope paths run.
                let scopes: Vec<Address> = journal.entries().filter_map(|e| e.scope).collect();
                match scopes.get(usize::try_from((h >> 16) % 64).unwrap_or(0) % scopes.len().max(1))
                {
                    Some(f) => UndoScope::Function(*f),
                    None => UndoScope::Global,
                }
            }
        };
        let mut next = journal.clone();
        let events: Result<Vec<JournalEvent>, _> = match h % 4 {
            0 | 1 => next.undo(scope).map(|e| e.into_iter().collect()),
            2 => next.redo(scope).map(|e| e.into_iter().collect()),
            _ => {
                let addr = if h & 0x100 == 0 { CODE } else { DATA } + (h >> 40) % 8;
                let op = if h & 0x200 == 0 {
                    Operation::Rename {
                        address: Address(addr),
                        name: Some(format!("n{step}")),
                    }
                } else {
                    Operation::PatchBytes {
                        address: Address(addr),
                        bytes: vec![(h >> 24) as u8],
                    }
                };
                let meta = OpMeta {
                    author: "fuzz".into(),
                    timestamp_ms: 0,
                    source: OpSource::Cli,
                };
                let scope = (h & 0x400 != 0).then_some(Address(CODE));
                next.apply(op, meta, scope)
            }
        };
        let Ok(events) = events else {
            // Session keeps the old journal on error; so do we.
            continue;
        };
        if !persist(&mut store, &events) {
            continue;
        }
        journal = next;
        check_consistent(&journal, &store, "after a step");
    }
}

/// Applies events like a conforming store; `false` if the store would
/// reject them (the session then keeps its old journal).
fn persist(store: &mut BTreeMap<u64, JournalEntry>, events: &[JournalEvent]) -> bool {
    let mut next = store.clone();
    for e in events {
        match e {
            JournalEvent::Appended(entry) => {
                if next.insert(entry.seq, entry.clone()).is_some() {
                    crate::report::violation(
                        "SEC-CORE-04",
                        format_args!("journal appended duplicate seq {}", entry.seq),
                    );
                    return false;
                }
            }
            JournalEvent::StateChanged {
                seq,
                state,
                inverse,
            } => match next.get_mut(seq) {
                Some(entry) => {
                    entry.state = *state;
                    entry.inverse = inverse.clone();
                }
                None => {
                    check!(false, "JRN-02", "state change of unknown seq {seq}");
                    return false;
                }
            },
        }
    }
    *store = next;
    true
}

fn check_consistent(journal: &Journal, store: &BTreeMap<u64, JournalEntry>, when: &str) {
    let live = fingerprint(journal.user_state());
    match Journal::replay(base_state(), store.values().cloned().collect()) {
        Ok(reopened) => {
            check!(
                fingerprint(reopened.user_state()) == live,
                "JRN-01",
                "{when}: live state differs from replay of the store"
            );
            check!(
                reopened.can_redo(UndoScope::Global) == journal.can_redo(UndoScope::Global),
                "JRN-03",
                "{when}: redo availability differs after reopening"
            );
        }
        Err(e) => check!(false, "JRN-01", "{when}: store no longer replays: {e}"),
    }
}
