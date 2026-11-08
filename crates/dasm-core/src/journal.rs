//! The operation journal: source of truth for user changes, with undo/redo.
//!
//! The journal is pure in-memory logic. Persistence is the job of a
//! [`crate::ProjectStore`]: every mutating call returns the
//! [`JournalEvent`]s the store must record (ADR 0002).

use imbl::{OrdMap, OrdSet};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::error::Error;
use crate::ops::{
    MAX_NAME_LEN, MAX_OPERATION_JSON_BYTES, MAX_PATCHED_BYTES, MAX_REPLAY_PATCHED_BYTES, Operation,
    UserState,
};
use crate::text::is_clean_label;

/// Version of the persisted journal format: the JSON form of
/// [`Operation`], [`OpMeta`] and [`JournalEntry`]. Adding operation
/// variants or optional fields keeps the version; anything an older build
/// could misread bumps it. A store records the version a project was
/// created with; [`crate::Session::open`] refuses newer projects with
/// [`Error::NewerProjectFormat`].
pub const JOURNAL_FORMAT_VERSION: u32 = 1;

/// Largest sequence number: SQLite stores `INTEGER` as `i64`, and a
/// journal must never saturate into a duplicate.
pub const MAX_SEQ: u64 = i64::MAX as u64;

/// Maximum number of journal entries in a project. A store should check
/// the count before loading ([`crate::ProjectStore::load_journal`]).
pub const MAX_JOURNAL_ENTRIES: usize = 1 << 22;

/// Who issued an operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum OpSource {
    /// Interactive UI.
    Ui,
    /// `dasm` command line.
    Cli,
    /// Python script.
    Script,
    /// Plugin with this id.
    Plugin(String),
    /// Import from IDA/Ghidra/another project.
    Import,
}

/// Metadata stored with every journal entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpMeta {
    /// Author (user name or plugin id).
    pub author: String,
    /// Unix time in milliseconds.
    pub timestamp_ms: i64,
    /// Origin.
    pub source: OpSource,
}

impl OpMeta {
    /// Checks the metadata: author and plugin id are bounded (a project
    /// file is untrusted input).
    pub fn validate(&self) -> Result<(), Error> {
        let plugin = match &self.source {
            OpSource::Plugin(id) => id.len(),
            _ => 0,
        };
        if self.author.len() > MAX_NAME_LEN || plugin > MAX_NAME_LEN {
            return Err(Error::InvalidOperation(format!(
                "author or plugin id longer than {MAX_NAME_LEN} bytes"
            )));
        }
        let plugin_clean = match &self.source {
            OpSource::Plugin(id) => is_clean_label(id),
            _ => true,
        };
        if !is_clean_label(&self.author) || !plugin_clean {
            return Err(Error::InvalidOperation(
                "author or plugin id contains control or invisible characters".into(),
            ));
        }
        Ok(())
    }

    /// Metadata for "now" from the given source.
    #[must_use]
    pub fn now(author: impl Into<String>, source: OpSource) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        OpMeta {
            author: author.into(),
            timestamp_ms,
            source,
        }
    }
}

/// The author recorded in [`OpMeta`] (customer decision, ADR 0002).
///
/// The setting lives in the **user profile**, not in the project: it
/// identifies a person across projects, and a project shared between
/// people must not impose one name. Binaries read it from
/// `$XDG_CONFIG_HOME/dasm/config.toml` (`[user] name = "..."`) and pass it
/// as `configured`. Resolution: non-blank `configured` > `$USER` >
/// `$LOGNAME` > `"unknown"`.
#[must_use]
pub fn resolve_author(configured: Option<&str>) -> String {
    pick_author(
        configured,
        std::env::var("USER").ok().as_deref(),
        std::env::var("LOGNAME").ok().as_deref(),
    )
}

fn pick_author(configured: Option<&str>, user: Option<&str>, logname: Option<&str>) -> String {
    [configured, user, logname]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty() && s.len() <= MAX_NAME_LEN && is_clean_label(s))
        .unwrap_or("unknown")
        .to_owned()
}

/// Lifecycle of a journal entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// In effect.
    Active,
    /// Undone; can be redone.
    Undone,
    /// Undone and then abandoned by a new operation; kept for history only.
    Discarded,
}

/// One recorded operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Monotonic sequence number, starting at 1.
    pub seq: u64,
    /// The operation as issued.
    pub op: Operation,
    /// Its inverse, computed when it was (last) applied.
    pub inverse: Operation,
    /// Metadata.
    pub meta: OpMeta,
    /// Entry address of the function the operation belongs to, if any;
    /// enables per-function undo.
    pub scope: Option<Address>,
    /// Current state.
    pub state: EntryState,
}

/// What the project store must persist after a journal mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalEvent {
    /// A new entry was appended.
    Appended(JournalEntry),
    /// An existing entry changed state (and maybe its stored inverse).
    StateChanged {
        /// Entry.
        seq: u64,
        /// New state.
        state: EntryState,
        /// Inverse to store (recomputed on redo).
        inverse: Operation,
    },
}

/// Which history undo/redo works on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "function", rename_all = "snake_case")]
pub enum UndoScope {
    /// The whole project (Ctrl+Z).
    Global,
    /// Only entries scoped to this function.
    Function(Address),
}

/// The journal plus the user state it produces.
///
/// Cloning is cheap (O(1) for the entries, which live in a persistent
/// vector; the user state uses persistent maps), so a [`crate::Session`]
/// can apply an operation to a copy and swap it in only after the store
/// has persisted it (ADR 0002).
#[derive(Clone, Debug, Default)]
pub struct Journal {
    entries: imbl::Vector<JournalEntry>,
    /// Seqs of `Undone` entries; the last element is redone first.
    redo: imbl::Vector<u64>,
    /// The same stack, per function scope.
    scoped_redo: OrdMap<Address, imbl::Vector<u64>>,
    /// Seqs of `Active` entries.
    active: OrdSet<u64>,
    /// The same set, per function scope.
    scoped_active: OrdMap<Address, OrdSet<u64>>,
    limits: JournalLimits,
    user: UserState,
}

/// Size limits of a journal; constants in production, small in tests.
#[derive(Clone, Copy, Debug)]
struct JournalLimits {
    /// Overlay limit of live changes and of the final replayed state.
    patched: usize,
    /// Overlay limit while replaying.
    replay_patched: usize,
    /// Maximum number of entries.
    entries: usize,
}

impl Default for JournalLimits {
    fn default() -> Self {
        JournalLimits {
            patched: MAX_PATCHED_BYTES,
            replay_patched: MAX_REPLAY_PATCHED_BYTES,
            entries: MAX_JOURNAL_ENTRIES,
        }
    }
}

impl Journal {
    /// Empty journal over an initial user state.
    #[must_use]
    pub fn new(user: UserState) -> Self {
        Journal {
            user,
            ..Default::default()
        }
    }

    /// Rebuilds a journal from persisted entries (any order). Active entries
    /// are re-applied in sequence order; undone entries form the redo stack
    /// (lowest seq redone first). Fails if an active entry no longer applies,
    /// which means the project is corrupt.
    pub fn replay(user: UserState, entries: Vec<JournalEntry>) -> Result<Self, Error> {
        Self::replay_with(user, entries, JournalLimits::default())
    }

    fn replay_with(
        user: UserState,
        mut entries: Vec<JournalEntry>,
        limits: JournalLimits,
    ) -> Result<Self, Error> {
        if entries.len() > limits.entries {
            return Err(Error::Store(format!(
                "journal has {} entries, limit is {}",
                entries.len(),
                limits.entries
            )));
        }
        entries.sort_by_key(|e| e.seq);
        // The project file is untrusted input: seqs must be >= 1 and unique.
        let mut prev = 0u64;
        for e in &entries {
            if e.seq <= prev || e.seq > MAX_SEQ {
                return Err(Error::Store(format!(
                    "journal entry seq {} is zero, duplicated or out of range",
                    e.seq
                )));
            }
            prev = e.seq;
        }
        let mut j = Journal {
            limits,
            ..Journal::new(user)
        };
        for mut e in entries {
            let shape = match e.state {
                // Never applied again; kept for history only.
                EntryState::Discarded => Ok(()),
                _ => e.op.validate().and_then(|()| e.meta.validate()),
            };
            shape.map_err(|err| {
                Error::Store(format!("journal entry #{} is invalid: {err}", e.seq))
            })?;
            if e.state == EntryState::Active {
                let replayed = j.user.apply_limited(&e.op, limits.replay_patched);
                e.inverse = replayed.map_err(|err| {
                    Error::Store(format!("journal entry #{} does not replay: {err}", e.seq))
                })?;
                j.mark_active(e.seq, e.scope);
            }
            j.entries.push_back(e);
        }
        let undone: Vec<(u64, Option<Address>)> = j
            .entries
            .iter()
            .rev()
            .filter(|e| e.state == EntryState::Undone)
            .map(|e| (e.seq, e.scope))
            .collect();
        for (seq, scope) in undone {
            j.push_redo(seq, scope);
        }
        // Every state of a live session fits the budget, so the final one
        // must too; only the states in between may legitimately exceed it.
        if j.user.memory().patch_count() > limits.patched {
            return Err(Error::Store(format!(
                "journal patches more than {} bytes",
                limits.patched
            )));
        }
        Ok(j)
    }

    /// Current user state.
    #[must_use]
    pub fn user_state(&self) -> &UserState {
        &self.user
    }

    /// All entries in sequence order.
    pub fn entries(
        &self,
    ) -> impl DoubleEndedIterator<Item = &JournalEntry> + ExactSizeIterator + '_ {
        self.entries.iter()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if nothing was ever recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry with sequence number `seq`.
    #[must_use]
    pub fn entry(&self, seq: u64) -> Option<&JournalEntry> {
        self.index_of(seq).and_then(|i| self.entries.get(i))
    }

    /// Next sequence number.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.entries.last().map_or(1, |e| e.seq.saturating_add(1))
    }

    /// Applies a new operation. Clears the redo stack (those entries become
    /// `Discarded`).
    pub fn apply(
        &mut self,
        op: Operation,
        meta: OpMeta,
        scope: Option<Address>,
    ) -> Result<Vec<JournalEvent>, Error> {
        let seq = self.next_seq();
        if seq > MAX_SEQ || self.entries.len() >= self.limits.entries {
            return Err(Error::Store("journal is full".into()));
        }
        meta.validate()?;
        let op = op.validated()?;
        let (user, inverse) = self.applied(&op)?;
        self.user = user;
        let mut events = Vec::new();
        self.scoped_redo = OrdMap::new();
        for seq in std::mem::take(&mut self.redo) {
            if let Some(e) = self.entry_mut(seq) {
                e.state = EntryState::Discarded;
                events.push(JournalEvent::StateChanged {
                    seq,
                    state: EntryState::Discarded,
                    inverse: e.inverse.clone(),
                });
            }
        }
        self.mark_active(seq, scope);
        let entry = JournalEntry {
            seq,
            op,
            inverse,
            meta,
            scope,
            state: EntryState::Active,
        };
        self.entries.push_back(entry.clone());
        events.push(JournalEvent::Appended(entry));
        Ok(events)
    }

    /// True if [`Journal::undo`] would do something in this scope.
    #[must_use]
    pub fn can_undo(&self, scope: UndoScope) -> bool {
        self.last_active(scope).is_some()
    }

    /// True if [`Journal::redo`] would do something in this scope.
    #[must_use]
    pub fn can_redo(&self, scope: UndoScope) -> bool {
        self.redo_top(scope).is_some()
    }

    /// Undoes the latest active entry in `scope`. Returns `Ok(None)` if there
    /// is nothing to undo. In a function scope, fails with
    /// [`Error::UndoConflict`] if a later active entry touches the same item.
    pub fn undo(&mut self, scope: UndoScope) -> Result<Option<JournalEvent>, Error> {
        let Some(seq) = self.last_active(scope) else {
            return Ok(None);
        };
        let Some((inverse, entry_scope)) = self.entry(seq).map(|e| (e.inverse.clone(), e.scope))
        else {
            return Ok(None);
        };
        if let Some(blocked_by) = self.later_conflict(seq) {
            return Err(Error::UndoConflict { seq, blocked_by });
        }
        self.user.apply_limited(&inverse, self.limits.patched)?;
        if let Some(e) = self.entry_mut(seq) {
            e.state = EntryState::Undone;
        }
        self.unmark_active(seq, entry_scope);
        self.push_redo(seq, entry_scope);
        Ok(Some(JournalEvent::StateChanged {
            seq,
            state: EntryState::Undone,
            inverse,
        }))
    }

    /// Redoes the most recently undone entry in `scope`. Fails with
    /// [`Error::UndoConflict`] if a later (by seq) active entry touches the
    /// same item: re-applying it out of order would make the live state
    /// differ from a replay of the journal.
    pub fn redo(&mut self, scope: UndoScope) -> Result<Option<JournalEvent>, Error> {
        let Some(seq) = self.redo_top(scope) else {
            return Ok(None);
        };
        if let Some(blocked_by) = self.later_conflict(seq) {
            return Err(Error::UndoConflict { seq, blocked_by });
        }
        let Some((op, entry_scope)) = self.entry(seq).map(|e| (e.op.clone(), e.scope)) else {
            return Ok(None);
        };
        let (user, inverse) = self.applied(&op)?;
        self.user = user;
        if let Some(e) = self.entry_mut(seq) {
            e.state = EntryState::Active;
            e.inverse = inverse.clone();
        }
        self.remove_redo(seq, entry_scope);
        self.mark_active(seq, entry_scope);
        Ok(Some(JournalEvent::StateChanged {
            seq,
            state: EntryState::Active,
            inverse,
        }))
    }

    /// The user state after `op` and the inverse to record, leaving `self`
    /// untouched on error. An inverse can be far larger than its operation
    /// (clearing many long comments), and it is stored too.
    fn applied(&self, op: &Operation) -> Result<(UserState, Operation), Error> {
        let mut user = self.user.clone();
        let inverse = user.apply_limited(op, self.limits.patched)?;
        if inverse.json_size_bound() > MAX_OPERATION_JSON_BYTES {
            return Err(Error::InvalidOperation(
                "this change is too large to undo; split it".into(),
            ));
        }
        Ok((user, inverse))
    }

    /// The first active entry after `seq` that touches an item entry `seq`
    /// touches. Undo/redo of `seq` must be refused then: the live state
    /// must always equal a replay of active entries in seq order. Visits
    /// only later *active* entries, so linear undo/redo is O(log n).
    fn later_conflict(&self, seq: u64) -> Option<u64> {
        let changes = self.entry(seq)?.op.changes();
        self.active
            .range(seq.saturating_add(1)..)
            .find(|later| {
                self.entry(**later).is_some_and(|e| {
                    e.op.changes()
                        .iter()
                        .any(|c| changes.iter().any(|m| m.conflicts_with(c)))
                })
            })
            .copied()
    }

    fn last_active(&self, scope: UndoScope) -> Option<u64> {
        match scope {
            UndoScope::Global => self.active.get_max().copied(),
            UndoScope::Function(f) => self.scoped_active.get(&f)?.get_max().copied(),
        }
    }

    fn redo_top(&self, scope: UndoScope) -> Option<u64> {
        match scope {
            UndoScope::Global => self.redo.last().copied(),
            UndoScope::Function(f) => self.scoped_redo.get(&f)?.last().copied(),
        }
    }

    fn mark_active(&mut self, seq: u64, scope: Option<Address>) {
        self.active.insert(seq);
        if let Some(f) = scope {
            self.scoped_active.entry(f).or_default().insert(seq);
        }
    }

    fn unmark_active(&mut self, seq: u64, scope: Option<Address>) {
        self.active.remove(&seq);
        if let Some(f) = scope
            && let Some(set) = self.scoped_active.get_mut(&f)
        {
            set.remove(&seq);
            if set.is_empty() {
                self.scoped_active.remove(&f);
            }
        }
    }

    fn push_redo(&mut self, seq: u64, scope: Option<Address>) {
        self.redo.push_back(seq);
        if let Some(f) = scope {
            self.scoped_redo.entry(f).or_default().push_back(seq);
        }
    }

    fn remove_redo(&mut self, seq: u64, scope: Option<Address>) {
        remove_last(&mut self.redo, seq);
        if let Some(f) = scope
            && let Some(stack) = self.scoped_redo.get_mut(&f)
        {
            remove_last(stack, seq);
            if stack.is_empty() {
                self.scoped_redo.remove(&f);
            }
        }
    }

    /// Entries are sorted by unique seq (append order; replay checks it).
    fn index_of(&self, seq: u64) -> Option<usize> {
        self.entries.binary_search_by(|e| e.seq.cmp(&seq)).ok()
    }

    fn entry_mut(&mut self, seq: u64) -> Option<&mut JournalEntry> {
        let i = self.index_of(seq)?;
        self.entries.get_mut(i)
    }
}

/// Removes the last occurrence of `seq` (normally the top of the stack).
fn remove_last(stack: &mut imbl::Vector<u64>, seq: u64) {
    if stack.last() == Some(&seq) {
        stack.pop_back();
    } else if let Some(i) = stack.iter().rposition(|s| *s == seq) {
        stack.remove(i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::AddressRange;
    use crate::memory::{MemoryMap, MemoryRegion, Permissions, SharedBytes};

    fn meta() -> OpMeta {
        OpMeta {
            author: "t".into(),
            timestamp_ms: 0,
            source: OpSource::Ui,
        }
    }

    fn rename(a: u64, n: &str) -> Operation {
        Operation::Rename {
            address: Address(a),
            name: Some(n.into()),
        }
    }

    #[test]
    fn linear_undo_redo() {
        let mut j = Journal::default();
        j.apply(rename(1, "a"), meta(), None).unwrap();
        j.apply(rename(1, "b"), meta(), None).unwrap();
        assert_eq!(j.user_state().name(Address(1)), Some("b"));
        j.undo(UndoScope::Global).unwrap();
        assert_eq!(j.user_state().name(Address(1)), Some("a"));
        j.undo(UndoScope::Global).unwrap();
        assert_eq!(j.user_state().name(Address(1)), None);
        assert!(j.undo(UndoScope::Global).unwrap().is_none());
        j.redo(UndoScope::Global).unwrap();
        assert_eq!(j.user_state().name(Address(1)), Some("a"));
        // New op discards the remaining redo entry.
        let ev = j.apply(rename(2, "c"), meta(), None).unwrap();
        assert!(ev.iter().any(|e| matches!(
            e,
            JournalEvent::StateChanged {
                state: EntryState::Discarded,
                ..
            }
        )));
        assert!(!j.can_redo(UndoScope::Global));
    }

    #[test]
    fn scoped_undo_and_conflicts() {
        let mut j = Journal::default();
        let f = Some(Address(0x100));
        j.apply(rename(0x100, "f"), meta(), f).unwrap();
        j.apply(rename(0x200, "g"), meta(), Some(Address(0x200)))
            .unwrap();
        // Undo in f's scope skips the later, unrelated entry.
        j.undo(UndoScope::Function(Address(0x100))).unwrap();
        assert_eq!(j.user_state().name(Address(0x100)), None);
        assert_eq!(j.user_state().name(Address(0x200)), Some("g"));
        j.redo(UndoScope::Function(Address(0x100))).unwrap();
        // A later global entry on the same item blocks scoped undo.
        j.apply(rename(0x100, "f2"), meta(), None).unwrap();
        let err = j.undo(UndoScope::Function(Address(0x100))).unwrap_err();
        assert!(matches!(err, Error::UndoConflict { .. }));
    }

    #[test]
    fn replay_reproduces_state() {
        let mut j = Journal::default();
        j.apply(rename(1, "a"), meta(), None).unwrap();
        j.apply(rename(2, "b"), meta(), None).unwrap();
        j.apply(rename(3, "c"), meta(), None).unwrap();
        j.undo(UndoScope::Global).unwrap();
        let mut stored: Vec<_> = j.entries().cloned().collect();
        stored.reverse();
        let mut r = Journal::replay(UserState::default(), stored).unwrap();
        assert_eq!(r.user_state().name(Address(2)), Some("b"));
        assert_eq!(r.user_state().name(Address(3)), None);
        r.redo(UndoScope::Global).unwrap();
        assert_eq!(r.user_state().name(Address(3)), Some("c"));
        assert_eq!(r.next_seq(), 4);
    }

    #[test]
    fn author_resolution_order() {
        assert_eq!(pick_author(Some("Eve"), Some("eve"), None), "Eve");
        assert_eq!(pick_author(Some("  "), Some("eve"), Some("x")), "eve");
        assert_eq!(pick_author(None, None, Some("log")), "log");
        assert_eq!(pick_author(None, Some(""), None), "unknown");
        // A bad value must not make every project unopenable.
        assert_eq!(pick_author(Some("a\u{1b}b"), Some("eve"), None), "eve");
        assert_eq!(
            pick_author(Some(&"x".repeat(MAX_NAME_LEN + 1)), None, None),
            "unknown"
        );
    }

    #[test]
    fn sequence_numbers_never_saturate() {
        // SEC-CORE-04: seq = u64::MAX used to produce a duplicate seq.
        let mut j = Journal::default();
        j.apply(rename(1, "a"), meta(), None).unwrap();
        let mut too_big: Vec<_> = j.entries().cloned().collect();
        too_big[0].seq = u64::MAX;
        assert!(Journal::replay(UserState::default(), too_big).is_err());

        let mut at_limit: Vec<_> = j.entries().cloned().collect();
        at_limit[0].seq = MAX_SEQ;
        let mut r = Journal::replay(UserState::default(), at_limit).unwrap();
        let err = r.apply(rename(2, "b"), meta(), None).unwrap_err();
        assert!(matches!(err, Error::Store(_)), "{err}");
        assert_eq!(r.user_state().name(Address(2)), None, "state unchanged");
    }

    #[test]
    fn undo_state_queries_do_not_scan_the_journal() {
        // SEC-CORE-05: can_redo(Function) took 1.7 s at 50k undone entries.
        const N: u64 = 50_000;
        let mut j = Journal::default();
        for i in 0..N {
            j.apply(rename(i, "n"), meta(), Some(Address(0x10)))
                .unwrap();
        }
        for _ in 0..N {
            j.undo(UndoScope::Global).unwrap();
        }
        let other = UndoScope::Function(Address(0x20));
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            assert!(!j.can_redo(other));
            assert!(!j.can_undo(other));
            assert!(j.can_redo(UndoScope::Function(Address(0x10))));
            assert!(!j.can_undo(UndoScope::Global));
        }
        let elapsed = start.elapsed();
        // Generous for loaded CI: a scan would take far longer (1.7 s per
        // call before the indices).
        assert!(elapsed.as_secs() < 5, "1000 rounds took {elapsed:?}");
    }

    fn patch_state(len: u64) -> UserState {
        let region = MemoryRegion::new(
            AddressRange::from_len(Address(0), len).unwrap(),
            SharedBytes::from(vec![0u8; usize::try_from(len).unwrap()]),
            Permissions::RW,
        )
        .unwrap();
        UserState::new(MemoryMap::new(vec![region]).unwrap())
    }

    fn patch(a: u64, byte: u8, len: usize) -> Operation {
        Operation::PatchBytes {
            address: Address(a),
            bytes: vec![byte; len],
        }
    }

    const SMALL: JournalLimits = JournalLimits {
        patched: 8,
        replay_patched: 32,
        entries: 4,
    };

    fn small_journal() -> Journal {
        Journal {
            limits: SMALL,
            ..Journal::new(patch_state(64))
        }
    }

    #[test]
    fn replay_tolerates_intermediate_states_over_the_patch_budget() {
        // Reviewer's B1: after the scoped undo the live overlay is 5 bytes,
        // but a replay passes through 10 on its way there.
        let f = Address(0x500);
        let mut j = small_journal();
        j.apply(patch(0, 1, 5), meta(), None).unwrap();
        j.apply(patch(0, 0, 5), meta(), Some(f)).unwrap();
        j.apply(patch(16, 1, 5), meta(), None).unwrap();
        j.apply(patch(16, 0, 5), meta(), None).unwrap();
        j.undo(UndoScope::Function(f)).unwrap();
        assert_eq!(j.user_state().memory().patch_count(), 5);
        let stored: Vec<_> = j.entries().cloned().collect();
        let r = Journal::replay_with(patch_state(64), stored, SMALL).unwrap();
        assert_eq!(r.user_state().memory().patch_count(), 5);
    }

    #[test]
    fn replay_bounds_intermediate_and_final_overlay() {
        let entry = |seq, op| JournalEntry {
            seq,
            inverse: Operation::Batch { ops: Vec::new() },
            op,
            meta: meta(),
            scope: None,
            state: EntryState::Active,
        };
        let limits = JournalLimits {
            entries: 16,
            ..SMALL
        };
        // Final state over the budget although each step fits replay_patched.
        let over = vec![entry(1, patch(0, 1, 9))];
        assert!(Journal::replay_with(patch_state(64), over, limits).is_err());
        // A forged journal cannot grow past replay_patched on the way.
        let forged = vec![
            entry(1, patch(0, 1, 30)),
            entry(2, patch(32, 1, 8)),
            entry(3, patch(0, 0, 40)),
        ];
        assert!(Journal::replay_with(patch_state(64), forged, limits).is_err());
    }

    #[test]
    fn live_changes_respect_the_patch_budget() {
        let mut j = small_journal();
        j.apply(patch(0, 1, 8), meta(), None).unwrap();
        assert!(j.apply(patch(16, 1, 1), meta(), None).is_err());
        assert_eq!(j.len(), 1, "refused change is not recorded");
        // Shrinking is always allowed.
        j.apply(patch(0, 0, 4), meta(), None).unwrap();
    }

    #[test]
    fn scoped_undo_can_be_refused_by_the_budget() {
        let f = Address(0x500);
        let mut j = small_journal();
        j.apply(patch(0, 1, 5), meta(), None).unwrap();
        j.apply(patch(0, 0, 5), meta(), Some(f)).unwrap();
        j.apply(patch(16, 1, 5), meta(), None).unwrap();
        assert!(j.undo(UndoScope::Function(f)).is_err());
        assert_eq!(j.user_state().memory().patch_count(), 5, "state unchanged");
    }

    #[test]
    fn entry_limit_is_enforced_live_and_on_replay() {
        let mut j = small_journal();
        for a in 0..4 {
            j.apply(rename(a, "n"), meta(), None).unwrap();
        }
        let err = j.apply(rename(9, "n"), meta(), None).unwrap_err();
        assert!(matches!(err, Error::Store(_)), "{err}");
        let stored: Vec<_> = j.entries().cloned().collect();
        let tight = JournalLimits {
            entries: 3,
            ..SMALL
        };
        assert!(Journal::replay_with(patch_state(64), stored, tight).is_err());
    }

    #[test]
    fn change_with_an_oversized_inverse_is_refused() {
        // The batch itself is tiny; its inverse holds every old comment.
        let mut j = Journal::default();
        let text = "x".repeat(crate::ops::MAX_COMMENT_LEN);
        let count = MAX_OPERATION_JSON_BYTES / text.len() / 2 + 1;
        for a in 0..count as u64 {
            let op = Operation::Comment {
                address: Address(a),
                text: Some(text.clone()),
            };
            j.apply(op, meta(), None).unwrap();
        }
        let clear = Operation::Batch {
            ops: (0..count as u64)
                .map(|a| Operation::Comment {
                    address: Address(a),
                    text: None,
                })
                .collect(),
        };
        assert!(j.apply(clear, meta(), None).is_err());
        assert_eq!(j.user_state().comment(Address(0)), Some(text.as_str()));
        assert_eq!(j.len(), count);
    }

    #[test]
    fn replay_validates_only_entries_that_can_be_applied() {
        let bad_name = Operation::Rename {
            address: Address(1),
            name: Some("a\u{202e}b".into()),
        };
        let with_state = |state| {
            vec![JournalEntry {
                seq: 1,
                inverse: Operation::Batch { ops: Vec::new() },
                op: bad_name.clone(),
                meta: meta(),
                scope: None,
                state,
            }]
        };
        // Discarded entries are history only and must not block opening.
        assert!(Journal::replay(UserState::default(), with_state(EntryState::Discarded)).is_ok());
        assert!(Journal::replay(UserState::default(), with_state(EntryState::Undone)).is_err());
        assert!(Journal::replay(UserState::default(), with_state(EntryState::Active)).is_err());
    }

    #[test]
    fn oversized_metadata_is_rejected() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        let mut j = Journal::default();
        let mut m = meta();
        m.author = long.clone();
        assert!(j.apply(rename(1, "a"), m, None).is_err());
        let mut m = meta();
        m.source = OpSource::Plugin(long.clone());
        assert!(j.apply(rename(1, "a"), m, None).is_err());
        assert_eq!(j.len(), 0);

        j.apply(rename(1, "a"), meta(), None).unwrap();
        let mut stored: Vec<_> = j.entries().cloned().collect();
        stored[0].meta.author = long;
        assert!(Journal::replay(UserState::default(), stored).is_err());
    }

    #[test]
    fn replay_rejects_bad_sequence_numbers() {
        let mut j = Journal::default();
        j.apply(rename(1, "a"), meta(), None).unwrap();
        j.apply(rename(2, "b"), meta(), None).unwrap();
        let mut dup: Vec<_> = j.entries().cloned().collect();
        if let Some(e) = dup.get_mut(1) {
            e.seq = 1;
        }
        assert!(matches!(
            Journal::replay(UserState::default(), dup),
            Err(Error::Store(_))
        ));
        let mut zero: Vec<_> = j.entries().cloned().collect();
        if let Some(e) = zero.get_mut(0) {
            e.seq = 0;
        }
        assert!(Journal::replay(UserState::default(), zero).is_err());
    }

    #[test]
    fn redo_out_of_order_is_refused() {
        // Reviewer scenario: live state must not diverge from replay.
        let x = 0x100;
        let f = UndoScope::Function(Address(0x500));
        let mut j = Journal::default();
        j.apply(rename(x, "a"), meta(), None).unwrap();
        j.apply(rename(x, "b"), meta(), Some(Address(0x500)))
            .unwrap();
        j.undo(UndoScope::Global).unwrap();
        j.undo(UndoScope::Global).unwrap();
        j.redo(f).unwrap();
        let err = j.redo(UndoScope::Global).unwrap_err();
        assert!(matches!(
            err,
            Error::UndoConflict {
                seq: 1,
                blocked_by: 2
            }
        ));
        assert!(
            j.can_redo(UndoScope::Global),
            "refused entry stays redoable"
        );
        let r = Journal::replay(UserState::default(), j.entries().cloned().collect()).unwrap();
        assert_eq!(
            r.user_state().name(Address(x)),
            j.user_state().name(Address(x))
        );
    }

    mod differential {
        //! The journal's indices against a full scan of its entries, after
        //! every step and across reloads.
        use super::*;
        use proptest::prelude::*;
        use std::collections::BTreeSet;

        const SCOPES: [u64; 3] = [0, 1, 2];

        #[derive(Clone, Debug)]
        enum Step {
            Apply(Operation, Option<u64>),
            Undo(Option<u64>),
            Redo(Option<u64>),
            Reload,
        }

        fn leaf() -> impl Strategy<Value = Operation> {
            let address = (0u64..3).prop_map(Address);
            prop_oneof![
                (address.clone(), 0u8..3).prop_map(|(address, n)| Operation::Rename {
                    address,
                    name: Some(format!("n{n}")),
                }),
                (address.clone(), 0u8..2).prop_map(|(address, n)| Operation::AddTag {
                    address,
                    tag: format!("t{n}"),
                }),
                (address.clone(), 0u8..2).prop_map(|(address, n)| Operation::RemoveTag {
                    address,
                    tag: format!("t{n}"),
                }),
                (address, proptest::option::of(0u8..2)).prop_map(|(address, n)| {
                    Operation::Bookmark {
                        address,
                        note: n.map(|n| format!("b{n}")),
                    }
                }),
                (0u64..12, 0u8..3, 1usize..4).prop_map(|(a, byte, len)| Operation::PatchBytes {
                    address: Address(a),
                    bytes: vec![byte; len],
                }),
            ]
        }

        fn op() -> impl Strategy<Value = Operation> {
            prop_oneof![
                3 => leaf(),
                1 => proptest::collection::vec(leaf(), 0..4).prop_map(|ops| Operation::Batch { ops }),
            ]
        }

        fn scope() -> impl Strategy<Value = Option<u64>> {
            prop_oneof![Just(None), (0u64..3).prop_map(Some)]
        }

        fn step() -> impl Strategy<Value = Step> {
            prop_oneof![
                4 => (op(), scope()).prop_map(|(o, s)| Step::Apply(o, s)),
                2 => scope().prop_map(Step::Undo),
                2 => scope().prop_map(Step::Redo),
                1 => Just(Step::Reload),
            ]
        }

        fn to_scope(s: Option<u64>) -> UndoScope {
            s.map_or(UndoScope::Global, |f| UndoScope::Function(Address(f)))
        }

        fn seqs(j: &Journal, state: EntryState, f: Option<Address>) -> BTreeSet<u64> {
            j.entries()
                .filter(|e| e.state == state && (f.is_none() || e.scope == f))
                .map(|e| e.seq)
                .collect()
        }

        fn check_indices(j: &Journal) {
            let active = seqs(j, EntryState::Active, None);
            assert_eq!(j.active.iter().copied().collect::<BTreeSet<_>>(), active);
            let undone = seqs(j, EntryState::Undone, None);
            assert_eq!(
                j.redo.len(),
                undone.len(),
                "no duplicates in the redo stack"
            );
            assert_eq!(j.redo.iter().copied().collect::<BTreeSet<_>>(), undone);
            assert_eq!(j.can_undo(UndoScope::Global), !active.is_empty());
            assert_eq!(j.can_redo(UndoScope::Global), !undone.is_empty());
            for f in SCOPES.map(Address) {
                let scope = UndoScope::Function(f);
                let scoped_active = seqs(j, EntryState::Active, Some(f));
                let indexed: BTreeSet<u64> = j
                    .scoped_active
                    .get(&f)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default();
                assert_eq!(indexed, scoped_active);
                assert_eq!(j.can_undo(scope), !scoped_active.is_empty());
                assert_eq!(
                    j.last_active(scope),
                    scoped_active.iter().next_back().copied()
                );

                // The scoped stack is the global stack filtered by scope.
                let expected: Vec<u64> = j
                    .redo
                    .iter()
                    .copied()
                    .filter(|s| j.entry(*s).is_some_and(|e| e.scope == Some(f)))
                    .collect();
                let stack: Vec<u64> = j
                    .scoped_redo
                    .get(&f)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default();
                assert_eq!(stack, expected);
                assert_eq!(j.can_redo(scope), !expected.is_empty());
            }
            assert!(j.scoped_active.values().all(|s| !s.is_empty()));
            assert!(j.scoped_redo.values().all(|s| !s.is_empty()));
        }

        fn reload(j: &Journal) -> Journal {
            Journal::replay(patch_state(16), j.entries().cloned().collect()).unwrap()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(300))]
            #[test]
            fn indices_match_a_full_scan(steps in proptest::collection::vec(step(), 0..40)) {
                let mut j = Journal::new(patch_state(16));
                for s in steps {
                    let before = format!("{:?}", j.user_state());
                    match s {
                        Step::Apply(op, scope) => {
                            let _ = j.apply(op, meta(), scope.map(Address));
                        }
                        Step::Undo(sc) => {
                            if j.undo(to_scope(sc)).is_err() {
                                prop_assert_eq!(&before, &format!("{:?}", j.user_state()));
                            }
                        }
                        Step::Redo(sc) => {
                            if j.redo(to_scope(sc)).is_err() {
                                prop_assert_eq!(&before, &format!("{:?}", j.user_state()));
                            }
                        }
                        Step::Reload => j = reload(&j),
                    }
                    check_indices(&j);
                    let replayed = reload(&j);
                    check_indices(&replayed);
                    prop_assert_eq!(
                        format!("{:?}", j.user_state()),
                        format!("{:?}", replayed.user_state())
                    );
                }
            }
        }
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        #[derive(Clone, Debug)]
        enum Step {
            Apply {
                addr: u64,
                name: u8,
                scope: Option<u64>,
            },
            Undo(Option<u64>),
            Redo(Option<u64>),
        }

        fn scope_strategy() -> impl Strategy<Value = Option<u64>> {
            prop_oneof![Just(None), (0u64..2).prop_map(Some)]
        }

        fn step() -> impl Strategy<Value = Step> {
            prop_oneof![
                (0u64..3, 0u8..4, scope_strategy()).prop_map(|(addr, name, scope)| Step::Apply {
                    addr,
                    name,
                    scope
                }),
                scope_strategy().prop_map(Step::Undo),
                scope_strategy().prop_map(Step::Redo),
            ]
        }

        fn to_scope(s: Option<u64>) -> UndoScope {
            s.map_or(UndoScope::Global, |f| UndoScope::Function(Address(f)))
        }

        proptest! {
            #[test]
            fn live_state_equals_replay(steps in proptest::collection::vec(step(), 0..40)) {
                let mut j = Journal::default();
                for s in steps {
                    match s {
                        Step::Apply { addr, name, scope } => {
                            let op = Operation::Rename {
                                address: Address(addr),
                                name: Some(format!("n{name}")),
                            };
                            j.apply(op, meta(), scope.map(Address)).unwrap();
                        }
                        // Conflicts are allowed outcomes; they must not change state.
                        Step::Undo(sc) => { let _ = j.undo(to_scope(sc)); }
                        Step::Redo(sc) => { let _ = j.redo(to_scope(sc)); }
                    }
                    let r = Journal::replay(UserState::default(), j.entries().cloned().collect()).unwrap();
                    for a in 0..3 {
                        prop_assert_eq!(
                            r.user_state().name(Address(a)),
                            j.user_state().name(Address(a))
                        );
                    }
                }
            }
        }
    }
}
