//! Analysis results: functions, basic blocks, cross-references, strings.
//!
//! [`AnalysisResults`] is a *cache* (ADR 0002): it can always be recomputed
//! from the image and the journal. It uses persistent maps (`imbl`) so that
//! publishing a new snapshot after a small change costs O(log n), not O(n).

use std::sync::Arc;

use imbl::OrdMap;
use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressRange};
use crate::error::Error;
use crate::image::FunctionHintSource;
use crate::insn::Target;
use crate::pass::PassId;

/// Kind of a cross-reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum XrefKind {
    /// Code calls code.
    Call,
    /// Code jumps to code (including tail calls and conditional branches).
    Jump,
    /// Code reads data.
    Read,
    /// Code writes data.
    Write,
    /// Code reads and writes the same location in one instruction
    /// (`inc qword ptr [rip+x]`, `xchg`, `lock add`). One xref, not two.
    ReadWrite,
    /// The address is taken (`lea`, address-sized immediate, or a pointer
    /// stored in data).
    DataPtr,
}

/// A reference from one address to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Xref {
    /// Referencing instruction (or data word).
    pub from: Address,
    /// Referenced address.
    pub to: Address,
    /// Kind.
    pub kind: XrefKind,
}

/// How a CFG edge is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EdgeKind {
    /// Falls into the next block (no branch).
    Fallthrough,
    /// Unconditional jump.
    Jump,
    /// Conditional branch, taken.
    ConditionalTaken,
    /// Conditional branch, not taken.
    ConditionalNotTaken,
    /// One case of a resolved jump table.
    Switch,
    /// Jump leaving the function (tail call).
    TailCall,
}

/// An outgoing CFG edge of a basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Edge {
    /// Destination.
    pub target: Target,
    /// Kind.
    pub kind: EdgeKind,
}

/// A maximal straight-line run of instructions.
///
/// Invariant: `insn_lens` is non-empty, contains no zero, and sums to
/// `range.len()`. Enforced by [`BasicBlock::new`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BasicBlockRepr", into = "BasicBlockRepr")]
pub struct BasicBlock {
    range: AddressRange,
    insn_lens: Vec<u8>,
    /// Outgoing edges.
    pub successors: Vec<Edge>,
}

/// Wire form of [`BasicBlock`]; deserialization goes through
/// [`BasicBlock::new`] so it cannot bypass the invariants.
#[derive(Serialize, Deserialize)]
struct BasicBlockRepr {
    range: AddressRange,
    insn_lens: Vec<u8>,
    successors: Vec<Edge>,
}

impl TryFrom<BasicBlockRepr> for BasicBlock {
    type Error = Error;
    fn try_from(r: BasicBlockRepr) -> Result<Self, Error> {
        let block = BasicBlock::new(r.range.start(), r.insn_lens, r.successors)?;
        if block.range != r.range {
            return Err(Error::InvalidArgument(format!(
                "block {} does not match its instruction lengths",
                r.range
            )));
        }
        Ok(block)
    }
}

impl From<BasicBlock> for BasicBlockRepr {
    fn from(b: BasicBlock) -> Self {
        BasicBlockRepr {
            range: b.range,
            insn_lens: b.insn_lens,
            successors: b.successors,
        }
    }
}

impl BasicBlock {
    /// Creates a block starting at `start` from instruction lengths.
    pub fn new(start: Address, insn_lens: Vec<u8>, successors: Vec<Edge>) -> Result<Self, Error> {
        if insn_lens.is_empty() || insn_lens.contains(&0) {
            return Err(Error::InvalidArgument(format!(
                "block at {start} needs non-empty, non-zero instruction lengths"
            )));
        }
        let len: u64 = insn_lens.iter().map(|&l| u64::from(l)).sum();
        let range = AddressRange::from_len(start, len)?;
        Ok(BasicBlock {
            range,
            insn_lens,
            successors,
        })
    }

    /// Address range covered.
    #[must_use]
    pub fn range(&self) -> AddressRange {
        self.range
    }

    /// Start address.
    #[must_use]
    pub fn start(&self) -> Address {
        self.range.start()
    }

    /// Number of instructions.
    #[must_use]
    pub fn insn_count(&self) -> usize {
        self.insn_lens.len()
    }

    /// Instruction lengths in order.
    #[must_use]
    pub fn insn_lens(&self) -> &[u8] {
        &self.insn_lens
    }

    /// Addresses of the instructions in order.
    pub fn insn_addresses(&self) -> impl Iterator<Item = Address> + '_ {
        let start = self.range.start().get();
        self.insn_lens.iter().scan(start, |pc, &l| {
            let cur = *pc;
            *pc = pc.saturating_add(u64::from(l));
            Some(Address(cur))
        })
    }

    /// Length of the instruction starting exactly at `addr`, if any.
    #[must_use]
    pub fn insn_len_at(&self, addr: Address) -> Option<u8> {
        if !self.range.contains(addr) {
            return None;
        }
        self.insn_addresses()
            .zip(self.insn_lens.iter().copied())
            .find(|(a, _)| *a == addr)
            .map(|(_, l)| l)
    }
}

/// Why analysis created a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "hint", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FunctionSource {
    /// A loader hint (entry, symbol, FDE, ...).
    Hint(FunctionHintSource),
    /// Target of a direct call.
    CallTarget,
    /// Target of a tail call.
    TailCallTarget,
    /// Linear sweep found a prologue.
    Prologue,
    /// `create_function` operation.
    User,
    /// A `define_code` definition: the code has no other reason to be
    /// analysed, so it becomes a function root. Exists exactly as long as
    /// the definition does (ADR 0003, "who owns a function").
    UserCode,
}

/// Function attributes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FunctionFlags {
    /// Never returns (`exit`, `abort`, `__stack_chk_fail`, ...).
    pub noreturn: bool,
    /// Consists of a single jump to another function.
    pub thunk: bool,
    /// A PLT stub.
    pub plt: bool,
    /// Identified as library code (signatures; stage 4).
    pub library: bool,
}

/// A function: an entry point and the blocks reachable from it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    /// Entry address.
    pub entry: Address,
    /// Blocks sorted by start address. Normally contains a block starting
    /// at `entry`; may be empty if decoding failed at the entry.
    pub blocks: Vec<BasicBlock>,
    /// Attributes.
    pub flags: FunctionFlags,
    /// Why it exists.
    pub source: FunctionSource,
}

impl Function {
    /// A function with default flags. (No `Default`: a function always
    /// has a meaningful entry and source.) Set `flags` afterwards.
    #[must_use]
    pub fn new(entry: Address, source: FunctionSource, blocks: Vec<BasicBlock>) -> Self {
        Function {
            entry,
            blocks,
            flags: FunctionFlags::default(),
            source,
        }
    }

    /// The block containing `addr`.
    #[must_use]
    pub fn block_containing(&self, addr: Address) -> Option<&BasicBlock> {
        let idx = self.blocks.partition_point(|b| b.range().end() <= addr);
        self.blocks.get(idx).filter(|b| b.range().contains(addr))
    }

    /// Sum of block sizes in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.blocks.iter().map(|b| b.range().len()).sum()
    }

    /// Number of instructions.
    #[must_use]
    pub fn insn_count(&self) -> usize {
        self.blocks.iter().map(BasicBlock::insn_count).sum()
    }
}

/// Character encoding of a string literal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StringEncoding {
    /// 7-bit ASCII.
    #[default]
    Ascii,
    /// UTF-8 (contains non-ASCII).
    Utf8,
    /// UTF-16 little-endian.
    Utf16Le,
    /// UTF-16 big-endian.
    Utf16Be,
    /// UTF-32 little-endian (`wchar_t` on Linux).
    Utf32Le,
    /// UTF-32 big-endian.
    Utf32Be,
}

/// A string found in memory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringLiteral {
    /// Start address.
    pub address: Address,
    /// Encoding.
    pub encoding: StringEncoding,
    /// Size in bytes including the terminator, if any.
    pub byte_len: u64,
    /// Decoded text (lossy for invalid sequences).
    pub value: String,
}

/// A primitive or composite data layout for `define_data`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DataType {
    /// 1 byte.
    Byte,
    /// 2 bytes.
    Word,
    /// 4 bytes.
    Dword,
    /// 8 bytes.
    Qword,
    /// Pointer-sized.
    Pointer,
    /// IEEE single.
    Float,
    /// IEEE double.
    Double,
    /// Terminated string.
    String {
        /// Encoding.
        encoding: StringEncoding,
    },
    /// Fixed-size array.
    Array {
        /// Element type.
        element: Box<DataType>,
        /// Element count.
        count: u32,
    },
}

/// Maximum nesting of [`DataType::Array`].
pub const MAX_DATA_DEPTH: usize = 8;
/// Maximum size of one defined data item, in bytes (16 MiB).
pub const MAX_DATA_SIZE: u64 = 16 << 20;

impl DataType {
    /// Array nesting depth (0 for a scalar). Iterative: safe on any input.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut d = 0;
        let mut t = self;
        while let DataType::Array { element, .. } = t {
            d += 1;
            t = element;
        }
        d
    }

    /// Size in bytes for a pointer size of `ptr` bytes; `None` for
    /// variable-length types (`String`, or arrays of them) and on
    /// overflow.
    #[must_use]
    pub fn fixed_size(&self, ptr: u64) -> Option<u64> {
        let mut mult: u64 = 1;
        let mut t = self;
        loop {
            let base = match t {
                DataType::Byte => 1,
                DataType::Word => 2,
                DataType::Dword | DataType::Float => 4,
                DataType::Qword | DataType::Double => 8,
                DataType::Pointer => ptr,
                DataType::String { .. } => return None,
                DataType::Array { element, count } => {
                    mult = mult.checked_mul(u64::from(*count))?;
                    t = element;
                    continue;
                }
            };
            return mult.checked_mul(base);
        }
    }
}

/// A C type written as text (`"char *"`, `"struct stat"`). Parsed and
/// validated by the type system in a later stage; at stage 1 it is stored and
/// displayed verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TypeExpr(pub String);

/// State of the background analysis.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnalysisState {
    /// Not started.
    #[default]
    Idle,
    /// Passes are running.
    Running,
    /// All scheduled work finished.
    Done,
    /// Stopped by cancellation; results are partial but consistent.
    Cancelled,
    /// Stopped by an internal error (e.g. a pass panicked); results are
    /// partial but consistent, [`AnalysisProgress::error`] says why.
    Failed,
}

impl AnalysisState {
    /// True for states after which the driver publishes nothing more until
    /// the next `start`/`invalidate`: `Done`, `Cancelled`, `Failed`.
    /// Waiters (CLI) must stop on any of them.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            AnalysisState::Done | AnalysisState::Cancelled | AnalysisState::Failed
        )
    }
}

/// Progress reported in snapshots (for the status bar).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisProgress {
    /// Overall state.
    pub state: AnalysisState,
    /// Name of the pass currently running, if any.
    pub current_pass: Option<String>,
    /// Work units completed.
    pub done: u64,
    /// Work units known so far (may grow).
    pub total: u64,
    /// Why analysis is `Failed` (pass id and panic/error message).
    #[serde(default)]
    pub error: Option<String>,
}

/// Who owns a group of xrefs. A pass that recomputes something replaces
/// exactly the group it owns, so groups of different producers never
/// overwrite each other even when they start at the same address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum XrefOwner {
    /// Code xrefs of one function (keyed by entry). Removed together with
    /// the function.
    Function(Address),
    /// Xrefs found by a program-level pass in a region (e.g. pointers in
    /// `.data` found by the `xrefs` pass).
    Region {
        /// Producing pass.
        pass: PassId,
        /// Region scanned.
        range: AddressRange,
    },
}

/// Incremental update produced by an analysis pass and merged by the
/// scheduler into [`AnalysisResults`].
#[derive(Clone, Debug, Default)]
pub struct AnalysisDelta {
    /// Functions to insert or replace (keyed by entry).
    pub upsert_functions: Vec<Function>,
    /// Function entries to remove (their [`XrefOwner::Function`] groups
    /// are removed too).
    pub remove_functions: Vec<Address>,
    /// Replace the xref group of each owner with the given list (an empty
    /// list removes the group).
    pub set_xrefs: Vec<(XrefOwner, Vec<Xref>)>,
    /// Strings to insert or replace.
    pub upsert_strings: Vec<StringLiteral>,
    /// Remove all strings starting inside these ranges.
    pub remove_strings_in: Vec<AddressRange>,
}

impl AnalysisDelta {
    /// True if the delta changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.upsert_functions.is_empty()
            && self.remove_functions.is_empty()
            && self.set_xrefs.is_empty()
            && self.upsert_strings.is_empty()
            && self.remove_strings_in.is_empty()
    }
}

/// Multiset index: key → xref → number of groups containing it.
type XrefIndex = OrdMap<Address, OrdMap<Xref, u32>>;

/// The analysis cache visible through a [`crate::Snapshot`].
///
/// Cloning is O(1) (persistent maps). Indices are kept consistent by
/// [`AnalysisResults::apply`]; there is no other way to mutate.
#[derive(Clone, Debug, Default)]
pub struct AnalysisResults {
    functions: OrdMap<Address, Arc<Function>>,
    /// block start → (owning function entry → block end). A block may be
    /// shared by several functions; blocks of different functions may
    /// overlap.
    blocks: OrdMap<Address, OrdMap<Address, Address>>,
    /// Longest block ever indexed; bounds the backward scan in
    /// [`AnalysisResults::functions_containing`].
    max_block_len: u64,
    xref_groups: OrdMap<XrefOwner, Arc<[Xref]>>,
    xrefs_to: XrefIndex,
    xrefs_from: XrefIndex,
    strings: OrdMap<Address, Arc<StringLiteral>>,
    /// Progress of the producer.
    pub progress: AnalysisProgress,
}

impl AnalysisResults {
    /// Merges a delta. Order: removals, then upserts, then xref groups,
    /// then strings.
    pub fn apply(&mut self, delta: AnalysisDelta) {
        for entry in delta.remove_functions {
            self.remove_function(entry);
            self.set_xref_group(XrefOwner::Function(entry), Vec::new());
        }
        for f in delta.upsert_functions {
            let entry = f.entry;
            self.remove_function(entry);
            for b in &f.blocks {
                self.max_block_len = self.max_block_len.max(b.range().len());
                self.blocks
                    .entry(b.start())
                    .or_default()
                    .insert(entry, b.range().end());
            }
            self.functions.insert(entry, Arc::new(f));
        }
        for (owner, xrefs) in delta.set_xrefs {
            self.set_xref_group(owner, xrefs);
        }
        for r in delta.remove_strings_in {
            let doomed: Vec<Address> = self
                .strings
                .range(r.start()..r.end())
                .map(|(a, _)| *a)
                .collect();
            for a in doomed {
                self.strings.remove(&a);
            }
        }
        for s in delta.upsert_strings {
            self.strings.insert(s.address, Arc::new(s));
        }
    }

    fn remove_function(&mut self, entry: Address) {
        let Some(old) = self.functions.remove(&entry) else {
            return;
        };
        for b in &old.blocks {
            let now_empty = match self.blocks.get_mut(&b.start()) {
                Some(owners) => {
                    owners.remove(&entry);
                    owners.is_empty()
                }
                None => false,
            };
            if now_empty {
                self.blocks.remove(&b.start());
            }
        }
    }

    fn set_xref_group(&mut self, owner: XrefOwner, xrefs: Vec<Xref>) {
        if let Some(old) = self.xref_groups.remove(&owner) {
            for x in old.iter() {
                index_remove(&mut self.xrefs_to, x.to, x);
                index_remove(&mut self.xrefs_from, x.from, x);
            }
        }
        if xrefs.is_empty() {
            return;
        }
        let mut xrefs = xrefs;
        xrefs.sort_unstable();
        xrefs.dedup();
        for x in &xrefs {
            index_add(&mut self.xrefs_to, x.to, x);
            index_add(&mut self.xrefs_from, x.from, x);
        }
        self.xref_groups.insert(owner, Arc::from(xrefs));
    }

    /// All functions in address order.
    pub fn functions(&self) -> impl Iterator<Item = &Arc<Function>> + '_ {
        self.functions.values()
    }

    /// Number of functions.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// The function whose entry is exactly `entry`.
    #[must_use]
    pub fn function_at(&self, entry: Address) -> Option<&Arc<Function>> {
        self.functions.get(&entry)
    }

    /// All functions having a block that contains `addr`, the one whose
    /// block starts closest below `addr` first (ties: lower entry first).
    #[must_use]
    pub fn functions_containing(&self, addr: Address) -> Vec<&Arc<Function>> {
        let lo = Address(
            addr.get()
                .saturating_sub(self.max_block_len.saturating_sub(1)),
        );
        self.blocks
            .range(lo..=addr)
            .rev()
            .flat_map(|(_, owners)| owners.iter())
            .filter(|(_, end)| addr < **end)
            .filter_map(|(entry, _)| self.functions.get(entry))
            .collect()
    }

    /// The function a user most likely means at `addr`: the first of
    /// [`AnalysisResults::functions_containing`].
    #[must_use]
    pub fn function_containing(&self, addr: Address) -> Option<&Arc<Function>> {
        self.functions_containing(addr).into_iter().next()
    }

    /// Distinct xrefs pointing at `to`, in (from, to, kind) order.
    pub fn xrefs_to(&self, to: Address) -> impl Iterator<Item = Xref> + '_ {
        self.xrefs_to
            .get(&to)
            .into_iter()
            .flat_map(|m| m.keys().copied())
    }

    /// Distinct xrefs originating at `from`, in (from, to, kind) order.
    pub fn xrefs_from(&self, from: Address) -> impl Iterator<Item = Xref> + '_ {
        self.xrefs_from
            .get(&from)
            .into_iter()
            .flat_map(|m| m.keys().copied())
    }

    /// All xrefs, group by group (an xref reported by two owners appears
    /// twice; the JSON report de-duplicates).
    pub fn all_xrefs(&self) -> impl Iterator<Item = &Xref> + '_ {
        self.xref_groups.values().flat_map(|g| g.iter())
    }

    /// The xref group of an owner.
    #[must_use]
    pub fn xref_group(&self, owner: &XrefOwner) -> Option<&[Xref]> {
        self.xref_groups.get(owner).map(|g| &**g)
    }

    /// All strings in address order.
    pub fn strings(&self) -> impl Iterator<Item = &Arc<StringLiteral>> + '_ {
        self.strings.values()
    }

    /// The string covering `addr` (the closest one starting at or below
    /// it, if it extends past `addr`).
    #[must_use]
    pub fn string_containing(&self, addr: Address) -> Option<&Arc<StringLiteral>> {
        let (start, s) = self.strings.range(..=addr).next_back()?;
        let end = start.checked_add(s.byte_len.max(1))?;
        (addr < end).then_some(s)
    }

    /// The string starting exactly at `addr`.
    #[must_use]
    pub fn string_at(&self, addr: Address) -> Option<&Arc<StringLiteral>> {
        self.strings.get(&addr)
    }
}

fn index_add(index: &mut XrefIndex, key: Address, x: &Xref) {
    let counts = index.entry(key).or_default();
    let n = counts.get(x).copied().unwrap_or(0);
    counts.insert(*x, n.saturating_add(1));
}

fn index_remove(index: &mut XrefIndex, key: Address, x: &Xref) {
    let now_empty = match index.get_mut(&key) {
        Some(counts) => {
            match counts.get(x).copied() {
                Some(n) if n > 1 => {
                    counts.insert(*x, n - 1);
                }
                Some(_) => {
                    counts.remove(x);
                }
                None => {}
            }
            counts.is_empty()
        }
        None => false,
    };
    if now_empty {
        index.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(entry: u64, lens: Vec<u8>) -> Function {
        Function {
            entry: Address(entry),
            blocks: vec![BasicBlock::new(Address(entry), lens, vec![]).unwrap()],
            flags: FunctionFlags::default(),
            source: FunctionSource::User,
        }
    }

    #[test]
    fn block_deserialization_enforces_invariants() {
        let good = BasicBlock::new(Address(0x10), vec![1, 2], vec![]).unwrap();
        let json = serde_json::to_string(&good).unwrap();
        assert_eq!(serde_json::from_str::<BasicBlock>(&json).unwrap(), good);
        for bad in [
            r#"{"range":{"start":"0x10","end":"0x13"},"insn_lens":[],"successors":[]}"#,
            r#"{"range":{"start":"0x10","end":"0x13"},"insn_lens":[3,0],"successors":[]}"#,
            r#"{"range":{"start":"0x10","end":"0x20"},"insn_lens":[1,2],"successors":[]}"#,
        ] {
            assert!(serde_json::from_str::<BasicBlock>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn block_invariants() {
        assert!(BasicBlock::new(Address(0), vec![], vec![]).is_err());
        assert!(BasicBlock::new(Address(0), vec![1, 0], vec![]).is_err());
        let b = BasicBlock::new(Address(0x10), vec![1, 4, 2], vec![]).unwrap();
        assert_eq!(b.range().len(), 7);
        let addrs: Vec<u64> = b.insn_addresses().map(Address::get).collect();
        assert_eq!(addrs, vec![0x10, 0x11, 0x15]);
        assert_eq!(b.insn_len_at(Address(0x11)), Some(4));
        assert_eq!(b.insn_len_at(Address(0x12)), None);
    }

    #[test]
    fn xref_groups_are_replaced_and_indices_stay_consistent() {
        let mut r = AnalysisResults::default();
        let x1 = Xref {
            from: Address(0x10),
            to: Address(0x100),
            kind: XrefKind::Call,
        };
        let x2 = Xref {
            from: Address(0x11),
            to: Address(0x200),
            kind: XrefKind::Read,
        };
        r.apply(AnalysisDelta {
            upsert_functions: vec![func(0x10, vec![1, 1])],
            set_xrefs: vec![(XrefOwner::Function(Address(0x10)), vec![x1, x2])],
            ..Default::default()
        });
        assert_eq!(r.xrefs_to(Address(0x100)).count(), 1);
        let snapshot_before = r.clone();
        r.apply(AnalysisDelta {
            set_xrefs: vec![(XrefOwner::Function(Address(0x10)), vec![x2])],
            ..Default::default()
        });
        assert_eq!(r.xrefs_to(Address(0x100)).count(), 0);
        assert_eq!(r.xrefs_from(Address(0x11)).count(), 1);
        // The old clone is unaffected (persistent structure).
        assert_eq!(snapshot_before.xrefs_to(Address(0x100)).count(), 1);
        r.apply(AnalysisDelta {
            remove_functions: vec![Address(0x10)],
            ..Default::default()
        });
        assert_eq!(r.function_count(), 0);
        assert_eq!(r.all_xrefs().count(), 0);
        assert!(r.function_containing(Address(0x10)).is_none());
    }

    #[test]
    fn function_containing_uses_block_ranges() {
        let mut r = AnalysisResults::default();
        r.apply(AnalysisDelta {
            upsert_functions: vec![func(0x10, vec![2, 2]), func(0x20, vec![1])],
            ..Default::default()
        });
        assert_eq!(
            r.function_containing(Address(0x13)).map(|f| f.entry),
            Some(Address(0x10))
        );
        assert!(r.function_containing(Address(0x14)).is_none());
        assert_eq!(
            r.function_containing(Address(0x20)).map(|f| f.entry),
            Some(Address(0x20))
        );
    }

    #[test]
    fn strings_range_removal() {
        let mut r = AnalysisResults::default();
        let s = |a: u64| StringLiteral {
            address: Address(a),
            encoding: StringEncoding::Ascii,
            byte_len: 2,
            value: "a".into(),
        };
        r.apply(AnalysisDelta {
            upsert_strings: vec![s(1), s(5), s(9)],
            ..Default::default()
        });
        r.apply(AnalysisDelta {
            remove_strings_in: vec![AddressRange::new(Address(2), Address(9)).unwrap()],
            ..Default::default()
        });
        let left: Vec<u64> = r.strings().map(|s| s.address.get()).collect();
        assert_eq!(left, vec![1, 9]);
    }

    fn xref(from: u64, to: u64) -> Xref {
        Xref {
            from: Address(from),
            to: Address(to),
            kind: XrefKind::DataPtr,
        }
    }

    #[test]
    fn groups_with_same_start_address_do_not_collide() {
        // `_start` at the beginning of .text and a region scan of .text
        // used to share the key 0x10.
        let mut r = AnalysisResults::default();
        let region = XrefOwner::Region {
            pass: crate::pass::passes::XREFS,
            range: AddressRange::from_len(Address(0x10), 0x100).unwrap(),
        };
        r.apply(AnalysisDelta {
            set_xrefs: vec![
                (XrefOwner::Function(Address(0x10)), vec![xref(0x11, 0x500)]),
                (region.clone(), vec![xref(0x40, 0x600)]),
            ],
            ..Default::default()
        });
        assert_eq!(r.xrefs_to(Address(0x500)).count(), 1);
        assert_eq!(r.xrefs_to(Address(0x600)).count(), 1);
        assert_eq!(r.xref_group(&region).map(<[Xref]>::len), Some(1));
    }

    #[test]
    fn duplicate_xref_survives_recomputing_one_owner() {
        let mut r = AnalysisResults::default();
        let a = XrefOwner::Function(Address(0x10));
        let b = XrefOwner::Function(Address(0x20));
        r.apply(AnalysisDelta {
            set_xrefs: vec![
                (a.clone(), vec![xref(0x18, 0x500)]),
                (b, vec![xref(0x18, 0x500)]),
            ],
            ..Default::default()
        });
        assert_eq!(r.xrefs_to(Address(0x500)).count(), 1, "distinct view");
        r.apply(AnalysisDelta {
            set_xrefs: vec![(a, Vec::new())],
            ..Default::default()
        });
        assert_eq!(r.xrefs_to(Address(0x500)).count(), 1, "still owned by b");
        assert_eq!(r.xrefs_from(Address(0x18)).count(), 1);
    }

    #[test]
    fn overlapping_and_shared_blocks() {
        let mut r = AnalysisResults::default();
        // f1: one long block [0x10, 0x20); f2: block [0x18, 0x1a).
        let f1 = func(0x10, vec![8, 8]);
        let mut f2 = func(0x18, vec![2]);
        // f3 shares f2's block start (shared tail).
        let mut f3 = func(0x30, vec![1]);
        f3.blocks
            .push(BasicBlock::new(Address(0x18), vec![2], vec![]).unwrap());
        f2.entry = Address(0x18);
        r.apply(AnalysisDelta {
            upsert_functions: vec![f1, f2, f3],
            ..Default::default()
        });
        assert_eq!(
            r.function_containing(Address(0x1c)).map(|f| f.entry),
            Some(Address(0x10))
        );
        let at_19: Vec<u64> = r
            .functions_containing(Address(0x19))
            .iter()
            .map(|f| f.entry.get())
            .collect();
        assert_eq!(at_19, vec![0x18, 0x30, 0x10]);
        // Removing the first owner of the shared block re-indexes it.
        r.apply(AnalysisDelta {
            remove_functions: vec![Address(0x18)],
            ..Default::default()
        });
        assert_eq!(
            r.function_containing(Address(0x18)).map(|f| f.entry),
            Some(Address(0x30))
        );
    }

    #[test]
    fn literal_conventions_compile() {
        let s = StringLiteral {
            address: Address(1),
            value: "x".into(),
            ..Default::default()
        };
        assert_eq!(s.encoding, StringEncoding::Ascii);
        let f = Function::new(Address(2), FunctionSource::User, Vec::new());
        assert_eq!(f.flags, FunctionFlags::default());
        let img = crate::image::LoadedImage {
            info: crate::image::BinaryInfo {
                bits: 32,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(img.symbols.is_empty() && img.info.bits == 32);
    }

    #[test]
    fn data_type_size_and_depth() {
        let arr = DataType::Array {
            element: Box::new(DataType::Array {
                element: Box::new(DataType::Dword),
                count: 3,
            }),
            count: 2,
        };
        assert_eq!(arr.depth(), 2);
        assert_eq!(arr.fixed_size(8), Some(24));
        let s = DataType::String {
            encoding: StringEncoding::Ascii,
        };
        assert_eq!(s.fixed_size(8), None);
        let huge = DataType::Array {
            element: Box::new(DataType::Array {
                element: Box::new(DataType::Qword),
                count: u32::MAX,
            }),
            count: u32::MAX,
        };
        assert_eq!(huge.fixed_size(8), None, "overflow is None, not a wrap");
    }

    #[test]
    fn new_enum_variants_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&XrefKind::ReadWrite).unwrap(),
            "\"read_write\""
        );
        assert_eq!(
            serde_json::to_string(&StringEncoding::Utf32Le).unwrap(),
            "\"utf32_le\""
        );
        assert_eq!(
            serde_json::to_string(&StringEncoding::Utf32Be).unwrap(),
            "\"utf32_be\""
        );
    }
}
