//! User operations and the user-state layer they modify.
//!
//! Every change to the model made by the UI, CLI, scripts or plugins is an
//! [`Operation`]. Applying an operation to [`UserState`] yields its exact
//! inverse (also an `Operation`), which the [`crate::Journal`] stores for
//! undo. See ADR 0002.

use imbl::OrdMap;
use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressRange};
use crate::error::Error;
use crate::memory::MemoryMap;
use crate::model::{DataType, TypeExpr};
use crate::text::{is_clean_label, is_clean_text};

/// Maximum length of a user-supplied name, in bytes.
pub const MAX_NAME_LEN: usize = 1024;
/// Maximum length of a comment or bookmark note, in bytes.
pub const MAX_COMMENT_LEN: usize = 64 * 1024;
/// Maximum length of a tag, in bytes.
pub const MAX_TAG_LEN: usize = 64;
/// Maximum number of operations in one [`Operation::Batch`], counting
/// nested batches and their contents.
pub const MAX_BATCH_OPS: usize = 10_000;
/// Maximum nesting of [`Operation::Batch`].
pub const MAX_BATCH_DEPTH: usize = 4;
/// Maximum number of bytes that may differ from the original image at
/// once (each costs a map entry). Any change that would grow the overlay
/// past this is refused, including a scoped undo of a patch that had
/// restored original bytes; a change that shrinks the overlay always passes.
pub const MAX_PATCHED_BYTES: usize = 64 << 20;
/// Upper bound of the overlay on the way through a replay. A replay visits
/// states the live session never had (a scoped undo can remove a rollback
/// from the middle of the journal), so only its final state must fit
/// [`MAX_PATCHED_BYTES`]; this bound only stops a forged project from
/// exhausting memory.
pub const MAX_REPLAY_PATCHED_BYTES: usize = 4 * MAX_PATCHED_BYTES;
/// Maximum length of one operation (or its inverse) as JSON. The single
/// source of truth for storage: a store must be able to read back anything
/// of this size, so every accepted operation stays readable.
pub const MAX_OPERATION_JSON_BYTES: usize = 32 << 20;
/// Maximum size of one byte patch.
pub const MAX_PATCH_LEN: usize = 64 * 1024;

/// A change to the user layer of the model.
///
/// `None` in an `Option` field means "remove / reset to automatic".
/// Serialized with a `"op"` tag; the JSON form is what the project store
/// persists, so variants and fields may only be *added* (ADR 0002).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Operation {
    /// Set (or with `None` reset) the user name of an address.
    Rename {
        /// Address being named.
        address: Address,
        /// New name.
        name: Option<String>,
    },
    /// Set (or reset) the C type of a function, global or data item.
    SetType {
        /// Address.
        address: Address,
        /// Type.
        ty: Option<TypeExpr>,
    },
    /// Set (or remove) the comment at an address.
    Comment {
        /// Address.
        address: Address,
        /// Text.
        text: Option<String>,
    },
    /// Force code at an address (analysis will decode from here).
    DefineCode {
        /// Address.
        address: Address,
    },
    /// Force data of a type at an address.
    DefineData {
        /// Address.
        address: Address,
        /// Layout.
        ty: DataType,
    },
    /// Remove a user code/data definition (back to automatic).
    Undefine {
        /// Address.
        address: Address,
    },
    /// Force a function to start at an address.
    CreateFunction {
        /// Entry.
        address: Address,
    },
    /// Suppress the (auto-detected) function at an address.
    DeleteFunction {
        /// Entry.
        address: Address,
    },
    /// Remove a user create/delete override for a function.
    ResetFunction {
        /// Entry.
        address: Address,
    },
    /// Overwrite bytes (in the patch overlay; the original is kept).
    PatchBytes {
        /// First byte.
        address: Address,
        /// New bytes.
        bytes: Vec<u8>,
    },
    /// Set (or with `None` remove) a bookmark.
    Bookmark {
        /// Address.
        address: Address,
        /// Note; `Some("")` is a bookmark without a note.
        note: Option<String>,
    },
    /// Add a tag to an address.
    AddTag {
        /// Address.
        address: Address,
        /// Tag name.
        tag: String,
    },
    /// Remove a tag from an address.
    RemoveTag {
        /// Address.
        address: Address,
        /// Tag name.
        tag: String,
    },
    /// Several operations as one undo step. Applied in order; an empty
    /// batch is a no-op.
    Batch {
        /// Operations.
        ops: Vec<Operation>,
    },
}

/// Which aspect of the model an operation touches. Analysis passes declare
/// the kinds they depend on; the scheduler re-runs only those (ADR 0003).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Names (display only).
    Name,
    /// Types (feed type propagation, decompiler).
    Type,
    /// Comments (display only).
    Comment,
    /// Bookmarks and tags (display only).
    Annotation,
    /// Code/data definitions (affect disassembly and function discovery).
    Definition,
    /// Function create/delete overrides.
    Function,
    /// Byte patches (affect everything that reads bytes).
    Bytes,
}

impl ChangeKind {
    /// True if this kind can change analysis results (not just display).
    #[must_use]
    pub fn affects_analysis(self) -> bool {
        matches!(
            self,
            ChangeKind::Type | ChangeKind::Definition | ChangeKind::Function | ChangeKind::Bytes
        )
    }
}

/// One touched item: kind plus the address range it covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Change {
    /// Aspect.
    pub kind: ChangeKind,
    /// Addresses.
    pub range: AddressRange,
}

impl Change {
    fn at(kind: ChangeKind, address: Address) -> Change {
        let range =
            AddressRange::from_len(address, 1).unwrap_or_else(|_| AddressRange::empty_at(address));
        Change { kind, range }
    }

    /// True if two changes touch the same item (used for undo conflicts).
    #[must_use]
    pub fn conflicts_with(&self, other: &Change) -> bool {
        self.kind == other.kind
            && (self.range.overlaps(&other.range) || self.range.start() == other.range.start())
    }
}

impl Operation {
    /// The items this operation touches.
    #[must_use]
    pub fn changes(&self) -> Vec<Change> {
        use ChangeKind as K;
        match self {
            Operation::Rename { address, .. } => vec![Change::at(K::Name, *address)],
            Operation::SetType { address, .. } => vec![Change::at(K::Type, *address)],
            Operation::Comment { address, .. } => vec![Change::at(K::Comment, *address)],
            Operation::DefineCode { address }
            | Operation::DefineData { address, .. }
            | Operation::Undefine { address } => vec![Change::at(K::Definition, *address)],
            Operation::CreateFunction { address }
            | Operation::DeleteFunction { address }
            | Operation::ResetFunction { address } => vec![Change::at(K::Function, *address)],
            Operation::PatchBytes { address, bytes } => {
                let range = AddressRange::from_len(*address, bytes.len() as u64)
                    .unwrap_or_else(|_| AddressRange::empty_at(*address));
                vec![Change {
                    kind: K::Bytes,
                    range,
                }]
            }
            Operation::Bookmark { address, .. }
            | Operation::AddTag { address, .. }
            | Operation::RemoveTag { address, .. } => vec![Change::at(K::Annotation, *address)],
            Operation::Batch { ops } => ops.iter().flat_map(Operation::changes).collect(),
        }
    }

    /// The address the operation is "about" (first one for a batch). Used to
    /// pick the function scope for per-function undo.
    #[must_use]
    pub fn primary_address(&self) -> Option<Address> {
        self.changes().first().map(|c| c.range.start())
    }

    /// Checks arguments without touching state.
    pub fn validate(&self) -> Result<(), Error> {
        self.check_batch_shape()?;
        self.validate_contents()?;
        if self.json_size_bound() > MAX_OPERATION_JSON_BYTES {
            return Err(Error::InvalidOperation(format!(
                "operation is larger than {MAX_OPERATION_JSON_BYTES} bytes as JSON"
            )));
        }
        Ok(())
    }

    /// Like [`Operation::validate`] but consumes the operation. A rejected
    /// batch is taken apart iteratively: the compiler-generated drop would
    /// recurse and overflow the stack on the depth this check exists for.
    pub(crate) fn validated(self) -> Result<Self, Error> {
        match self.validate() {
            Ok(()) => Ok(self),
            Err(e) => {
                let mut stack = vec![self];
                while let Some(op) = stack.pop() {
                    if let Operation::Batch { ops } = op {
                        stack.extend(ops);
                    }
                }
                Err(e)
            }
        }
    }

    /// An upper bound of the JSON length, for an operation whose contents
    /// passed validation: such strings escape to at most twice their length
    /// and a patch byte takes at most four characters (`255,`).
    pub(crate) fn json_size_bound(&self) -> usize {
        const FIXED: usize = 128;
        const PER_DATA_LEVEL: usize = 64;
        let text = |s: &Option<String>| s.as_ref().map_or(0, |t| t.len().saturating_mul(2));
        let payload = match self {
            Operation::Rename { name, .. } => text(name),
            Operation::Comment { text: t, .. } => text(t),
            Operation::Bookmark { note, .. } => text(note),
            Operation::SetType { ty, .. } => ty.as_ref().map_or(0, |t| t.0.len().saturating_mul(2)),
            Operation::AddTag { tag, .. } | Operation::RemoveTag { tag, .. } => {
                tag.len().saturating_mul(2)
            }
            Operation::DefineData { ty, .. } => PER_DATA_LEVEL.saturating_mul(ty.depth() + 1),
            Operation::PatchBytes { bytes, .. } => bytes.len().saturating_mul(4),
            Operation::Batch { ops } => ops
                .iter()
                .fold(0usize, |n, o| n.saturating_add(o.json_size_bound())),
            _ => 0,
        };
        payload.saturating_add(FIXED)
    }

    /// Iterative, so that a pathologically deep batch built by a plugin or
    /// IPC client is rejected before any recursion over it.
    fn check_batch_shape(&self) -> Result<(), Error> {
        let mut total = 0usize;
        let mut stack: Vec<(&Operation, usize)> = vec![(self, 0)];
        while let Some((op, depth)) = stack.pop() {
            let Operation::Batch { ops } = op else {
                continue;
            };
            let depth = depth + 1;
            if depth > MAX_BATCH_DEPTH {
                return Err(Error::InvalidOperation(format!(
                    "batch nested deeper than {MAX_BATCH_DEPTH}"
                )));
            }
            total = total.saturating_add(ops.len());
            if total > MAX_BATCH_OPS {
                return Err(Error::InvalidOperation(format!(
                    "batch has more than {MAX_BATCH_OPS} operations"
                )));
            }
            stack.extend(ops.iter().map(|o| (o, depth)));
        }
        Ok(())
    }

    fn validate_contents(&self) -> Result<(), Error> {
        let bad = |m: String| Err(Error::InvalidOperation(m));
        match self {
            Operation::Rename {
                name: Some(name), ..
            } => {
                if name.is_empty() || name.len() > MAX_NAME_LEN {
                    return bad(format!("name must be 1..={MAX_NAME_LEN} bytes"));
                }
                if name.chars().any(char::is_whitespace) || !is_clean_label(name) {
                    return bad(format!(
                        "name {name:?} contains whitespace, control or invisible characters"
                    ));
                }
            }
            Operation::Comment { text: Some(t), .. }
            | Operation::Bookmark { note: Some(t), .. } => {
                if t.len() > MAX_COMMENT_LEN {
                    return bad(format!("text longer than {MAX_COMMENT_LEN} bytes"));
                }
                if !is_clean_text(t) {
                    return bad("text contains control or bidi override characters".into());
                }
            }
            Operation::SetType { ty: Some(t), .. } => {
                if t.0.trim().is_empty() || t.0.len() > MAX_NAME_LEN || !is_clean_label(&t.0) {
                    return bad("type must be non-empty, short and printable".into());
                }
            }
            Operation::AddTag { tag, .. } | Operation::RemoveTag { tag, .. } => {
                if tag.is_empty() || tag.len() > MAX_TAG_LEN || !is_clean_label(tag) {
                    return bad(format!("tag must be 1..={MAX_TAG_LEN} printable bytes"));
                }
            }
            Operation::DefineData { ty, .. } => {
                if ty.depth() > crate::model::MAX_DATA_DEPTH {
                    return bad(format!(
                        "data type nested deeper than {}",
                        crate::model::MAX_DATA_DEPTH
                    ));
                }
                let mut scalar = ty;
                while let DataType::Array { element, .. } = scalar {
                    scalar = element;
                }
                let too_big = match ty.fixed_size(8) {
                    Some(n) => n == 0 || n > crate::model::MAX_DATA_SIZE,
                    // Arrays of strings have no fixed size: not supported.
                    None => !matches!(scalar, DataType::String { .. }) || ty.depth() > 0,
                };
                if too_big {
                    return bad(format!(
                        "data item must be 1..={} bytes",
                        crate::model::MAX_DATA_SIZE
                    ));
                }
            }
            Operation::PatchBytes { bytes, .. } => {
                if bytes.is_empty() || bytes.len() > MAX_PATCH_LEN {
                    return bad(format!("patch must be 1..={MAX_PATCH_LEN} bytes"));
                }
            }
            Operation::Batch { ops } => {
                for op in ops {
                    op.validate_contents()?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// A user code/data definition at an address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Definition {
    /// Code.
    Code,
    /// Data of a type.
    Data {
        /// Layout.
        ty: DataType,
    },
}

/// A user override of function discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionOverride {
    /// A function must exist here.
    Create,
    /// No function may exist here.
    Delete,
}

/// The user layer: everything the journal determines. Cheap to clone
/// (persistent maps; byte regions are shared).
#[derive(Clone, Debug, Default)]
pub struct UserState {
    names: OrdMap<Address, String>,
    types: OrdMap<Address, TypeExpr>,
    comments: OrdMap<Address, String>,
    definitions: OrdMap<Address, Definition>,
    functions: OrdMap<Address, FunctionOverride>,
    bookmarks: OrdMap<Address, String>,
    tags: OrdMap<Address, imbl::OrdSet<String>>,
    memory: MemoryMap,
}

fn set_slot<V: Clone>(map: &mut OrdMap<Address, V>, key: Address, value: Option<V>) -> Option<V> {
    match value {
        Some(v) => map.insert(key, v),
        None => map.remove(&key),
    }
}

impl UserState {
    /// Fresh state over the image's memory (no patches).
    #[must_use]
    pub fn new(memory: MemoryMap) -> Self {
        UserState {
            memory,
            ..Default::default()
        }
    }

    /// Validates and applies `op`, returning its inverse. On error the state
    /// is unchanged (batches are applied to a copy first).
    pub fn apply(&mut self, op: &Operation) -> Result<Operation, Error> {
        self.apply_limited(op, MAX_PATCHED_BYTES)
    }

    /// [`UserState::apply`] with an explicit overlay limit.
    pub(crate) fn apply_limited(
        &mut self,
        op: &Operation,
        patched_limit: usize,
    ) -> Result<Operation, Error> {
        op.validate()?;
        if let Operation::Batch { ops } = op {
            let mut scratch = self.clone();
            let mut inverses = Vec::with_capacity(ops.len());
            for o in ops {
                // A no-op's inverse is an empty batch; keeping it would
                // make the inverse one level deeper than the original.
                let inverse = scratch.apply_limited(o, patched_limit)?;
                if !matches!(&inverse, Operation::Batch { ops } if ops.is_empty()) {
                    inverses.push(inverse);
                }
            }
            inverses.reverse();
            *self = scratch;
            return Ok(Operation::Batch { ops: inverses });
        }
        self.apply_one(op, patched_limit)
    }

    fn apply_one(&mut self, op: &Operation, patched_limit: usize) -> Result<Operation, Error> {
        Ok(match op {
            Operation::Rename { address, name } => {
                let prev = set_slot(&mut self.names, *address, name.clone());
                Operation::Rename {
                    address: *address,
                    name: prev,
                }
            }
            Operation::SetType { address, ty } => {
                let prev = set_slot(&mut self.types, *address, ty.clone());
                Operation::SetType {
                    address: *address,
                    ty: prev,
                }
            }
            Operation::Comment { address, text } => {
                let prev = set_slot(&mut self.comments, *address, text.clone());
                Operation::Comment {
                    address: *address,
                    text: prev,
                }
            }
            Operation::DefineCode { address } => {
                let prev = set_slot(&mut self.definitions, *address, Some(Definition::Code));
                definition_inverse(*address, prev)
            }
            Operation::DefineData { address, ty } => {
                let prev = set_slot(
                    &mut self.definitions,
                    *address,
                    Some(Definition::Data { ty: ty.clone() }),
                );
                definition_inverse(*address, prev)
            }
            Operation::Undefine { address } => {
                let prev = set_slot(&mut self.definitions, *address, None);
                definition_inverse(*address, prev)
            }
            Operation::CreateFunction { address } => {
                let prev = set_slot(
                    &mut self.functions,
                    *address,
                    Some(FunctionOverride::Create),
                );
                function_inverse(*address, prev)
            }
            Operation::DeleteFunction { address } => {
                let prev = set_slot(
                    &mut self.functions,
                    *address,
                    Some(FunctionOverride::Delete),
                );
                function_inverse(*address, prev)
            }
            Operation::ResetFunction { address } => {
                let prev = set_slot(&mut self.functions, *address, None);
                function_inverse(*address, prev)
            }
            Operation::PatchBytes { address, bytes } => {
                let old = self
                    .memory
                    .read(*address, bytes.len())
                    .ok_or_else(|| {
                        Error::InvalidOperation(format!(
                            "patch at {address} (+{}) is not mapped",
                            bytes.len()
                        ))
                    })?
                    .into_owned();
                let patched = self.memory.with_patch(*address, bytes)?;
                check_patch_growth(
                    self.memory.patch_count(),
                    patched.patch_count(),
                    patched_limit,
                )?;
                self.memory = patched;
                Operation::PatchBytes {
                    address: *address,
                    bytes: old,
                }
            }
            Operation::Bookmark { address, note } => {
                let prev = set_slot(&mut self.bookmarks, *address, note.clone());
                Operation::Bookmark {
                    address: *address,
                    note: prev,
                }
            }
            Operation::AddTag { address, tag } => {
                let set = self.tags.entry(*address).or_default();
                if set.insert(tag.clone()).is_some() {
                    Operation::Batch { ops: Vec::new() }
                } else {
                    Operation::RemoveTag {
                        address: *address,
                        tag: tag.clone(),
                    }
                }
            }
            Operation::RemoveTag { address, tag } => {
                let removed = match self.tags.get_mut(address) {
                    Some(set) => set.remove(tag).is_some(),
                    None => false,
                };
                if self.tags.get(address).is_some_and(imbl::OrdSet::is_empty) {
                    self.tags.remove(address);
                }
                if removed {
                    Operation::AddTag {
                        address: *address,
                        tag: tag.clone(),
                    }
                } else {
                    Operation::Batch { ops: Vec::new() }
                }
            }
            Operation::Batch { .. } => self.apply_limited(op, patched_limit)?,
        })
    }

    /// User name at an address.
    #[must_use]
    pub fn name(&self, address: Address) -> Option<&str> {
        self.names.get(&address).map(String::as_str)
    }

    /// All user names in address order.
    pub fn names(&self) -> impl Iterator<Item = (Address, &str)> + '_ {
        self.names.iter().map(|(a, n)| (*a, n.as_str()))
    }

    /// User type at an address.
    #[must_use]
    pub fn type_at(&self, address: Address) -> Option<&TypeExpr> {
        self.types.get(&address)
    }

    /// Comment at an address.
    #[must_use]
    pub fn comment(&self, address: Address) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    /// All comments in address order.
    pub fn comments(&self) -> impl Iterator<Item = (Address, &str)> + '_ {
        self.comments.iter().map(|(a, n)| (*a, n.as_str()))
    }

    /// User code/data definition at an address.
    #[must_use]
    pub fn definition(&self, address: Address) -> Option<&Definition> {
        self.definitions.get(&address)
    }

    /// The definition starting at or closest below `address`.
    #[must_use]
    pub fn definition_at_or_before(&self, address: Address) -> Option<(Address, &Definition)> {
        self.definitions
            .range(..=address)
            .next_back()
            .map(|(a, d)| (*a, d))
    }

    /// All definitions in address order.
    pub fn definitions(&self) -> impl Iterator<Item = (Address, &Definition)> + '_ {
        self.definitions.iter().map(|(a, d)| (*a, d))
    }

    /// Function override at an address.
    #[must_use]
    pub fn function_override(&self, address: Address) -> Option<FunctionOverride> {
        self.functions.get(&address).copied()
    }

    /// All function overrides in address order.
    pub fn function_overrides(&self) -> impl Iterator<Item = (Address, FunctionOverride)> + '_ {
        self.functions.iter().map(|(a, o)| (*a, *o))
    }

    /// Bookmark note at an address.
    #[must_use]
    pub fn bookmark(&self, address: Address) -> Option<&str> {
        self.bookmarks.get(&address).map(String::as_str)
    }

    /// All bookmarks in address order.
    pub fn bookmarks(&self) -> impl Iterator<Item = (Address, &str)> + '_ {
        self.bookmarks.iter().map(|(a, n)| (*a, n.as_str()))
    }

    /// Tags at an address, sorted.
    pub fn tags(&self, address: Address) -> impl Iterator<Item = &str> + '_ {
        self.tags
            .get(&address)
            .into_iter()
            .flat_map(|s| s.iter().map(String::as_str))
    }

    /// Memory with user patches applied.
    #[must_use]
    pub fn memory(&self) -> &MemoryMap {
        &self.memory
    }
}

fn check_patch_growth(before: usize, after: usize, limit: usize) -> Result<(), Error> {
    if after > before && after > limit {
        return Err(Error::InvalidOperation(format!(
            "more than {limit} patched bytes"
        )));
    }
    Ok(())
}

fn definition_inverse(address: Address, prev: Option<Definition>) -> Operation {
    match prev {
        None => Operation::Undefine { address },
        Some(Definition::Code) => Operation::DefineCode { address },
        Some(Definition::Data { ty }) => Operation::DefineData { address, ty },
    }
}

fn function_inverse(address: Address, prev: Option<FunctionOverride>) -> Operation {
    match prev {
        None => Operation::ResetFunction { address },
        Some(FunctionOverride::Create) => Operation::CreateFunction { address },
        Some(FunctionOverride::Delete) => Operation::DeleteFunction { address },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryRegion, Permissions, SharedBytes};

    fn state() -> UserState {
        let r = MemoryRegion::new(
            AddressRange::from_len(Address(0x1000), 16).unwrap(),
            SharedBytes::from(vec![0xAA; 16]),
            Permissions::RX,
        )
        .unwrap();
        UserState::new(MemoryMap::new(vec![r]).unwrap())
    }

    fn sample_ops() -> Vec<Operation> {
        let a = Address(0x1004);
        vec![
            Operation::Rename {
                address: a,
                name: Some("main".into()),
            },
            Operation::Rename {
                address: a,
                name: Some("real_main".into()),
            },
            Operation::SetType {
                address: a,
                ty: Some(TypeExpr("int (int, char **)".into())),
            },
            Operation::Comment {
                address: a,
                text: Some("entry".into()),
            },
            Operation::DefineCode { address: a },
            Operation::DefineData {
                address: a,
                ty: DataType::Qword,
            },
            Operation::Undefine { address: a },
            Operation::CreateFunction { address: a },
            Operation::DeleteFunction { address: a },
            Operation::ResetFunction { address: a },
            Operation::PatchBytes {
                address: a,
                bytes: vec![0x90, 0x90],
            },
            Operation::Bookmark {
                address: a,
                note: Some(String::new()),
            },
            Operation::AddTag {
                address: a,
                tag: "crypto".into(),
            },
            Operation::AddTag {
                address: a,
                tag: "crypto".into(),
            },
            Operation::RemoveTag {
                address: a,
                tag: "crypto".into(),
            },
            Operation::Batch {
                ops: vec![
                    Operation::Rename {
                        address: Address(0x1000),
                        name: Some("start".into()),
                    },
                    Operation::Comment {
                        address: Address(0x1000),
                        text: Some("x".into()),
                    },
                ],
            },
        ]
    }

    fn fingerprint(s: &UserState) -> String {
        format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            s.names,
            s.types,
            s.comments,
            s.definitions,
            s.functions,
            s.bookmarks,
            s.tags,
            s.memory.patches().collect::<Vec<_>>()
        )
    }

    #[test]
    fn every_operation_is_exactly_reversible() {
        let mut s = state();
        let mut history = vec![fingerprint(&s)];
        let mut inverses = Vec::new();
        for op in sample_ops() {
            inverses.push(s.apply(&op).unwrap());
            history.push(fingerprint(&s));
        }
        history.pop();
        while let Some(inv) = inverses.pop() {
            s.apply(&inv).unwrap();
            assert_eq!(fingerprint(&s), history.pop().unwrap());
        }
        assert_eq!(s.memory().patch_count(), 0);
    }

    #[test]
    fn spoofing_characters_are_rejected() {
        let a = Address(1);
        for bad in [
            Operation::Rename {
                address: a,
                name: Some("gnp\u{202e}exe".into()),
            },
            Operation::Rename {
                address: a,
                name: Some("mai\u{200b}n".into()),
            },
            Operation::AddTag {
                address: a,
                tag: "x\u{2066}".into(),
            },
            Operation::SetType {
                address: a,
                ty: Some(TypeExpr("int\u{1b}[0m".into())),
            },
            Operation::Comment {
                address: a,
                text: Some("\u{1b}]0;owned\u{7}".into()),
            },
            Operation::Bookmark {
                address: a,
                note: Some("x\u{202e}".into()),
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let multiline = Operation::Comment {
            address: a,
            text: Some("first\n\tsecond".into()),
        };
        assert!(multiline.validate().is_ok());
    }

    #[test]
    fn json_size_bound_holds_for_worst_case_contents() {
        let mut ops = sample_ops();
        ops.extend([
            Operation::Comment {
                address: Address(u64::MAX),
                text: Some("\"\\\n\t".repeat(100)),
            },
            Operation::Rename {
                address: Address(u64::MAX),
                name: Some("\"\\".repeat(MAX_NAME_LEN / 2)),
            },
            Operation::PatchBytes {
                address: Address(u64::MAX),
                bytes: vec![0xff; 1000],
            },
            Operation::DefineData {
                address: Address(u64::MAX),
                ty: DataType::Array {
                    element: Box::new(DataType::String {
                        encoding: crate::model::StringEncoding::Utf16Le,
                    }),
                    count: u32::MAX,
                },
            },
        ]);
        ops.push(Operation::Batch { ops: ops.clone() });
        for op in ops {
            let actual = serde_json::to_string(&op).unwrap().len();
            assert!(actual <= op.json_size_bound(), "{actual}: {op:?}");
        }
    }

    #[test]
    fn largest_accepted_operation_reads_back() {
        let comment = |i: u64| Operation::Comment {
            address: Address(i),
            text: Some("\"".repeat(MAX_COMMENT_LEN)),
        };
        let unit = comment(0).json_size_bound();
        let count = (MAX_OPERATION_JSON_BYTES - 128) / unit;
        let largest = Operation::Batch {
            ops: (0..count as u64).map(comment).collect(),
        };
        largest.validate().unwrap();
        let json = serde_json::to_string(&largest).unwrap();
        assert!(json.len() <= MAX_OPERATION_JSON_BYTES, "{}", json.len());
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), largest);
        let too_big = Operation::Batch {
            ops: (0..=count as u64).map(comment).collect(),
        };
        assert!(too_big.validate().is_err());
    }

    #[test]
    fn deep_or_huge_batches_are_rejected() {
        let nest = |levels: usize| {
            (0..levels).fold(
                Operation::Comment {
                    address: Address(1),
                    text: Some("x".into()),
                },
                |inner, _| Operation::Batch { ops: vec![inner] },
            )
        };
        let mut s = state();
        assert!(s.apply(&nest(MAX_BATCH_DEPTH)).is_ok());
        assert!(s.apply(&nest(MAX_BATCH_DEPTH + 1)).is_err());
        let wide = Operation::Batch {
            ops: vec![
                Operation::Bookmark {
                    address: Address(1),
                    note: None,
                };
                MAX_BATCH_OPS + 1
            ],
        };
        assert!(s.apply(&wide).is_err());
        // Far deeper than the stack could recurse; still a clean error.
        // (Dropped iteratively below so the test itself cannot overflow.)
        let mut deep = nest(0);
        for _ in 0..200_000 {
            deep = Operation::Batch { ops: vec![deep] };
        }
        assert!(deep.validate().is_err());
        while let Operation::Batch { mut ops } = deep {
            deep = ops.pop().unwrap();
        }
    }

    #[test]
    fn inverse_of_a_maximally_nested_batch_stays_valid() {
        // A no-op AddTag has an empty-batch inverse at max depth.
        let tag = Operation::AddTag {
            address: Address(1),
            tag: "t".into(),
        };
        let nested = (1..MAX_BATCH_DEPTH).fold(
            Operation::Batch {
                ops: vec![tag.clone(), tag],
            },
            |inner, _| Operation::Batch { ops: vec![inner] },
        );
        let mut s = state();
        let inverse = s.apply(&nested).unwrap();
        inverse.validate().unwrap();
        s.apply(&inverse).unwrap();
        assert_eq!(s.tags(Address(1)).count(), 0);
    }

    #[test]
    fn patch_budget_blocks_growth_only() {
        assert!(check_patch_growth(8, 9, 8).is_err());
        assert!(check_patch_growth(0, 8, 8).is_ok());
        // Shrinking near (or past) the limit must still work.
        assert!(check_patch_growth(13, 9, 8).is_ok());
    }

    #[test]
    fn invalid_operations_leave_state_untouched() {
        let mut s = state();
        let before = fingerprint(&s);
        let deep =
            (0..=crate::model::MAX_DATA_DEPTH).fold(DataType::Byte, |t, _| DataType::Array {
                element: Box::new(t),
                count: 1,
            });
        let bad = [
            Operation::DefineData {
                address: Address(0x1000),
                ty: deep,
            },
            Operation::DefineData {
                address: Address(0x1000),
                ty: DataType::Array {
                    element: Box::new(DataType::Qword),
                    count: u32::MAX,
                },
            },
            Operation::DefineData {
                address: Address(0x1000),
                ty: DataType::Array {
                    element: Box::new(DataType::Byte),
                    count: 0,
                },
            },
            Operation::Rename {
                address: Address(1),
                name: Some(String::new()),
            },
            Operation::Rename {
                address: Address(1),
                name: Some("a b".into()),
            },
            Operation::PatchBytes {
                address: Address(0x100f),
                bytes: vec![1, 2],
            },
            Operation::PatchBytes {
                address: Address(0x1000),
                bytes: vec![],
            },
            Operation::Batch {
                ops: vec![
                    Operation::Comment {
                        address: Address(1),
                        text: Some("ok".into()),
                    },
                    Operation::PatchBytes {
                        address: Address(0),
                        bytes: vec![1],
                    },
                ],
            },
        ];
        for op in bad {
            assert!(s.apply(&op).is_err(), "{op:?} must fail");
            assert_eq!(fingerprint(&s), before);
        }
    }

    #[test]
    fn operation_json_is_stable() {
        let op = Operation::Rename {
            address: Address(0x401000),
            name: Some("main".into()),
        };
        let json = serde_json::to_string(&op).unwrap();
        assert_eq!(
            json,
            r#"{"op":"rename","address":"0x401000","name":"main"}"#
        );
        for op in sample_ops() {
            let text = serde_json::to_string(&op).unwrap();
            let back: Operation = serde_json::from_str(&text).unwrap();
            assert_eq!(back, op);
        }
    }

    #[test]
    fn only_semantic_changes_affect_analysis() {
        let rename = Operation::Rename {
            address: Address(1),
            name: None,
        };
        assert!(rename.changes().iter().all(|c| !c.kind.affects_analysis()));
        let patch = Operation::PatchBytes {
            address: Address(1),
            bytes: vec![0; 4],
        };
        let c = patch.changes();
        assert!(c.iter().all(|c| c.kind.affects_analysis()));
        assert_eq!(c.first().map(|c| c.range.len()), Some(4));
    }
}
