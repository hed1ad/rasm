//! Immutable snapshots of the whole model and the hub that publishes them.
//!
//! Readers (UI thread, CLI, scripts) call [`SnapshotHub::load`] and get an
//! `Arc<Snapshot>` without taking any lock (`arc-swap`). Writers (the
//! session applying operations, the analysis driver merging results)
//! build a new snapshot from the old one — cheap thanks to `Arc` parts and
//! persistent maps — and swap it in. See ADR 0002.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;

use crate::address::{Address, AddressRange};
use crate::arch::Arch;
use crate::error::{DecodeError, Error};
use crate::image::{BinaryInfo, LoadedImage, SymbolBinding};
use crate::insn::{RenderedInsn, SymbolLookup};
use crate::memory::MemoryMap;
use crate::model::{AnalysisResults, DataType, Function, StringEncoding};
use crate::ops::{Definition, UserState};
use crate::text::sanitize_for_display;

/// The immutable part of a project: loaded image, its decoder and lookup
/// indices built once at load.
#[derive(Debug)]
pub struct Program {
    image: LoadedImage,
    arch: Arc<dyn Arch>,
    /// address → index into `image.symbols` of the best symbol there.
    symbol_index: BTreeMap<Address, usize>,
    /// PLT stub address → index into `image.imports`.
    plt_index: BTreeMap<Address, usize>,
    /// GOT slot address → index into `image.imports`.
    got_index: BTreeMap<Address, usize>,
}

impl Program {
    /// Wraps a loaded image and builds indices.
    #[must_use]
    pub fn new(image: LoadedImage, arch: Arc<dyn Arch>) -> Self {
        let mut symbol_index: BTreeMap<Address, usize> = BTreeMap::new();
        for (i, s) in image.symbols.iter().enumerate() {
            if !s.names_address() {
                continue;
            }
            let better = match symbol_index
                .get(&s.address)
                .and_then(|&j| image.symbols.get(j))
            {
                None => true,
                Some(cur) => {
                    (s.source, binding_rank(s.binding)) > (cur.source, binding_rank(cur.binding))
                }
            };
            if better {
                symbol_index.insert(s.address, i);
            }
        }
        let plt_index = image
            .imports
            .iter()
            .enumerate()
            .filter_map(|(i, imp)| imp.plt.map(|a| (a, i)))
            .collect();
        let got_index = image
            .imports
            .iter()
            .enumerate()
            .filter_map(|(i, imp)| imp.got.map(|a| (a, i)))
            .collect();
        Program {
            image,
            arch,
            symbol_index,
            plt_index,
            got_index,
        }
    }

    /// The loaded image.
    #[must_use]
    pub fn image(&self) -> &LoadedImage {
        &self.image
    }

    /// Binary summary.
    #[must_use]
    pub fn info(&self) -> &BinaryInfo {
        &self.image.info
    }

    /// The decoder.
    #[must_use]
    pub fn arch(&self) -> &Arc<dyn Arch> {
        &self.arch
    }

    /// Best loader-provided name at exactly `addr`, sanitized for display
    /// (the file is untrusted, [`crate::text`]): symbol (demangled if
    /// available), else `import@plt` for a PLT stub, else `import@got` for
    /// a GOT slot (`-fno-plt` binaries call through it).
    #[must_use]
    pub fn symbol_name(&self, addr: Address) -> Option<String> {
        if let Some(s) = self
            .symbol_index
            .get(&addr)
            .and_then(|&i| self.image.symbols.get(i))
        {
            let name = s.demangled.as_deref().unwrap_or(&s.name);
            return Some(sanitize_for_display(name).into_owned());
        }
        if let Some(imp) = self
            .plt_index
            .get(&addr)
            .and_then(|&i| self.image.imports.get(i))
        {
            return Some(format!("{}@plt", sanitize_for_display(&imp.name)));
        }
        self.got_index
            .get(&addr)
            .and_then(|&i| self.image.imports.get(i))
            .map(|imp| format!("{}@got", sanitize_for_display(&imp.name)))
    }

    /// The import whose PLT stub or GOT slot is exactly `addr`. Analysis
    /// uses it to treat `call [rip+GOT]` like a call to the import (e.g.
    /// for noreturn imports such as `exit`).
    #[must_use]
    pub fn import_at(&self, addr: Address) -> Option<&crate::image::Import> {
        self.plt_index
            .get(&addr)
            .or_else(|| self.got_index.get(&addr))
            .and_then(|&i| self.image.imports.get(i))
    }
}

/// Global beats weak beats local when two symbols share an address.
fn binding_rank(b: SymbolBinding) -> u8 {
    match b {
        SymbolBinding::Local => 0,
        SymbolBinding::Weak => 1,
        SymbolBinding::Global => 2,
    }
}

/// Undo/redo availability, for enabling menu items without asking the
/// session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UndoInfo {
    /// Something to undo globally.
    pub can_undo: bool,
    /// Something to redo globally.
    pub can_redo: bool,
    /// Sequence number of the latest journal entry (0 if none).
    pub last_seq: u64,
}

/// One consistent, immutable view of the whole model.
///
/// Cloning is cheap (four `Arc`s). Holding a snapshot never blocks writers;
/// it only keeps the old version alive.
#[derive(Clone, Debug)]
pub struct Snapshot {
    generation: u64,
    program: Arc<Program>,
    user: Arc<UserState>,
    analysis: Arc<AnalysisResults>,
    undo: UndoInfo,
}

impl Snapshot {
    /// The first snapshot of a program: no user changes, no analysis.
    #[must_use]
    pub fn initial(program: Arc<Program>) -> Self {
        let user = UserState::new(program.image().memory.clone());
        Snapshot {
            generation: 0,
            program,
            user: Arc::new(user),
            analysis: Arc::new(AnalysisResults::default()),
            undo: UndoInfo::default(),
        }
    }

    /// Copy with a new user layer (generation is set by the hub).
    #[must_use]
    pub fn with_user(&self, user: UserState, undo: UndoInfo) -> Self {
        Snapshot {
            user: Arc::new(user),
            undo,
            ..self.clone()
        }
    }

    /// Copy with new analysis results (generation is set by the hub).
    #[must_use]
    pub fn with_analysis(&self, analysis: AnalysisResults) -> Self {
        Snapshot {
            analysis: Arc::new(analysis),
            ..self.clone()
        }
    }

    /// Monotonic version number; increases on every publish.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Immutable program.
    #[must_use]
    pub fn program(&self) -> &Arc<Program> {
        &self.program
    }

    /// Loaded image.
    #[must_use]
    pub fn image(&self) -> &LoadedImage {
        self.program.image()
    }

    /// Decoder.
    #[must_use]
    pub fn arch(&self) -> &Arc<dyn Arch> {
        self.program.arch()
    }

    /// User layer.
    #[must_use]
    pub fn user(&self) -> &UserState {
        &self.user
    }

    /// Analysis cache.
    #[must_use]
    pub fn analysis(&self) -> &AnalysisResults {
        &self.analysis
    }

    /// Undo availability.
    #[must_use]
    pub fn undo_info(&self) -> UndoInfo {
        self.undo
    }

    /// Memory with patches applied.
    #[must_use]
    pub fn memory(&self) -> &MemoryMap {
        self.user.memory()
    }

    /// Display name of exactly `addr`: user name, else loader symbol, else
    /// `sub_<hex>` for function entries.
    #[must_use]
    pub fn display_name(&self, addr: Address) -> Option<String> {
        if let Some(n) = self.user.name(addr) {
            return Some(n.to_owned());
        }
        if let Some(n) = self.program.symbol_name(addr) {
            return Some(n);
        }
        self.analysis
            .function_at(addr)
            .map(|_| format!("sub_{:x}", addr.get()))
    }

    /// Name of a function (always succeeds).
    #[must_use]
    pub fn function_name(&self, f: &Function) -> String {
        self.display_name(f.entry)
            .unwrap_or_else(|| format!("sub_{:x}", f.entry.get()))
    }

    /// Renders the instruction at `addr` with current names.
    pub fn render_insn(&self, addr: Address) -> Result<RenderedInsn, Error> {
        let arch = self.arch();
        let bytes = self
            .memory()
            .read_up_to(addr, arch.max_insn_len())
            .ok_or(DecodeError::Unmapped(addr))?;
        Ok(arch.render(&bytes, addr, self)?)
    }

    /// The listing item covering `addr` (its range may start before
    /// `addr`, e.g. when a cross-reference points into the middle of an
    /// instruction), or `None` if `addr` is unmapped. Precedence: code in
    /// an analysed function, user data definition, analysed string,
    /// unknown byte (analysis is expected to honour user definitions, so
    /// code vs. user data does not normally overlap).
    /// Items never cross a region boundary.
    #[must_use]
    pub fn item_containing(&self, addr: Address) -> Option<ListingItem> {
        let region = self.memory().region_at(addr)?;
        let rr = region.range();
        let fits = |start: Address, len: u64| -> Option<AddressRange> {
            let r = AddressRange::from_len(start, len.max(1)).ok()?;
            let r = r.intersection(&rr)?;
            r.contains(addr).then_some(r)
        };
        for f in self.analysis.functions_containing(addr) {
            let Some(b) = f.block_containing(addr) else {
                continue;
            };
            let hit = b
                .insn_addresses()
                .zip(b.insn_lens().iter().copied())
                .find_map(|(a, l)| fits(a, u64::from(l)));
            if let Some(range) = hit {
                return Some(ListingItem {
                    range,
                    kind: ItemKind::Code,
                });
            }
        }
        if let Some((a, Definition::Data { ty })) = self.user.definition_at_or_before(addr) {
            let ptr = u64::from(self.program.info().bits / 8);
            let len = match ty.fixed_size(ptr) {
                Some(n) => n,
                None => self.string_len_at(a, ty),
            };
            if let Some(range) = fits(a, len) {
                return Some(ListingItem {
                    range,
                    kind: ItemKind::Data(ty.clone()),
                });
            }
        }
        if let Some(s) = self.analysis.string_containing(addr)
            && let Some(range) = fits(s.address, s.byte_len)
        {
            return Some(ListingItem {
                range,
                kind: ItemKind::String,
            });
        }
        Some(ListingItem::new(addr, 1, ItemKind::Unknown))
    }

    /// Length of a user-defined string at `a`: the analysed string there,
    /// else up to and including the terminator (at most 4 KiB), else 1.
    fn string_len_at(&self, a: Address, ty: &DataType) -> u64 {
        if let Some(s) = self.analysis.string_at(a) {
            return s.byte_len;
        }
        let unit: usize = match ty {
            DataType::String { encoding } => match encoding {
                StringEncoding::Utf16Le | StringEncoding::Utf16Be => 2,
                StringEncoding::Utf32Le | StringEncoding::Utf32Be => 4,
                _ => 1,
            },
            _ => 1,
        };
        let Some(bytes) = self.memory().read_up_to(a, 4096) else {
            return 1;
        };
        let units = bytes.chunks(unit);
        let mut len = 0u64;
        for u in units {
            len = len.saturating_add(u.len() as u64);
            if u.len() == unit && u.iter().all(|b| *b == 0) {
                return len;
            }
        }
        len.max(1)
    }

    /// Listing items from the item covering `addr` onward, crossing region
    /// gaps (an unmapped `addr` starts at the next region). Lazy: the UI
    /// asks only for the rows it shows (ADR 0002, "listing by address").
    pub fn listing_from(&self, addr: Address) -> impl Iterator<Item = ListingItem> + '_ {
        let first = if self.memory().region_at(addr).is_some() {
            self.item_containing(addr)
        } else {
            self.next_mapped(addr).and_then(|a| self.item_containing(a))
        };
        std::iter::successors(first, move |prev| {
            let next = prev.range.end();
            if self.memory().region_at(next).is_some() {
                self.item_containing(next)
            } else {
                self.next_mapped(next).and_then(|a| self.item_containing(a))
            }
        })
    }

    /// Listing items that end at or before `addr`, walking backward (for
    /// scrolling up), crossing region gaps. If `addr` is inside an item,
    /// that item is skipped (it does not end at or before `addr`).
    pub fn listing_before(&self, addr: Address) -> impl Iterator<Item = ListingItem> + '_ {
        let first = self
            .prev_mapped(addr)
            .and_then(|a| self.item_containing(a))
            .and_then(|item| {
                if item.range.end() > addr {
                    self.prev_mapped(item.range.start())
                        .and_then(|a| self.item_containing(a))
                } else {
                    Some(item)
                }
            });
        std::iter::successors(first, move |prev| {
            self.prev_mapped(prev.range.start())
                .and_then(|a| self.item_containing(a))
        })
    }

    fn next_mapped(&self, addr: Address) -> Option<Address> {
        let regions = self.memory().regions();
        let idx = regions.partition_point(|r| r.range().start() < addr);
        regions.get(idx).map(|r| r.range().start())
    }

    /// The last mapped byte strictly below `addr`.
    fn prev_mapped(&self, addr: Address) -> Option<Address> {
        let below = addr.get().checked_sub(1).map(Address)?;
        if self.memory().region_at(below).is_some() {
            return Some(below);
        }
        let regions = self.memory().regions();
        let idx = regions.partition_point(|r| r.range().end() <= below);
        idx.checked_sub(1)
            .and_then(|i| regions.get(i))
            .and_then(|r| r.range().end().get().checked_sub(1).map(Address))
    }
}

impl SymbolLookup for Snapshot {
    fn name_at(&self, address: Address) -> Option<String> {
        self.display_name(address)
    }
    fn is_mapped(&self, address: Address) -> bool {
        self.memory().region_at(address).is_some()
    }
}

/// What occupies a listing row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemKind {
    /// An instruction inside an analysed function.
    Code,
    /// A string literal.
    String,
    /// User-defined data.
    Data(DataType),
    /// A byte nobody has classified yet.
    Unknown,
}

/// One row of the linear listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingItem {
    /// Bytes covered (never empty).
    pub range: AddressRange,
    /// Classification.
    pub kind: ItemKind,
}

impl ListingItem {
    fn new(addr: Address, len: u64, kind: ItemKind) -> Self {
        let range = AddressRange::from_len(addr, len.max(1))
            .unwrap_or_else(|_| AddressRange::empty_at(addr));
        ListingItem { range, kind }
    }
}

/// Receives "a new snapshot is available" notifications.
///
/// Called **synchronously on the publishing thread** (the analysis
/// controller, or the thread that applied an operation, which may hold the
/// session lock). A slow listener slows every publisher. Implementations
/// must be cheap and must not block, must not call back into the hub or
/// the session, and must not wait for analysis (`wait_idle`, `cancel` with
/// waiting): the publisher cannot finish until the listener returns, so
/// that deadlocks. Hand the work to another thread instead; the Qt bridge
/// forwards to the UI thread with a coalescing flag (ADR 0005).
///
/// A panic in a listener is contained by the hub: it does not reach the
/// publisher, and the other listeners are still called. See
/// [`SnapshotHub::listener_panics`].
pub trait SnapshotListener: Send + Sync {
    /// A snapshot with this generation (or newer) is now current.
    fn snapshot_published(&self, generation: u64);
}

/// Handle returned by [`SnapshotHub::subscribe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

type Listeners = Vec<(SubscriptionId, Arc<dyn SnapshotListener>)>;

/// Holds the current snapshot; lock-free for readers, serialised for
/// writers.
pub struct SnapshotHub {
    current: ArcSwap<Snapshot>,
    writer: Mutex<()>,
    listeners: Mutex<Listeners>,
    next_id: AtomicU64,
    listener_panics: AtomicU64,
}

impl std::fmt::Debug for SnapshotHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotHub")
            .field("generation", &self.current.load().generation)
            .finish_non_exhaustive()
    }
}

impl SnapshotHub {
    /// Creates a hub holding `initial`.
    #[must_use]
    pub fn new(initial: Snapshot) -> Arc<Self> {
        Arc::new(SnapshotHub {
            current: ArcSwap::from_pointee(initial),
            writer: Mutex::new(()),
            listeners: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            listener_panics: AtomicU64::new(0),
        })
    }

    /// The current snapshot. Lock-free; safe on the UI thread.
    #[must_use]
    pub fn load(&self) -> Arc<Snapshot> {
        self.current.load_full()
    }

    /// Atomically derives and publishes a new snapshot. Returns the new
    /// generation.
    ///
    /// `f` runs **under the writer lock** and receives the current
    /// snapshot, so concurrent writers never lose each other's updates.
    /// Keep `f` short (merge prepared results; never run analysis inside
    /// it) and never call back into the hub from it (deadlock). Readers are
    /// not blocked meanwhile. Listeners are notified after the lock is
    /// released.
    pub fn update(&self, f: impl FnOnce(&Snapshot) -> Snapshot) -> u64 {
        let generation = {
            let _guard = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
            let old = self.current.load();
            let mut next = f(&old);
            next.generation = old.generation.saturating_add(1);
            let generation = next.generation;
            self.current.store(Arc::new(next));
            generation
        };
        self.notify(generation);
        generation
    }

    /// Publishes a new user layer.
    pub fn publish_user(&self, user: UserState, undo: UndoInfo) -> u64 {
        self.update(|s| s.with_user(user, undo))
    }

    /// Merges analysis changes into the *current* results under the
    /// writer lock and publishes. Use this, not "build results from an
    /// old snapshot and store them": that would lose a concurrent writer's
    /// update. Drivers should batch deltas and throttle calls to a few
    /// per second during bulk analysis.
    pub fn update_analysis(&self, f: impl FnOnce(&mut AnalysisResults)) -> u64 {
        self.update(|s| {
            let mut results = s.analysis().clone();
            f(&mut results);
            s.with_analysis(results)
        })
    }

    /// Registers a listener.
    pub fn subscribe(&self, listener: Arc<dyn SnapshotListener>) -> SubscriptionId {
        let id = SubscriptionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((id, listener));
        id
    }

    /// Removes a listener.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(i, _)| *i != id);
    }

    fn notify(&self, generation: u64) {
        let listeners: Vec<Arc<dyn SnapshotListener>> = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, l)| Arc::clone(l))
            .collect();
        for l in listeners {
            // A buggy listener must not kill the publisher (for analysis,
            // that would leave the state at `Running` forever). Unwind
            // safety: no hub state is borrowed here and both locks are
            // released, so a panic cannot leave the hub inconsistent.
            let call = AssertUnwindSafe(|| l.snapshot_published(generation));
            if catch_unwind(call).is_err() {
                self.listener_panics.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// How many listener calls have panicked so far (the panic hook has
    /// already reported each one). Requires unwinding panics, the default
    /// in all dasm profiles.
    #[must_use]
    pub fn listener_panics(&self) -> u64 {
        self.listener_panics.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AnalysisDelta, StringEncoding, StringLiteral};

    #[test]
    fn panicking_listener_is_contained() {
        struct Boom;
        impl SnapshotListener for Boom {
            fn snapshot_published(&self, _g: u64) {
                panic!("listener bug");
            }
        }
        struct Seen(AtomicU64);
        impl SnapshotListener for Seen {
            fn snapshot_published(&self, g: u64) {
                self.0.store(g, Ordering::SeqCst);
            }
        }
        let program = crate::testing::synthetic_program().unwrap();
        let hub = SnapshotHub::new(Snapshot::initial(Arc::new(program)));
        hub.subscribe(Arc::new(Boom));
        let seen = Arc::new(Seen(AtomicU64::new(0)));
        hub.subscribe(seen.clone());
        let g = hub.update_analysis(|_| {});
        assert_eq!(
            seen.0.load(Ordering::SeqCst),
            g,
            "later listener still runs"
        );
        assert_eq!(hub.listener_panics(), 1);
        assert_eq!(hub.update_analysis(|_| {}), g + 1, "hub still works");
    }

    #[test]
    fn concurrent_analysis_updates_are_not_lost() {
        let program = crate::testing::synthetic_program().unwrap();
        let hub = SnapshotHub::new(Snapshot::initial(Arc::new(program)));
        let threads: Vec<_> = (0..8u64)
            .map(|t| {
                let hub = Arc::clone(&hub);
                std::thread::spawn(move || {
                    for k in 0..50u64 {
                        let a = Address(0x10_0000 + t * 0x1000 + k);
                        hub.update_analysis(|r| {
                            r.apply(AnalysisDelta {
                                upsert_strings: vec![StringLiteral {
                                    address: a,
                                    encoding: StringEncoding::Ascii,
                                    byte_len: 1,
                                    value: String::new(),
                                }],
                                ..Default::default()
                            });
                        });
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let snap = hub.load();
        assert_eq!(snap.analysis().strings().count(), 400);
        assert_eq!(snap.generation(), 400);
    }
}
