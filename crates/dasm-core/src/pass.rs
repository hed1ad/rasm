//! Analysis passes and the driver that schedules them (ADR 0003).

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressRange};
use crate::error::Error;
use crate::model::AnalysisDelta;
use crate::ops::{Change, ChangeKind};
use crate::snapshot::{Snapshot, SnapshotHub};

/// Stable identifier of a pass (`"functions"`, `"xrefs"`). Also used by
/// plugins in `after = [...]`, so ids can be built at run time
/// ([`PassId::new`]) as well as at compile time ([`PassId::from_static`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PassId(Cow<'static, str>);

impl PassId {
    /// An id from a string literal (usable in `const`).
    #[must_use]
    pub const fn from_static(id: &'static str) -> Self {
        PassId(Cow::Borrowed(id))
    }

    /// An id built at run time (plugins).
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        PassId(Cow::Owned(id.into()))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PassId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Well-known pass ids of stage 1 (implemented in `dasm-analysis`).
pub mod passes {
    use super::PassId;
    /// Seeds from loader hints, entry, user `create_function`.
    pub const ENTRY_POINTS: PassId = PassId::from_static("entry_points");
    /// Recursive descent + CFG per function.
    pub const FUNCTIONS: PassId = PassId::from_static("functions");
    /// Linear sweep with prologue heuristics over unexplored code.
    pub const LINEAR_SWEEP: PassId = PassId::from_static("linear_sweep");
    /// Noreturn propagation and tail-call detection.
    pub const NORETURN: PassId = PassId::from_static("noreturn");
    /// Code→code and code→data references.
    pub const XREFS: PassId = PassId::from_static("xrefs");
    /// String discovery.
    pub const STRINGS: PassId = PassId::from_static("strings");
}

/// Unit of work a pass operates on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    /// Runs once over the whole program.
    Program,
    /// Runs independently per function (parallel with rayon).
    Function,
}

/// What a single pass invocation covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PassScope {
    /// The whole program.
    Program,
    /// One function, by entry.
    Function(Address),
    /// An address range (e.g. after a patch, for program-level passes that
    /// can work incrementally).
    Range(AddressRange),
}

/// Cooperative cancellation flag shared between the scheduler and passes.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// New, not cancelled.
    #[must_use]
    pub fn new() -> Self {
        CancelToken::default()
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// True once cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// `Err(Error::Cancelled)` once cancelled; use with `?` in loops.
    pub fn check(&self) -> Result<(), Error> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Input of a pass invocation.
#[derive(Debug)]
pub struct PassContext<'a> {
    /// State to read: image, user layer and results of passes this one
    /// depends on (at least as new as when the invocation was scheduled).
    pub snapshot: &'a Snapshot,
    /// Check periodically (at least every few milliseconds of work).
    pub cancel: &'a CancelToken,
}

/// One analysis pass.
///
/// A pass is a pure function `(snapshot, scope) -> AnalysisDelta`: it does
/// not mutate shared state; the scheduler merges deltas and publishes new
/// snapshots. This makes passes trivially parallel and testable.
pub trait AnalysisPass: Send + Sync {
    /// Stable id.
    fn id(&self) -> PassId;

    /// Passes whose results this one reads. Must form a DAG. Called once
    /// at registration.
    fn dependencies(&self) -> Vec<PassId>;

    /// Unit of work.
    fn granularity(&self) -> Granularity;

    /// User change kinds that invalidate this pass's results in the
    /// affected range (and thus everything depending on them).
    fn invalidated_by(&self) -> &[ChangeKind];

    /// Runs the pass on `scope`. Returns `Err(Error::Cancelled)` promptly
    /// when `ctx.cancel` is set; partial work is discarded.
    fn run(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<AnalysisDelta, Error>;
}

/// What the user is looking at; the scheduler analyses this first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Focus {
    /// Cursor address.
    pub cursor: Option<Address>,
    /// Visible range of the active view.
    pub visible: Option<AddressRange>,
}

/// Runs analysis in the background and publishes results through the hub.
///
/// Implemented by the scheduler in `dasm-analysis`; [`crate::testing`] has
/// a synchronous one. All methods return immediately.
///
/// **Termination contract.** After `start` and after every `invalidate`,
/// the driver MUST eventually publish an [`crate::AnalysisProgress`] whose
/// state is terminal ([`crate::AnalysisState::is_terminal`]): `Done` when
/// all scheduled work finished, `Cancelled` after [`AnalysisDriver::cancel`],
/// `Failed` (with `error` set) when a pass returned an unexpected error or
/// **panicked** — the driver must run passes under
/// `std::panic::catch_unwind` (or an equivalent on its worker threads) and
/// must not let a panic leave the state at `Running`. Clients such as the
/// CLI wait for a terminal state and would otherwise hang forever.
pub trait AnalysisDriver: Send + Sync {
    /// Starts (or restarts) analysis of the hub's current snapshot.
    /// Results are merged and published with [`SnapshotHub::update_analysis`].
    fn start(&self, hub: Arc<SnapshotHub>);

    /// User changes happened; re-run what depends on them.
    fn invalidate(&self, changes: &[Change]);

    /// Reprioritise around the user's focus.
    fn set_focus(&self, focus: Focus);

    /// Stops all work; already published results stay valid.
    fn cancel(&self);
}

/// A driver that does no analysis (headless loading). It still honours
/// the termination contract: `start` publishes `Done` immediately.
#[derive(Debug, Default)]
pub struct NoAnalysis;

impl AnalysisDriver for NoAnalysis {
    fn start(&self, hub: Arc<SnapshotHub>) {
        hub.update_analysis(|r| {
            r.progress.state = crate::model::AnalysisState::Done;
        });
    }
    fn invalidate(&self, _changes: &[Change]) {}
    fn set_focus(&self, _focus: Focus) {}
    fn cancel(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_analysis_reaches_a_terminal_state() {
        let program = crate::testing::synthetic_program().unwrap();
        let hub = SnapshotHub::new(Snapshot::initial(Arc::new(program)));
        assert!(!hub.load().analysis().progress.state.is_terminal());
        NoAnalysis.start(Arc::clone(&hub));
        assert!(hub.load().analysis().progress.state.is_terminal());
        assert!(crate::model::AnalysisState::Failed.is_terminal());
        assert!(!crate::model::AnalysisState::Running.is_terminal());
    }

    #[test]
    fn static_and_runtime_ids_are_equal() {
        let plugin = PassId::new(String::from("functions"));
        assert_eq!(plugin, passes::FUNCTIONS);
        assert_eq!(plugin.as_str(), "functions");
        let json = serde_json::to_string(&passes::XREFS).unwrap();
        assert_eq!(json, "\"xrefs\"");
        let back: PassId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, passes::XREFS);
    }
}
