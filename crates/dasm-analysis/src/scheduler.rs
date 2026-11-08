//! The analysis scheduler (ADR 0003).
//!
//! One controller thread owns all scheduling decisions; passes run on a
//! private rayon pool. The controller keeps a *working* copy of the
//! results, which every task snapshot is built from, and publishes the
//! accumulated deltas to the hub at a throttled rate.
//!
//! ## Why the result does not depend on scheduling
//!
//! - Every pass is a pure function of a snapshot.
//! - `noreturn` is a monotone fixpoint: a function starts as "not proven to
//!   return" and flips to "returns" at most once; callers are re-run when a
//!   callee they were waiting for flips (observed statuses are compared at
//!   merge time, so a flip between a task's start and its merge is never
//!   lost). Function bodies only grow as statuses flip, so the least
//!   fixpoint is reached whatever the order.
//! - Program-level passes (`linear_sweep`, `noreturn`) wait until every
//!   pass they transitively depend on is idle, so they always see a
//!   quiescent state.
//! - Unchanged results are dropped at merge time, so work stops as soon as
//!   nothing changes.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, unbounded};
use dasm_core::ops::FunctionOverride;
use dasm_core::pass::passes;
use dasm_core::{
    Address, AddressRange, AnalysisDelta, AnalysisDriver, AnalysisPass, AnalysisProgress,
    AnalysisResults, AnalysisState, CancelToken, Change, ChangeKind, Error, Focus, FunctionSource,
    Granularity, PassContext, PassId, PassScope, Snapshot, SnapshotHub,
};

use crate::common::{is_placeholder, returns_now, source_rank};
use crate::entry_points::EntryPointsPass;
use crate::functions::FunctionsPass;
use crate::noreturn::NoReturnPass;
use crate::stage::{Generic, PassInfo, Stage, StageOutput};
use crate::strings::StringsPass;
use crate::sweep::LinearSweepPass;
use crate::xrefs::XrefsPass;

/// Scheduler tunables.
#[derive(Clone, Debug)]
pub struct Config {
    /// Worker threads of the private pool (at least 1).
    pub threads: usize,
    /// Minimum time between publications of non-urgent results.
    pub publish_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
        Config {
            threads: cpus.saturating_sub(1).max(1),
            publish_interval: Duration::from_millis(150),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    Prog,
    Func(Address),
    Range(AddressRange),
}

impl Scope {
    fn pass_scope(self) -> PassScope {
        match self {
            Scope::Prog => PassScope::Program,
            Scope::Func(a) => PassScope::Function(a),
            Scope::Range(r) => PassScope::Range(r),
        }
    }
}

type Key = (usize, Scope);

#[derive(Default)]
struct Pending {
    prog: bool,
    funcs: BTreeSet<Address>,
    ranges: BTreeSet<AddressRange>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        !self.prog && self.funcs.is_empty() && self.ranges.is_empty()
    }
    fn len(&self) -> u64 {
        (self.funcs.len() + self.ranges.len() + usize::from(self.prog)) as u64
    }
}

struct RunInfo {
    token: CancelToken,
    stale: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    NotStarted,
    Running,
    Done,
    Cancelled,
    Failed,
}

/// Per-function facts reported by the function pass.
#[derive(Default)]
struct Tables {
    /// Direct call targets of each function.
    calls: BTreeMap<Address, Vec<Address>>,
    /// Observed "returns" status of the callees each function waited on.
    deps: BTreeMap<Address, Vec<(Address, bool)>>,
    /// Union of calls and deps per function.
    refs_out: BTreeMap<Address, Vec<Address>>,
    /// Reverse of `refs_out`.
    refs_to: BTreeMap<Address, BTreeSet<Address>>,
}

#[derive(Default)]
struct FocusSets {
    p0: Option<Address>,
    visible: Option<AddressRange>,
    near: Vec<Address>,
}

struct State {
    hub: Option<Arc<SnapshotHub>>,
    phase: Phase,
    generation: u64,
    working: AnalysisResults,
    pending: Vec<Pending>,
    running: BTreeMap<Key, RunInfo>,
    tables: Tables,
    to_publish: Vec<AnalysisDelta>,
    reset_results: bool,
    last_publish: Instant,
    urgent: bool,
    publishing: bool,
    focus: Focus,
    fs: FocusSets,
    done: u64,
    errors: u64,
    error: Option<String>,
    current_pass: Option<String>,
    gc_dirty: bool,
}

struct DoneMsg {
    key: Key,
    generation: u64,
    result: Result<StageOutput, Error>,
}

enum Event {
    Wake,
    Done(Box<DoneMsg>),
    Shutdown,
}

struct Publish {
    hub: Arc<SnapshotHub>,
    deltas: Vec<AnalysisDelta>,
    reset: bool,
    progress: AnalysisProgress,
}

struct Shared {
    cfg: Config,
    stages: Vec<Arc<dyn Stage>>,
    infos: Vec<PassInfo>,
    /// Transitive dependencies of each pass.
    trans_deps: Vec<Vec<usize>>,
    /// Transitive dependents of each pass.
    dependents: Vec<Vec<usize>>,
    range_scope: Vec<bool>,
    fn_idx: Option<usize>,
    counts: Arc<Vec<AtomicU64>>,
    cancelled: AtomicBool,
    pool: rayon::ThreadPool,
    tx: Sender<Event>,
    state: Mutex<State>,
    idle: Condvar,
}

/// The analysis scheduler: runs the stage 1 passes (and any extra passes)
/// in the background and publishes results through the hub.
///
/// Dropping the scheduler stops the controller thread; call
/// [`AnalysisDriver::cancel`] first to abandon running work promptly.
pub struct Scheduler {
    shared: Arc<Shared>,
    controller: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("threads", &self.shared.cfg.threads)
            .finish_non_exhaustive()
    }
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Scheduler {
    /// A scheduler with the stage 1 passes.
    pub fn new(cfg: Config) -> Result<Scheduler, Error> {
        Scheduler::with_passes(cfg, Vec::new())
    }

    /// A scheduler with the stage 1 passes plus `extra` passes (plugins).
    /// Extra passes may depend on any registered pass; a function-granular
    /// extra pass must (transitively) depend on `functions`, otherwise it
    /// is never given work.
    pub fn with_passes(cfg: Config, extra: Vec<Arc<dyn AnalysisPass>>) -> Result<Scheduler, Error> {
        let mut stages: Vec<Arc<dyn Stage>> = vec![
            Arc::new(EntryPointsPass),
            Arc::new(FunctionsPass::default()),
            Arc::new(LinearSweepPass),
            Arc::new(NoReturnPass::default()),
            Arc::new(XrefsPass),
            Arc::new(StringsPass::default()),
        ];
        stages.extend(
            extra
                .into_iter()
                .map(|p| Arc::new(Generic(p)) as Arc<dyn Stage>),
        );
        let stages = topological(stages)?;
        let ids: Vec<PassId> = stages.iter().map(|s| s.pass().id()).collect();
        let direct: Vec<Vec<usize>> = stages
            .iter()
            .map(|s| {
                s.pass()
                    .dependencies()
                    .iter()
                    .filter_map(|d| ids.iter().position(|i| i == d))
                    .collect()
            })
            .collect();
        let n = stages.len();
        let mut trans_deps: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (p, out) in trans_deps.iter_mut().enumerate() {
            let mut seen = BTreeSet::new();
            let mut stack = direct.get(p).cloned().unwrap_or_default();
            while let Some(q) = stack.pop() {
                if seen.insert(q) {
                    stack.extend(direct.get(q).cloned().unwrap_or_default());
                }
            }
            *out = seen.into_iter().collect();
        }
        let dependents: Vec<Vec<usize>> = (0..n)
            .map(|q| {
                (0..n)
                    .filter(|p| trans_deps.get(*p).is_some_and(|d| d.contains(&q)))
                    .collect()
            })
            .collect();
        let infos = stages
            .iter()
            .map(|s| PassInfo {
                id: s.pass().id(),
                granularity: s.pass().granularity(),
                invalidated_by: s.pass().invalidated_by().to_vec(),
            })
            .collect();
        let range_scope = stages.iter().map(|s| s.range_scope()).collect();
        let fn_idx = stages.iter().position(|s| s.is_function_discovery());
        let counts: Arc<Vec<AtomicU64>> = Arc::new((0..n).map(|_| AtomicU64::new(0)).collect());
        let threads = cfg.threads.max(1);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("dasm-analysis-{i}"))
            .build()
            .map_err(|e| Error::Unsupported(format!("cannot start analysis pool: {e}")))?;
        let (tx, rx) = unbounded();
        let state = State {
            hub: None,
            phase: Phase::NotStarted,
            generation: 0,
            working: AnalysisResults::default(),
            pending: (0..n).map(|_| Pending::default()).collect(),
            running: BTreeMap::new(),
            tables: Tables::default(),
            to_publish: Vec::new(),
            reset_results: false,
            last_publish: Instant::now(),
            urgent: false,
            publishing: false,
            focus: Focus::default(),
            fs: FocusSets::default(),
            done: 0,
            errors: 0,
            error: None,
            current_pass: None,
            gc_dirty: false,
        };
        let shared = Arc::new(Shared {
            cfg: Config { threads, ..cfg },
            stages,
            infos,
            trans_deps,
            dependents,
            range_scope,
            fn_idx,
            counts,
            cancelled: AtomicBool::new(false),
            pool,
            tx,
            state: Mutex::new(state),
            idle: Condvar::new(),
        });
        let ctl = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name("dasm-analysis-ctl".into())
            .spawn(move || ctl.control_loop(&rx))
            .map_err(|e| Error::Unsupported(format!("cannot start scheduler thread: {e}")))?;
        Ok(Scheduler {
            shared,
            controller: Mutex::new(Some(handle)),
        })
    }

    /// Blocks until all work is done (or cancelled) and published, or the
    /// timeout expires. Returns `true` if the scheduler is idle.
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400 * 365));
        let mut st = lock(&self.shared.state);
        loop {
            if st.phase != Phase::Running
                && st.running.is_empty()
                && st.to_publish.is_empty()
                && !st.publishing
            {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            st = self
                .shared
                .idle
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Overall state.
    #[must_use]
    pub fn state(&self) -> AnalysisState {
        match lock(&self.shared.state).phase {
            Phase::NotStarted => AnalysisState::Idle,
            Phase::Running => AnalysisState::Running,
            Phase::Done => AnalysisState::Done,
            Phase::Cancelled => AnalysisState::Cancelled,
            Phase::Failed => AnalysisState::Failed,
        }
    }

    /// Number of pass invocations since creation (or the last
    /// [`Scheduler::reset_run_counts`]), by pass id.
    #[must_use]
    pub fn run_counts(&self) -> BTreeMap<PassId, u64> {
        self.shared
            .infos
            .iter()
            .zip(self.shared.counts.iter())
            .map(|(i, c)| (i.id.clone(), c.load(Ordering::Relaxed)))
            .collect()
    }

    /// Resets the counters of [`Scheduler::run_counts`].
    pub fn reset_run_counts(&self) {
        for c in self.shared.counts.iter() {
            c.store(0, Ordering::Relaxed);
        }
    }

    /// Number of pass invocations that failed with an error other than
    /// cancellation.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        lock(&self.shared.state).errors
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.shared.tx.send(Event::Shutdown);
        let handle = self
            .controller
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            let _ = h.join();
        }
    }
}

/// Orders stages so dependencies come first (stable); rejects unknown
/// dependencies, duplicate ids and cycles.
fn topological(stages: Vec<Arc<dyn Stage>>) -> Result<Vec<Arc<dyn Stage>>, Error> {
    let ids: Vec<PassId> = stages.iter().map(|s| s.pass().id()).collect();
    for (i, id) in ids.iter().enumerate() {
        if ids.iter().skip(i + 1).any(|o| o == id) {
            return Err(Error::InvalidArgument(format!("duplicate pass id {id}")));
        }
    }
    let mut deps: Vec<Vec<usize>> = Vec::new();
    for s in &stages {
        let mut d = Vec::new();
        for dep in s.pass().dependencies() {
            let Some(pos) = ids.iter().position(|i| *i == dep) else {
                return Err(Error::InvalidArgument(format!(
                    "pass {} depends on unknown pass {dep}",
                    s.pass().id()
                )));
            };
            d.push(pos);
        }
        deps.push(d);
    }
    let mut placed: Vec<usize> = Vec::new();
    while placed.len() < stages.len() {
        let next = (0..stages.len()).find(|i| {
            !placed.contains(i)
                && deps
                    .get(*i)
                    .is_some_and(|d| d.iter().all(|x| placed.contains(x)))
        });
        match next {
            Some(i) => placed.push(i),
            None => {
                return Err(Error::InvalidArgument(
                    "pass dependencies form a cycle".into(),
                ));
            }
        }
    }
    Ok(placed
        .into_iter()
        .filter_map(|i| stages.get(i).cloned())
        .collect())
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_owned())
}

impl Shared {
    // ------------------------------------------------------------ control

    fn control_loop(self: &Arc<Self>, rx: &Receiver<Event>) {
        loop {
            let timeout = {
                let st = lock(&self.state);
                if st.to_publish.is_empty() {
                    Duration::from_secs(3600)
                } else {
                    self.cfg
                        .publish_interval
                        .saturating_sub(st.last_publish.elapsed())
                }
            };
            let mut events = Vec::new();
            match rx.recv_timeout(timeout) {
                Ok(Event::Shutdown) | Err(RecvTimeoutError::Disconnected) => return,
                Ok(e) => events.push(e),
                Err(RecvTimeoutError::Timeout) => {}
            }
            while let Ok(e) = rx.try_recv() {
                if matches!(e, Event::Shutdown) {
                    return;
                }
                events.push(e);
            }
            if let Err(panic) = catch_unwind(AssertUnwindSafe(|| self.step(events))) {
                self.fail(&panic_message(&*panic));
            }
        }
    }

    /// The controller itself panicked: stop the analysis in a terminal `Failed` state instead of
    /// leaving it `Running` forever.
    fn fail(&self, message: &str) {
        let job = {
            let mut st = lock(&self.state);
            Self::cancel_running(&mut st);
            for p in &mut st.pending {
                *p = Pending::default();
            }
            st.phase = Phase::Failed;
            st.error
                .get_or_insert_with(|| format!("analysis controller: {message}"));
            st.to_publish.clear();
            st.reset_results = false;
            st.urgent = true;
            st.publishing = false;
            self.take_publish(&mut st)
        };
        if let Some(job) = job {
            // The listener that panicked may panic again; the progress is
            // stored before listeners run, so ignoring that is fine.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                job.hub.update_analysis(|r| r.progress = job.progress);
            }));
        }
        lock(&self.state).publishing = false;
        self.idle.notify_all();
    }

    fn step(&self, events: Vec<Event>) {
        // Merge in small batches so that `cancel`, `invalidate` and
        // `set_focus` never wait long for the state lock.
        let mut events = events.into_iter().peekable();
        while events.peek().is_some() {
            let mut st = lock(&self.state);
            for e in events.by_ref().take(16) {
                if let Event::Done(msg) = e {
                    self.handle_done(&mut st, *msg);
                }
            }
        }
        let job = {
            let mut st = lock(&self.state);
            if st.phase == Phase::Running {
                self.maybe_gc(&mut st);
                self.refresh_focus(&mut st);
                self.dispatch(&mut st);
                let idle = st.running.is_empty() && st.pending.iter().all(Pending::is_empty);
                if idle {
                    st.phase = if st.error.is_some() {
                        Phase::Failed
                    } else {
                        Phase::Done
                    };
                    st.current_pass = None;
                    st.urgent = true;
                }
            }
            self.take_publish(&mut st)
        };
        if let Some(job) = job {
            let Publish {
                hub,
                deltas,
                reset,
                progress,
            } = job;
            // Publish in slices so the hub's writer lock is held briefly and
            // a cancel does not wait for a big batch.
            let mut deltas = deltas.into_iter().peekable();
            let mut first = true;
            while first || deltas.peek().is_some() {
                if self.cancelled.load(Ordering::Relaxed) {
                    break;
                }
                let reset_now = reset && first;
                first = false;
                let slice: Vec<AnalysisDelta> = deltas.by_ref().take(128).collect();
                let last = deltas.peek().is_none();
                let progress = progress.clone();
                hub.update_analysis(|r| {
                    if reset_now {
                        *r = AnalysisResults::default();
                    }
                    for d in slice {
                        r.apply(d);
                    }
                    if last {
                        r.progress = progress;
                    }
                });
            }
            if self.cancelled.load(Ordering::Relaxed) {
                let p = AnalysisProgress {
                    state: AnalysisState::Cancelled,
                    ..progress
                };
                hub.update_analysis(|r| r.progress = p);
            }
            let mut st = lock(&self.state);
            st.publishing = false;
        }
        self.idle.notify_all();
    }

    fn progress(&self, st: &State) -> AnalysisProgress {
        let queued: u64 = st.pending.iter().map(Pending::len).sum();
        AnalysisProgress {
            state: match st.phase {
                Phase::NotStarted => AnalysisState::Idle,
                Phase::Running => AnalysisState::Running,
                Phase::Done => AnalysisState::Done,
                Phase::Cancelled => AnalysisState::Cancelled,
                Phase::Failed => AnalysisState::Failed,
            },
            current_pass: st.current_pass.clone(),
            error: st.error.clone(),
            done: st.done,
            total: st.done + queued + st.running.len() as u64,
        }
    }

    fn take_publish(&self, st: &mut State) -> Option<Publish> {
        let hub = st.hub.clone()?;
        let settled = st.phase != Phase::Running;
        let due = st.urgent
            || settled
            || (!st.to_publish.is_empty()
                && st.last_publish.elapsed() >= self.cfg.publish_interval);
        let something = !st.to_publish.is_empty() || st.reset_results || st.urgent;
        if !due || !something {
            return None;
        }
        st.urgent = false;
        st.last_publish = Instant::now();
        st.publishing = true;
        Some(Publish {
            hub,
            deltas: std::mem::take(&mut st.to_publish),
            reset: std::mem::take(&mut st.reset_results),
            progress: self.progress(st),
        })
    }

    // ----------------------------------------------------------- dispatch

    /// Dependencies a task of `p` must wait for regardless of its scope:
    /// every pass for program/range tasks, program-level passes for
    /// function tasks (function-level ones are checked per function).
    fn deps_ready(&self, st: &State, p: usize, func_scope: bool) -> bool {
        self.trans_deps.get(p).is_none_or(|deps| {
            deps.iter().all(|&q| {
                (func_scope
                    && self
                        .infos
                        .get(q)
                        .is_some_and(|i| i.granularity == Granularity::Function))
                    || self.idle_pass(st, q)
            })
        })
    }

    fn idle_pass(&self, st: &State, q: usize) -> bool {
        st.pending.get(q).is_none_or(Pending::is_empty) && !st.running.keys().any(|(p, _)| *p == q)
    }

    fn func_deps_ready(&self, st: &State, p: usize, e: Address) -> bool {
        self.trans_deps.get(p).is_none_or(|deps| {
            deps.iter().all(|&q| {
                let function = self
                    .infos
                    .get(q)
                    .is_some_and(|i| i.granularity == Granularity::Function);
                !function
                    || (st.pending.get(q).is_some_and(|pq| {
                        !pq.funcs.contains(&e) && !pq.prog && pq.ranges.is_empty()
                    }) && !st.running.contains_key(&(q, Scope::Func(e))))
            })
        })
    }

    fn best_func(&self, st: &State, p: usize) -> Option<(u8, Address)> {
        let pend = &st.pending.get(p)?.funcs;
        let ok = |e: Address| {
            !st.running.contains_key(&(p, Scope::Func(e))) && self.func_deps_ready(st, p, e)
        };
        if let Some(a) = st.fs.p0
            && pend.contains(&a)
            && ok(a)
        {
            return Some((0, a));
        }
        if let Some(v) = st.fs.visible {
            for &e in pend.range(v.start()..v.end()).take(64) {
                if ok(e) {
                    return Some((1, e));
                }
            }
        }
        for &e in &st.fs.near {
            if pend.contains(&e) && ok(e) {
                return Some((2, e));
            }
        }
        pend.iter().copied().find(|&e| ok(e)).map(|e| (3, e))
    }

    fn pick(&self, st: &State) -> Option<Key> {
        let mut best: Option<(u8, usize, Scope)> = None;
        let mut consider = |prio: u8, p: usize, scope: Scope| {
            if best.is_none_or(|(bp, bi, _)| (prio, p) < (bp, bi)) {
                best = Some((prio, p, scope));
            }
        };
        for (p, pend) in st.pending.iter().enumerate() {
            if pend.is_empty() {
                continue;
            }
            if self.deps_ready(st, p, false) {
                if pend.prog && !st.running.contains_key(&(p, Scope::Prog)) {
                    consider(3, p, Scope::Prog);
                }
                if let Some(r) = pend
                    .ranges
                    .iter()
                    .find(|r| !st.running.contains_key(&(p, Scope::Range(**r))))
                {
                    consider(3, p, Scope::Range(*r));
                }
            }
            if !pend.funcs.is_empty()
                && self.deps_ready(st, p, true)
                && let Some((prio, e)) = self.best_func(st, p)
            {
                consider(prio, p, Scope::Func(e));
            }
        }
        best.map(|(_, p, s)| (p, s))
    }

    fn dispatch(&self, st: &mut State) {
        let Some(hub) = st.hub.clone() else {
            return;
        };
        while st.running.len() < self.cfg.threads {
            let Some(key) = self.pick(st) else {
                break;
            };
            let (p, scope) = key;
            if let Some(pend) = st.pending.get_mut(p) {
                match scope {
                    Scope::Prog => pend.prog = false,
                    Scope::Func(a) => {
                        pend.funcs.remove(&a);
                    }
                    Scope::Range(r) => {
                        pend.ranges.remove(&r);
                    }
                }
            }
            let Some(stage) = self.stages.get(p).cloned() else {
                continue;
            };
            let token = CancelToken::new();
            st.running.insert(
                key,
                RunInfo {
                    token: token.clone(),
                    stale: false,
                },
            );
            st.current_pass = self.infos.get(p).map(|i| i.id.to_string());
            let snap = hub.load().with_analysis(st.working.clone());
            let generation = st.generation;
            let tx = self.tx.clone();
            let counts = Arc::clone(&self.counts);
            self.pool.spawn(move || {
                if let Some(c) = counts.get(p) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                let ctx = PassContext {
                    snapshot: &snap,
                    cancel: &token,
                };
                let result = catch_unwind(AssertUnwindSafe(|| {
                    stage.run_stage(&ctx, scope.pass_scope())
                }))
                .unwrap_or_else(|p| {
                    Err(Error::InvalidOperation(format!(
                        "analysis pass panicked: {}",
                        panic_message(&*p)
                    )))
                });
                let _ = tx.send(Event::Done(Box::new(DoneMsg {
                    key,
                    generation,
                    result,
                })));
            });
        }
    }

    fn refresh_focus(&self, st: &mut State) {
        let Some(fi) = self.fn_idx else {
            return;
        };
        let mut fs = FocusSets {
            visible: st.focus.visible,
            ..FocusSets::default()
        };
        if let Some(cur) = st.focus.cursor {
            fs.p0 = st
                .working
                .function_containing(cur)
                .map(|f| f.entry)
                .or_else(|| {
                    st.pending
                        .get(fi)
                        .and_then(|p| p.funcs.range(..=cur).next_back().copied())
                        .filter(|e| cur.get() - e.get() < 0x10000)
                });
        }
        let mut near: BTreeSet<Address> = BTreeSet::new();
        for e in fs.p0.into_iter().chain(
            st.pending
                .get(fi)
                .into_iter()
                .flat_map(|p| {
                    fs.visible
                        .into_iter()
                        .flat_map(|v| p.funcs.range(v.start()..v.end()).take(16))
                })
                .copied(),
        ) {
            near.extend(st.tables.calls.get(&e).into_iter().flatten().take(32));
            near.extend(st.tables.refs_to.get(&e).into_iter().flatten().take(32));
        }
        fs.near = near.into_iter().collect();
        st.fs = fs;
    }

    // -------------------------------------------------------------- merge

    fn handle_done(&self, st: &mut State, msg: DoneMsg) {
        let Some(info) = st.running.remove(&msg.key) else {
            return;
        };
        if msg.generation != st.generation
            || st.phase == Phase::Cancelled
            || info.stale
            || info.token.is_cancelled()
        {
            return;
        }
        match msg.result {
            Ok(out) => {
                st.done += 1;
                self.merge(st, msg.key, out);
            }
            Err(Error::Cancelled) => {}
            Err(e) => {
                st.done += 1;
                st.errors += 1;
                let pass = self
                    .infos
                    .get(msg.key.0)
                    .map_or_else(String::new, |i| i.id.to_string());
                st.error.get_or_insert_with(|| format!("pass {pass}: {e}"));
            }
        }
    }

    fn pend_func(&self, st: &mut State, p: usize, e: Address) {
        if let Some(pend) = st.pending.get_mut(p) {
            pend.funcs.insert(e);
        }
    }

    fn merge(&self, st: &mut State, key: Key, out: StageOutput) {
        let (p, scope) = key;
        let user = st.hub.as_ref().map(|h| h.load());
        let forbidden = |a: Address| {
            user.as_ref()
                .is_some_and(|s| s.user().function_override(a) == Some(FunctionOverride::Delete))
        };
        let StageOutput { delta, calls, deps } = out;
        let mut acc = AnalysisDelta::default();
        let mut changed: Vec<Address> = Vec::new();
        let mut new_placeholders: Vec<Address> = Vec::new();
        let mut flips_up: Vec<Address> = Vec::new();
        let mut regress: Vec<Address> = Vec::new();
        let mut removed: Vec<Address> = Vec::new();

        for f in delta.upsert_functions {
            if forbidden(f.entry) {
                continue;
            }
            let entry = f.entry;
            match st.working.function_at(entry).cloned() {
                None => {
                    if is_placeholder(&f) {
                        new_placeholders.push(entry);
                    } else {
                        changed.push(entry);
                    }
                    acc.upsert_functions.push(f);
                }
                Some(ex) => {
                    // The analysis of a function may legitimately come out
                    // empty (user data over its entry); only upserts from
                    // other tasks are placeholders.
                    let own = Some(p) == self.fn_idx && scope == Scope::Func(entry);
                    if is_placeholder(&f) && !own {
                        if source_rank(&f.source) > source_rank(&ex.source) {
                            let mut up = (*ex).clone();
                            up.source = f.source;
                            acc.upsert_functions.push(up);
                            changed.push(entry);
                        }
                    } else if *ex != f {
                        if ex.flags.noreturn && !f.flags.noreturn {
                            flips_up.push(entry);
                        }
                        if !ex.flags.noreturn && f.flags.noreturn {
                            regress.push(entry);
                        }
                        changed.push(entry);
                        acc.upsert_functions.push(f);
                    }
                }
            }
        }
        for a in delta.remove_functions {
            if st.working.function_at(a).is_some() {
                acc.remove_functions.push(a);
                removed.push(a);
            }
        }
        for (owner, mut xs) in delta.set_xrefs {
            xs.sort_unstable();
            xs.dedup();
            let same = match st.working.xref_group(&owner) {
                Some(old) => old == xs.as_slice(),
                None => xs.is_empty(),
            };
            if !same {
                acc.set_xrefs.push((owner, xs));
            }
        }
        acc.upsert_strings = delta.upsert_strings;
        acc.remove_strings_in = delta.remove_strings_in;

        let any_change = !acc.is_empty();
        if any_change {
            st.to_publish.push(acc.clone());
            st.working.apply(acc);
        }

        // Side tables of the function pass.
        if Some(p) == self.fn_idx
            && let Scope::Func(e) = scope
        {
            self.update_tables(st, e, calls, deps.clone());
            if let Some(fi) = self.fn_idx
                && deps
                    .iter()
                    .any(|(g, observed)| returns_now(&st.working, *g) != *observed)
            {
                self.pend_func(st, fi, e);
            }
        }
        if let Some(fi) = self.fn_idx {
            for a in &removed {
                let referrers: Vec<Address> = st
                    .tables
                    .refs_to
                    .get(a)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default();
                for r in referrers {
                    self.pend_func(st, fi, r);
                }
                self.drop_tables(st, *a);
                for pend in &mut st.pending {
                    pend.funcs.remove(a);
                }
                st.gc_dirty = true;
            }
            for a in &new_placeholders {
                self.pend_func(st, fi, *a);
            }
            for e in &flips_up {
                let waiting: Vec<Address> = st
                    .tables
                    .refs_to
                    .get(e)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|r| {
                        st.tables
                            .deps
                            .get(r)
                            .is_some_and(|d| d.iter().any(|(g, ok)| g == e && !*ok))
                    })
                    .collect();
                for r in waiting {
                    self.pend_func(st, fi, r);
                }
            }
            if !regress.is_empty() {
                self.reset_dependents(st, &regress, fi);
            }
        }

        // Mark dependents.
        if any_change {
            let entries: Vec<Address> = changed;
            for &q in self
                .dependents
                .get(p)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let Some(pend) = st.pending.get_mut(q) else {
                    continue;
                };
                match self.infos.get(q).map(|i| i.granularity) {
                    Some(Granularity::Function) => pend.funcs.extend(entries.iter().copied()),
                    _ => pend.prog = true,
                }
            }
        }
        if let Scope::Func(e) = scope
            && st.fs.p0 == Some(e)
        {
            st.urgent = true;
        }
    }

    fn update_tables(
        &self,
        st: &mut State,
        e: Address,
        calls: Vec<Address>,
        deps: Vec<(Address, bool)>,
    ) {
        if let Some(old) = st.tables.refs_out.remove(&e) {
            for g in old {
                if let Some(set) = st.tables.refs_to.get_mut(&g) {
                    set.remove(&e);
                    if set.is_empty() {
                        st.tables.refs_to.remove(&g);
                    }
                }
            }
        }
        let refs: BTreeSet<Address> = calls
            .iter()
            .copied()
            .chain(deps.iter().map(|(g, _)| *g))
            .collect();
        for g in &refs {
            st.tables.refs_to.entry(*g).or_default().insert(e);
        }
        st.tables.refs_out.insert(e, refs.into_iter().collect());
        if let Some(old_calls) = st.tables.calls.get(&e)
            && old_calls.iter().any(|c| !calls.contains(c))
        {
            st.gc_dirty = true;
        }
        st.tables.calls.insert(e, calls);
        st.tables.deps.insert(e, deps);
    }

    fn drop_tables(&self, st: &mut State, e: Address) {
        st.tables.calls.remove(&e);
        st.tables.deps.remove(&e);
        if let Some(old) = st.tables.refs_out.remove(&e) {
            for g in old {
                if let Some(set) = st.tables.refs_to.get_mut(&g) {
                    set.remove(&e);
                    if set.is_empty() {
                        st.tables.refs_to.remove(&g);
                    }
                }
            }
        }
    }

    /// A function stopped returning (a non-monotone change such as a
    /// patch): everything that transitively depends on it forgets its
    /// "returns" conclusion and is re-derived.
    fn reset_dependents(&self, st: &mut State, seeds: &[Address], fi: usize) {
        let mut seen: BTreeSet<Address> = seeds.iter().copied().collect();
        let mut stack: Vec<Address> = seeds.to_vec();
        let mut extra = AnalysisDelta::default();
        while let Some(x) = stack.pop() {
            let referrers: Vec<Address> = st
                .tables
                .refs_to
                .get(&x)
                .into_iter()
                .flatten()
                .copied()
                .collect();
            for r in referrers {
                if !seen.insert(r) {
                    continue;
                }
                stack.push(r);
                if let Some(f) = st.working.function_at(r)
                    && !f.flags.noreturn
                {
                    let mut up = (**f).clone();
                    up.flags.noreturn = true;
                    extra.upsert_functions.push(up);
                }
                self.pend_func(st, fi, r);
            }
        }
        if !extra.is_empty() {
            st.to_publish.push(extra.clone());
            st.working.apply(extra);
        }
    }

    /// Removes call-target functions no root reaches any more.
    fn maybe_gc(&self, st: &mut State) {
        let Some(fi) = self.fn_idx else {
            return;
        };
        if !st.gc_dirty || !self.idle_pass(st, fi) {
            return;
        }
        let entry_idle = self
            .infos
            .iter()
            .position(|i| i.id == passes::ENTRY_POINTS)
            .is_none_or(|e| self.idle_pass(st, e));
        if !entry_idle {
            return;
        }
        st.gc_dirty = false;
        let mut reached: BTreeSet<Address> = BTreeSet::new();
        let mut stack: Vec<Address> = Vec::new();
        for f in st.working.functions() {
            if matches!(
                f.source,
                FunctionSource::Hint(_) | FunctionSource::User | FunctionSource::Prologue
            ) && reached.insert(f.entry)
            {
                stack.push(f.entry);
            }
        }
        while let Some(x) = stack.pop() {
            for c in st.tables.calls.get(&x).into_iter().flatten() {
                if reached.insert(*c) {
                    stack.push(*c);
                }
            }
        }
        let doomed: Vec<Address> = st
            .working
            .functions()
            .map(|f| f.entry)
            .filter(|e| !reached.contains(e))
            .collect();
        if doomed.is_empty() {
            return;
        }
        for d in &doomed {
            self.drop_tables(st, *d);
        }
        let delta = AnalysisDelta {
            remove_functions: doomed,
            ..AnalysisDelta::default()
        };
        st.to_publish.push(delta.clone());
        st.working.apply(delta);
        for q in self.dependents.get(fi).into_iter().flatten() {
            if let (Some(pend), Some(i)) = (st.pending.get_mut(*q), self.infos.get(*q))
                && i.granularity == Granularity::Program
            {
                pend.prog = true;
            }
        }
    }

    // ----------------------------------------------------- driver surface

    fn cancel_running(st: &mut State) {
        for r in st.running.values_mut() {
            r.token.cancel();
            r.stale = true;
        }
    }

    fn start(&self, hub: Arc<SnapshotHub>) {
        self.cancelled.store(false, Ordering::Relaxed);
        {
            let mut st = lock(&self.state);
            Self::cancel_running(&mut st);
            st.generation += 1;
            st.working = AnalysisResults::default();
            for p in &mut st.pending {
                *p = Pending::default();
            }
            st.tables = Tables::default();
            st.to_publish.clear();
            st.done = 0;
            st.errors = 0;
            st.error = None;
            st.gc_dirty = false;
            st.current_pass = None;
            let snap = hub.load();
            let regions: Vec<AddressRange> = snap
                .memory()
                .regions()
                .iter()
                .filter(|r| !r.perms().execute)
                .map(|r| r.range())
                .collect();
            for (p, info) in self.infos.iter().enumerate() {
                let Some(pend) = st.pending.get_mut(p) else {
                    continue;
                };
                match info.granularity {
                    Granularity::Program => pend.prog = true,
                    Granularity::Function => {
                        if self.range_scope.get(p).copied().unwrap_or(false) {
                            pend.ranges.extend(regions.iter().copied());
                        }
                    }
                }
            }
            st.hub = Some(hub);
            st.phase = Phase::Running;
            st.reset_results = true;
            st.urgent = true;
        }
        let _ = self.tx.send(Event::Wake);
    }

    fn mark_range(&self, st: &mut State, p: usize, r: AddressRange) {
        if let Some(pend) = st.pending.get_mut(p) {
            pend.ranges.insert(r);
        }
        for (k, info) in st.running.iter_mut() {
            if k.0 == p && matches!(k.1, Scope::Range(_)) {
                info.token.cancel();
                info.stale = true;
            }
        }
    }

    fn mark_prog(&self, st: &mut State, p: usize) {
        if let Some(pend) = st.pending.get_mut(p) {
            pend.prog = true;
        }
        if let Some(info) = st.running.get_mut(&(p, Scope::Prog)) {
            info.token.cancel();
            info.stale = true;
        }
    }

    fn mark_func(&self, st: &mut State, p: usize, e: Address) {
        if let Some(pend) = st.pending.get_mut(p) {
            pend.funcs.insert(e);
        }
        if let Some(info) = st.running.get_mut(&(p, Scope::Func(e))) {
            info.token.cancel();
            info.stale = true;
        }
    }

    fn affected(&self, st: &State, snap: &Snapshot, ch: &Change) -> Vec<Address> {
        let r = ch.range;
        let start = r.start();
        let mut out: BTreeSet<Address> = BTreeSet::new();
        // Addresses whose bytes or classification changed: `[start, cover)`.
        // A `Definition` change carries only the start of the item, so its
        // extent comes from the current definition (a removed definition
        // has none; functions it truncated are found by `stopped` below).
        let cover = match ch.kind {
            ChangeKind::Bytes => Some(r.end().max(start)),
            ChangeKind::Definition => {
                let ptr = u64::from(snap.program().info().bits / 8);
                let size = match snap.user().definition(start) {
                    Some(dasm_core::ops::Definition::Data { ty }) => {
                        ty.fixed_size(ptr).unwrap_or(1)
                    }
                    _ => 1,
                };
                Some(start.checked_add(size.max(1)).unwrap_or(Address(u64::MAX)))
            }
            _ => None,
        };
        if let Some(cover) = cover {
            let lo = Address(start.get().saturating_sub(16));
            // A cut or failed decode ends a function within one
            // instruction of the changed range.
            let near_hi = Address(start.get().saturating_add(16));
            for f in st.working.functions() {
                // Functions that never decoded may start just before.
                // (After `Undefine` the old extent is unknown, so every
                // empty function up to the largest item counts.)
                let empty_hi = if ch.kind == ChangeKind::Definition {
                    Address(start.get().saturating_add(dasm_core::model::MAX_DATA_SIZE))
                } else {
                    cover
                };
                let in_range = f.blocks.is_empty() && f.entry >= lo && f.entry < empty_hi;
                let overlaps = f
                    .blocks
                    .iter()
                    .any(|b| b.range().end() > start && b.range().start() < cover)
                    || (f.entry >= start && f.entry < cover);
                // A function that stopped right before the change: its
                // last block should fall through but has no successor.
                let stopped = f.blocks.iter().any(|b| {
                    b.successors.is_empty()
                        && b.range().end() >= lo
                        && b.range().end() <= near_hi
                        && b.insn_addresses().last().is_some_and(|last| {
                            snap.memory()
                                .read_up_to(last, snap.arch().max_insn_len())
                                .and_then(|bytes| snap.arch().decode(&bytes, last).ok())
                                .is_some_and(|d| d.flow.falls_through())
                        })
                });
                if in_range || overlaps || stopped {
                    out.insert(f.entry);
                }
            }
        }
        if ch.kind != ChangeKind::Bytes {
            out.extend(
                st.working
                    .functions_containing(start)
                    .iter()
                    .map(|f| f.entry),
            );
            out.insert(start);
            out.extend(st.tables.refs_to.get(&start).into_iter().flatten());
        }
        out.into_iter().collect()
    }

    fn invalidate(&self, changes: &[Change]) {
        let mut st = lock(&self.state);
        if matches!(
            st.phase,
            Phase::NotStarted | Phase::Cancelled | Phase::Failed
        ) {
            return;
        }
        let Some(snap) = st.hub.as_ref().map(|h| h.load()) else {
            return;
        };
        let mut touched = false;
        for ch in changes {
            if !ch.kind.affects_analysis() || ch.kind == ChangeKind::Type {
                continue;
            }
            let entries = self.affected(&st, &snap, ch);
            let range_kind = matches!(ch.kind, ChangeKind::Bytes | ChangeKind::Definition);
            let regions: Vec<AddressRange> = snap
                .memory()
                .regions()
                .iter()
                .filter(|reg| !reg.perms().execute && reg.range().overlaps(&ch.range))
                .map(|reg| reg.range())
                .collect();
            // Tasks already running read an older snapshot: whatever they
            // are doing may be stale, so they are redone as well.
            let running: Vec<Key> = st.running.keys().copied().collect();
            for (p, info) in self.infos.iter().enumerate() {
                if !info.invalidated_by.contains(&ch.kind) {
                    continue;
                }
                touched = true;
                let mut targets = vec![p];
                targets.extend(self.dependents.get(p).into_iter().flatten().copied());
                for q in targets {
                    let Some(qi) = self.infos.get(q) else {
                        continue;
                    };
                    let ranged = self.range_scope.get(q).copied().unwrap_or(false) && range_kind;
                    if ranged {
                        for reg in &regions {
                            self.mark_range(&mut st, q, *reg);
                        }
                        for &(rp, scope) in &running {
                            if let (true, Scope::Range(r)) = (rp == q, scope) {
                                self.mark_range(&mut st, q, r);
                            }
                        }
                    }
                    match qi.granularity {
                        Granularity::Function => {
                            for &e in &entries {
                                if st.working.function_at(e).is_some() {
                                    self.mark_func(&mut st, q, e);
                                }
                            }
                            for &(rp, scope) in &running {
                                if let (true, Scope::Func(e)) = (rp == q, scope) {
                                    self.mark_func(&mut st, q, e);
                                }
                            }
                        }
                        Granularity::Program => {
                            if !ranged {
                                self.mark_prog(&mut st, q);
                            }
                        }
                    }
                }
            }
        }
        if touched {
            st.phase = Phase::Running;
            drop(st);
            let _ = self.tx.send(Event::Wake);
        }
    }

    fn cancel(&self) {
        {
            let mut st = lock(&self.state);
            if st.phase == Phase::NotStarted {
                return;
            }
            self.cancelled.store(true, Ordering::Relaxed);
            Self::cancel_running(&mut st);
            for p in &mut st.pending {
                *p = Pending::default();
            }
            st.phase = Phase::Cancelled;
            // Unpublished deltas are abandoned: published results stay
            // valid, and cancellation must not wait for a big merge.
            st.to_publish.clear();
            st.urgent = true;
        }
        let _ = self.tx.send(Event::Wake);
        self.idle.notify_all();
    }
}

impl AnalysisDriver for Scheduler {
    fn start(&self, hub: Arc<SnapshotHub>) {
        self.shared.start(hub);
    }

    fn invalidate(&self, changes: &[Change]) {
        self.shared.invalidate(changes);
    }

    fn set_focus(&self, focus: Focus) {
        lock(&self.shared.state).focus = focus;
        let _ = self.shared.tx.send(Event::Wake);
    }

    fn cancel(&self) {
        self.shared.cancel();
    }
}
