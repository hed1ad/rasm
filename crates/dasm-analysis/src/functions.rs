//! The `functions` pass: recursive descent and CFG construction.

use dasm_core::pass::passes;
use dasm_core::{
    Address, AnalysisDelta, AnalysisPass, CancelToken, ChangeKind, Error, FunctionSource,
    Granularity, PassContext, PassId, PassScope,
};

use crate::common::{HintSizes, placeholder};
use crate::descent::{TailSet, descend};
use crate::stage::{Stage, StageOutput};

/// Builds the CFG of one function by recursive descent.
///
/// Scope `Function(entry)` analyses that function and, for every direct
/// call target that is not yet a function, adds a placeholder (the
/// scheduler queues it). `Program` and `Range` scopes analyse every known
/// function (in the range) once, which is what a standalone caller wants.
///
/// `flags.noreturn` is `true` until the function is proven to return; see
/// the module documentation of the descent for why the analysis is a
/// monotone fixpoint driven by the scheduler.
#[derive(Debug, Default)]
pub struct FunctionsPass {
    sizes: HintSizes,
}

pub(crate) fn analyse_function(
    snap: &dasm_core::Snapshot,
    entry: Address,
    tail: TailSet,
    sizes: &HintSizes,
    cancel: &CancelToken,
) -> Result<StageOutput, Error> {
    let results = snap.analysis();
    let Some(existing) = results.function_at(entry) else {
        return Ok(StageOutput::default());
    };
    let d = descend(
        snap,
        entry,
        existing.source,
        tail,
        sizes.get(snap, entry),
        cancel,
    )?;
    let mut delta = AnalysisDelta::default();
    for c in &d.calls {
        if results.function_at(*c).is_none() {
            delta
                .upsert_functions
                .push(placeholder(*c, FunctionSource::CallTarget));
        }
    }
    delta.upsert_functions.push(d.function);
    Ok(StageOutput {
        delta,
        calls: d.calls,
        deps: d.deps,
    })
}

impl AnalysisPass for FunctionsPass {
    fn id(&self) -> PassId {
        passes::FUNCTIONS
    }
    fn dependencies(&self) -> Vec<PassId> {
        vec![passes::ENTRY_POINTS]
    }
    fn granularity(&self) -> Granularity {
        Granularity::Function
    }
    fn invalidated_by(&self) -> &[ChangeKind] {
        &[
            ChangeKind::Definition,
            ChangeKind::Function,
            ChangeKind::Bytes,
        ]
    }
    fn run(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<AnalysisDelta, Error> {
        Stage::run_stage(self, ctx, scope).map(|o| o.delta)
    }
}

impl Stage for FunctionsPass {
    fn pass(&self) -> &dyn AnalysisPass {
        self
    }

    fn is_function_discovery(&self) -> bool {
        true
    }

    fn run_stage(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<StageOutput, Error> {
        match scope {
            PassScope::Function(entry) => {
                analyse_function(ctx.snapshot, entry, TailSet::Seeds, &self.sizes, ctx.cancel)
            }
            PassScope::Program | PassScope::Range(_) => {
                let mut out = StageOutput::default();
                let entries: Vec<Address> = ctx
                    .snapshot
                    .analysis()
                    .functions()
                    .filter(|f| match scope {
                        PassScope::Range(r) => r.contains(f.entry),
                        _ => true,
                    })
                    .map(|f| f.entry)
                    .collect();
                for e in entries {
                    ctx.cancel.check()?;
                    let one =
                        analyse_function(ctx.snapshot, e, TailSet::Seeds, &self.sizes, ctx.cancel)?;
                    out.delta
                        .upsert_functions
                        .extend(one.delta.upsert_functions);
                }
                Ok(out)
            }
        }
    }
}
