//! The `noreturn` pass: final tail-call resolution.

use dasm_core::pass::passes;
use dasm_core::{
    AnalysisDelta, AnalysisPass, ChangeKind, EdgeKind, Error, Function, Granularity, PassContext,
    PassId, PassScope, Target,
};

use crate::common::HintSizes;
use crate::descent::{TailSet, descend};
use crate::stage::{Stage, StageOutput};

/// Resolves tail calls once the set of functions is known, after
/// `linear_sweep`.
///
/// While `functions` runs, only loader/user functions end a jump chain; a
/// `jmp` to a function that was merely discovered through a call is
/// followed like any jump. This pass re-analyses every function that jumps
/// to the entry of another function with *all* functions known, which
/// turns that jump into an [`EdgeKind::TailCall`] edge and removes the
/// other function's code from the body.
///
/// Noreturn *propagation* itself is the scheduler's feedback loop over the
/// `noreturn` flags computed by `functions` (a call to a function not yet
/// proven to return ends the path; proving it re-runs the callers). The
/// flags are final when this pass runs and are kept as they are.
#[derive(Debug, Default)]
pub struct NoReturnPass {
    sizes: HintSizes,
}

fn needs_tail_resolution(snap: &dasm_core::Snapshot, f: &Function) -> bool {
    f.blocks.iter().flat_map(|b| b.successors.iter()).any(|e| {
        matches!(
            (e.kind, e.target),
            (EdgeKind::Jump, Target::Direct(t))
                if t != f.entry && snap.analysis().function_at(t).is_some()
        )
    })
}

impl AnalysisPass for NoReturnPass {
    fn id(&self) -> PassId {
        passes::NORETURN
    }
    fn dependencies(&self) -> Vec<PassId> {
        vec![passes::LINEAR_SWEEP]
    }
    fn granularity(&self) -> Granularity {
        Granularity::Program
    }
    fn invalidated_by(&self) -> &[ChangeKind] {
        &[]
    }
    fn run(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<AnalysisDelta, Error> {
        Stage::run_stage(self, ctx, scope).map(|o| o.delta)
    }
}

impl Stage for NoReturnPass {
    fn pass(&self) -> &dyn AnalysisPass {
        self
    }

    fn run_stage(&self, ctx: &PassContext<'_>, _scope: PassScope) -> Result<StageOutput, Error> {
        let snap = ctx.snapshot;
        let mut delta = AnalysisDelta::default();
        for f in snap.analysis().functions() {
            if !needs_tail_resolution(snap, f) {
                continue;
            }
            ctx.cancel.check()?;
            let d = descend(
                snap,
                f.entry,
                f.source,
                TailSet::All,
                self.sizes.get(snap, f.entry),
                ctx.cancel,
            )?;
            let mut new = d.function;
            new.flags = f.flags;
            if new != **f {
                delta.upsert_functions.push(new);
            }
        }
        Ok(StageOutput {
            delta,
            ..StageOutput::default()
        })
    }
}
