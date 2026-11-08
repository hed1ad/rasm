//! The scheduler-facing form of a pass.

use std::sync::Arc;

use dasm_core::{
    Address, AnalysisDelta, AnalysisPass, ChangeKind, Error, Granularity, PassContext, PassId,
    PassScope,
};

/// What one pass invocation produced.
#[derive(Debug, Default)]
pub(crate) struct StageOutput {
    /// The model update.
    pub(crate) delta: AnalysisDelta,
    /// Direct call targets of the analysed function (function passes).
    pub(crate) calls: Vec<Address>,
    /// Functions whose "returns" status the result depends on, with the
    /// status observed (function passes).
    pub(crate) deps: Vec<(Address, bool)>,
}

/// A pass as the scheduler runs it.
pub(crate) trait Stage: Send + Sync {
    /// The underlying pass.
    fn pass(&self) -> &dyn AnalysisPass;

    /// Runs the pass, returning side information with the delta.
    fn run_stage(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<StageOutput, Error>;

    /// True if the pass also accepts [`PassScope::Range`] tasks (data
    /// regions, string scans).
    fn range_scope(&self) -> bool {
        false
    }

    /// True for the pass that analyses functions and reports `calls` and
    /// `deps` (at most one per scheduler).
    fn is_function_discovery(&self) -> bool {
        false
    }
}

/// Adapter for a plain [`AnalysisPass`] (plugins, tests).
pub(crate) struct Generic(pub(crate) Arc<dyn AnalysisPass>);

impl Stage for Generic {
    fn pass(&self) -> &dyn AnalysisPass {
        &*self.0
    }

    fn run_stage(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<StageOutput, Error> {
        Ok(StageOutput {
            delta: self.0.run(ctx, scope)?,
            ..StageOutput::default()
        })
    }
}

/// Static description of a registered pass.
#[derive(Clone, Debug)]
pub(crate) struct PassInfo {
    pub(crate) id: PassId,
    pub(crate) granularity: Granularity,
    pub(crate) invalidated_by: Vec<ChangeKind>,
}
