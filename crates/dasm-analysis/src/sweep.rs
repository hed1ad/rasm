//! The `linear_sweep` pass: functions in code no other pass reached.

use dasm_core::ops::{Definition, FunctionOverride};
use dasm_core::pass::passes;
use dasm_core::{
    Address, AnalysisDelta, AnalysisPass, ChangeKind, Error, Flow, FunctionSource, Granularity,
    PassContext, PassId, PassScope, Target,
};

use crate::common::{fetch, got_import_noreturn, in_user_data, noreturn_at, placeholder};
use crate::descent::callable;
use crate::stage::{Stage, StageOutput};

/// Looks for prologues in executable memory not covered by any function.
///
/// Every prologue found in a gap (as judged by [`dasm_core::Arch::is_prologue`],
/// skipping padding) becomes a function with source `Prologue`. After a
/// prologue the scan resumes past the fall-through body that the
/// `functions` pass will cover anyway, so one sweep round finds every
/// prologue of the gap instead of one per round. Uncovered addresses the
/// user defined as code become functions with source `User`.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinearSweepPass;

/// Sorted, merged `[start, end)` intervals covered by function blocks.
fn coverage(snap: &dasm_core::Snapshot) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = snap
        .analysis()
        .functions()
        .flat_map(|f| f.blocks.iter())
        .map(|b| (b.range().start().get(), b.range().end().get()))
        .collect();
    v.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

fn is_covered(cov: &[(u64, u64)], a: u64) -> bool {
    let i = cov.partition_point(|(s, _)| *s <= a);
    i.checked_sub(1)
        .and_then(|j| cov.get(j))
        .is_some_and(|(_, e)| a < *e)
}

/// The address after the fall-through body starting at `entry`: decodes
/// forward from `entry + first_len`, following the same fall-through rules
/// as recursive descent (through conditional jumps and calls whose callee
/// is known to return, never past a jump, return or halt), and stops where
/// descent would stop. Whatever it spans, descent from `entry` spans too,
/// so skipping it cannot hide a prologue the `functions` pass would not
/// cover this round.
fn skip_body(
    snap: &dasm_core::Snapshot,
    entry: Address,
    first_len: u64,
    gap_end: u64,
    steps: &mut usize,
    ctx: &PassContext<'_>,
) -> Result<u64, Error> {
    let arch = snap.arch();
    let program = snap.program();
    let results = snap.analysis();
    let mut p = entry.get().saturating_add(first_len);
    while p < gap_end {
        *steps += 1;
        if *steps % 256 == 0 {
            ctx.cancel.check()?;
        }
        let at = Address(p);
        let Some(bytes) = snap.memory().read_up_to(at, arch.max_insn_len()) else {
            break;
        };
        let Ok(d) = arch.decode(&bytes, at) else {
            break;
        };
        let len = u64::from(d.len).max(1);
        // Does descent from `entry` cover the instruction after `d`?
        let falls = match d.flow {
            Flow::Sequential | Flow::Syscall | Flow::ConditionalJump { .. } => true,
            Flow::Call {
                target: Target::Direct(t),
            } => {
                !noreturn_at(program, t)
                    && match results.function_at(t) {
                        Some(g) => !g.flags.noreturn,
                        None => !callable(snap, t),
                    }
            }
            Flow::Call {
                target: Target::Indirect,
            } => got_import_noreturn(program, &d) != Some(true),
            _ => false,
        };
        p = p.saturating_add(len);
        if !falls {
            break;
        }
    }
    Ok(p)
}

impl AnalysisPass for LinearSweepPass {
    fn id(&self) -> PassId {
        passes::LINEAR_SWEEP
    }
    fn dependencies(&self) -> Vec<PassId> {
        vec![passes::FUNCTIONS]
    }
    fn granularity(&self) -> Granularity {
        Granularity::Program
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

impl Stage for LinearSweepPass {
    fn pass(&self) -> &dyn AnalysisPass {
        self
    }

    fn run_stage(&self, ctx: &PassContext<'_>, _scope: PassScope) -> Result<StageOutput, Error> {
        let snap = ctx.snapshot;
        let arch = snap.arch();
        let results = snap.analysis();
        let cov = coverage(snap);
        let mut delta = AnalysisDelta::default();
        let usable = |a: Address| {
            snap.user().function_override(a) != Some(FunctionOverride::Delete)
                && results.function_at(a).is_none()
                && !in_user_data(snap, a)
                && fetch(snap, a).is_some()
        };

        for (a, def) in snap.user().definitions() {
            if matches!(def, Definition::Code) && !is_covered(&cov, a.get()) && usable(a) {
                delta
                    .upsert_functions
                    .push(placeholder(a, FunctionSource::User));
            }
        }

        let mut steps = 0usize;
        for region in snap.memory().regions() {
            if !region.perms().execute {
                continue;
            }
            let (rs, re) = (region.range().start().get(), region.range().end().get());
            // Gaps of [rs, re) not in `cov`.
            let first = cov.partition_point(|(_, e)| *e <= rs);
            let mut gaps: Vec<(u64, u64)> = Vec::new();
            let mut pos = rs;
            for (s, e) in cov.iter().skip(first) {
                if *s >= re {
                    break;
                }
                if *s > pos {
                    gaps.push((pos, *s));
                }
                pos = pos.max(*e);
            }
            if pos < re {
                gaps.push((pos, re));
            }
            for (g0, g1) in gaps {
                let mut p = g0;
                while p < g1 {
                    steps += 1;
                    if steps % 256 == 0 {
                        ctx.cancel.check()?;
                    }
                    let at = Address(p);
                    let Some(bytes) = snap.memory().read_up_to(at, arch.max_insn_len()) else {
                        break;
                    };
                    let step = match arch.decode(&bytes, at) {
                        Ok(d) => {
                            if !arch.is_padding(&bytes) && arch.is_prologue(&bytes) && usable(at) {
                                delta
                                    .upsert_functions
                                    .push(placeholder(at, FunctionSource::Prologue));
                                // Skip the fall-through body this prologue
                                // will grow: the `functions` pass covers it,
                                // so prologues are only searched past it.
                                p = skip_body(
                                    snap,
                                    at,
                                    u64::from(d.len).max(1),
                                    g1,
                                    &mut steps,
                                    ctx,
                                )?;
                                continue;
                            }
                            u64::from(d.len).max(1)
                        }
                        Err(_) => 1,
                    };
                    p = p.saturating_add(step);
                }
            }
        }
        delta.upsert_functions.sort_by_key(|f| f.entry);
        delta.upsert_functions.dedup_by_key(|f| f.entry);
        Ok(StageOutput {
            delta,
            ..StageOutput::default()
        })
    }
}
