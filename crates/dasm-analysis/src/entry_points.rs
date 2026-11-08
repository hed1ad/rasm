//! The `entry_points` pass: function seeds from loader hints and user
//! overrides.

use std::collections::{BTreeMap, BTreeSet};

use dasm_core::ops::FunctionOverride;
use dasm_core::pass::passes;
use dasm_core::{
    Address, AnalysisDelta, AnalysisPass, ChangeKind, Error, FunctionSource, Granularity,
    PassContext, PassId, PassScope,
};

use crate::common::{placeholder, source_rank};
use crate::stage::{Stage, StageOutput};

/// Seeds: every loader function hint (first hint per address wins) and
/// every user `create_function`, minus user `delete_function`.
///
/// Missing seeds become placeholder functions (no blocks yet) that the
/// `functions` pass fills in; functions that lost their justification
/// (user override reset, deleted by the user) are removed.
#[derive(Clone, Copy, Debug, Default)]
pub struct EntryPointsPass;

impl AnalysisPass for EntryPointsPass {
    fn id(&self) -> PassId {
        passes::ENTRY_POINTS
    }
    fn dependencies(&self) -> Vec<PassId> {
        Vec::new()
    }
    fn granularity(&self) -> Granularity {
        Granularity::Program
    }
    fn invalidated_by(&self) -> &[ChangeKind] {
        &[ChangeKind::Function]
    }
    fn run(
        &self,
        ctx: &PassContext<'_>,
        scope: PassScope,
    ) -> Result<dasm_core::AnalysisDelta, Error> {
        Stage::run_stage(self, ctx, scope).map(|o| o.delta)
    }
}

/// Some unwind tables start a function inside the padding before it (glibc's
/// signal trampoline `__restore_rt` has its FDE one byte early). A hint that
/// points into the middle of a padding instruction moves to the end of that
/// instruction, where the code really starts.
fn realigned(snap: &dasm_core::Snapshot, hint: Address) -> Address {
    let arch = snap.arch();
    for back in 1..arch.max_insn_len() as u64 {
        let Some(start) = hint.get().checked_sub(back).map(Address) else {
            break;
        };
        let Some(bytes) = snap.memory().read_up_to(start, arch.max_insn_len()) else {
            continue;
        };
        if let Ok(d) = arch.decode(&bytes, start)
            && u64::from(d.len) > back
            && arch.is_padding(&bytes)
        {
            return start.checked_add(u64::from(d.len)).unwrap_or(hint);
        }
    }
    hint
}

impl Stage for EntryPointsPass {
    fn pass(&self) -> &dyn AnalysisPass {
        self
    }

    fn run_stage(&self, ctx: &PassContext<'_>, _scope: PassScope) -> Result<StageOutput, Error> {
        let snap = ctx.snapshot;
        let user = snap.user();
        let mut seeds: BTreeMap<Address, FunctionSource> = BTreeMap::new();
        for (i, h) in snap.image().function_hints.iter().enumerate() {
            if i % 1024 == 0 {
                ctx.cancel.check()?;
            }
            let exec = snap
                .memory()
                .region_at(h.address)
                .is_some_and(|r| r.perms().execute);
            if exec {
                seeds
                    .entry(realigned(snap, h.address))
                    .or_insert(FunctionSource::Hint(h.source));
            }
        }
        let mut forbidden: BTreeSet<Address> = BTreeSet::new();
        for (a, o) in user.function_overrides() {
            match o {
                FunctionOverride::Create => {
                    seeds.insert(a, FunctionSource::User);
                }
                FunctionOverride::Delete => {
                    seeds.remove(&a);
                    forbidden.insert(a);
                }
            }
        }
        ctx.cancel.check()?;
        let results = snap.analysis();
        let mut delta = AnalysisDelta::default();
        for (i, (a, src)) in seeds.iter().enumerate() {
            if i % 1024 == 0 {
                ctx.cancel.check()?;
            }
            let missing_or_weaker = match results.function_at(*a) {
                None => true,
                Some(f) => source_rank(src) > source_rank(&f.source),
            };
            if missing_or_weaker {
                delta.upsert_functions.push(placeholder(*a, *src));
            }
        }
        for (i, f) in results.functions().enumerate() {
            if i % 1024 == 0 {
                ctx.cancel.check()?;
            }
            let justified = matches!(f.source, FunctionSource::Hint(_) | FunctionSource::User)
                .then(|| seeds.contains_key(&f.entry))
                .unwrap_or(true);
            if forbidden.contains(&f.entry) || !justified {
                delta.remove_functions.push(f.entry);
            }
        }
        Ok(StageOutput {
            delta,
            ..StageOutput::default()
        })
    }
}
