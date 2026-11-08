//! The `xrefs` pass: code references per function, pointers in data per
//! region.

use dasm_core::pass::passes;
use dasm_core::{
    Address, AddressRange, AnalysisDelta, AnalysisPass, ChangeKind, Error, Flow, Granularity,
    PassContext, PassId, PassScope, Snapshot, Target, Xref, XrefKind, XrefOwner,
};

use crate::stage::{Stage, StageOutput};

/// Size of one chunk read while scanning a data region.
const CHUNK: u64 = 1 << 20;
/// Pointers below this value are treated as plain integers.
const MIN_POINTER: u64 = 0x1000;

/// Cross-references.
///
/// - Scope `Function(entry)`: re-decodes the function's instructions and
///   replaces the group [`XrefOwner::Function`]`(entry)` with calls, jumps
///   (including tail calls), and the data references reported by the
///   decoder (`Read`, `Write`, `ReadWrite`, `DataPtr`).
/// - Scope `Range`/`Program`: scans non-executable regions for pointer-sized,
///   aligned words that point into mapped memory and replaces the group
///   [`XrefOwner::Region`] of each region with `DataPtr` references. GOT
///   slots are skipped (their initial content is a lazy-binding stub) and
///   so are values below `0x1000`.
///
/// Immediates that merely look like addresses are not references: the
/// decoder does not report them.
#[derive(Clone, Copy, Debug, Default)]
pub struct XrefsPass;

fn function_xrefs(
    snap: &Snapshot,
    entry: Address,
    cancel: &dasm_core::CancelToken,
) -> Result<Vec<Xref>, Error> {
    let Some(f) = snap.analysis().function_at(entry) else {
        return Ok(Vec::new());
    };
    let arch = snap.arch();
    let mut out = Vec::new();
    let mut n = 0usize;
    for b in &f.blocks {
        for addr in b.insn_addresses() {
            n += 1;
            if n % 256 == 0 {
                cancel.check()?;
            }
            let Some(bytes) = snap.memory().read_up_to(addr, arch.max_insn_len()) else {
                continue;
            };
            let Ok(d) = arch.decode(&bytes, addr) else {
                continue;
            };
            out.extend(d.refs().map(|r| Xref {
                from: addr,
                to: r.target,
                kind: r.kind,
            }));
            let (to, kind) = match d.flow {
                Flow::Call {
                    target: Target::Direct(t),
                } => (t, XrefKind::Call),
                Flow::Jump {
                    target: Target::Direct(t),
                }
                | Flow::ConditionalJump {
                    target: Target::Direct(t),
                } => (t, XrefKind::Jump),
                _ => continue,
            };
            out.push(Xref {
                from: addr,
                to,
                kind,
            });
        }
    }
    Ok(out)
}

fn region_xrefs(
    snap: &Snapshot,
    range: AddressRange,
    cancel: &dasm_core::CancelToken,
) -> Result<Vec<Xref>, Error> {
    let word = u64::from(snap.program().info().bits / 8).clamp(1, 8);
    let mem = snap.memory();
    let mut out = Vec::new();
    let mut pos = range.start().get();
    let end = range.end().get();
    while pos < end {
        cancel.check()?;
        // Start on a word boundary of the address space.
        let aligned = pos.div_ceil(word).saturating_mul(word);
        if aligned >= end {
            break;
        }
        let len = (end - aligned).min(CHUNK);
        let len = len - len % word;
        if len == 0 {
            break;
        }
        let Some(bytes) = usize::try_from(len)
            .ok()
            .and_then(|l| mem.read(Address(aligned), l))
        else {
            break;
        };
        for (i, w) in bytes.chunks_exact(word as usize).enumerate() {
            let value = w
                .iter()
                .rev()
                .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            if value < MIN_POINTER || mem.region_at(Address(value)).is_none() {
                continue;
            }
            let at = Address(aligned + i as u64 * word);
            let is_got = snap
                .program()
                .import_at(at)
                .is_some_and(|imp| imp.got == Some(at));
            if !is_got {
                out.push(Xref {
                    from: at,
                    to: Address(value),
                    kind: XrefKind::DataPtr,
                });
            }
        }
        pos = aligned + len;
    }
    Ok(out)
}

impl AnalysisPass for XrefsPass {
    fn id(&self) -> PassId {
        passes::XREFS
    }
    fn dependencies(&self) -> Vec<PassId> {
        vec![passes::NORETURN]
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

impl Stage for XrefsPass {
    fn pass(&self) -> &dyn AnalysisPass {
        self
    }

    fn range_scope(&self) -> bool {
        true
    }

    fn run_stage(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<StageOutput, Error> {
        let snap = ctx.snapshot;
        let mut delta = AnalysisDelta::default();
        match scope {
            PassScope::Function(entry) => {
                let x = function_xrefs(snap, entry, ctx.cancel)?;
                delta.set_xrefs.push((XrefOwner::Function(entry), x));
            }
            PassScope::Program | PassScope::Range(_) => {
                for region in snap.memory().regions() {
                    if region.perms().execute {
                        continue;
                    }
                    if let PassScope::Range(r) = scope
                        && !r.overlaps(&region.range())
                    {
                        continue;
                    }
                    let x = region_xrefs(snap, region.range(), ctx.cancel)?;
                    delta.set_xrefs.push((
                        XrefOwner::Region {
                            pass: passes::XREFS,
                            range: region.range(),
                        },
                        x,
                    ));
                }
                if scope == PassScope::Program {
                    // Whole-program run also covers every function.
                    let entries: Vec<Address> =
                        snap.analysis().functions().map(|f| f.entry).collect();
                    for e in entries {
                        let x = function_xrefs(snap, e, ctx.cancel)?;
                        delta.set_xrefs.push((XrefOwner::Function(e), x));
                    }
                }
            }
        }
        Ok(StageOutput {
            delta,
            ..StageOutput::default()
        })
    }
}
