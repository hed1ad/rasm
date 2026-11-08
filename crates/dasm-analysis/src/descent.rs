//! Recursive descent over one function.
//!
//! [`descend`] is a pure function of the snapshot. It reads the `noreturn`
//! flags of callees from the snapshot's results and reports which callees
//! it depended on, so the scheduler can re-run it when they change.
//!
//! The flag convention makes the whole analysis a *monotone* fixpoint: a
//! function is `noreturn` until it is proven to return (it reaches a
//! `ret`, a jump through an unknown pointer, or a tail call to a function
//! that returns). A call to a function that is not yet proven to return
//! ends the path; when the callee is proven, the caller is re-run and its
//! body grows. The result is the least fixpoint, independent of the order
//! in which functions are analysed.

use std::collections::{BTreeMap, BTreeSet};

use dasm_core::ops::FunctionOverride;
use dasm_core::{
    Address, BasicBlock, CancelToken, DecodedInsn, Edge, EdgeKind, Error, Flow, Function,
    FunctionFlags, FunctionHintSource, FunctionSource, Snapshot, Target,
};

use crate::common::{fetch, got_import_noreturn, in_user_data, noreturn_at};

/// Upper bound on instructions of one function.
const MAX_FUNCTION_INSNS: usize = 1_000_000;
/// Cancellation is checked every this many instructions.
const CANCEL_STRIDE: usize = 256;
/// Upper bound on gap-filling rounds per function.
const MAX_GAP_ROUNDS: usize = 4096;

/// Which functions end a jump chain as tail-call targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TailSet {
    /// Functions from loader hints and the user only (stable during
    /// discovery).
    Seeds,
    /// Every known function (final tail-call resolution).
    All,
}

/// Result of analysing one function.
#[derive(Debug)]
pub(crate) struct Descent {
    /// The function.
    pub(crate) function: Function,
    /// Direct call targets that are (or should become) functions.
    pub(crate) calls: Vec<Address>,
    /// Callees whose "returns" status the result depends on, with the
    /// status that was observed.
    pub(crate) deps: Vec<(Address, bool)>,
}

/// True if a call/jump to `t` can be a function: executable, decodable,
/// not forbidden by the user.
pub(crate) fn callable(snap: &Snapshot, t: Address) -> bool {
    snap.user().function_override(t) != Some(FunctionOverride::Delete)
        && !in_user_data(snap, t)
        && fetch(snap, t).is_some()
}

/// Analyses the function at `entry`.
pub(crate) fn descend(
    snap: &Snapshot,
    entry: Address,
    source: FunctionSource,
    tail: TailSet,
    extent: Option<u64>,
    cancel: &CancelToken,
) -> Result<Descent, Error> {
    let results = snap.analysis();
    let program = snap.program();
    let is_tail = |t: Address| {
        t != entry
            && results.function_at(t).is_some_and(|f| match tail {
                TailSet::Seeds => {
                    matches!(
                        f.source,
                        FunctionSource::Hint(_) | FunctionSource::User | FunctionSource::UserCode
                    )
                }
                TailSet::All => true,
            })
    };

    let mut insns: BTreeMap<Address, DecodedInsn> = BTreeMap::new();
    let mut leaders: BTreeSet<Address> = BTreeSet::from([entry]);
    let mut tails: BTreeSet<Address> = BTreeSet::new();
    // Instruction that falls straight into another function's entry.
    let mut fall_out: BTreeMap<Address, Address> = BTreeMap::new();
    let mut prev: Option<Address> = None;
    let mut work = vec![entry];
    let mut calls: BTreeSet<Address> = BTreeSet::new();
    let mut deps: BTreeMap<Address, bool> = BTreeMap::new();
    let mut returns = false;
    let mut steps = 0usize;
    // Roots started at uncovered gaps inside the function's declared range.
    let mut gap_roots: BTreeSet<Address> = BTreeSet::new();
    let range_end = extent.and_then(|n| entry.checked_add(n));
    let mut rounds = 0usize;

    'rounds: loop {
        while let Some(mut pc) = work.pop() {
            prev = None;
            loop {
                if insns.contains_key(&pc) {
                    break;
                }
                steps += 1;
                if steps % CANCEL_STRIDE == 0 {
                    cancel.check()?;
                }
                if pc != entry && is_tail(pc) {
                    // Falls into another function: like a tail call.
                    if let Some(last) = prev {
                        fall_out.insert(last, pc);
                    }
                    if !noreturn_at(program, pc) {
                        let ret = results.function_at(pc).is_some_and(|g| !g.flags.noreturn);
                        deps.insert(pc, ret);
                        returns |= ret;
                    }
                    break;
                }
                if steps > MAX_FUNCTION_INSNS || in_user_data(snap, pc) {
                    break;
                }
                let Some(d) = fetch(snap, pc) else {
                    break;
                };
                insns.insert(pc, d);
                let next = d.next_address();
                let mut blocked = false;
                match d.flow {
                    Flow::Call {
                        target: Target::Direct(t),
                    } => {
                        if noreturn_at(program, t) {
                            blocked = true;
                        } else if let Some(g) = results.function_at(t) {
                            calls.insert(t);
                            let ret = !g.flags.noreturn;
                            deps.insert(t, ret);
                            blocked = !ret;
                        } else if callable(snap, t) {
                            calls.insert(t);
                            deps.insert(t, false);
                            blocked = true;
                        }
                    }
                    Flow::Call {
                        target: Target::Indirect,
                    } => {
                        blocked = got_import_noreturn(program, &d) == Some(true);
                    }
                    Flow::Jump {
                        target: Target::Direct(t),
                    } => {
                        if is_tail(t) {
                            tails.insert(pc);
                            if !noreturn_at(program, t) {
                                let ret = results.function_at(t).is_some_and(|g| !g.flags.noreturn);
                                deps.insert(t, ret);
                                returns |= ret;
                            }
                        } else {
                            leaders.insert(t);
                            work.push(t);
                        }
                    }
                    Flow::Jump {
                        target: Target::Indirect,
                    } => {
                        // A PLT-style stub returns unless the import is noreturn;
                        // an unresolved indirect jump is assumed to return.
                        returns |= got_import_noreturn(program, &d) != Some(true);
                    }
                    Flow::ConditionalJump {
                        target: Target::Direct(t),
                    } => {
                        if !is_tail(t) {
                            leaders.insert(t);
                            work.push(t);
                        }
                    }
                    Flow::Return => returns = true,
                    _ => {}
                }
                if blocked {
                    break;
                }
                let Some(next) = next else {
                    break;
                };
                if d.flow.ends_block() {
                    if d.flow.falls_through() {
                        leaders.insert(next);
                        work.push(next);
                    }
                    break;
                }
                prev = Some(pc);
                pc = next;
            }
        }
        // The loader says where the function ends (FDE): code inside that range
        // that the flow did not reach (switch cases behind an indirect jump,
        // cold paths after a noreturn call) is part of the function. Decoding
        // resumes only where an already decoded instruction ends, so the
        // instruction boundaries stay in sync.
        rounds += 1;
        let Some(end) = range_end else {
            break 'rounds;
        };
        if rounds > MAX_GAP_ROUNDS {
            break 'rounds;
        }
        let mut cursor = entry;
        let mut roots: Vec<Address> = Vec::new();
        for (a, d) in insns.range(entry..end) {
            if *a > cursor && !insns.contains_key(&cursor) && cursor_is_boundary(&insns, cursor) {
                roots.push(cursor);
            }
            cursor = d.next_address().unwrap_or(end).max(cursor);
        }
        if cursor < end && cursor_is_boundary(&insns, cursor) {
            roots.push(cursor);
        }
        roots.retain(|r| {
            !insns.contains_key(r)
                && !is_tail(*r)
                && !in_user_data(snap, *r)
                && fetch(snap, *r).is_some()
        });
        if roots.is_empty() {
            break 'rounds;
        }
        for r in roots {
            gap_roots.insert(r);
            leaders.insert(r);
            work.push(r);
        }
    }
    let _ = prev;

    let blocks = build_blocks(&insns, &leaders, &tails, &fall_out, &gap_roots);
    let thunk = insns.len() == 1 && insns.values().all(|d| matches!(d.flow, Flow::Jump { .. }));
    let plt = matches!(source, FunctionSource::Hint(FunctionHintSource::Plt))
        || program
            .import_at(entry)
            .is_some_and(|i| i.plt == Some(entry));
    let function = Function {
        entry,
        blocks,
        flags: FunctionFlags {
            noreturn: !returns,
            thunk,
            plt,
            library: false,
        },
        source,
    };
    Ok(Descent {
        function,
        calls: calls.into_iter().collect(),
        deps: deps.into_iter().collect(),
    })
}

/// Splits decoded instructions into basic blocks at leaders and gaps.
fn build_blocks(
    insns: &BTreeMap<Address, DecodedInsn>,
    leaders: &BTreeSet<Address>,
    tails: &BTreeSet<Address>,
    fall_out: &BTreeMap<Address, Address>,
    gap_roots: &BTreeSet<Address>,
) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
    let mut cur: Vec<DecodedInsn> = Vec::new();
    let flush =
        |cur: &mut Vec<DecodedInsn>, blocks: &mut Vec<BasicBlock>, next: Option<Address>| {
            let (Some(first), Some(last)) = (cur.first(), cur.last()) else {
                return;
            };
            let mut succ = Vec::new();
            match last.flow {
                Flow::Jump { target } => succ.push(Edge {
                    target,
                    kind: if tails.contains(&last.address) {
                        EdgeKind::TailCall
                    } else {
                        EdgeKind::Jump
                    },
                }),
                Flow::ConditionalJump { target } => {
                    succ.push(Edge {
                        target,
                        kind: EdgeKind::ConditionalTaken,
                    });
                    if let Some(n) = last.next_address() {
                        succ.push(Edge {
                            target: Target::Direct(n),
                            kind: EdgeKind::ConditionalNotTaken,
                        });
                    }
                }
                f if f.falls_through() => {
                    if let Some(n) = next.or_else(|| fall_out.get(&last.address).copied()) {
                        succ.push(Edge {
                            target: Target::Direct(n),
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
                _ => {}
            }
            let lens = cur.iter().map(|i| i.len).collect();
            if let Ok(b) = BasicBlock::new(first.address, lens, succ) {
                blocks.push(b);
            }
            cur.clear();
        };
    for (addr, d) in insns {
        let contiguous = cur.last().and_then(DecodedInsn::next_address) == Some(*addr);
        if !cur.is_empty() && (!contiguous || leaders.contains(addr)) {
            let next = (contiguous && !gap_roots.contains(addr)).then_some(*addr);
            flush(&mut cur, &mut blocks, next);
        }
        cur.push(*d);
        if d.flow.ends_block() {
            flush(&mut cur, &mut blocks, None);
        }
    }
    flush(&mut cur, &mut blocks, None);
    blocks
}

/// True if `at` directly follows a decoded instruction (so decoding from
/// there is in sync) or is the function's first address.
fn cursor_is_boundary(insns: &BTreeMap<Address, DecodedInsn>, at: Address) -> bool {
    insns
        .range(..at)
        .next_back()
        .is_some_and(|(_, d)| d.next_address() == Some(at))
}
