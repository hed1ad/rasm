//! Helpers shared by the passes.

use dasm_core::ops::Definition;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use dasm_core::{
    Address, AnalysisResults, DecodedInsn, Function, FunctionFlags, FunctionSource, Program,
    Snapshot,
};

/// Decodes the instruction at `addr` if it lies in executable memory.
pub(crate) fn fetch(snap: &Snapshot, addr: Address) -> Option<DecodedInsn> {
    let mem = snap.memory();
    let region = mem.region_at(addr)?;
    if !region.perms().execute {
        return None;
    }
    let arch = snap.arch();
    let bytes = mem.read_up_to(addr, arch.max_insn_len())?;
    arch.decode(&bytes, addr).ok()
}

/// True if `addr` lies inside a user-defined data item that is not code.
pub(crate) fn in_user_data(snap: &Snapshot, addr: Address) -> bool {
    let Some((start, Definition::Data { ty })) = snap.user().definition_at_or_before(addr) else {
        return false;
    };
    let ptr = u64::from(snap.program().info().bits / 8);
    let size = ty.fixed_size(ptr).unwrap_or_else(|| {
        snap.analysis()
            .string_at(start)
            .map_or(1, |s| s.byte_len.max(1))
    });
    start.checked_add(size).is_some_and(|end| addr < end)
}

/// Functions that never return, by name (imports, PLT stubs and symbols).
const NORETURN_NAMES: &[&str] = &[
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "quick_exit",
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__assert_fail",
    "__assert",
    "__assert_perror_fail",
    "__chk_fail",
    "__fortify_fail",
    "__libc_fatal",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_pure_virtual",
    "__cxa_call_terminate",
    "_Unwind_Resume",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "err",
    "errx",
    "verr",
    "verrx",
];

/// True if `name` (possibly `foo@plt`, `foo@got`, `foo@GLIBC_2.2.5`) is a
/// known noreturn function.
pub(crate) fn is_noreturn_name(name: &str) -> bool {
    let base = name.split('@').next().unwrap_or(name);
    NORETURN_NAMES.contains(&base)
}

/// True if the loader names `addr` (PLT stub, GOT slot or symbol) as a
/// noreturn function.
pub(crate) fn noreturn_at(program: &Program, addr: Address) -> bool {
    if let Some(imp) = program.import_at(addr) {
        return is_noreturn_name(&imp.name);
    }
    program
        .symbol_name(addr)
        .is_some_and(|n| is_noreturn_name(&n))
}

/// For an indirect transfer through a GOT slot (`call [rip+GOT]`): the
/// import's noreturn-ness, or `None` if no import is referenced.
pub(crate) fn got_import_noreturn(program: &Program, insn: &DecodedInsn) -> Option<bool> {
    insn.refs()
        .find_map(|r| program.import_at(r.target))
        .map(|imp| is_noreturn_name(&imp.name))
}

/// Strength of the reason for a function to exist; a placeholder never
/// downgrades an existing function.
pub(crate) fn source_rank(s: &FunctionSource) -> u8 {
    match s {
        FunctionSource::User | FunctionSource::UserCode => 3,
        FunctionSource::Hint(_) => 2,
        FunctionSource::Prologue => 1,
        _ => 0,
    }
}

/// A function that exists but has not been analysed yet. Its `noreturn`
/// flag is set: "not yet proven to return" (see the `functions` pass).
pub(crate) fn placeholder(entry: Address, source: FunctionSource) -> Function {
    let mut f = Function::new(entry, source, Vec::new());
    f.flags = FunctionFlags {
        noreturn: true,
        ..FunctionFlags::default()
    };
    f
}

/// True for [`placeholder`]-shaped functions.
pub(crate) fn is_placeholder(f: &Function) -> bool {
    f.blocks.is_empty() && f.flags.noreturn && !f.flags.thunk && !f.flags.plt
}

/// Whether `target` is known to return, as seen in `results`.
pub(crate) fn returns_now(results: &AnalysisResults, target: Address) -> bool {
    results
        .function_at(target)
        .is_some_and(|f| !f.flags.noreturn)
}

/// Sizes the loader gave to function hints (FDE ranges), indexed once per
/// program. The index is rebuilt when the program changes.
#[derive(Debug, Default)]
pub(crate) struct HintSizes(Mutex<Option<SizeIndex>>);

type SizeIndex = (Weak<Program>, Arc<BTreeMap<Address, u64>>);

impl HintSizes {
    /// Size of the function hint at `entry`, if any.
    pub(crate) fn get(&self, snap: &Snapshot, entry: Address) -> Option<u64> {
        let program = snap.program();
        let index = {
            let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            match &*guard {
                Some((w, idx)) if Weak::ptr_eq(w, &Arc::downgrade(program)) => Arc::clone(idx),
                _ => {
                    let mut idx: BTreeMap<Address, u64> = BTreeMap::new();
                    for h in &snap.image().function_hints {
                        if let Some(sz) = h.size.filter(|s| *s > 0) {
                            let e = idx.entry(h.address).or_insert(0);
                            *e = (*e).max(sz);
                        }
                    }
                    let idx = Arc::new(idx);
                    *guard = Some((Arc::downgrade(program), Arc::clone(&idx)));
                    idx
                }
            }
        };
        index.get(&entry).copied()
    }
}
