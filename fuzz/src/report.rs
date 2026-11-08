//! Reporting of oracle violations.
//!
//! Every invariant a target checks has an id. Ids of findings that are
//! already filed are listed in
//! [`KNOWN`]; with `DASM_FUZZ_IGNORE_KNOWN=1` their violations are skipped
//! instead of crashing, so a long campaign keeps looking for new bugs.

use std::sync::OnceLock;

/// Findings filed and not yet fixed. Remove an id when its fix lands: the
/// reproducer in `regressions/` must then pass.
pub const KNOWN: &[&str] = &["SEC-CORE-04", "SEC-CORE-06"];

fn ignore_known() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| std::env::var_os("DASM_FUZZ_IGNORE_KNOWN").is_some_and(|v| v == "1"))
}

/// Reports a violated invariant `id`. Panics (a crash for libFuzzer) unless
/// `id` is a known finding and known findings are ignored.
///
/// # Panics
/// That is the point: a panic is how a fuzz target reports a bug.
#[track_caller]
pub fn violation(id: &str, message: std::fmt::Arguments<'_>) {
    if ignore_known() && KNOWN.contains(&id) {
        return;
    }
    panic!("[{id}] {message}");
}

/// `if !cond { violation(id, ...) }`.
#[macro_export]
macro_rules! check {
    ($cond:expr, $id:literal, $($fmt:tt)+) => {
        if !$cond {
            $crate::report::violation($id, format_args!($($fmt)+));
        }
    };
}
