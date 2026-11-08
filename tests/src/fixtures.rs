//! Locating fixture binaries built by `scripts/fixtures/build.sh`.
//!
//! With `DASM_STRICT=1` a missing fixture is a failure, not a skip.

use std::path::{Path, PathBuf};

/// Strict mode (`DASM_STRICT` set): skips become failures.
pub fn strict() -> bool {
    std::env::var_os("DASM_STRICT").is_some()
}

/// Directory with built fixtures (`tests/fixtures/bin`).
pub fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/bin")
}

/// Names of all built fixtures (from the directory listing), sorted.
pub fn all() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(bin_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "MANIFEST")
        .collect();
    v.sort();
    v
}

/// Fixtures whose name contains all of `parts`.
pub fn matching(parts: &[&str]) -> Vec<PathBuf> {
    all()
        .into_iter()
        .filter(|n| parts.iter().all(|p| n.contains(p)))
        .map(|n| bin_dir().join(n))
        .collect()
}

/// Path of a fixture or `None` (skip message; failure in strict mode).
pub fn require(name: &str) -> Option<PathBuf> {
    let p = bin_dir().join(name);
    if p.is_file() {
        Some(p)
    } else {
        skip(&format!("fixture `{name}` not built"));
        None
    }
}

/// All fixtures, or an empty list and a skip message when none are built
/// (failure in strict mode).
pub fn require_any() -> Vec<PathBuf> {
    let v = matching(&[]);
    if v.is_empty() {
        skip("no fixtures built");
    }
    v
}

/// Prints a visible skip notice (run with `--nocapture` to see it); panics
/// in strict mode.
pub fn skip(why: &str) {
    assert!(!strict(), "DASM_STRICT: {why}");
    eprintln!("SKIPPED: {why}; run scripts/fixtures/build.sh");
}
