#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Benchmarks (plain `harness = false`, no extra dependencies).
//!
//! Run: `cargo bench --manifest-path tests/Cargo.toml`
//!
//! Output: one JSON object per line on stdout, stable keys, for CI to diff:
//! `{"bench":"name","profile":"release","samples":N,"min_ns":..,"median_ns":..,"max_ns":..}`.
//! `BENCH_OUT=file` additionally appends the lines to a file;
//! `BENCH_SAMPLES=n` overrides the sample count (default 10, CLI cases 3).
//!
//! Cases:
//! * `mock/session_open`, `mock/report_json` - in-process baselines on the
//!   synthetic program (always run; detect regressions in the core).
//! * `cli/analyze_json/<binary>` - wall time of `dasm analyze --json` on a
//!   large binary (`$DASM_BENCH_BIN`, else `/usr/lib/libLLVM.so` or
//!   `/usr/bin/ls`...). Skipped with a message until the CLI exists.
//! * `cli/first_publication` - TODO for wave C: needs in-process access
//!   to loader + driver (`SnapshotHub` first non-empty publication); the
//!   CLI only reports the total. Tracked in the QA report.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use dasm_core::report::{AnalyzeReport, ReportOptions};
use dasm_core::testing::mock_session;
use dasm_tests::cli::dasm_binary;

/// Build profile of this binary: numbers from `debug` must not be compared
/// with `release` ones (`cargo bench` builds release).
const PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

fn samples(default: usize) -> usize {
    std::env::var("BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .max(1)
}

fn emit(name: &str, mut ns: Vec<u128>) {
    ns.sort_unstable();
    let line = format!(
        "{{\"bench\":\"{name}\",\"profile\":\"{PROFILE}\",\"samples\":{},\"min_ns\":{},\"median_ns\":{},\"max_ns\":{}}}",
        ns.len(),
        ns.first().copied().unwrap_or(0),
        ns.get(ns.len() / 2).copied().unwrap_or(0),
        ns.last().copied().unwrap_or(0)
    );
    println!("{line}");
    if let Some(path) = std::env::var_os("BENCH_OUT")
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

fn measure(name: &str, n: usize, mut f: impl FnMut()) {
    f(); // warm-up
    let ns = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_nanos()
        })
        .collect();
    emit(name, ns);
}

fn big_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("DASM_BENCH_BIN") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/lib/libLLVM.so",
        "/usr/lib/x86_64-linux-gnu/libLLVM.so",
        "/usr/bin/ls",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

fn main() {
    // `cargo test` also builds benches with `--test`-like args: do nothing.
    if std::env::args().any(|a| a == "--list" || a == "--test") {
        return;
    }
    measure("mock/session_open", samples(50), || {
        let s = mock_session().expect("mock session");
        std::hint::black_box(s.snapshot().generation());
    });
    let session = mock_session().expect("mock session");
    measure("mock/report_json", samples(50), || {
        let r = AnalyzeReport::from_snapshot(
            &session.snapshot(),
            &ReportOptions {
                path: "synthetic".into(),
                include_instructions: true,
                analysis_ms: 0,
            },
        );
        std::hint::black_box(serde_json::to_string(&r).expect("json").len());
    });

    let (Some(dasm), Some(bin)) = (dasm_binary(), big_binary()) else {
        eprintln!(
            "SKIPPED cli benchmarks: dasm binary or large input not found (set DASM_BIN, DASM_BENCH_BIN)"
        );
        return;
    };
    let probe = Command::new(&dasm)
        .arg("analyze")
        .arg("--json")
        .arg(&bin)
        .output();
    match probe {
        Ok(o) if o.status.success() => {
            let name = bin
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            measure(&format!("cli/analyze_json/{name}"), samples(3), || {
                let o = Command::new(&dasm)
                    .arg("analyze")
                    .arg("--json")
                    .arg(&bin)
                    .output()
                    .expect("run dasm");
                assert!(o.status.success());
                std::hint::black_box(o.stdout.len());
            });
        }
        Ok(o) => eprintln!(
            "SKIPPED cli benchmarks: dasm exited with {:?} ({})",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .next()
                .unwrap_or("")
        ),
        Err(e) => eprintln!("SKIPPED cli benchmarks: {e}"),
    }
}
