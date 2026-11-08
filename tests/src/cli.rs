//! Running the `dasm` CLI.
//!
//! Wave B: while the CLI is a stub, not built or has no ELF loader, callers
//! get [`Run::Skipped`]. With `DASM_STRICT=1` (wave C, CI) every skip path
//! becomes a panic instead, and `DASM_BIN` must name the binary explicitly
//! (no guessing in a shared target directory).

use std::path::{Path, PathBuf};
use std::process::Command;

use dasm_core::report::AnalyzeReport;

use crate::fixtures::strict;

/// Skips (or, in strict mode, fails) with a reason.
pub fn skip_or_fail(why: &str) -> Run {
    assert!(!strict(), "DASM_STRICT: {why}");
    Run::Skipped(why.to_string())
}

/// Finds the `dasm` binary. `$DASM_BIN` if set (must exist). Without it:
/// strict mode fails; otherwise `$CARGO_TARGET_DIR/{release,debug}/dasm`
/// is guessed (and printed, since it may belong to another branch).
pub fn dasm_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("DASM_BIN") {
        let p = PathBuf::from(p);
        assert!(
            p.is_file() || !strict(),
            "DASM_STRICT: DASM_BIN={} is not a file",
            p.display()
        );
        return p.is_file().then_some(p);
    }
    assert!(
        !strict(),
        "DASM_STRICT: set DASM_BIN to the dasm binary under test"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let found = ["release", "debug"]
        .iter()
        .map(|p| target.join(p).join("dasm"))
        .find(|p| p.is_file());
    if let Some(p) = &found {
        eprintln!(
            "note: guessed dasm binary {} (set DASM_BIN to pin)",
            p.display()
        );
    }
    found
}

/// Result of running `dasm analyze`.
pub enum Run {
    /// CLI unavailable or not implemented yet (reason).
    Skipped(String),
    /// Exit code and stdout/stderr.
    Done {
        /// Exit status code.
        code: i32,
        /// Standard output.
        stdout: String,
        /// Standard error.
        stderr: String,
    },
}

/// Runs `dasm analyze <args...>`.
pub fn analyze(args: &[&str], file: &Path) -> Run {
    let Some(bin) = dasm_binary() else {
        return skip_or_fail("`dasm` binary not found (cargo build -p dasm-cli, or set DASM_BIN)");
    };
    let out = match Command::new(&bin)
        .arg("analyze")
        .args(args)
        .arg(file)
        .output()
    {
        Ok(o) => o,
        Err(e) => return skip_or_fail(&format!("cannot run {}: {e}", bin.display())),
    };
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if stderr.contains("not implemented yet") {
        return skip_or_fail("CLI is still a stub");
    }
    // TODO(wave C): delete this branch once the ELF loader is wired into
    // the CLI. Until then valid ELF input is rejected as "unrecognised".
    if out.status.code() == Some(1)
        && stderr.contains("unrecognised file format")
        && std::fs::read(file).is_ok_and(|b| b.starts_with(b"\x7fELF"))
    {
        return skip_or_fail("dasm has no ELF loader wired in yet");
    }
    Run::Done {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr,
    }
}

/// Runs `dasm analyze --json [--insns]` and parses stdout both as raw JSON
/// and as the typed report. `Ok(None)` means skipped.
pub fn analyze_json(
    file: &Path,
    insns: bool,
) -> Result<Option<(serde_json::Value, AnalyzeReport)>, String> {
    let mut args = vec!["--json"];
    if insns {
        args.push("--insns");
    }
    match analyze(&args, file) {
        Run::Skipped(why) => {
            eprintln!("SKIPPED: {why}");
            Ok(None)
        }
        Run::Done {
            code,
            stdout,
            stderr,
        } => {
            if code != 0 {
                return Err(format!("dasm exited with {code}: {stderr}"));
            }
            let raw: serde_json::Value =
                serde_json::from_str(&stdout).map_err(|e| format!("invalid JSON: {e}"))?;
            let typed: AnalyzeReport =
                serde_json::from_str(&stdout).map_err(|e| format!("schema mismatch: {e}"))?;
            Ok(Some((raw, typed)))
        }
    }
}
