//! # dasm (CLI)
//!
//! `dasm analyze <bin> [--json] [--insns] [--project file.dasm] [--link]
//! [--base 0x...]`: loads a binary through a `dasm_core::Registry`, runs
//! analysis to completion and prints a summary or the JSON report
//! (`dasm_core::report::AnalyzeReport`, `docs/api/analyze-json.md`).
//!
//! Exit codes: `0` success, `1` load/analysis/project error (message on
//! stderr, stdout empty), `2` bad arguments.
//!
//! The concrete backends are chosen in one place, [`build_services`].
//!
//! Owner: Backend #3.

mod analyze;
mod args;
mod config;
mod services;

use std::ffi::OsString;
use std::io::Write;

use clap::Parser;
use dasm_core::report::AnalyzeReport;
use dasm_core::resolve_author;

pub use args::{AnalyzeArgs, Cli, Command};
pub use config::{Env, parse_user_name};
pub use services::{Services, build_services};

/// Exit code: success.
pub const EXIT_OK: i32 = 0;
/// Exit code: load, analysis or project error.
pub const EXIT_ERROR: i32 = 1;
/// Exit code: invalid arguments.
pub const EXIT_USAGE: i32 = 2;

/// Runs the CLI with explicit arguments and streams (testable). Returns
/// the process exit code.
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    services: &Services,
    env: &Env,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            // --help / --version go to stdout with code 0; mistakes to stderr.
            let code = if e.use_stderr() { EXIT_USAGE } else { EXIT_OK };
            let text = e.render().to_string();
            let _ = if code == EXIT_OK {
                out.write_all(text.as_bytes())
            } else {
                err.write_all(text.as_bytes())
            };
            return code;
        }
    };
    match cli.command {
        Command::Analyze(a) => {
            let author = resolve_author(env.user_name().as_deref());
            match analyze::analyze(&a, services, author) {
                Ok(done) => match print_all(&done, &a, out, err) {
                    Ok(()) => EXIT_OK,
                    // `dasm ... | head`: the reader left, not our failure.
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => EXIT_OK,
                    Err(e) => {
                        let _ = writeln!(err, "dasm: error: cannot write output: {e}");
                        EXIT_ERROR
                    }
                },
                Err(e) => {
                    let _ = writeln!(err, "dasm: error: {}", describe(&e));
                    EXIT_ERROR
                }
            }
        }
    }
}

/// Makes text from untrusted sources (file names stored in a project, paths)
/// safe for a terminal: control characters, escape sequences included,
/// are shown escaped (`\u{1b}`) instead of being interpreted.
fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    out
}

/// The error chain, with a hint for the errors a user can act on.
fn describe(e: &anyhow::Error) -> String {
    let mut text = sanitize(&format!("{e:#}"));
    if let Some(dasm_core::Error::ProjectMismatch(_)) = e.downcast_ref::<dasm_core::Error>() {
        text.push_str(" (use the original binary, or a new project file)");
    }
    text
}

fn print_all(
    done: &analyze::Analysis,
    args: &AnalyzeArgs,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> std::io::Result<()> {
    for w in &done.warnings {
        let _ = writeln!(err, "dasm: warning: {}", sanitize(w));
    }
    print_report(&done.report, args, out)
}

fn print_report(
    report: &AnalyzeReport,
    args: &AnalyzeArgs,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    if args.json {
        let json = serde_json::to_string(report).map_err(std::io::Error::other)?;
        out.write_all(json.as_bytes())?;
        out.write_all(b"\n")?;
    } else {
        let b = &report.binary;
        let s = &report.stats;
        writeln!(out, "file:       {}", sanitize(&b.path))?;
        writeln!(out, "sha256:     {}", b.sha256)?;
        writeln!(out, "format:     {:?} {:?} {:?}", b.format, b.kind, b.arch)?;
        writeln!(out, "functions:  {}", s.function_count)?;
        writeln!(out, "insns:      {}", s.insn_count)?;
        writeln!(out, "xrefs:      {}", s.xref_count)?;
        writeln!(out, "strings:    {}", s.string_count)?;
        writeln!(out, "analysis:   {} ms", s.analysis_ms)?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(sanitize("a\u{1b}[31mb\nc\u{7}"), "a\\u{1b}[31mb\\nc\\u{7}");
        assert_eq!(sanitize("plain Ünïcode"), "plain Ünïcode");
    }
}
