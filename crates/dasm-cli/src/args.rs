//! Command-line arguments.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `dasm` - Linux-first disassembler.
#[derive(Debug, Parser)]
#[command(name = "dasm", version, about)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Load a binary, run the analysis to completion and print the result.
    Analyze(AnalyzeArgs),
}

/// Arguments of `dasm analyze`.
#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    /// The binary to analyse (for an existing project: the same binary,
    /// checked against the project).
    pub bin: PathBuf,
    /// Print the machine-readable report (docs/api/analyze-json.md).
    #[arg(long)]
    pub json: bool,
    /// Include every instruction of every function in the JSON report.
    #[arg(long)]
    pub insns: bool,
    /// Open this project (created if missing); without it the project
    /// lives in memory and is discarded.
    #[arg(long, value_name = "FILE")]
    pub project: Option<PathBuf>,
    /// New project only: store a path + SHA-256 instead of a copy of the
    /// binary.
    #[arg(long, requires = "project")]
    pub link: bool,
    /// Load base address (hex with 0x, or decimal).
    #[arg(long, value_name = "ADDR", value_parser = parse_base)]
    pub base: Option<u64>,
}

fn parse_base(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    };
    parsed.map_err(|e| format!("invalid address {s:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_formats() {
        assert_eq!(parse_base("0x400000"), Ok(0x40_0000));
        assert_eq!(parse_base("4096"), Ok(4096));
        assert!(parse_base("0x").is_err());
        assert!(parse_base("zz").is_err());
        assert!(parse_base("0x1ffffffffffffffff").is_err());
    }
}
