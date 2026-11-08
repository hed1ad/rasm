#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! QA harness for dasm: fixture discovery, parsers for the output of the
//! reference tools (`readelf`, `objdump`, `nm`), comparison rules against
//! `dasm analyze --json`, a schema validator for the JSON report and a CLI
//! runner that skips gracefully while the CLI is not implemented.

pub mod cli;
pub mod compare;
pub mod fixtures;
pub mod oracle;
pub mod schema;
