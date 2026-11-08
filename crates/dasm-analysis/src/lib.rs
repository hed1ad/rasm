//! # dasm-analysis
//!
//! The stage 1 analysis passes and the [`Scheduler`] that runs them (ADR
//! 0003).
//!
//! | Pass | Granularity | Role |
//! |---|---|---|
//! | [`EntryPointsPass`] | program | seeds from loader hints and user overrides |
//! | [`FunctionsPass`] | function | recursive descent, CFG, `noreturn` flag |
//! | [`LinearSweepPass`] | program | prologues in code nothing reached |
//! | [`NoReturnPass`] | program | final tail-call resolution |
//! | [`XrefsPass`] | function / region | code references, pointers in data |
//! | [`StringsPass`] | program | ASCII/UTF-8/UTF-16/UTF-32 strings |
//!
//! Every pass is a pure function of a snapshot; the scheduler merges the
//! deltas, so results do not depend on the number of threads or on the
//! order of work.

// `is_multiple_of` needs Rust 1.90; the workspace MSRV is 1.88.
#![allow(clippy::manual_is_multiple_of)]

mod common;
mod descent;
mod entry_points;
mod functions;
mod noreturn;
mod scheduler;
mod stage;
mod strings;
mod sweep;
mod xrefs;

pub use entry_points::EntryPointsPass;
pub use functions::FunctionsPass;
pub use noreturn::NoReturnPass;
pub use scheduler::{Config, Scheduler};
pub use strings::{StringsConfig, StringsPass};
pub use sweep::LinearSweepPass;
pub use xrefs::XrefsPass;

#[cfg(test)]
mod tests;
