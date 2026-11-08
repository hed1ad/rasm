//! Fuzz targets for dasm (owner: Security, see `docs/security/threat-model.md`).
//!
//! Every target is a plain `pub fn run(data: &[u8])` in its own module.
//! `fuzz_targets/*.rs` wrap them for `cargo fuzz` (libFuzzer, nightly);
//! `tests/smoke.rs` drives the same functions on stable with a
//! deterministic generator, so the targets never rot.
//!
//! A target panics only when it observes a bug: a panic inside dasm code,
//! or a violated invariant checked by the target (an "oracle"). Oracles of
//! already reported findings go through [`report::violation`], which can be
//! silenced with `DASM_FUZZ_IGNORE_KNOWN=1` to keep a long campaign going.
//!
//! | Target | Code under test | Available |
//! |---|---|---|
//! | [`journal_replay`] | `Journal::replay` + undo/redo vs. a store model | now |
//! | [`memory_read`] | `MemoryMap::{new, read, read_up_to, with_patch, region_at}` vs. a byte model | now |
//! | [`operation_json`] | JSON → `Operation` → `UserState::apply` → inverse | now |
//! | `elf_load` | `ElfLoader::load` on raw bytes | feature `elf` (Backend #1) |
//! | `eh_frame` | `ElfLoader::load` on an ELF whose `.eh_frame` is the input | feature `elf` |
//! | `dwarf` | `ElfLoader::load` on an ELF whose `.debug_*` sections are the input | feature `elf` |
//! | `x86_decode` | `X86_64::{decode, render, is_prologue, is_padding}` | feature `x86` (Backend #2) |

pub mod arch;
pub mod elf_image;
pub mod fixtures;
pub mod generate;
pub mod input;
pub mod journal_replay;
pub mod loader;
pub mod memory_read;
pub mod operation_json;
pub mod report;

#[cfg(feature = "elf")]
pub mod dwarf;
#[cfg(feature = "elf")]
pub mod eh_frame;
#[cfg(feature = "elf")]
pub mod elf_load;
#[cfg(feature = "x86")]
pub mod x86_decode;
