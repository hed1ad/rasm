//! cargo-fuzz entry point; the logic lives in `dasm_fuzz::dwarf::run` so that
//! it is also exercised on stable by `cargo test` (see `tests/smoke.rs`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dasm_fuzz::dwarf::run(data));
