//! `X86_64` decode + render (Backend #2, feature `x86`).

/// The target.
pub fn run(data: &[u8]) {
    crate::arch::run_with(&dasm_x86::X86_64, data);
}
