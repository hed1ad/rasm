//! `ElfLoader::load` on raw bytes (Backend #1, feature `elf`).

/// The target.
pub fn run(data: &[u8]) {
    crate::loader::run_with(&dasm_elf::ElfLoader, data);
}
