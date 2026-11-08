//! `.eh_frame` parsing through `ElfLoader::load` (feature `elf`): the input
//! becomes the `.eh_frame` section of an otherwise valid ELF.

use crate::elf_image::{SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS, SectionSpec, build};

/// The target.
pub fn run(data: &[u8]) {
    let text = [0xc3u8; 64];
    let (file, _) = build(&[
        SectionSpec {
            name: ".text",
            sh_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            data: &text,
        },
        SectionSpec {
            name: ".eh_frame",
            sh_type: SHT_PROGBITS,
            flags: SHF_ALLOC,
            data,
        },
    ]);
    crate::loader::run_with(&dasm_elf::ElfLoader, &file);
}
