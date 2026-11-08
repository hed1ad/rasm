//! DWARF parsing through `ElfLoader::load` (feature `elf`): the input is
//! split into the `.debug_*` sections of an otherwise valid ELF, in the
//! order of [`NAMES`] (see [`crate::elf_image::split`]).

use crate::elf_image::{SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS, SectionSpec, build, split};

/// Sections fed by the input; `.debug_info` takes the rest of it.
pub const NAMES: [&str; 9] = [
    ".debug_abbrev",
    ".debug_str",
    ".debug_line",
    ".debug_line_str",
    ".debug_ranges",
    ".debug_rnglists",
    ".debug_addr",
    ".debug_str_offsets",
    ".debug_info",
];

/// The target.
pub fn run(data: &[u8]) {
    let text = [0xc3u8; 64];
    let parts = split(data, NAMES.len());
    let mut sections = vec![SectionSpec {
        name: ".text",
        sh_type: SHT_PROGBITS,
        flags: SHF_ALLOC | SHF_EXECINSTR,
        data: &text,
    }];
    for (name, part) in NAMES.iter().zip(parts) {
        sections.push(SectionSpec {
            name,
            sh_type: SHT_PROGBITS,
            flags: 0,
            data: part,
        });
    }
    let (file, _) = build(&sections);
    crate::loader::run_with(&dasm_elf::ElfLoader, &file);
}
