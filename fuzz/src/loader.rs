//! Generic loader target: any `dasm_core::Loader` on arbitrary bytes.
//!
//! Oracles: no panic; `LoadOptions::limits` are honoured; the image is
//! internally consistent; `Program`/`Snapshot` built from it can be listed
//! without panics and the listing always makes progress.

use std::sync::Arc;

use dasm_core::{
    Address, Arch, ArchId, DecodeError, DecodedInsn, Limits, LoadOptions, LoadedImage, Loader,
    Program, RenderedInsn, SharedBytes, Snapshot, SymbolLookup, sha256,
};

use crate::check;

/// Limits small enough that the fuzzer reaches `LimitExceeded` paths and
/// cannot exhaust memory, large enough for real binaries in the corpus.
#[must_use]
#[allow(clippy::needless_update)] // future `Limits` fields keep their defaults
pub fn fuzz_limits() -> Limits {
    Limits {
        max_file_size: 16 << 20,
        max_sections: 512,
        max_symbols: 1 << 15,
        max_relocations: 1 << 15,
        max_mapped_size: 1 << 30,
        max_string_bytes: 4 << 20,
        max_debug_work: 1 << 18,
        ..Limits::default()
    }
}

/// An architecture that decodes nothing (the loader target does not care
/// about instructions, `Program` just needs one).
#[derive(Debug, Clone, Copy)]
pub struct NullArch(pub ArchId);

impl Arch for NullArch {
    fn id(&self) -> ArchId {
        self.0
    }
    fn max_insn_len(&self) -> usize {
        1
    }
    fn decode(&self, _bytes: &[u8], address: Address) -> Result<DecodedInsn, DecodeError> {
        Err(DecodeError::Invalid(address))
    }
    fn render(
        &self,
        _bytes: &[u8],
        address: Address,
        _symbols: &dyn SymbolLookup,
    ) -> Result<RenderedInsn, DecodeError> {
        Err(DecodeError::Invalid(address))
    }
}

/// Runs `loader` on `data` with default base, a high PIE base and a base
/// that overflows any non-empty image.
pub fn run_with(loader: &dyn Loader, data: &[u8]) {
    let _ = loader.probe(data);
    let file = SharedBytes::from(data.to_vec());
    for base in [
        None,
        Some(Address(0x5555_5555_4000)),
        Some(Address(u64::MAX - 0xfff)),
    ] {
        let options = LoadOptions {
            base,
            limits: fuzz_limits(),
        };
        // `load` must be safe even when `probe` said no.
        if let Ok(image) = loader.load(file.clone(), &options) {
            check_image(&image, &options, data);
        }
    }
}

/// Invariants of a successfully loaded image.
pub fn check_image(image: &LoadedImage, options: &LoadOptions, file: &[u8]) {
    let l = &options.limits;
    check!(
        image.info.sha256 == sha256(file),
        "LDR-01",
        "BinaryInfo::sha256 is not the SHA-256 of the input"
    );
    check!(
        image.sections.len() <= l.max_sections,
        "LDR-02",
        "{} sections > limit",
        image.sections.len()
    );
    check!(
        image.segments.len() <= l.max_sections,
        "LDR-02",
        "{} segments > limit",
        image.segments.len()
    );
    check!(
        image.symbols.len() <= l.max_symbols,
        "LDR-02",
        "{} symbols > limit",
        image.symbols.len()
    );
    check!(
        image.relocations.len() <= l.max_relocations,
        "LDR-02",
        "{} relocations > limit",
        image.relocations.len()
    );
    let mapped: u128 = image
        .memory
        .regions()
        .iter()
        .map(|r| u128::from(r.range().len()))
        .sum();
    check!(
        mapped <= u128::from(l.max_mapped_size),
        "LDR-02",
        "{mapped} mapped bytes > limit"
    );
    let file_backed: u128 = image
        .memory
        .regions()
        .iter()
        .map(|r| r.data().len() as u128)
        .sum();
    check!(
        image
            .memory
            .regions()
            .iter()
            .all(|r| r.data().len() <= file.len()),
        "LDR-03",
        "region holds more bytes than the file ({file_backed} total)"
    );
    check!(
        image.memory.regions().iter().all(|r| !r.range().is_empty()),
        "LDR-04",
        "loader produced an empty memory region (SEC-CORE-06: breaks region lookup and the listing)"
    );

    let strings: u128 = image
        .symbols
        .iter()
        .map(|s| s.name.len() + s.demangled.as_ref().map_or(0, String::len))
        .chain(image.imports.iter().map(|i| i.name.len()))
        .chain(
            image
                .relocations
                .iter()
                .map(|r| r.symbol.as_ref().map_or(0, String::len)),
        )
        .map(|n| n as u128)
        .sum();
    check!(
        strings <= u128::from(l.max_string_bytes),
        "LDR-02",
        "{strings} bytes of names > limit"
    );

    let arch: Arc<dyn Arch> = Arc::new(NullArch(image.info.arch));
    let program = Program::new(image.clone(), arch);
    let snapshot = Snapshot::initial(Arc::new(program));
    for s in image.symbols.iter().take(64) {
        let _ = snapshot.display_name(s.address);
    }
    let Some(first) = image.memory.regions().first() else {
        return;
    };
    let mut prev_end = first.range().start();
    for item in snapshot.listing_from(first.range().start()).take(4096) {
        check!(
            !item.range.is_empty(),
            "LST-01",
            "empty listing item at {}",
            item.range.start()
        );
        check!(
            item.range.start() >= prev_end,
            "LST-01",
            "listing went backwards at {}",
            item.range.start()
        );
        prev_end = item.range.end();
    }
    if let Some(last) = image.memory.regions().last() {
        for item in snapshot.listing_before(last.range().end()).take(1024) {
            check!(
                !item.range.is_empty(),
                "LST-01",
                "empty listing item at {}",
                item.range.start()
            );
        }
    }
}
