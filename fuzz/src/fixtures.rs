//! Fixed state the targets run against.

use dasm_core::{
    Address, AddressRange, MemoryMap, MemoryRegion, Permissions, SharedBytes, UserState,
};

/// Start of the code region of [`base_memory`].
pub const CODE: u64 = 0x1000;
/// Start of the data region of [`base_memory`] (16 file bytes, 4 KiB zero-filled).
pub const DATA: u64 = 0x2000;

/// A small memory map: `[0x1000, 0x1100)` r-x fully file-backed and
/// `[0x2000, 0x3000)` rw- with a zero-filled tail.
#[must_use]
pub fn base_memory() -> MemoryMap {
    let code: Vec<u8> = (0..0x100u32).map(|i| (i * 7 + 1) as u8).collect();
    let data: Vec<u8> = (0..16u8).collect();
    let regions = [
        (CODE, 0x100, code, Permissions::RX),
        (DATA, 0x1000, data, Permissions::RW),
    ]
    .into_iter()
    .filter_map(|(start, len, bytes, perms)| {
        let range = AddressRange::from_len(Address(start), len).ok()?;
        MemoryRegion::new(range, SharedBytes::from(bytes), perms).ok()
    })
    .collect();
    MemoryMap::new(regions).unwrap_or_default()
}

/// Fresh user state over [`base_memory`].
#[must_use]
pub fn base_state() -> UserState {
    UserState::new(base_memory())
}

/// Everything observable in a user state, as text (imbl maps print in key
/// order, so equal states print equally).
#[must_use]
pub fn fingerprint(state: &UserState) -> String {
    format!("{state:?}")
}
