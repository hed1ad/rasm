//! `MemoryMap` against a naive byte model.
//!
//! Input: up to 6 region specs, then up to 64 operations (`read`,
//! `read_up_to`, `with_patch`, `region_at`). Every result is compared with
//! a model that stores regions as plain vectors and patches in a
//! `BTreeMap`.

use std::collections::BTreeMap;

use dasm_core::memory::MAX_READ_LEN;
use dasm_core::{Address, AddressRange, MemoryMap, MemoryRegion, Permissions, SharedBytes};

use crate::check;
use crate::input::Reader;

struct ModelRegion {
    start: u64,
    /// Exclusive end; `start <= end`.
    end: u64,
    data: Vec<u8>,
}

struct Model {
    regions: Vec<ModelRegion>,
    patches: BTreeMap<u64, u8>,
}

impl Model {
    /// The region holding the byte at `addr` (empty regions hold nothing).
    fn region_of(&self, addr: u64) -> Option<&ModelRegion> {
        self.regions
            .iter()
            .find(|r| r.start <= addr && addr < r.end)
    }

    fn original(r: &ModelRegion, addr: u64) -> u8 {
        usize::try_from(addr - r.start)
            .ok()
            .and_then(|o| r.data.get(o).copied())
            .unwrap_or(0)
    }

    /// Expected `MemoryMap::read`.
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len > MAX_READ_LEN {
            return None;
        }
        let end = addr.checked_add(len as u64)?;
        let r = self.region_of(addr)?;
        if end > r.end {
            return None;
        }
        // Bulk copy, not per byte: reads may be up to MAX_READ_LEN long.
        let mut out = vec![0u8; len];
        let off = usize::try_from(addr - r.start).unwrap_or(usize::MAX);
        if let Some(src) = r.data.get(off.min(r.data.len())..) {
            let n = src.len().min(len);
            out[..n].copy_from_slice(&src[..n]);
        }
        for (a, b) in self.patches.range(addr..end) {
            out[(a - addr) as usize] = *b;
        }
        Some(out)
    }

    /// Expected `MemoryMap::with_patch` success.
    fn patchable(&self, addr: u64, len: usize) -> bool {
        let Some(end) = addr.checked_add(len as u64) else {
            return false;
        };
        self.region_of(addr).is_some_and(|r| end <= r.end)
    }
}

/// The target.
pub fn run(data: &[u8]) {
    let mut input = Reader::new(data);
    let mut regions = Vec::new();
    let mut model = Model {
        regions: Vec::new(),
        patches: BTreeMap::new(),
    };
    for _ in 0..input.u8() % 7 {
        let start = input.address();
        let flags = input.u8();
        let len = match flags & 3 {
            0 => 0,
            1 => u64::from(input.u8()),
            2 => u64::from(input.u16()),
            _ => input.u64(),
        };
        let file_len = usize::from(input.u8());
        let bytes = input.bytes(file_len).to_vec();
        let perms = Permissions {
            read: flags & 4 != 0,
            write: flags & 8 != 0,
            execute: flags & 16 != 0,
        };
        let Ok(range) = AddressRange::from_len(Address(start), len) else {
            check!(
                start.checked_add(len).is_none(),
                "MEM-01",
                "from_len rejected a valid range"
            );
            continue;
        };
        match MemoryRegion::new(range, SharedBytes::from(bytes.clone()), perms) {
            Ok(r) => {
                check!(
                    bytes.len() as u64 <= len,
                    "MEM-02",
                    "region accepted data longer than its range"
                );
                regions.push(r);
                model.regions.push(ModelRegion {
                    start,
                    end: start + len,
                    data: bytes,
                });
            }
            Err(_) => check!(
                bytes.len() as u64 > len,
                "MEM-02",
                "region rejected valid data"
            ),
        }
    }
    let overlapping = model.regions.iter().enumerate().any(|(i, a)| {
        model
            .regions
            .iter()
            .skip(i + 1)
            .any(|b| a.start < b.end && b.start < a.end)
    });
    let map = match MemoryMap::new(regions) {
        Ok(m) => {
            if overlapping {
                // Known root cause: an empty region hides its neighbours from
                // the pairwise overlap check in `MemoryMap::new`.
                let id = if model.regions.iter().any(|r| r.start == r.end) {
                    "SEC-CORE-06"
                } else {
                    "MEM-03"
                };
                crate::report::violation(id, format_args!("overlapping regions accepted"));
            }
            m
        }
        Err(_) => {
            check!(overlapping, "MEM-03", "non-overlapping regions rejected");
            return;
        }
    };
    exercise(&map, &mut model, &mut input);
}

fn exercise(map: &MemoryMap, model: &mut Model, input: &mut Reader<'_>) {
    let mut map = map.clone();
    for _ in 0..64 {
        if input.is_empty() {
            break;
        }
        let op = input.u8();
        let addr = input.address();
        let len = match op >> 4 {
            0 => MAX_READ_LEN + usize::from(input.u8()),
            1 => usize::from(input.u16()),
            _ => usize::from(input.u8() & 0x3f),
        };
        match op % 4 {
            0 => {
                let got = map.read(Address(addr), len).map(|c| c.into_owned());
                let want = model.read(addr, len);
                check!(
                    got == want,
                    "SEC-CORE-06",
                    "read({addr:#x}, {len}) = {got:?}, model {want:?}"
                );
            }
            1 => {
                let got = map.read_up_to(Address(addr), len).map(|c| c.into_owned());
                let want = model.region_of(addr).and_then(|r| {
                    let avail = usize::try_from(r.end - addr).unwrap_or(usize::MAX);
                    model.read(addr, avail.min(len))
                });
                check!(
                    got == want,
                    "SEC-CORE-06",
                    "read_up_to({addr:#x}, {len}) = {got:?}, model {want:?}"
                );
            }
            2 => {
                let bytes = input.bytes(len.min(64)).to_vec();
                let ok = model.patchable(addr, bytes.len());
                match map.with_patch(Address(addr), &bytes) {
                    Ok(next) => {
                        check!(
                            ok,
                            "SEC-CORE-06",
                            "patch at {addr:#x}+{} accepted, model refuses",
                            bytes.len()
                        );
                        if let Some(r) = model.region_of(addr) {
                            let originals: Vec<u8> = (0..bytes.len() as u64)
                                .map(|i| Model::original(r, addr + i))
                                .collect();
                            for (i, (new, old)) in bytes.iter().zip(originals).enumerate() {
                                let a = addr + i as u64;
                                if *new == old {
                                    model.patches.remove(&a);
                                } else {
                                    model.patches.insert(a, *new);
                                }
                            }
                        }
                        map = next;
                    }
                    Err(_) => check!(
                        !ok,
                        "SEC-CORE-06",
                        "patch at {addr:#x}+{} refused, model accepts",
                        bytes.len()
                    ),
                }
                let got: Vec<(u64, u8)> = map.patches().map(|(a, b)| (a.get(), b)).collect();
                let want: Vec<(u64, u8)> = model.patches.iter().map(|(a, b)| (*a, *b)).collect();
                check!(
                    got == want,
                    "MEM-04",
                    "patch overlay {got:?}, model {want:?}"
                );
                check!(
                    map.patch_count() == want.len(),
                    "MEM-04",
                    "patch_count disagrees"
                );
            }
            _ => {
                let got = map
                    .region_at(Address(addr))
                    .map(|r| r.range().start().get());
                let want = model.region_of(addr).map(|r| r.start);
                check!(
                    got == want,
                    "SEC-CORE-06",
                    "region_at({addr:#x}) = {got:x?}, model {want:x?}"
                );
            }
        }
    }
}
