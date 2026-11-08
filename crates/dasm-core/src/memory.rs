//! Shared file bytes and the virtual memory map of a loaded image.

use std::borrow::Cow;
use std::sync::Arc;

use imbl::OrdMap;
use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressRange};
use crate::error::Error;

/// An immutable, cheaply clonable view into a shared byte buffer.
///
/// The whole input file is read once into an `Arc<[u8]>` and every section,
/// segment and snapshot refers into it without copying. (A later ADR may
/// switch the backing store to `mmap`; the API stays the same.)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedBytes {
    buf: Arc<[u8]>,
    start: usize,
    len: usize,
}

impl SharedBytes {
    /// Wraps a whole buffer.
    #[must_use]
    pub fn new(buf: Arc<[u8]>) -> Self {
        let len = buf.len();
        SharedBytes { buf, start: 0, len }
    }

    /// A sub-slice `[offset, offset + len)` of this view, or `None` if it is
    /// out of bounds.
    #[must_use]
    pub fn slice(&self, offset: usize, len: usize) -> Option<SharedBytes> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(SharedBytes {
            buf: Arc::clone(&self.buf),
            start: self.start.checked_add(offset)?,
            len,
        })
    }

    /// The bytes of this view.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // Invariant upheld by constructors: start + len <= buf.len().
        self.buf
            .get(self.start..self.start + self.len)
            .unwrap_or(&[])
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if the view is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl From<Vec<u8>> for SharedBytes {
    fn from(v: Vec<u8>) -> Self {
        SharedBytes::new(Arc::from(v))
    }
}

/// Read/write/execute permissions of a segment, section or region.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permissions {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub execute: bool,
}

impl Permissions {
    /// `r-x`.
    pub const RX: Permissions = Permissions {
        read: true,
        write: false,
        execute: true,
    };
    /// `r--`.
    pub const R: Permissions = Permissions {
        read: true,
        write: false,
        execute: false,
    };
    /// `rw-`.
    pub const RW: Permissions = Permissions {
        read: true,
        write: true,
        execute: false,
    };
}

/// One contiguous mapped region of the virtual address space.
///
/// `range.len()` may exceed `data.len()`: the tail (e.g. `.bss`) reads as
/// zeros, like the ELF loader would map it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    range: AddressRange,
    data: SharedBytes,
    perms: Permissions,
}

impl MemoryRegion {
    /// Creates a region. Fails if `data` is longer than `range`.
    pub fn new(range: AddressRange, data: SharedBytes, perms: Permissions) -> Result<Self, Error> {
        if data.len() as u64 > range.len() {
            return Err(Error::InvalidArgument(format!(
                "region {range} has {} bytes of data, more than its size",
                data.len()
            )));
        }
        Ok(MemoryRegion { range, data, perms })
    }

    /// Virtual range covered by the region.
    #[must_use]
    pub fn range(&self) -> AddressRange {
        self.range
    }

    /// File-backed bytes (may be shorter than the range).
    #[must_use]
    pub fn data(&self) -> &SharedBytes {
        &self.data
    }

    /// Permissions.
    #[must_use]
    pub fn perms(&self) -> Permissions {
        self.perms
    }
}

/// Largest single [`MemoryMap::read`], in bytes (64 MiB).
pub const MAX_READ_LEN: usize = 64 << 20;

/// The virtual memory of a loaded image: non-overlapping regions plus an
/// overlay of user byte patches.
///
/// Reads never panic: unmapped addresses yield `None`.
#[derive(Clone, Debug, Default)]
pub struct MemoryMap {
    /// Sorted by start, non-empty, non-overlapping. Shared: cloning a map
    /// (every patch, every journal copy) does not copy the regions.
    regions: Arc<[MemoryRegion]>,
    patches: OrdMap<Address, u8>,
}

impl MemoryMap {
    /// Builds a map from regions. Regions are sorted by start; empty
    /// regions (a `PT_LOAD` with `p_memsz == 0`) map nothing and are
    /// dropped; overlapping regions are rejected.
    pub fn new(mut regions: Vec<MemoryRegion>) -> Result<Self, Error> {
        regions.retain(|r| !r.range.is_empty());
        regions.sort_by_key(|r| r.range.start());
        for pair in regions.windows(2) {
            if let [a, b] = pair
                && a.range.overlaps(&b.range)
            {
                return Err(Error::InvalidArgument(format!(
                    "memory regions {} and {} overlap",
                    a.range, b.range
                )));
            }
        }
        Ok(MemoryMap {
            regions: regions.into(),
            patches: OrdMap::new(),
        })
    }

    /// All regions, sorted by address.
    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// The region containing `addr`.
    #[must_use]
    pub fn region_at(&self, addr: Address) -> Option<&MemoryRegion> {
        let idx = self.regions.partition_point(|r| r.range.end() <= addr);
        self.regions.get(idx).filter(|r| r.range.contains(addr))
    }

    /// True if every byte of `range` is mapped in a single region.
    #[must_use]
    pub fn is_mapped(&self, range: &AddressRange) -> bool {
        self.region_at(range.start())
            .is_some_and(|r| r.range.contains_range(range))
    }

    /// Reads `len` bytes at `addr` with patches applied. Returns `None` if
    /// the range is not fully inside one region or `len` exceeds
    /// [`MAX_READ_LEN`] (scan big regions in chunks: a huge `.bss` must not
    /// turn into a huge allocation). Borrowed when no patch and no
    /// zero-fill is involved.
    #[must_use]
    pub fn read(&self, addr: Address, len: usize) -> Option<Cow<'_, [u8]>> {
        if len > MAX_READ_LEN {
            return None;
        }
        let range = AddressRange::from_len(addr, len as u64).ok()?;
        let region = self.region_at(addr)?;
        if !region.range.contains_range(&range) {
            return None;
        }
        let off = usize::try_from(addr.checked_distance(region.range.start())?).ok()?;
        let data = region.data.as_slice();
        let file_end = off.saturating_add(len).min(data.len());
        let has_patch = self.patches.range(addr..range.end()).next().is_some();
        if file_end == off.saturating_add(len) && !has_patch {
            return data.get(off..file_end).map(Cow::Borrowed);
        }
        let mut out = vec![0u8; len];
        if off < file_end {
            let src = data.get(off..file_end)?;
            out.get_mut(..src.len())?.copy_from_slice(src);
        }
        for (a, b) in self.patches.range(addr..range.end()) {
            let i = usize::try_from(a.checked_distance(addr)?).ok()?;
            *out.get_mut(i)? = *b;
        }
        Some(Cow::Owned(out))
    }

    /// Reads up to `max` bytes at `addr`, truncated at the end of the region
    /// (for decoders that need "as many bytes as available").
    #[must_use]
    pub fn read_up_to(&self, addr: Address, max: usize) -> Option<Cow<'_, [u8]>> {
        let region = self.region_at(addr)?;
        let avail = region.range.end().checked_distance(addr)?;
        let len = usize::try_from(avail).unwrap_or(usize::MAX).min(max);
        self.read(addr, len)
    }

    /// Returns a copy with `bytes` patched in at `addr`. Fails if the range
    /// is not mapped. Bytes equal to the original are removed from the
    /// overlay, so patching back to the original leaves no trace.
    pub fn with_patch(&self, addr: Address, bytes: &[u8]) -> Result<MemoryMap, Error> {
        let range = AddressRange::from_len(addr, bytes.len() as u64)?;
        if !self.is_mapped(&range) {
            return Err(Error::InvalidOperation(format!(
                "patch {range} is not mapped"
            )));
        }
        let unpatched = MemoryMap {
            regions: Arc::clone(&self.regions),
            patches: OrdMap::new(),
        };
        let original = unpatched
            .read(addr, bytes.len())
            .ok_or_else(|| Error::InvalidOperation(format!("patch {range} is not mapped")))?;
        let mut patches = self.patches.clone();
        for (i, (&new, &old)) in bytes.iter().zip(original.iter()).enumerate() {
            let a = addr
                .checked_add(i as u64)
                .ok_or_else(|| Error::InvalidArgument("patch overflows".into()))?;
            if new == old {
                patches.remove(&a);
            } else {
                patches.insert(a, new);
            }
        }
        Ok(MemoryMap {
            regions: Arc::clone(&self.regions),
            patches,
        })
    }

    /// Currently patched bytes (address → new value), in address order.
    pub fn patches(&self) -> impl Iterator<Item = (Address, u8)> + '_ {
        self.patches.iter().map(|(a, b)| (*a, *b))
    }

    /// Number of patched bytes.
    #[must_use]
    pub fn patch_count(&self) -> usize {
        self.patches.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> MemoryMap {
        let r = MemoryRegion::new(
            AddressRange::from_len(Address(0x1000), 8).unwrap(),
            SharedBytes::from(vec![1, 2, 3, 4]),
            Permissions::RW,
        )
        .unwrap();
        MemoryMap::new(vec![r]).unwrap()
    }

    #[test]
    fn reads_zero_fill_and_bounds() {
        let m = map();
        assert_eq!(m.read(Address(0x1000), 4).unwrap().as_ref(), &[1, 2, 3, 4]);
        assert_eq!(m.read(Address(0x1002), 4).unwrap().as_ref(), &[3, 4, 0, 0]);
        assert!(m.read(Address(0x1006), 4).is_none());
        assert!(m.read(Address(0xfff), 1).is_none());
        assert!(m.read(Address(u64::MAX), 2).is_none());
        assert_eq!(m.read_up_to(Address(0x1006), 16).unwrap().len(), 2);
    }

    #[test]
    fn patch_and_revert() {
        let m = map().with_patch(Address(0x1001), &[9, 3]).unwrap();
        assert_eq!(m.read(Address(0x1000), 3).unwrap().as_ref(), &[1, 9, 3]);
        assert_eq!(m.patch_count(), 1, "byte equal to original is not stored");
        let back = m.with_patch(Address(0x1001), &[2]).unwrap();
        assert_eq!(back.patch_count(), 0);
        // The earlier version is untouched (persistent overlay).
        assert_eq!(m.patches().collect::<Vec<_>>(), vec![(Address(0x1001), 9)]);
        assert!(map().with_patch(Address(0x1007), &[0, 0]).is_err());
    }

    fn region(start: u64, len: u64) -> MemoryRegion {
        MemoryRegion::new(
            AddressRange::from_len(Address(start), len).unwrap(),
            SharedBytes::default(),
            Permissions::R,
        )
        .unwrap()
    }

    #[test]
    fn empty_regions_cannot_hide_an_overlap() {
        // SEC-CORE-06: the empty region used to separate the overlapping
        // pair in the adjacent-pairs check.
        let r = MemoryMap::new(vec![
            region(0x1000, 0x80),
            region(0x1000, 0),
            region(0x1040, 0x10),
        ]);
        assert!(r.is_err());
    }

    #[test]
    fn empty_regions_are_dropped() {
        let m = MemoryMap::new(vec![
            region(0x1000, 4),
            region(0x2000, 0),
            region(0x3000, 4),
        ])
        .unwrap();
        assert_eq!(m.regions().len(), 2);
        assert!(m.region_at(Address(0x2000)).is_none());
        assert!(m.region_at(Address(0x3000)).is_some());
    }

    #[test]
    fn patching_shares_regions() {
        let m = map();
        let p = m.with_patch(Address(0x1000), &[9]).unwrap();
        assert!(Arc::ptr_eq(&m.regions, &p.regions));
    }

    #[test]
    fn huge_zero_fill_read_is_refused() {
        // A 4 GiB .bss must not become a 4 GiB allocation.
        let r = MemoryRegion::new(
            AddressRange::from_len(Address(0x10000), 4 << 30).unwrap(),
            SharedBytes::default(),
            Permissions::RW,
        )
        .unwrap();
        let m = MemoryMap::new(vec![r]).unwrap();
        assert!(m.read(Address(0x10000), 1 << 32).is_none());
        assert!(m.read(Address(0x10000), MAX_READ_LEN + 1).is_none());
        assert_eq!(m.read(Address(0x10000), 16).unwrap().len(), 16);
    }

    #[test]
    fn rejects_overlap() {
        let a = MemoryRegion::new(
            AddressRange::from_len(Address(0), 8).unwrap(),
            SharedBytes::default(),
            Permissions::R,
        )
        .unwrap();
        let b = MemoryRegion::new(
            AddressRange::from_len(Address(4), 8).unwrap(),
            SharedBytes::default(),
            Permissions::R,
        )
        .unwrap();
        assert!(MemoryMap::new(vec![a, b]).is_err());
    }

    #[test]
    fn shared_slice_bounds() {
        let b = SharedBytes::from(vec![0u8; 4]);
        assert!(b.slice(2, 2).is_some());
        assert!(b.slice(3, 2).is_none());
        assert!(b.slice(usize::MAX, 2).is_none());
    }
}
