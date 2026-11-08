//! Virtual addresses and half-open address ranges.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Error;

/// A virtual address in the loaded image's address space.
///
/// All addresses are absolute (already relocated to the image base chosen at
/// load time). Arithmetic is checked: overflow is an error, never a wrap.
///
/// In JSON and in the project journal an address is serialized as a
/// lower-case hex string with a `0x` prefix (`"0x401000"`), because 64-bit
/// integers do not survive JavaScript/JSON number precision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub u64);

impl Address {
    /// The zero address.
    pub const ZERO: Address = Address(0);

    /// Creates an address from a raw value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Address(raw)
    }

    /// Returns the raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// `self + delta`, or `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, delta: u64) -> Option<Address> {
        match self.0.checked_add(delta) {
            Some(v) => Some(Address(v)),
            None => None,
        }
    }

    /// `self + delta` for a signed displacement (branch offsets), or `None`
    /// on overflow/underflow.
    #[must_use]
    pub const fn checked_offset(self, delta: i64) -> Option<Address> {
        match self.0.checked_add_signed(delta) {
            Some(v) => Some(Address(v)),
            None => None,
        }
    }

    /// `self - other`, or `None` if `other > self`.
    #[must_use]
    pub const fn checked_distance(self, other: Address) -> Option<u64> {
        self.0.checked_sub(other.0)
    }

    /// Parses `0x`-prefixed hex or plain decimal.
    pub fn parse(text: &str) -> Result<Address, Error> {
        let t = text.trim();
        let parsed = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
        } else {
            t.parse::<u64>()
        };
        parsed
            .map(Address)
            .map_err(|_| Error::InvalidArgument(format!("not an address: {text:?}")))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl From<u64> for Address {
    fn from(v: u64) -> Self {
        Address(v)
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Num(u64),
            Str(String),
        }
        match Repr::deserialize(d)? {
            Repr::Num(n) => Ok(Address(n)),
            Repr::Str(s) => Address::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

/// A half-open range `[start, end)` of addresses.
///
/// Invariant: `start <= end` (an empty range has `start == end`). Enforced by
/// the constructors; fields are private.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(try_from = "RangeRepr", into = "RangeRepr")]
pub struct AddressRange {
    start: Address,
    end: Address,
}

#[derive(Serialize, Deserialize)]
struct RangeRepr {
    start: Address,
    end: Address,
}

impl TryFrom<RangeRepr> for AddressRange {
    type Error = Error;
    fn try_from(r: RangeRepr) -> Result<Self, Error> {
        AddressRange::new(r.start, r.end)
    }
}

impl From<AddressRange> for RangeRepr {
    fn from(r: AddressRange) -> Self {
        RangeRepr {
            start: r.start,
            end: r.end,
        }
    }
}

impl AddressRange {
    /// Creates `[start, end)`. Fails if `end < start`.
    pub fn new(start: Address, end: Address) -> Result<Self, Error> {
        if end < start {
            return Err(Error::InvalidArgument(format!(
                "range end {end} is below start {start}"
            )));
        }
        Ok(AddressRange { start, end })
    }

    /// Creates `[start, start + len)`. Fails on overflow.
    pub fn from_len(start: Address, len: u64) -> Result<Self, Error> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| Error::InvalidArgument(format!("range {start}+{len:#x} overflows")))?;
        Ok(AddressRange { start, end })
    }

    /// The empty range `[address, address)`.
    #[must_use]
    pub const fn empty_at(address: Address) -> Self {
        AddressRange {
            start: address,
            end: address,
        }
    }

    /// First address in the range.
    #[must_use]
    pub const fn start(&self) -> Address {
        self.start
    }

    /// One past the last address.
    #[must_use]
    pub const fn end(&self) -> Address {
        self.end
    }

    /// Number of bytes covered.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.0 - self.start.0
    }

    /// True if the range covers no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start.0 == self.end.0
    }

    /// True if `addr` lies inside the range.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        self.start.0 <= addr.0 && addr.0 < self.end.0
    }

    /// True if `other` lies entirely inside `self` (empty ranges are
    /// contained in any range whose bounds include them).
    #[must_use]
    pub const fn contains_range(&self, other: &AddressRange) -> bool {
        self.start.0 <= other.start.0 && other.end.0 <= self.end.0
    }

    /// True if the two ranges share at least one byte.
    #[must_use]
    pub const fn overlaps(&self, other: &AddressRange) -> bool {
        self.start.0 < other.end.0 && other.start.0 < self.end.0
    }

    /// The common part of two ranges, if non-empty.
    #[must_use]
    pub fn intersection(&self, other: &AddressRange) -> Option<AddressRange> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        (start < end).then_some(AddressRange { start, end })
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_inverted_range() {
        assert!(AddressRange::new(Address(10), Address(5)).is_err());
        assert!(AddressRange::from_len(Address(u64::MAX), 2).is_err());
    }

    #[test]
    fn address_json_is_hex_string() {
        let json = serde_json::to_string(&Address(0x401000)).unwrap_or_default();
        assert_eq!(json, "\"0x401000\"");
        let back: Address = serde_json::from_str("\"0x401000\"").unwrap_or_default();
        assert_eq!(back, Address(0x401000));
        let num: Address = serde_json::from_str("4198400").unwrap_or_default();
        assert_eq!(num, Address(0x401000));
    }

    #[test]
    fn range_json_rejects_inverted() {
        let r: Result<AddressRange, _> = serde_json::from_str(r#"{"start":"0x10","end":"0x5"}"#);
        assert!(r.is_err());
    }

    #[test]
    fn checked_offset_handles_negative() {
        assert_eq!(Address(0x10).checked_offset(-0x10), Some(Address(0)));
        assert_eq!(Address(0x10).checked_offset(-0x11), None);
    }

    proptest! {
        #[test]
        fn range_invariants(a in any::<u64>(), b in any::<u64>(), c in any::<u64>(), d in any::<u64>()) {
            let (s1, e1) = (a.min(b), a.max(b));
            let (s2, e2) = (c.min(d), c.max(d));
            let r1 = AddressRange::new(Address(s1), Address(e1)).unwrap_or_else(|_| unreachable!());
            let r2 = AddressRange::new(Address(s2), Address(e2)).unwrap_or_else(|_| unreachable!());
            prop_assert_eq!(r1.len(), e1 - s1);
            prop_assert_eq!(r1.overlaps(&r2), r2.overlaps(&r1));
            prop_assert_eq!(r1.overlaps(&r2), r1.intersection(&r2).is_some());
            if let Some(i) = r1.intersection(&r2) {
                prop_assert!(r1.contains_range(&i) && r2.contains_range(&i));
                prop_assert!(r1.contains(i.start()) && r2.contains(i.start()));
            }
        }
    }
}
