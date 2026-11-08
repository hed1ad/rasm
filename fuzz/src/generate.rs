//! Deterministic input generators for the stable smoke run
//! (`tests/smoke.rs`) and for seeding a libFuzzer corpus. Structured
//! generation (valid JSON of plausible operations) followed by byte-level
//! mutation reaches far deeper than uniform random bytes would.

use dasm_core::model::DataType;
use dasm_core::{
    Address, EntryState, JournalEntry, OpMeta, OpSource, Operation, StringEncoding, TypeExpr,
};

use crate::fixtures::{CODE, DATA};

/// SplitMix64.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seeded generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }

    /// True with probability `1/n`.
    pub fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }

    /// Random bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }

    /// An address, mostly inside [`crate::fixtures::base_memory`].
    pub fn address(&mut self) -> Address {
        Address(match self.below(10) {
            0 => self.next_u64(),
            1 => u64::MAX - self.below(4),
            2 => CODE + 0xf0 + self.below(32),
            3..=5 => CODE + self.below(0x100),
            _ => DATA + self.below(0x1010),
        })
    }

    fn text(&mut self, max: usize) -> String {
        const ALPHABET: &[char] = &[
            'a', 'z', '_', '0', ' ', '\n', '\u{1b}', 'é', '\u{0}', '\u{202e}', '@', '.',
        ];
        let len = self.below(max as u64 + 1) as usize;
        (0..len)
            .map(|_| {
                ALPHABET
                    .get(self.below(ALPHABET.len() as u64) as usize)
                    .copied()
                    .unwrap_or('a')
            })
            .collect()
    }

    fn data_type(&mut self, depth: u32) -> DataType {
        match self.below(10) {
            0 => DataType::Byte,
            1 => DataType::Word,
            2 => DataType::Dword,
            3 => DataType::Qword,
            4 => DataType::Pointer,
            5 => DataType::Float,
            6 => DataType::Double,
            7 => DataType::String {
                encoding: match self.below(3) {
                    0 => StringEncoding::Ascii,
                    1 => StringEncoding::Utf16Le,
                    _ => StringEncoding::Utf32Be,
                },
            },
            _ if depth < 10 => DataType::Array {
                element: Box::new(self.data_type(depth + 1)),
                count: match self.below(4) {
                    0 => 0,
                    1 => u32::MAX,
                    _ => self.below(64) as u32,
                },
            },
            _ => DataType::Byte,
        }
    }

    /// A random operation (batches nest up to `depth` levels).
    pub fn operation(&mut self, depth: u32) -> Operation {
        let address = self.address();
        let name_or_none = |r: &mut Rng, max| (!r.one_in(4)).then(|| r.text(max));
        match self.below(if depth > 0 { 15 } else { 14 }) {
            0 => Operation::Rename {
                address,
                name: name_or_none(self, 12),
            },
            1 => Operation::SetType {
                address,
                ty: name_or_none(self, 12).map(TypeExpr),
            },
            2 => Operation::Comment {
                address,
                text: name_or_none(self, 40),
            },
            3 => Operation::DefineCode { address },
            4 => Operation::DefineData {
                address,
                ty: self.data_type(0),
            },
            5 => Operation::Undefine { address },
            6 => Operation::CreateFunction { address },
            7 => Operation::DeleteFunction { address },
            8 => Operation::ResetFunction { address },
            9 | 10 => {
                let len = self.below(20) as usize;
                Operation::PatchBytes {
                    address,
                    bytes: self.bytes(len),
                }
            }
            11 => Operation::Bookmark {
                address,
                note: name_or_none(self, 12),
            },
            12 => Operation::AddTag {
                address,
                tag: self.text(8),
            },
            13 => Operation::RemoveTag {
                address,
                tag: self.text(8),
            },
            _ => {
                let n = self.below(5);
                Operation::Batch {
                    ops: (0..n).map(|_| self.operation(depth - 1)).collect(),
                }
            }
        }
    }

    /// A random persisted journal (seqs mostly valid, sometimes not).
    pub fn journal(&mut self) -> Vec<JournalEntry> {
        let n = self.below(16);
        let mut seq = 0u64;
        (0..n)
            .map(|_| {
                seq = match self.below(20) {
                    0 => seq,                      // duplicate
                    1 => 0,                        // invalid
                    2 => u64::MAX - self.below(2), // edge
                    3 => i64::MAX as u64,
                    _ => seq.saturating_add(1 + self.below(2)),
                };
                let op = self.operation(2);
                JournalEntry {
                    seq,
                    inverse: if self.one_in(3) {
                        op.clone()
                    } else {
                        self.operation(1)
                    },
                    op,
                    meta: OpMeta {
                        author: self.text(6),
                        timestamp_ms: self.next_u64() as i64,
                        source: OpSource::Ui,
                    },
                    scope: (!self.one_in(2)).then(|| Address(CODE + self.below(2) * 0x10)),
                    state: match self.below(4) {
                        0 => EntryState::Undone,
                        1 => EntryState::Discarded,
                        _ => EntryState::Active,
                    },
                }
            })
            .collect()
    }

    /// Byte-level mutation: flips, deletions, insertions of interesting
    /// tokens, truncation.
    pub fn mutate(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        const TOKENS: &[&[u8]] = &[
            b"\"0xffffffffffffffff\"",
            b"18446744073709551615",
            b"-1",
            b"{\"op\":\"batch\",\"ops\":[",
            b"]}",
            b"null",
            b"\"\\u0000\"",
            b"1e999",
            b"\"0x\"",
            b"[",
        ];
        for _ in 0..=self.below(4) {
            let len = data.len() as u64;
            match self.below(5) {
                0 if len > 0 => {
                    let i = self.below(len) as usize;
                    if let Some(b) = data.get_mut(i) {
                        *b ^= 1 << self.below(8);
                    }
                }
                1 if len > 0 => {
                    let i = self.below(len) as usize;
                    let n = (self.below(8) as usize).min(data.len() - i);
                    data.drain(i..i + n);
                }
                2 => {
                    let i = self.below(len + 1) as usize;
                    let t = TOKENS
                        .get(self.below(TOKENS.len() as u64) as usize)
                        .copied()
                        .unwrap_or(b"");
                    data.splice(i..i, t.iter().copied());
                }
                3 => data.truncate(self.below(len + 1) as usize),
                _ => {}
            }
        }
        data
    }
}
