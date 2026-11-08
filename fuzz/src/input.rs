//! A total (never panicking) reader over fuzzer bytes. Running out of input
//! yields zeros, so every byte string is a valid program for a target.

/// Cursor over the fuzzer input.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Wraps the input.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    /// True when all bytes are consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Up to `n` bytes (fewer at the end of input).
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.data.len());
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        head
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for (dst, src) in out.iter_mut().zip(self.bytes(N)) {
            *dst = *src;
        }
        out
    }

    /// One byte (0 at end of input).
    pub fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    /// Little-endian `u16`.
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.array())
    }

    /// Little-endian `u32`.
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }

    /// Little-endian `u64`.
    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    /// An address biased towards a few bases so that regions, reads and
    /// patches collide often; one in eight is fully arbitrary.
    pub fn address(&mut self) -> u64 {
        const BASES: [u64; 8] = [
            0,
            0x1000,
            0x1100,
            0x2000,
            0x40_0000,
            u64::MAX - 0x1000,
            u64::MAX - 0x10,
            0x7fff_ffff_ffff_f000,
        ];
        let sel = self.u8();
        let base = BASES[usize::from(sel & 7)];
        match sel >> 5 {
            0 => self.u64(),
            1 | 2 => base.wrapping_add(u64::from(self.u8())),
            _ => base.wrapping_add(u64::from(self.u16() & 0x1fff)),
        }
    }
}
