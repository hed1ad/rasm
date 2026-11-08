//! The architecture (decoder) extension point.

use std::fmt;

use crate::address::Address;
use crate::error::DecodeError;
use crate::image::ArchId;
use crate::insn::{DecodedInsn, RenderedInsn, SymbolLookup};

/// Decodes and renders instructions of one instruction set.
///
/// Implementations must be pure functions of their input (no interior
/// state that changes results), `Send + Sync`, and must never panic on any
/// byte sequence — invalid or truncated input is a [`DecodeError`].
///
/// Stage 1 implementation: `dasm-x86` (iced-x86). Later: SLEIGH runtime.
pub trait Arch: Send + Sync + fmt::Debug {
    /// Architecture handled.
    fn id(&self) -> ArchId;

    /// Longest possible instruction in bytes (15 for x86). Callers pass at
    /// least this many bytes when available.
    fn max_insn_len(&self) -> usize;

    /// Decodes the instruction at the start of `bytes`, which is located at
    /// `address`. `bytes` may be longer than one instruction.
    fn decode(&self, bytes: &[u8], address: Address) -> Result<DecodedInsn, DecodeError>;

    /// Renders the instruction at the start of `bytes` for display. Operand
    /// tokens that refer to addresses use `symbols` for names and carry a
    /// navigation `target`.
    fn render(
        &self,
        bytes: &[u8],
        address: Address,
        symbols: &dyn SymbolLookup,
    ) -> Result<RenderedInsn, DecodeError>;

    /// True if `bytes` start with a typical function prologue. Used by the
    /// linear sweep over unexplored code. Default: never.
    fn is_prologue(&self, bytes: &[u8]) -> bool {
        let _ = bytes;
        false
    }

    /// True if `bytes` start with alignment padding (`nop`, `int3`, ...).
    /// Default: never.
    fn is_padding(&self, bytes: &[u8]) -> bool {
        let _ = bytes;
        false
    }
}
