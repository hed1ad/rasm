//! Instructions: the compact form analysis works with, and the token form
//! the listing, UI and JSON show.
//!
//! Analysis never stores rendered text. A [`DecodedInsn`] is small and
//! `Copy`-friendly; text is produced on demand for visible rows only by
//! [`crate::Arch::render`] (see ADR 0002).

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::model::XrefKind;

/// Target of a control transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "address", rename_all = "snake_case")]
pub enum Target {
    /// Statically known destination.
    Direct(Address),
    /// Computed at run time (register, memory, jump table).
    Indirect,
}

/// How control leaves an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Flow {
    /// Falls through to the next instruction.
    Sequential,
    /// Unconditional jump.
    Jump {
        /// Destination.
        target: Target,
    },
    /// Conditional jump; falls through if not taken.
    ConditionalJump {
        /// Destination if taken.
        target: Target,
    },
    /// Call; normally returns to the next instruction.
    Call {
        /// Callee.
        target: Target,
    },
    /// Return.
    Return,
    /// System call / software interrupt; falls through.
    Syscall,
    /// Stops execution (`hlt`, `ud2`, `int3` used as a trap).
    Halt,
}

impl Flow {
    /// True if execution may continue at the next instruction.
    #[must_use]
    pub fn falls_through(&self) -> bool {
        matches!(
            self,
            Flow::Sequential | Flow::ConditionalJump { .. } | Flow::Call { .. } | Flow::Syscall
        )
    }

    /// True if this instruction ends a basic block.
    #[must_use]
    pub fn ends_block(&self) -> bool {
        !matches!(self, Flow::Sequential | Flow::Call { .. } | Flow::Syscall)
    }
}

/// A non-control-flow reference an instruction makes (memory operand,
/// address-sized immediate, RIP-relative `lea`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InsnRef {
    /// Referenced address.
    pub target: Address,
    /// Access kind: `Read`, `Write`, `ReadWrite` (one operand both read
    /// and written) or `DataPtr` (address taken).
    pub kind: XrefKind,
}

/// Maximum references recorded per instruction. x86 has at most one memory
/// operand plus one immediate; this leaves headroom for other ISAs.
pub const MAX_INSN_REFS: usize = 4;

/// The compact, analysis-oriented decoding of one instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecodedInsn {
    /// Address of the first byte.
    pub address: Address,
    /// Length in bytes (1..=15 on x86).
    pub len: u8,
    /// Control flow.
    pub flow: Flow,
    refs: [Option<InsnRef>; MAX_INSN_REFS],
}

impl DecodedInsn {
    /// Creates an instruction without data references.
    #[must_use]
    pub fn new(address: Address, len: u8, flow: Flow) -> Self {
        DecodedInsn {
            address,
            len,
            flow,
            refs: [None; MAX_INSN_REFS],
        }
    }

    /// Adds a data reference. Extra references beyond
    /// [`MAX_INSN_REFS`] are dropped (returns `false`).
    pub fn push_ref(&mut self, r: InsnRef) -> bool {
        if let Some(slot) = self.refs.iter_mut().find(|s| s.is_none()) {
            *slot = Some(r);
            true
        } else {
            false
        }
    }

    /// Data references.
    pub fn refs(&self) -> impl Iterator<Item = InsnRef> + '_ {
        self.refs.iter().flatten().copied()
    }

    /// Address of the next instruction, or `None` on overflow.
    #[must_use]
    pub fn next_address(&self) -> Option<Address> {
        self.address.checked_add(u64::from(self.len))
    }
}

/// Role of a token in rendered text. Drives syntax highlighting and
/// clickability in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TokenKind {
    /// Instruction mnemonic (`mov`), including prefixes (`lock`, `rep`).
    Mnemonic,
    /// Register name.
    Register,
    /// Numeric constant that is not known to be an address.
    Immediate,
    /// Number that is an address without a name (clickable).
    Address,
    /// Name of a symbol/function/label (clickable).
    Symbol,
    /// Size keywords and similar (`qword ptr`).
    Keyword,
    /// `[ ] + - * , :` and the like.
    Punctuation,
    /// Spacing.
    Whitespace,
    /// String literal preview.
    String,
    /// Comment text.
    Comment,
}

/// One piece of rendered text.
///
/// `target` is set for tokens the user can navigate from (address and
/// symbol tokens, and immediates that resolve to a mapped address). The
/// same token type is used by the future decompiler output.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token {
    /// Text to display.
    pub text: String,
    /// Role.
    pub kind: TokenKind,
    /// Navigation target, if clickable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Address>,
}

impl Token {
    /// A non-clickable token.
    #[must_use]
    pub fn new(kind: TokenKind, text: impl Into<String>) -> Self {
        Token {
            text: text.into(),
            kind,
            target: None,
        }
    }

    /// A clickable token.
    #[must_use]
    pub fn linked(kind: TokenKind, text: impl Into<String>, target: Address) -> Self {
        Token {
            text: text.into(),
            kind,
            target: Some(target),
        }
    }
}

/// One instruction as shown in a listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedInsn {
    /// Address.
    pub address: Address,
    /// Raw bytes (with patches applied).
    pub bytes: Vec<u8>,
    /// Mnemonic text (also present as the first token of `tokens`).
    pub mnemonic: String,
    /// Operand tokens (everything after the mnemonic).
    pub operands: Vec<Token>,
}

impl RenderedInsn {
    /// Operands joined into plain text (`rax, qword ptr [rip+0x2f]`).
    #[must_use]
    pub fn operands_text(&self) -> String {
        self.operands.iter().map(|t| t.text.as_str()).collect()
    }
}

/// Resolves addresses to display names while rendering. Implemented by
/// [`crate::Snapshot`], so user renames show up in operands immediately.
pub trait SymbolLookup {
    /// Best display name for exactly this address, if it has one.
    fn name_at(&self, address: Address) -> Option<String>;
    /// True if the address is mapped (so a bare number can be a link).
    fn is_mapped(&self, address: Address) -> bool;
}

/// A lookup that knows no names; for tests and raw dumps.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSymbols;

impl SymbolLookup for NoSymbols {
    fn name_at(&self, _address: Address) -> Option<String> {
        None
    }
    fn is_mapped(&self, _address: Address) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_block_rules() {
        assert!(!Flow::Sequential.ends_block());
        assert!(Flow::Return.ends_block());
        assert!(!Flow::Return.falls_through());
        let cj = Flow::ConditionalJump {
            target: Target::Indirect,
        };
        assert!(cj.ends_block() && cj.falls_through());
        let call = Flow::Call {
            target: Target::Direct(Address(1)),
        };
        assert!(!call.ends_block() && call.falls_through());
    }

    #[test]
    fn refs_are_bounded() {
        let mut i = DecodedInsn::new(Address(0), 1, Flow::Sequential);
        let r = InsnRef {
            target: Address(8),
            kind: XrefKind::Read,
        };
        for _ in 0..MAX_INSN_REFS {
            assert!(i.push_ref(r));
        }
        assert!(!i.push_ref(r));
        assert_eq!(i.refs().count(), MAX_INSN_REFS);
        assert_eq!(
            DecodedInsn::new(Address(u64::MAX), 1, Flow::Sequential).next_address(),
            None
        );
    }
}
