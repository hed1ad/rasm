//! x86-64 decoder for dasm built on `iced-x86`.
//!
//! [`X86_64`] implements [`dasm_core::Arch`]:
//!
//! - `decode` produces the compact [`DecodedInsn`] (length, control flow,
//!   RIP-relative data references) analysis works with;
//! - `render` produces Intel-syntax operand [`Token`]s, resolving branch
//!   targets and RIP-relative addresses through a [`SymbolLookup`];
//! - `is_prologue` / `is_padding` feed the linear sweep.
//!
//! Nothing here panics on malformed input: every byte sequence is either an
//! instruction or a [`DecodeError`].

use dasm_core::{
    Address, Arch, ArchId, DecodeError, DecodedInsn, Flow, InsnRef, RenderedInsn, SymbolLookup,
    Target, Token, TokenKind, XrefKind,
};
use iced_x86::{
    Decoder, DecoderError, DecoderOptions, FlowControl, Formatter, FormatterOutput,
    FormatterTextKind, Instruction, InstructionInfoFactory, InstructionInfoOptions, IntelFormatter,
    Mnemonic, NumberKind, OpAccess, OpKind, Register,
};

/// Longest x86 instruction.
const MAX_LEN: usize = 15;

/// The x86-64 architecture.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86_64;

/// Decodes one instruction; `bytes` is truncated to 15 bytes.
fn decode_raw(bytes: &[u8], address: Address) -> Result<Instruction, DecodeError> {
    let window = bytes.get(..bytes.len().min(MAX_LEN)).unwrap_or(&[]);
    if window.is_empty() {
        return Err(DecodeError::Truncated(address));
    }
    let mut decoder = Decoder::with_ip(64, window, address.get(), DecoderOptions::NONE);
    let insn = decoder.decode();
    if insn.is_invalid() {
        return Err(match decoder.last_error() {
            DecoderError::NoMoreBytes => DecodeError::Truncated(address),
            _ => DecodeError::Invalid(address),
        });
    }
    if insn.len() == 0 || insn.len() > window.len() {
        return Err(DecodeError::Invalid(address));
    }
    // The next address must exist.
    address
        .checked_add(insn.len() as u64)
        .ok_or(DecodeError::Invalid(address))?;
    Ok(insn)
}

/// Direct target of a near branch/call, indirect otherwise (far, register,
/// memory).
fn branch_target(insn: &Instruction) -> Target {
    match insn.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Target::Direct(Address(insn.near_branch_target()))
        }
        _ => Target::Indirect,
    }
}

fn flow_of(insn: &Instruction) -> Flow {
    match insn.mnemonic() {
        Mnemonic::Hlt | Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2 | Mnemonic::Int3 => {
            return Flow::Halt;
        }
        Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int | Mnemonic::Into => {
            return Flow::Syscall;
        }
        Mnemonic::Xbegin => {
            return Flow::ConditionalJump {
                target: branch_target(insn),
            };
        }
        _ => {}
    }
    match insn.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Flow::Jump {
            target: branch_target(insn),
        },
        FlowControl::ConditionalBranch => Flow::ConditionalJump {
            target: branch_target(insn),
        },
        FlowControl::Call | FlowControl::IndirectCall => Flow::Call {
            target: branch_target(insn),
        },
        FlowControl::Return => Flow::Return,
        FlowControl::Exception => Flow::Halt,
        FlowControl::Interrupt => Flow::Syscall,
        _ => Flow::Sequential,
    }
}

fn ref_kind(insn: &Instruction, access: OpAccess) -> Option<XrefKind> {
    match access {
        OpAccess::Read | OpAccess::CondRead => Some(XrefKind::Read),
        OpAccess::Write | OpAccess::CondWrite => Some(XrefKind::Write),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => Some(XrefKind::ReadWrite),
        OpAccess::NoMemAccess => (insn.mnemonic() == Mnemonic::Lea).then_some(XrefKind::DataPtr),
        _ => None,
    }
}

/// The address a memory operand refers to without any register base:
/// RIP-relative operands, absolute `[disp32]` / `moffs` operands and
/// `[index*scale+disp]` table accesses (the displacement is the table).
/// Thread-local `fs:`/`gs:` offsets are not addresses.
fn static_memory_target(insn: &Instruction) -> Option<Address> {
    if insn.is_ip_rel_memory_operand() {
        return Some(Address(insn.ip_rel_memory_address()));
    }
    let has_memory = (0..insn.op_count()).any(|i| insn.op_kind(i) == OpKind::Memory);
    if has_memory
        && insn.memory_base() == Register::None
        && !matches!(insn.memory_segment(), Register::FS | Register::GS)
    {
        return Some(Address(insn.memory_displacement64()));
    }
    None
}

fn decode_insn(bytes: &[u8], address: Address) -> Result<(Instruction, DecodedInsn), DecodeError> {
    let insn = decode_raw(bytes, address)?;
    let mut out = DecodedInsn::new(address, insn.len() as u8, flow_of(&insn));
    if let Some(target) = static_memory_target(&insn) {
        let mut factory = InstructionInfoFactory::new();
        let info = factory.info_options(&insn, InstructionInfoOptions::NO_REGISTER_USAGE);
        let kind = match info.used_memory().first() {
            Some(m) => ref_kind(&insn, m.access()),
            // `lea` reports no memory access at all.
            None => ref_kind(&insn, OpAccess::NoMemAccess),
        };
        if let Some(kind) = kind {
            out.push_ref(InsnRef { target, kind });
        }
    }
    Ok((insn, out))
}

/// Collects formatter output as tokens.
struct TokenOut<'a> {
    prefixes: Vec<String>,
    mnemonic: Option<String>,
    tokens: Vec<Token>,
    symbols: &'a dyn SymbolLookup,
}

impl TokenOut<'_> {
    fn push(&mut self, kind: TokenKind, text: &str) {
        self.tokens.push(Token::new(kind, text));
    }

    fn address_token(&mut self, text: &str, value: u64) {
        let target = Address(value);
        let token = match self.symbols.name_at(target) {
            Some(name) => Token::linked(TokenKind::Symbol, name, target),
            None if self.symbols.is_mapped(target) => {
                Token::linked(TokenKind::Address, text, target)
            }
            None => Token::new(TokenKind::Immediate, text),
        };
        self.tokens.push(token);
    }
}

impl FormatterOutput for TokenOut<'_> {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        match kind {
            FormatterTextKind::Prefix => self.prefixes.push(text.trim().to_owned()),
            FormatterTextKind::Mnemonic => {
                let mut m = self.prefixes.join(" ");
                if !m.is_empty() {
                    m.push(' ');
                }
                m.push_str(text);
                self.mnemonic = Some(m);
            }
            _ if self.mnemonic.is_none() => {
                // Spacing between prefixes and the mnemonic.
            }
            FormatterTextKind::Text if text.trim().is_empty() => {
                // Spacing glues to keywords and separators; leading
                // spacing (after the mnemonic) is dropped.
                match self.tokens.last_mut() {
                    Some(last)
                        if last.kind == TokenKind::Keyword
                            || (last.kind == TokenKind::Punctuation
                                && last.text.ends_with(',')) =>
                    {
                        last.text.push_str(text);
                    }
                    Some(_) => self.push(TokenKind::Whitespace, text),
                    None => {}
                }
            }
            FormatterTextKind::Register => self.push(TokenKind::Register, text),
            FormatterTextKind::Keyword => match self.tokens.last_mut() {
                Some(last) if last.kind == TokenKind::Keyword => last.text.push_str(text),
                _ => self.push(TokenKind::Keyword, text),
            },
            FormatterTextKind::Number
            | FormatterTextKind::SelectorValue
            | FormatterTextKind::Data => self.push(TokenKind::Immediate, text),
            FormatterTextKind::Label
            | FormatterTextKind::Function
            | FormatterTextKind::LabelAddress
            | FormatterTextKind::FunctionAddress => self.push(TokenKind::Symbol, text),
            _ => self.push(TokenKind::Punctuation, text),
        }
    }

    fn write_number(
        &mut self,
        instruction: &Instruction,
        _operand: u32,
        instruction_operand: Option<u32>,
        text: &str,
        value: u64,
        _number_kind: NumberKind,
        kind: FormatterTextKind,
    ) {
        let branch = matches!(
            kind,
            FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress
        );
        let rip_rel = instruction_operand.is_some()
            && instruction.is_ip_rel_memory_operand()
            && instruction.ip_rel_memory_address() == value;
        if branch || rip_rel {
            self.address_token(text, value);
        } else if kind == FormatterTextKind::Number && looks_like_address(value) {
            let target = Address(value);
            if self.symbols.is_mapped(target) {
                self.tokens
                    .push(Token::linked(TokenKind::Immediate, text, target));
            } else {
                self.push(TokenKind::Immediate, text);
            }
        } else {
            self.write(text, kind);
        }
    }
}

/// Immediates below this are never offered as links.
fn looks_like_address(value: u64) -> bool {
    value >= 0x1000
}

fn formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    let o = f.options_mut();
    o.set_space_after_operand_separator(true);
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_small_hex_numbers_in_decimal(false);
    o.set_rip_relative_addresses(false);
    o.set_show_branch_size(false);
    o.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    o.set_always_show_scale(true);
    o.set_show_zero_displacements(true);
    o.set_signed_memory_displacements(true);
    o.set_branch_leading_zeros(false);
    f
}

impl Arch for X86_64 {
    fn id(&self) -> ArchId {
        ArchId::X86_64
    }

    fn max_insn_len(&self) -> usize {
        MAX_LEN
    }

    fn decode(&self, bytes: &[u8], address: Address) -> Result<DecodedInsn, DecodeError> {
        decode_insn(bytes, address).map(|(_, d)| d)
    }

    fn render(
        &self,
        bytes: &[u8],
        address: Address,
        symbols: &dyn SymbolLookup,
    ) -> Result<RenderedInsn, DecodeError> {
        let insn = decode_raw(bytes, address)?;
        let mut out = TokenOut {
            prefixes: Vec::new(),
            mnemonic: None,
            tokens: Vec::new(),
            symbols,
        };
        formatter().format(&insn, &mut out);
        while out
            .tokens
            .last()
            .is_some_and(|t| t.kind == TokenKind::Whitespace)
        {
            out.tokens.pop();
        }
        let raw = bytes
            .get(..insn.len())
            .ok_or(DecodeError::Truncated(address))?;
        Ok(RenderedInsn {
            address,
            bytes: raw.to_vec(),
            mnemonic: out.mnemonic.unwrap_or_default(),
            operands: out.tokens,
        })
    }

    fn is_prologue(&self, bytes: &[u8]) -> bool {
        let Ok(first) = decode_raw(bytes, Address::ZERO) else {
            return false;
        };
        match first.mnemonic() {
            Mnemonic::Endbr64 => true,
            Mnemonic::Push if first.op0_register() == Register::RBP => {
                let rest = bytes.get(first.len()..).unwrap_or(&[]);
                decode_raw(rest, Address::ZERO).is_ok_and(|second| {
                    second.mnemonic() == Mnemonic::Mov
                        && second.op0_register() == Register::RBP
                        && second.op1_register() == Register::RSP
                })
            }
            Mnemonic::Sub => {
                first.op0_register() == Register::RSP
                    && matches!(
                        first.op1_kind(),
                        OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate32
                    )
            }
            _ => false,
        }
    }

    fn is_padding(&self, bytes: &[u8]) -> bool {
        decode_raw(bytes, Address::ZERO)
            .is_ok_and(|i| matches!(i.mnemonic(), Mnemonic::Nop | Mnemonic::Int3))
    }
}

#[cfg(test)]
mod tests;
