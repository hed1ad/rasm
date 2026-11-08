use std::collections::BTreeMap;
use std::process::Command;

use dasm_core::{
    Address, Arch, DecodeError, Flow, NoSymbols, SymbolLookup, Target, TokenKind, XrefKind,
};
use proptest::prelude::*;

use crate::X86_64;

const A: Address = Address(0x1000);

fn dec(bytes: &[u8]) -> dasm_core::DecodedInsn {
    X86_64.decode(bytes, A).unwrap()
}

fn text(bytes: &[u8]) -> String {
    let r = X86_64.render(bytes, A, &NoSymbols).unwrap();
    if r.operands.is_empty() {
        r.mnemonic
    } else {
        format!("{} {}", r.mnemonic, r.operands_text())
    }
}

#[test]
fn flows() {
    assert_eq!(dec(&[0xc3]).flow, Flow::Return);
    assert_eq!(dec(&[0xf4]).flow, Flow::Halt);
    assert_eq!(dec(&[0x0f, 0x0b]).flow, Flow::Halt);
    assert_eq!(dec(&[0xcc]).flow, Flow::Halt);
    assert_eq!(dec(&[0x0f, 0x05]).flow, Flow::Syscall);
    assert_eq!(dec(&[0xcd, 0x80]).flow, Flow::Syscall);
    assert_eq!(dec(&[0x90]).flow, Flow::Sequential);
    assert_eq!(
        dec(&[0xe8, 0x0b, 0, 0, 0]).flow,
        Flow::Call {
            target: Target::Direct(Address(0x1010))
        }
    );
    assert_eq!(
        dec(&[0xeb, 0xfe]).flow,
        Flow::Jump {
            target: Target::Direct(A)
        }
    );
    assert_eq!(
        dec(&[0x74, 0x02]).flow,
        Flow::ConditionalJump {
            target: Target::Direct(Address(0x1004))
        }
    );
    assert_eq!(
        dec(&[0xff, 0xe0]).flow,
        Flow::Jump {
            target: Target::Indirect
        }
    );
    assert_eq!(
        dec(&[0xff, 0xd0]).flow,
        Flow::Call {
            target: Target::Indirect
        }
    );
}

#[test]
fn rip_relative_refs() {
    // lea rdi, [rip+0x10]
    let i = dec(&[0x48, 0x8d, 0x3d, 0x10, 0, 0, 0]);
    let r: Vec<_> = i.refs().collect();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].target, Address(0x1017));
    assert_eq!(r[0].kind, XrefKind::DataPtr);
    // mov rax, [rip+0x10] / mov [rip+0x10], rax
    let rd = dec(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0]);
    assert_eq!(rd.refs().next().map(|r| r.kind), Some(XrefKind::Read));
    let wr = dec(&[0x48, 0x89, 0x05, 0x10, 0, 0, 0]);
    assert_eq!(wr.refs().next().map(|r| r.kind), Some(XrefKind::Write));
    // inc qword ptr [rip+0x10], lock add [rip+0x10], 1, xchg [rip+0x10], rax
    for bytes in [
        &[0x48, 0xff, 0x05, 0x10, 0, 0, 0][..],
        &[0xf0, 0x48, 0x83, 0x05, 0x10, 0, 0, 0, 0x01][..],
        &[0x48, 0x87, 0x05, 0x10, 0, 0, 0][..],
    ] {
        let i = dec(bytes);
        let refs: Vec<_> = i.refs().collect();
        assert_eq!(refs.len(), 1, "{bytes:x?}");
        assert_eq!(refs[0].kind, XrefKind::ReadWrite, "{bytes:x?}");
    }
    // call [rip+0x10] (-fno-plt) reads the GOT slot
    let c = dec(&[0xff, 0x15, 0x10, 0, 0, 0]);
    assert_eq!(c.refs().next().map(|r| r.target), Some(Address(0x1016)));
    assert_eq!(c.refs().next().map(|r| r.kind), Some(XrefKind::Read));
    // Plain register memory operand: no reference.
    assert_eq!(dec(&[0x48, 0x8b, 0x00]).refs().count(), 0);
}

#[test]
fn absolute_memory_operands_are_references() {
    // mov rax, [0x604000]  (48 8b 04 25 disp32)
    let r = dec(&[0x48, 0x8b, 0x04, 0x25, 0x00, 0x40, 0x60, 0x00]);
    let refs: Vec<_> = r.refs().collect();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].target, Address(0x604000));
    assert_eq!(refs[0].kind, XrefKind::Read);
    // mov [0x604000], eax  (89 04 25 disp32)
    let w = dec(&[0x89, 0x04, 0x25, 0x00, 0x40, 0x60, 0x00]);
    assert_eq!(w.refs().next().map(|r| r.kind), Some(XrefKind::Write));
    // movabs rax, [0x1122334455667788]  (48 a1 moffs64)
    let m = dec(&[0x48, 0xa1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    assert_eq!(
        m.refs().next().map(|r| r.target),
        Some(Address(0x1122334455667788))
    );
    // jmp [rax*8 + 0x604000]: the displacement is the table.
    let j = dec(&[0xff, 0x24, 0xc5, 0x00, 0x40, 0x60, 0x00]);
    assert_eq!(j.refs().next().map(|r| r.target), Some(Address(0x604000)));
    // fs:0x28 is a TLS offset, not an address.
    assert_eq!(
        dec(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0])
            .refs()
            .count(),
        0
    );
    // A register base is not static.
    assert_eq!(dec(&[0x48, 0x8b, 0x40, 0x10]).refs().count(), 0);
}

#[test]
fn errors_are_values() {
    assert_eq!(X86_64.decode(&[], A), Err(DecodeError::Truncated(A)));
    assert_eq!(X86_64.decode(&[0xe8, 1], A), Err(DecodeError::Truncated(A)));
    assert_eq!(
        X86_64.decode(&[0xd6, 0x90], A),
        Err(DecodeError::Invalid(A))
    );
    assert!(X86_64.decode(&[0x90], Address(u64::MAX)).is_err());
}

#[test]
fn prologue_and_padding() {
    assert!(X86_64.is_prologue(&[0xf3, 0x0f, 0x1e, 0xfa]));
    assert!(X86_64.is_prologue(&[0x55, 0x48, 0x89, 0xe5, 0x90]));
    assert!(X86_64.is_prologue(&[0x55, 0x48, 0x8b, 0xec]));
    assert!(X86_64.is_prologue(&[0x48, 0x83, 0xec, 0x28]));
    assert!(X86_64.is_prologue(&[0x48, 0x81, 0xec, 0x00, 0x01, 0, 0]));
    assert!(!X86_64.is_prologue(&[0x55, 0x90]));
    assert!(!X86_64.is_prologue(&[0xc3]));
    assert!(!X86_64.is_prologue(&[]));
    assert!(X86_64.is_padding(&[0x90]));
    assert!(X86_64.is_padding(&[0xcc]));
    assert!(X86_64.is_padding(&[0x66, 0x0f, 0x1f, 0x44, 0, 0]));
    assert!(X86_64.is_padding(&[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]));
    assert!(!X86_64.is_padding(&[0xc3]));
}

#[test]
fn render_tokens() {
    assert_eq!(text(&[0x48, 0x89, 0xe5]), "mov rbp, rsp");
    assert_eq!(
        text(&[0xf0, 0x48, 0x83, 0x05, 0x10, 0, 0, 0, 1]),
        "lock add qword ptr [0x1019], 0x1"
    );
    let r = X86_64
        .render(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0], A, &NoSymbols)
        .unwrap();
    assert_eq!(r.mnemonic, "mov");
    assert_eq!(r.operands_text(), "rax, qword ptr [0x1017]");
    assert!(
        r.operands
            .iter()
            .any(|t| t.kind == TokenKind::Keyword && t.text == "qword ptr ")
    );
    assert!(r.operands.iter().any(|t| t.kind == TokenKind::Register));
}

struct Syms;
impl SymbolLookup for Syms {
    fn name_at(&self, a: Address) -> Option<String> {
        (a == Address(0x1010)).then(|| "callee".to_owned())
    }
    fn is_mapped(&self, a: Address) -> bool {
        a.get() < 0x2000
    }
}

#[test]
fn branch_targets_carry_names_and_links() {
    let r = X86_64.render(&[0xe8, 0x0b, 0, 0, 0], A, &Syms).unwrap();
    assert_eq!(r.operands.len(), 1);
    assert_eq!(r.operands[0].text, "callee");
    assert_eq!(r.operands[0].kind, TokenKind::Symbol);
    assert_eq!(r.operands[0].target, Some(Address(0x1010)));
    let j = X86_64.render(&[0xeb, 0x20], A, &Syms).unwrap();
    assert_eq!(j.operands[0].kind, TokenKind::Address);
    assert_eq!(j.operands[0].target, Some(Address(0x1022)));
    // Unmapped target: plain number, no link.
    let far = X86_64.render(&[0xe8, 0, 0, 0, 0x10], A, &Syms).unwrap();
    assert_eq!(far.operands[0].target, None);
    // RIP-relative operand links too.
    let m = X86_64
        .render(&[0x48, 0x8d, 0x3d, 0x09, 0, 0, 0], A, &Syms)
        .unwrap();
    assert!(m.operands.iter().any(|t| t.target == Some(Address(0x1010))));
}

proptest! {
    #[test]
    fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..=15), addr in any::<u64>()) {
        let a = Address(addr);
        let d = X86_64.decode(&bytes, a);
        let r = X86_64.render(&bytes, a, &NoSymbols);
        prop_assert_eq!(d.is_ok(), r.is_ok());
        if let (Ok(d), Ok(r)) = (d, r) {
            prop_assert_eq!(usize::from(d.len), r.bytes.len());
            prop_assert!(d.len >= 1 && d.len <= 15);
        }
        let _ = X86_64.is_prologue(&bytes);
        let _ = X86_64.is_padding(&bytes);
    }

    #[test]
    fn decode_ignores_trailing_bytes(bytes in proptest::collection::vec(any::<u8>(), 15..40)) {
        let a = Address(0x4000);
        if let Ok(d) = X86_64.decode(&bytes, a) {
            let exact = &bytes[..usize::from(d.len)];
            prop_assert_eq!(X86_64.decode(exact, a), Ok(d));
        }
    }
}

// ----------------------------------------------------------- objdump

/// Normalises instruction text for comparison with objdump: lower case, no
/// spaces, no `0x` prefixes.
fn norm(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .replace("0x", "")
}

struct ObjLine {
    addr: u64,
    bytes: Vec<u8>,
    text: String,
}

fn parse_objdump(out: &str) -> Vec<ObjLine> {
    let mut v = Vec::new();
    for line in out.lines() {
        let mut parts = line.splitn(3, '\t');
        let (Some(a), Some(b), Some(t)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Ok(addr) = u64::from_str_radix(a.trim().trim_end_matches(':'), 16) else {
            continue;
        };
        let bytes: Option<Vec<u8>> = b
            .split_whitespace()
            .map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        let Some(bytes) = bytes else { continue };
        let mut t = t.to_owned();
        // Branch targets and rip-relative operands: objdump appends
        // `# target <sym>` / ` <sym>`; ours prints absolute addresses.
        let comment = t.find('#').map(|i| (i, t[i + 1..].trim().to_owned()));
        if let Some((i, c)) = comment {
            t.truncate(i);
            let target = c.split_whitespace().next().unwrap_or("").to_owned();
            if let (Some(s), Some(e)) = (t.find("[rip"), t.rfind(']')) {
                t.replace_range(s + 1..e, &format!("0x{target}"));
            }
        }
        if let Some(i) = t.find('<') {
            t.truncate(i);
        }
        // Allowed difference: objdump spells out redundant prefixes and
        // writes absolute segment offsets without brackets.
        let mut words: Vec<&str> = t.split_whitespace().collect();
        while words.len() > 1 && matches!(words[0], "addr32" | "data16" | "cs" | "ds" | "es" | "ss")
        {
            words.remove(0);
        }
        t = words.join(" ");
        for seg in ["fs", "gs"] {
            if let Some(i) = t.find(&format!("{seg}:0x")) {
                let rest = &t[i + 3..];
                let n = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .count();
                let (num, tail) = rest.split_at(n);
                t = format!("{}{seg}:[{num}]{tail}", &t[..i]);
            }
        }
        v.push(ObjLine {
            addr,
            bytes,
            text: t.trim().to_owned(),
        });
    }
    v
}

/// Known, accepted differences (about 0.6% of instructions): iced omits
/// implicit operands that objdump prints (`imul rdx,rdx,0xd0` vs
/// `imul rdx, 0xd0`, x87 `st` operands) and prints `movabs` as `mov`.
/// Redundant prefixes (`addr32`, `data16`, `cs`) are stripped from the
/// objdump side, and absolute `fs:0x28` is written `fs:[0x28]`.
///
/// Compares byte lengths and Intel-syntax text with `objdump -d` over the
/// whole `.text` of `/usr/bin/ls`. Skipped when objdump or the binary is
/// missing.
#[test]
fn matches_objdump_on_usr_bin_ls() {
    let Ok(out) = Command::new("objdump")
        .args([
            "-d",
            "-M",
            "intel",
            "--insn-width=15",
            "-j",
            ".text",
            "/usr/bin/ls",
        ])
        .output()
    else {
        eprintln!("objdump unavailable: skipped");
        return;
    };
    if !out.status.success() {
        eprintln!("objdump failed: skipped");
        return;
    }
    let lines = parse_objdump(&String::from_utf8_lossy(&out.stdout));
    assert!(lines.len() > 1000, "too few instructions: {}", lines.len());
    let mut total = 0usize;
    let mut len_bad = 0usize;
    let mut text_bad = 0usize;
    let mut kinds: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for l in &lines {
        if l.text.starts_with("(bad)") {
            continue;
        }
        total += 1;
        match X86_64.render(&l.bytes, Address(l.addr), &NoSymbols) {
            Ok(r) if r.bytes == l.bytes => {
                let ours = if r.operands.is_empty() {
                    r.mnemonic.clone()
                } else {
                    format!("{} {}", r.mnemonic, r.operands_text())
                };
                if norm(&ours) != norm(&l.text) {
                    text_bad += 1;
                    let key = l.text.split_whitespace().next().unwrap_or("").to_owned();
                    let e = kinds.entry(key).or_insert((0, String::new()));
                    e.0 += 1;
                    if e.1.is_empty() {
                        e.1 = format!("{:x}: objdump `{}` ours `{ours}`", l.addr, l.text);
                    }
                }
            }
            _ => len_bad += 1,
        }
        match X86_64.decode(&l.bytes, Address(l.addr)) {
            Ok(d) if usize::from(d.len) == l.bytes.len() => {}
            _ => len_bad += 1,
        }
    }
    let mut worst: Vec<_> = kinds.iter().collect();
    worst.sort_by_key(|(_, v)| std::cmp::Reverse(v.0));
    for (k, (n, ex)) in worst.iter().take(15) {
        eprintln!("{k}: {n} e.g. {ex}");
    }
    eprintln!("total {total}, length mismatches {len_bad}, text mismatches {text_bad}");
    assert_eq!(len_bad, 0, "lengths/bytes must match objdump exactly");
    assert!(
        text_bad * 100 <= total,
        "text mismatch {text_bad}/{total} exceeds 1%"
    );
}
