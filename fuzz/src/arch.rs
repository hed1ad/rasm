//! Generic decoder target: any `dasm_core::Arch` on arbitrary bytes.
//!
//! Oracles (the `Arch` contract): no panic; a decoded length is in
//! `1..=max_insn_len` and within the bytes given; decoding the same bytes
//! cut short of that length fails; `decode` and `render` agree on success
//! and on the instruction bytes.

use dasm_core::{Address, Arch, NoSymbols};

use crate::check;

/// Runs `arch` at every offset of the first 64 bytes, at a normal address
/// and at addresses where branch targets overflow.
pub fn run_with(arch: &dyn Arch, data: &[u8]) {
    let max = arch.max_insn_len();
    for offset in 0..data.len().min(64) {
        let Some(bytes) = data.get(offset..) else {
            break;
        };
        let _ = arch.is_prologue(bytes);
        let _ = arch.is_padding(bytes);
        for address in [
            Address(0x40_1000 + offset as u64),
            Address(u64::MAX - 3),
            Address(0),
        ] {
            let decoded = arch.decode(bytes, address);
            let rendered = arch.render(bytes, address, &NoSymbols);
            match (&decoded, &rendered) {
                (Ok(d), Ok(r)) => {
                    let len = usize::from(d.len);
                    check!(
                        len >= 1 && len <= max,
                        "ARCH-01",
                        "length {len} outside 1..={max}"
                    );
                    check!(
                        len <= bytes.len(),
                        "ARCH-01",
                        "length {len} beyond {} input bytes",
                        bytes.len()
                    );
                    check!(d.address == address, "ARCH-02", "decoded address differs");
                    check!(
                        bytes.get(..len) == Some(r.bytes.as_slice()),
                        "ARCH-02",
                        "render bytes {:02x?} differ from decoded length {len}",
                        r.bytes
                    );
                    let _ = d.next_address();
                    let _ = r.operands_text();
                    if let Some(short) = len.checked_sub(1).and_then(|n| bytes.get(..n)) {
                        check!(
                            arch.decode(short, address).map(|s| s.len) != Ok(d.len),
                            "ARCH-01",
                            "decoded {len} bytes from {} bytes",
                            short.len()
                        );
                    }
                }
                (Err(_), Err(_)) => {}
                _ => check!(
                    false,
                    "ARCH-03",
                    "decode {:?} and render {:?} disagree at {address}",
                    decoded.as_ref().map(|d| d.len),
                    rendered.as_ref().map(|r| r.mnemonic.clone())
                ),
            }
        }
    }
}
