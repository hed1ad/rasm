//! The `strings` pass.

use dasm_core::ops::Definition;
use dasm_core::pass::passes;
use dasm_core::{
    Address, AddressRange, AnalysisDelta, AnalysisPass, CancelToken, ChangeKind, Error,
    Granularity, PassContext, PassId, PassScope, Snapshot, StringEncoding, StringLiteral,
};

use crate::stage::{Stage, StageOutput};

/// Bytes scanned per memory read (plus an overlap of `max_len`).
const CHUNK: u64 = 1 << 20;

/// Tunables of the string scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StringsConfig {
    /// Minimum length in characters of ASCII and UTF-8 strings.
    pub min_len: usize,
    /// Minimum length in characters of UTF-16 and UTF-32 strings.
    pub min_len_wide: usize,
    /// Longest string reported, in bytes. A run of text longer than this
    /// is reported cut at the limit (and scanning continues after it).
    pub max_len: usize,
}

impl Default for StringsConfig {
    fn default() -> Self {
        StringsConfig {
            min_len: 4,
            min_len_wide: 3,
            max_len: 64 * 1024,
        }
    }
}

/// Finds NUL-terminated strings in non-executable regions: ASCII, UTF-8,
/// UTF-16 (LE/BE, 2-aligned) and UTF-32 (LE/BE, 4-aligned).
///
/// Scope `Range` re-scans the regions overlapping the range (a string can
/// start anywhere before it); `Program` scans all of them.
#[derive(Clone, Copy, Debug, Default)]
pub struct StringsPass {
    config: StringsConfig,
}

impl StringsPass {
    /// A scanner with custom limits.
    #[must_use]
    pub fn new(config: StringsConfig) -> Self {
        StringsPass { config }
    }
}

fn is_text_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | ' '..='~')
        || matches!(u32::from(c), 0xA0..=0x24F | 0x370..=0x52F)
}

fn is_wide_text(u: u32) -> bool {
    char::from_u32(u).is_some_and(is_text_char)
}

/// Outcome of looking for a string at the start of `bytes`.
enum Detect {
    /// A string and the bytes it occupies.
    Hit(StringLiteral, usize),
    /// No string starts here; the next position that can start one is this
    /// many bytes ahead (everything in between is proven to fail too, see
    /// [`miss_skip`]). Always at least 1.
    Miss(usize),
}

/// Two consecutive bytes of an ASCII/UTF-8 text run never form a wide-text
/// UTF-16 unit: printable ASCII pairs are `>= 0x2020`, pairs involving a
/// UTF-8 lead/continuation byte are `>= 0x8000` or have a high byte above
/// the wide-text ranges. The same holds for four-byte UTF-32 units. So when
/// the ASCII scan of a run fails at offset `i`, every encoding fails at
/// every start in `1..i.saturating_sub(1)`; only the last two offsets may
/// still start a wide string, and only if the wide scans at `addr` did not
/// cover them (`s16`/`s32` text bytes consumed there). Returns how far the
/// next candidate start is.
fn miss_skip(addr: Address, ascii: usize, s16: usize, s32: usize) -> usize {
    let mut dead = ascii.saturating_sub(2);
    loop {
        let j = dead + 1;
        let x = addr.get().wrapping_add(j as u64);
        let ascii_fails = j <= ascii;
        let utf16_fails = x % 2 != 0 || j <= s16 || j + 2 <= ascii;
        let utf32_fails = x % 4 != 0 || j <= s32 || j + 4 <= ascii;
        if ascii_fails && utf16_fails && utf32_fails {
            dead = j;
        } else {
            return dead.max(1);
        }
    }
}

/// A string at the start of `bytes`, or how far ahead to look next.
fn detect(bytes: &[u8], addr: Address, cfg: &StringsConfig) -> Detect {
    let tail = bytes;
    // ASCII / UTF-8: scan one run of text characters.
    let mut i = 0usize;
    let mut chars = 0usize;
    let mut ascii = true;
    while let Some(&b) = tail.get(i) {
        if i >= cfg.max_len {
            break;
        }
        let n = match b {
            0x09 | 0x0a | 0x0d | 0x20..=0x7e => 1,
            0xc2..=0xf4 => {
                let n = match b {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    _ => 4,
                };
                let Some(Ok(s)) = tail.get(i..i + n).map(std::str::from_utf8) else {
                    break;
                };
                if s.chars().next().is_none_or(char::is_control) {
                    break;
                }
                ascii = false;
                n
            }
            _ => break,
        };
        i += n;
        chars += 1;
    }
    // A run reaching the limit is cut there, as documented; a NUL right
    // after the cut is consumed.
    let cut = i >= cfg.max_len;
    if (cut || tail.get(i) == Some(&0)) && chars >= cfg.min_len {
        let nul = usize::from(tail.get(i) == Some(&0));
        let Some(text) = tail
            .get(..i)
            .map(|t| String::from_utf8_lossy(t).into_owned())
        else {
            return Detect::Miss(1);
        };
        return Detect::Hit(
            StringLiteral {
                address: addr,
                encoding: if ascii {
                    StringEncoding::Ascii
                } else {
                    StringEncoding::Utf8
                },
                byte_len: (i + nul) as u64,
                value: text,
            },
            (i + nul).max(1),
        );
    }
    // Wide encodings, remembering how much text each consumed: a wide
    // string starting inside a failed scan hits the same failing unit.
    let mut s16 = 0usize;
    let mut s32 = 0usize;
    // UTF-32.
    if addr.get() % 4 == 0 {
        for (enc, big) in [
            (StringEncoding::Utf32Le, false),
            (StringEncoding::Utf32Be, true),
        ] {
            let mut units = Vec::new();
            let mut term = false;
            for ch in tail.as_chunks::<4>().0.iter().take(cfg.max_len / 4 + 1) {
                if units.len() >= cfg.max_len / 4 {
                    break;
                }
                let u = if big {
                    u32::from_be_bytes(*ch)
                } else {
                    u32::from_le_bytes(*ch)
                };
                if u == 0 {
                    term = true;
                    break;
                }
                if !is_wide_text(u) {
                    break;
                }
                units.push(u);
            }
            s32 = s32.max(units.len() * 4);
            if (term || units.len() >= cfg.max_len / 4) && units.len() >= cfg.min_len_wide {
                let value: String = units.iter().filter_map(|u| char::from_u32(*u)).collect();
                let used = (units.len() + usize::from(term)) * 4;
                return Detect::Hit(
                    StringLiteral {
                        address: addr,
                        encoding: enc,
                        byte_len: used as u64,
                        value,
                    },
                    used.max(1),
                );
            }
        }
    }
    // UTF-16.
    if addr.get() % 2 == 0 {
        for (enc, big) in [
            (StringEncoding::Utf16Le, false),
            (StringEncoding::Utf16Be, true),
        ] {
            let mut units: Vec<u16> = Vec::new();
            let mut term = false;
            for ch in tail.as_chunks::<2>().0.iter().take(cfg.max_len / 2 + 1) {
                if units.len() >= cfg.max_len / 2 {
                    break;
                }
                let u = if big {
                    u16::from_be_bytes(*ch)
                } else {
                    u16::from_le_bytes(*ch)
                };
                if u == 0 {
                    term = true;
                    break;
                }
                if !is_wide_text(u32::from(u)) {
                    break;
                }
                units.push(u);
            }
            s16 = s16.max(units.len() * 2);
            if (term || units.len() >= cfg.max_len / 2) && units.len() >= cfg.min_len_wide {
                let used = (units.len() + usize::from(term)) * 2;
                return Detect::Hit(
                    StringLiteral {
                        address: addr,
                        encoding: enc,
                        byte_len: used as u64,
                        value: String::from_utf16_lossy(&units),
                    },
                    used.max(1),
                );
            }
        }
    }
    Detect::Miss(miss_skip(addr, i, s16, s32))
}

fn user_data_blocks(snap: &Snapshot, addr: Address) -> bool {
    match snap.user().definition_at_or_before(addr) {
        Some((start, Definition::Data { ty }))
            if !matches!(ty, dasm_core::DataType::String { .. }) =>
        {
            let ptr = u64::from(snap.program().info().bits / 8);
            ty.fixed_size(ptr)
                .and_then(|n| start.checked_add(n))
                .is_some_and(|end| addr < end)
        }
        _ => false,
    }
}

fn scan_region(
    snap: &Snapshot,
    range: AddressRange,
    cfg: &StringsConfig,
    cancel: &CancelToken,
    out: &mut Vec<StringLiteral>,
) -> Result<(), Error> {
    let mem = snap.memory();
    let end = range.end().get();
    let mut pos = range.start().get();
    let overlap = cfg.max_len as u64 + 8;
    while pos < end {
        cancel.check()?;
        let limit = (end - pos).min(CHUNK);
        let want = usize::try_from((limit + overlap).min(end - pos)).unwrap_or(0);
        let Some(bytes) = mem.read(Address(pos), want) else {
            break;
        };
        let limit = limit as usize;
        let mut i = 0usize;
        while i < limit {
            if i % 4096 == 0 {
                cancel.check()?;
            }
            let addr = Address(pos + i as u64);
            let found = bytes.get(i..).map(|t| detect(t, addr, cfg));
            match found {
                Some(Detect::Hit(lit, used)) if !user_data_blocks(snap, addr) => {
                    out.push(lit);
                    i += used.max(1);
                }
                Some(Detect::Miss(skip)) => i += skip,
                _ => i += 1,
            }
        }
        pos += i.max(1) as u64;
    }
    Ok(())
}

impl AnalysisPass for StringsPass {
    fn id(&self) -> PassId {
        passes::STRINGS
    }
    fn dependencies(&self) -> Vec<PassId> {
        Vec::new()
    }
    fn granularity(&self) -> Granularity {
        Granularity::Program
    }
    fn invalidated_by(&self) -> &[ChangeKind] {
        &[ChangeKind::Definition, ChangeKind::Bytes]
    }
    fn run(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<AnalysisDelta, Error> {
        Stage::run_stage(self, ctx, scope).map(|o| o.delta)
    }
}

impl Stage for StringsPass {
    fn pass(&self) -> &dyn AnalysisPass {
        self
    }

    fn range_scope(&self) -> bool {
        true
    }

    fn run_stage(&self, ctx: &PassContext<'_>, scope: PassScope) -> Result<StageOutput, Error> {
        let snap = ctx.snapshot;
        let mut delta = AnalysisDelta::default();
        for region in snap.memory().regions() {
            if region.perms().execute {
                continue;
            }
            if let PassScope::Range(r) = scope
                && !r.overlaps(&region.range())
            {
                continue;
            }
            scan_region(
                snap,
                region.range(),
                &self.config,
                ctx.cancel,
                &mut delta.upsert_strings,
            )?;
            delta.remove_strings_in.push(region.range());
        }
        Ok(StageOutput {
            delta,
            ..StageOutput::default()
        })
    }
}
