//! Conversion of snapshot contents into the bridge's plain records.
//!
//! Pure Rust (no Qt runtime needed), so it is unit-tested against the
//! synthetic program.

use std::fmt::Write as _;

use dasm_core::{
    Address, AnalysisState, DataType, ItemKind, JournalEntry, ListingItem, Operation, Snapshot,
    TokenKind,
};

use crate::bridge::qobject::{
    FuncDto, HistoryDto, ImportDto, RowDto, StatusDto, StringDto, TokenDto,
};

/// Upper bound of rows per request, so a bad argument cannot stall the UI.
const MAX_ROWS: usize = 1024;
/// Longest text (bytes) copied out of the model for display. Names, strings
/// and comments come from untrusted binaries and may be megabytes long;
/// measuring and drawing them every frame would stall the UI.
const MAX_TEXT_BYTES: usize = 4096;
/// Bytes shown in the hex column.
const MAX_SHOWN_BYTES: usize = 10;

/// Stable numeric id of a token kind (mirrored in `ui/src/Common.h`).
pub(crate) fn token_kind_id(kind: TokenKind) -> u8 {
    match kind {
        TokenKind::Mnemonic => 0,
        TokenKind::Register => 1,
        TokenKind::Immediate => 2,
        TokenKind::Address => 3,
        TokenKind::Symbol => 4,
        TokenKind::Keyword => 5,
        TokenKind::Punctuation => 6,
        TokenKind::Whitespace => 7,
        TokenKind::String => 8,
        TokenKind::Comment => 9,
        _ => 6,
    }
}

/// `s` cut to [`MAX_TEXT_BYTES`] on a character boundary, with `…` appended
/// when something was removed.
fn clip(s: &str) -> String {
    if s.len() <= MAX_TEXT_BYTES {
        return s.to_owned();
    }
    let mut cut = MAX_TEXT_BYTES;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(cut + 3);
    out.push_str(s.get(..cut).unwrap_or_default());
    out.push('…');
    out
}

fn clamp_count(count: i32) -> usize {
    usize::try_from(count).unwrap_or(0).min(MAX_ROWS)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().min(MAX_SHOWN_BYTES) * 3 + 1);
    for (i, b) in bytes.iter().take(MAX_SHOWN_BYTES).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    if bytes.len() > MAX_SHOWN_BYTES {
        out.push('…');
    }
    out
}

fn token(kind: TokenKind, text: impl Into<String>) -> TokenDto {
    TokenDto {
        text: text.into(),
        kind: token_kind_id(kind),
        has_target: false,
        target: 0,
    }
}

fn data_type_text(ty: &DataType) -> String {
    match ty {
        DataType::Byte => "db".into(),
        DataType::Word => "dw".into(),
        DataType::Dword => "dd".into(),
        DataType::Qword => "dq".into(),
        DataType::Pointer => "ptr".into(),
        DataType::Float => "float".into(),
        DataType::Double => "double".into(),
        DataType::String { .. } => "string".into(),
        DataType::Array { element, count } => format!("{}[{count}]", data_type_text(element)),
        _ => "data".into(),
    }
}

fn row_for(snap: &Snapshot, item: &ListingItem) -> RowDto {
    let addr = item.range.start();
    let len = item.range.len();
    let raw = snap
        .memory()
        .read_up_to(addr, usize::try_from(len).unwrap_or(usize::MAX).min(64))
        .map(|b| b.into_owned())
        .unwrap_or_default();
    let mut row = RowDto {
        addr: addr.get(),
        len: u32::try_from(len).unwrap_or(u32::MAX),
        label: clip(&snap.display_name(addr).unwrap_or_default()),
        is_function: snap.analysis().function_at(addr).is_some(),
        bytes: hex_bytes(&raw),
        comment: clip(snap.user().comment(addr).unwrap_or_default()),
        bookmarked: snap.user().bookmark(addr).is_some(),
        ..RowDto::default()
    };
    match &item.kind {
        ItemKind::Code => match snap.render_insn(addr) {
            Ok(r) => {
                row.kind = 0;
                row.mnemonic = clip(&r.mnemonic);
                row.tokens = r
                    .operands
                    .into_iter()
                    .map(|t| TokenDto {
                        text: clip(&t.text),
                        kind: token_kind_id(t.kind),
                        has_target: t.target.is_some(),
                        target: t.target.map_or(0, Address::get),
                    })
                    .collect();
            }
            Err(_) => {
                row.kind = 3;
                row.mnemonic = "db".into();
                row.tokens = vec![token(TokenKind::Immediate, bytes_as_imm(&raw))];
            }
        },
        ItemKind::String => {
            row.kind = 1;
            row.mnemonic = "string".into();
            let text = snap
                .analysis()
                .string_at(addr)
                .map_or_else(String::new, |s| clip(&s.value));
            row.tokens = vec![token(TokenKind::String, format!("{text:?}"))];
        }
        ItemKind::Data(ty) => {
            row.kind = 2;
            row.mnemonic = data_type_text(ty);
            row.tokens = vec![token(TokenKind::Immediate, bytes_as_imm(&raw))];
        }
        _ => {
            row.kind = 3;
            row.mnemonic = "db".into();
            row.tokens = vec![token(TokenKind::Immediate, bytes_as_imm(&raw))];
        }
    }
    row
}

fn bytes_as_imm(raw: &[u8]) -> String {
    match raw.first() {
        Some(b) if raw.len() == 1 => format!("{b:#04x}"),
        _ => hex_bytes(raw),
    }
}

/// `count` rows starting at the item containing `addr`.
pub(crate) fn rows_from(snap: &Snapshot, addr: Address, count: i32) -> Vec<RowDto> {
    snap.listing_from(addr)
        .take(clamp_count(count))
        .map(|i| row_for(snap, &i))
        .collect()
}

/// Up to `count` rows strictly before `addr`, ascending.
pub(crate) fn rows_before(snap: &Snapshot, addr: Address, count: i32) -> Vec<RowDto> {
    let mut rows: Vec<RowDto> = snap
        .listing_before(addr)
        .take(clamp_count(count))
        .map(|i| row_for(snap, &i))
        .collect();
    rows.reverse();
    rows
}

/// Total number of mapped bytes.
pub(crate) fn mapped_size(snap: &Snapshot) -> u64 {
    snap.memory()
        .regions()
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.range().len()))
}

/// Address of the `offset`-th mapped byte; the last mapped byte if beyond.
pub(crate) fn offset_to_address(snap: &Snapshot, offset: u64) -> u64 {
    let mut left = offset;
    let mut last = 0;
    for r in snap.memory().regions() {
        let range = r.range();
        if range.is_empty() {
            continue;
        }
        if left < range.len() {
            return range.start().get().saturating_add(left);
        }
        left -= range.len();
        last = range.end().get().saturating_sub(1);
    }
    last
}

/// Number of mapped bytes below `addr`.
pub(crate) fn address_to_offset(snap: &Snapshot, addr: u64) -> u64 {
    let mut before = 0u64;
    for r in snap.memory().regions() {
        let range = r.range();
        if addr >= range.end().get() {
            before = before.saturating_add(range.len());
        } else if addr >= range.start().get() {
            return before.saturating_add(addr - range.start().get());
        } else {
            break;
        }
    }
    before
}

/// All functions, in address order.
pub(crate) fn functions(snap: &Snapshot) -> Vec<FuncDto> {
    snap.analysis()
        .functions()
        .map(|f| {
            let mut flags = 0;
            flags |= u32::from(f.flags.thunk);
            flags |= u32::from(f.flags.plt) << 1;
            flags |= u32::from(f.flags.library) << 2;
            flags |= u32::from(f.flags.noreturn) << 3;
            flags |= u32::from(snap.user().name(f.entry).is_some()) << 4;
            FuncDto {
                entry: f.entry.get(),
                name: clip(&snap.function_name(f)),
                size: f.size(),
                blocks: u32::try_from(f.blocks.len()).unwrap_or(u32::MAX),
                insns: u32::try_from(f.insn_count()).unwrap_or(u32::MAX),
                flags,
            }
        })
        .collect()
}

/// All discovered strings.
pub(crate) fn strings(snap: &Snapshot) -> Vec<StringDto> {
    snap.analysis()
        .strings()
        .map(|s| StringDto {
            addr: s.address.get(),
            value: clip(&s.value),
            byte_len: s.byte_len,
            encoding: format!("{:?}", s.encoding).to_lowercase(),
        })
        .collect()
}

/// All imports.
pub(crate) fn imports(snap: &Snapshot) -> Vec<ImportDto> {
    snap.image()
        .imports
        .iter()
        .map(|i| ImportDto {
            name: clip(&i.name),
            library: clip(i.library.as_deref().unwrap_or_default()),
            version: clip(i.version.as_deref().unwrap_or_default()),
            has_plt: i.plt.is_some(),
            plt: i.plt.map_or(0, Address::get),
            got: i.got.map_or(0, Address::get),
        })
        .collect()
}

fn describe(op: &Operation) -> String {
    match op {
        Operation::Rename { address, name } => match name {
            Some(n) => format!("Rename {address} to {n}"),
            None => format!("Reset name at {address}"),
        },
        Operation::Comment { address, text } => match text {
            Some(_) => format!("Comment at {address}"),
            None => format!("Remove comment at {address}"),
        },
        Operation::Batch { ops } => format!("Batch of {} operations", ops.len()),
        other => {
            let mut s = format!("{other:?}");
            // Cut on a character boundary: the text may be non-ASCII.
            let mut cut = s.len().min(80);
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
            s
        }
    }
}

/// Journal entries for the history panel.
pub(crate) fn history(entries: &[JournalEntry]) -> Vec<HistoryDto> {
    entries
        .iter()
        .map(|e| HistoryDto {
            seq: e.seq,
            text: describe(&e.op),
            undone: !matches!(e.state, dasm_core::EntryState::Active),
        })
        .collect()
}

/// Status record for the status bar and action states.
pub(crate) fn status(snap: &Snapshot) -> StatusDto {
    let progress = &snap.analysis().progress;
    let info = snap.program().info();
    let undo = snap.undo_info();
    StatusDto {
        generation: snap.generation(),
        analysis_state: match progress.state {
            AnalysisState::Idle => 0,
            AnalysisState::Running => 1,
            AnalysisState::Done => 2,
            AnalysisState::Cancelled => 3,
            AnalysisState::Failed => 4,
            _ => 4,
        },
        error: progress.error.clone().unwrap_or_default(),
        current_pass: progress.current_pass.clone().unwrap_or_default(),
        done: progress.done,
        total: progress.total,
        can_undo: undo.can_undo,
        can_redo: undo.can_redo,
        function_count: u64::try_from(snap.analysis().function_count()).unwrap_or(u64::MAX),
        file_info: format!(
            "{:?} {:?} {}-bit {:?}",
            info.format, info.arch, info.bits, info.endian
        ),
        has_entry: info.entry.is_some(),
        entry: info.entry.map_or(0, Address::get),
        addr_width: info.bits / 4,
    }
}

/// "section > function" for the breadcrumb line.
pub(crate) fn breadcrumb(snap: &Snapshot, addr: Address) -> String {
    let mut parts = Vec::new();
    if let Some(sec) = snap
        .image()
        .sections
        .iter()
        .find(|s| s.range.contains(addr))
    {
        parts.push(sec.name.clone());
    }
    if let Some(f) = snap.analysis().function_containing(addr) {
        parts.push(snap.function_name(f));
        if let Some(b) = f.block_containing(addr) {
            parts.push(format!("block {}", b.start()));
        }
    }
    parts.join(" › ")
}

#[cfg(test)]
mod tests;
