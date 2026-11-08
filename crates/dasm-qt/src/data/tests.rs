//! Tests of the snapshot -> plain-record conversion, on the synthetic
//! program and on hand-built images (no Qt runtime involved).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dasm_core::testing::{MockArch, mock_session};
use dasm_core::{
    Address, AddressRange, AnalysisDelta, AnalysisProgress, AnalysisResults, AnalysisState,
    BasicBlock, DataType, Function, FunctionSource, LoadedImage, MemoryMap, MemoryRegion, OpSource,
    Operation, Permissions, Program, SharedBytes, Snapshot, UndoScope,
};

use super::*;

// ------------------------------------------------------------- builders

fn region(start: u64, bytes: Vec<u8>) -> MemoryRegion {
    MemoryRegion::new(
        AddressRange::from_len(Address(start), bytes.len() as u64).unwrap(),
        SharedBytes::from(bytes),
        Permissions::RX,
    )
    .unwrap()
}

fn snapshot_of(regions: Vec<MemoryRegion>, bits: u8) -> Snapshot {
    let mut image = LoadedImage::default();
    image.info.bits = bits;
    image.memory = MemoryMap::new(regions).unwrap();
    Snapshot::initial(Arc::new(Program::new(image, Arc::new(MockArch))))
}

fn with_functions(snap: &Snapshot, funcs: Vec<Function>) -> Snapshot {
    let mut results = AnalysisResults::default();
    results.apply(AnalysisDelta {
        upsert_functions: funcs,
        ..AnalysisDelta::default()
    });
    snap.with_analysis(results)
}

fn function(entry: u64, lens: Vec<u8>) -> Function {
    Function::new(
        Address(entry),
        FunctionSource::User,
        vec![BasicBlock::new(Address(entry), lens, Vec::new()).unwrap()],
    )
}

fn synthetic() -> (dasm_core::Session, Arc<Snapshot>) {
    let session = mock_session().expect("mock session");
    let snap = session.snapshot();
    (session, snap)
}

fn ui(session: &dasm_core::Session, op: Operation) {
    session.apply(op, OpSource::Ui).expect("apply");
}

fn rename(addr: u64, name: &str) -> Operation {
    Operation::Rename {
        address: Address(addr),
        name: Some(name.into()),
    }
}

// ------------------------------------------------- 1. alignment (basic)

#[test]
fn listing_pages_are_contiguous_in_both_directions() {
    let (_s, s) = synthetic();
    let start = Address(0x40_1000);
    let fwd = rows_from(&s, start, 8);
    assert_eq!(fwd.len(), 8);
    assert_eq!(fwd[0].addr, start.get());
    let back = rows_before(&s, Address(fwd[4].addr), 4);
    let addrs: Vec<u64> = back.iter().map(|r| r.addr).collect();
    let expected: Vec<u64> = fwd[..4].iter().map(|r| r.addr).collect();
    assert_eq!(addrs, expected);
}

#[test]
fn start_in_the_middle_of_an_instruction_aligns_to_the_item() {
    let (_s, s) = synthetic();
    // main: push rbp (0x401010, 1 byte); mov rbp, rsp (0x401011, 3 bytes).
    let r = rows_from(&s, Address(0x40_1012), 1);
    assert_eq!(r[0].addr, 0x40_1011);
    assert_eq!(r[0].len, 3);
    assert_eq!(r[0].mnemonic, "mov");
    // Inside the string "Hello, dasm!" at 0x402000.
    let r = rows_from(&s, Address(0x40_2003), 1);
    assert_eq!(r[0].addr, 0x40_2000);
    assert_eq!(r[0].kind, 1);
}

// ------------------------------------------------------ 2. boundaries

#[test]
fn listing_boundaries() {
    let (_s, s) = synthetic();
    // First address: nothing before it.
    assert_eq!(rows_from(&s, Address(0x40_1000), 1)[0].addr, 0x40_1000);
    assert!(rows_before(&s, Address(0x40_1000), 5).is_empty());
    // Last mapped byte.
    let last = s.memory().regions().last().unwrap().range().end().get() - 1;
    let tail = rows_from(&s, Address(last), 5);
    assert_eq!(tail.len(), 1);
    assert_eq!(u64::from(tail[0].len) + tail[0].addr, last + 1);
    // Beyond everything.
    assert!(rows_from(&s, Address(0xffff_ffff), 3).is_empty());
    assert!(rows_from(&s, Address(u64::MAX), 3).is_empty());
    let before_end = rows_before(&s, Address(u64::MAX), 2);
    assert_eq!(before_end.len(), 2);
    assert!(before_end[0].addr < before_end[1].addr);
    assert_eq!(
        u64::from(before_end[1].len) + before_end[1].addr,
        last + 1,
        "last row ends at the last mapped byte"
    );
    // Gap between .text (ends 0x401060) and .rodata (0x402000).
    let after_gap = rows_from(&s, Address(0x40_1800), 1);
    assert_eq!(after_gap[0].addr, 0x40_2000);
    let before_gap = rows_before(&s, Address(0x40_1800), 1);
    assert_eq!(before_gap.len(), 1);
    assert_eq!(
        u64::from(before_gap[0].len) + before_gap[0].addr,
        0x40_1060,
        "row before a gap address is the last item of .text"
    );
    // count == 0.
    assert!(rows_from(&s, Address(0x40_1000), 0).is_empty());
    assert!(rows_before(&s, Address(0x40_2000), 0).is_empty());
}

#[test]
fn full_forward_walk_is_contiguous_inside_regions() {
    let (_s, s) = synthetic();
    let rows = rows_from(&s, Address(0x40_1000), 1024);
    assert!(rows.len() > 50);
    for pair in rows.windows(2) {
        let end = pair[0].addr + u64::from(pair[0].len);
        assert!(pair[1].addr >= end, "rows must not overlap");
        if pair[1].addr != end {
            assert!(
                s.memory().region_at(Address(end)).is_none(),
                "a jump is only allowed over a gap at {end:#x}"
            );
        }
    }
}

// --------------------------------------------------------- 3. offsets

fn three_regions() -> Snapshot {
    snapshot_of(
        vec![
            region(0x1000, vec![0x90; 0x10]),
            region(0x2000, Vec::new()), // empty region
            region(0x3000, vec![0x90; 0x20]),
            region(0x1_0000, vec![0x90; 8]),
        ],
        64,
    )
}

#[test]
fn offsets_across_regions_gaps_and_empty_region() {
    let s = three_regions();
    assert_eq!(mapped_size(&s), 0x38);
    for (off, addr) in [
        (0u64, 0x1000u64),
        (0xf, 0x100f),
        (0x10, 0x3000),
        (0x2f, 0x301f),
        (0x30, 0x1_0000),
        (0x37, 0x1_0007),
    ] {
        assert_eq!(offset_to_address(&s, off), addr, "offset {off:#x}");
        assert_eq!(address_to_offset(&s, addr), off, "address {addr:#x}");
    }
    // Offsets at or past the end clamp to the last mapped byte.
    assert_eq!(offset_to_address(&s, 0x38), 0x1_0007);
    assert_eq!(offset_to_address(&s, u64::MAX), 0x1_0007);
    // Addresses outside regions.
    assert_eq!(address_to_offset(&s, 0x10), 0, "below the first region");
    assert_eq!(address_to_offset(&s, 0x2500), 0x10, "in a gap");
    assert_eq!(address_to_offset(&s, 0x2000), 0x10, "at the empty region");
    assert_eq!(address_to_offset(&s, 0x2_0000), 0x38, "above the last");
    assert_eq!(address_to_offset(&s, u64::MAX), 0x38);
}

#[test]
fn offsets_without_regions() {
    let s = snapshot_of(Vec::new(), 64);
    assert_eq!(mapped_size(&s), 0);
    assert_eq!(offset_to_address(&s, 0), 0);
    assert_eq!(offset_to_address(&s, 100), 0);
    assert_eq!(address_to_offset(&s, 0x1000), 0);
    assert!(rows_from(&s, Address(0), 4).is_empty());
    assert!(rows_before(&s, Address(0x1000), 4).is_empty());
}

#[test]
fn offsets_roundtrip_on_synthetic() {
    let (_s, s) = synthetic();
    let total = mapped_size(&s);
    assert!(total > 0);
    for off in [0, 1, total / 2, total - 1] {
        let a = offset_to_address(&s, off);
        assert_eq!(address_to_offset(&s, a), off, "offset {off}");
    }
}

// --------------------------------------------------------- 4. row_for

#[test]
fn undecodable_code_becomes_a_raw_byte_row() {
    // 0x06 is not a MockArch instruction, but the analysis claims code.
    let base = snapshot_of(vec![region(0x1000, vec![0x06, 0x90, 0xc3])], 64);
    let snap = with_functions(&base, vec![function(0x1000, vec![1, 1, 1])]);
    let rows = rows_from(&snap, Address(0x1000), 3);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].kind, 3);
    assert_eq!(rows[0].mnemonic, "db");
    assert_eq!(rows[0].tokens[0].text, "0x06");
    assert_eq!(rows[1].kind, 0, "valid code after it is still code");
    assert_eq!(rows[1].mnemonic, "nop");
}

#[test]
fn truncated_code_at_region_end_does_not_panic() {
    // `call rel32` cut by the end of the region.
    let base = snapshot_of(vec![region(0x1000, vec![0xe8, 0x00])], 64);
    let snap = with_functions(&base, vec![function(0x1000, vec![5])]);
    let rows = rows_from(&snap, Address(0x1000), 4);
    assert!(!rows.is_empty());
    assert_eq!(rows[0].kind, 3);
}

#[test]
fn string_row() {
    let (_s, s) = synthetic();
    let r = &rows_from(&s, Address(0x40_2000), 1)[0];
    assert_eq!(r.kind, 1);
    assert_eq!(r.mnemonic, "string");
    assert_eq!(r.tokens[0].text, "\"Hello, dasm!\"");
    assert_eq!(r.len, 13);
    assert!(
        r.bytes.ends_with('…'),
        "13 bytes are cut to 10: {}",
        r.bytes
    );
}

#[test]
fn data_array_row_and_byte_truncation() {
    let (session, _) = synthetic();
    ui(
        &session,
        Operation::DefineData {
            address: Address(0x40_4010),
            ty: DataType::Array {
                element: Box::new(DataType::Byte),
                count: 16,
            },
        },
    );
    let s = session.snapshot();
    let r = &rows_from(&s, Address(0x40_4010), 1)[0];
    assert_eq!(r.kind, 2);
    assert_eq!(r.len, 16);
    assert_eq!(r.mnemonic, "db[16]");
    assert_eq!(r.bytes, format!("{}…", ["00"; 10].join(" ")));
    // Exactly 10 bytes: no ellipsis.
    assert_eq!(hex_bytes(&[1; 10]), ["01"; 10].join(" "));
    assert!(hex_bytes(&[1; 11]).ends_with('…'));
    assert_eq!(hex_bytes(&[]), "");
}

#[test]
fn linked_tokens_carry_targets() {
    let (_s, s) = synthetic();
    // _start: call main at 0x401002.
    let r = &rows_from(&s, Address(0x40_1002), 1)[0];
    assert_eq!(r.mnemonic, "call");
    let linked: Vec<_> = r.tokens.iter().filter(|t| t.has_target).collect();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].target, 0x40_1010);
    assert!(r.tokens.iter().any(|t| !t.has_target) || r.tokens.len() == 1);
}

#[test]
fn label_comment_and_bookmark_follow_user_operations() {
    let (session, _) = synthetic();
    ui(&session, rename(0x40_1010, "entry_fn"));
    ui(
        &session,
        Operation::Comment {
            address: Address(0x40_1011),
            text: Some("note".into()),
        },
    );
    ui(
        &session,
        Operation::Bookmark {
            address: Address(0x40_1011),
            note: Some("b".into()),
        },
    );
    let rows = rows_from(&session.snapshot(), Address(0x40_1010), 2);
    assert_eq!(rows[0].label, "entry_fn");
    assert!(rows[0].is_function);
    assert_eq!(rows[1].comment, "note");
    assert!(rows[1].bookmarked);
    assert!(!rows[0].bookmarked);
    assert!(rows[1].label.is_empty());
}

// --------------------------------------------------------- 5. history

#[test]
fn history_after_rename_undo_redo() {
    let (session, _) = synthetic();
    ui(&session, rename(0x40_1010, "x"));
    ui(
        &session,
        Operation::Comment {
            address: Address(0x40_1011),
            text: Some("c".into()),
        },
    );
    let h = history(&session.history(UndoScope::Global));
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].text, "Rename 0x401010 to x");
    assert_eq!(h[1].text, "Comment at 0x401011");
    assert!(!h[0].undone && !h[1].undone);

    assert!(session.undo(UndoScope::Global).unwrap());
    let h = history(&session.history(UndoScope::Global));
    assert_eq!(h.len(), 2, "undone entries stay in the list");
    assert!(!h[0].undone && h[1].undone);

    assert!(session.redo(UndoScope::Global).unwrap());
    let h = history(&session.history(UndoScope::Global));
    assert!(!h[0].undone && !h[1].undone);

    // Undo both, then a new operation discards the redo tail: the entry
    // is kept but shown as undone.
    session.undo(UndoScope::Global).unwrap();
    session.undo(UndoScope::Global).unwrap();
    ui(&session, rename(0x40_1010, "y"));
    let h = history(&session.history(UndoScope::Global));
    assert_eq!(h.len(), 3);
    assert!(h[0].undone && h[1].undone && !h[2].undone);
}

#[test]
fn describe_texts() {
    assert_eq!(
        describe(&Operation::Rename {
            address: Address(0x10),
            name: None
        }),
        "Reset name at 0x10"
    );
    assert_eq!(
        describe(&Operation::Comment {
            address: Address(0x10),
            text: None
        }),
        "Remove comment at 0x10"
    );
    assert_eq!(
        describe(&Operation::Batch {
            ops: vec![rename(1, "a"), rename(2, "b")]
        }),
        "Batch of 2 operations"
    );
    let other = describe(&Operation::AddTag {
        address: Address(1),
        tag: "t".into(),
    });
    assert!(other.contains("AddTag"));
}

#[test]
fn describe_never_splits_a_multibyte_character() {
    // The generic branch truncates a Debug string; non-ASCII text must
    // not make it cut inside a character.
    for n in 1..80 {
        for ch in ['é', 'я', '日', '😀'] {
            let note: String = std::iter::repeat_n(ch, n).collect();
            let text = describe(&Operation::Bookmark {
                address: Address(0x1000),
                note: Some(note),
            });
            assert!(text.len() <= 84, "bounded: {} bytes", text.len());
        }
    }
}

// ---------------------------------------------------------- 6. status

#[test]
fn status_reflects_undo_state_and_width() {
    let (session, s) = synthetic();
    let st = status(&s);
    assert!(!st.can_undo && !st.can_redo);
    assert_eq!(st.addr_width, 16);
    assert!(st.has_entry);
    assert_eq!(st.entry, 0x40_1000);

    ui(&session, rename(0x40_1010, "x"));
    let st = status(&session.snapshot());
    assert!(st.can_undo && !st.can_redo);
    session.undo(UndoScope::Global).unwrap();
    let st = status(&session.snapshot());
    assert!(!st.can_undo && st.can_redo);
    session.redo(UndoScope::Global).unwrap();
    let st = status(&session.snapshot());
    assert!(st.can_undo && !st.can_redo);

    let narrow = snapshot_of(vec![region(0x1000, vec![0x90])], 32);
    assert_eq!(status(&narrow).addr_width, 8);
    assert!(!status(&narrow).has_entry);
}

#[test]
fn status_reports_progress_states() {
    let (session, _) = synthetic();
    assert_eq!(status(&session.snapshot()).analysis_state, 2);
    session.hub().update_analysis(|r| {
        r.progress = AnalysisProgress {
            state: AnalysisState::Running,
            current_pass: Some("xrefs".into()),
            done: 3,
            total: 10,
            error: None,
        };
    });
    let st = status(&session.snapshot());
    assert_eq!(st.analysis_state, 1);
    assert_eq!(
        (st.current_pass.as_str(), st.done, st.total),
        ("xrefs", 3, 10)
    );
    session.hub().update_analysis(|r| {
        r.progress = AnalysisProgress {
            state: AnalysisState::Failed,
            error: Some("pass x panicked".into()),
            ..AnalysisProgress::default()
        };
    });
    let st = status(&session.snapshot());
    assert_eq!(st.analysis_state, 4);
    assert_eq!(st.error, "pass x panicked");
    session.hub().update_analysis(|r| {
        r.progress.state = AnalysisState::Cancelled;
    });
    assert_eq!(status(&session.snapshot()).analysis_state, 3);
}

#[test]
fn tables_are_filled() {
    let (_s, s) = synthetic();
    assert!(functions(&s).len() >= 3);
    assert!(strings(&s).iter().any(|x| x.value == "Hello, dasm!"));
    assert!(!imports(&s).is_empty());
}

#[test]
fn count_is_clamped() {
    let (_s, s) = synthetic();
    assert!(rows_from(&s, Address(0x40_1000), -5).is_empty());
    assert!(rows_from(&s, Address(0x40_1000), i32::MAX).len() <= MAX_ROWS);
    // A listing longer than the cap is cut exactly at the cap.
    let big = snapshot_of(vec![region(0x1000, vec![0; 3000])], 64);
    assert_eq!(rows_from(&big, Address(0x1000), i32::MAX).len(), MAX_ROWS);
    assert_eq!(rows_from(&big, Address(0x1000), 1025).len(), MAX_ROWS);
    assert_eq!(
        rows_before(&big, Address(0x1000 + 3000), i32::MAX).len(),
        MAX_ROWS
    );
    assert_eq!(rows_from(&big, Address(0x1000), 1000).len(), 1000);
}

// ------------------------------------------------- 7. size independence

fn median(mut f: impl FnMut()) -> Duration {
    let mut times: Vec<Duration> = (0..7)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    times.sort();
    times[times.len() / 2]
}

#[test]
fn page_cost_does_not_depend_on_position_in_a_million_item_listing() {
    const FUNCS: u64 = 150_000; // 8 one-byte instructions each: 1.2 M code items
    const BASE: u64 = 0x10_0000;
    const ZERO_BASE: u64 = 0x4000_0000;
    let mut code = Vec::with_capacity(FUNCS as usize * 8);
    for _ in 0..FUNCS {
        code.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]);
    }
    let base = snapshot_of(
        vec![region(BASE, code), region(ZERO_BASE, vec![0; 2 << 20])],
        64,
    );
    let funcs = (0..FUNCS)
        .map(|i| function(BASE + i * 8, vec![1; 8]))
        .collect();
    let snap = with_functions(&base, funcs);

    let end = BASE + FUNCS * 8;
    let positions = [BASE, BASE + FUNCS * 4, end - 8 * 64, ZERO_BASE + 1_000_000];
    let mut fwd = Vec::new();
    let mut back = Vec::new();
    for &p in &positions {
        let rows = rows_from(&snap, Address(p), 64);
        assert_eq!(rows.len(), 64, "forward page at {p:#x}");
        let rows = rows_before(&snap, Address(p + 4096), 64);
        assert_eq!(rows.len(), 64, "backward page at {p:#x}");
        fwd.push(median(|| {
            assert_eq!(rows_from(&snap, Address(p), 64).len(), 64);
        }));
        back.push(median(|| {
            assert_eq!(rows_before(&snap, Address(p + 4096), 64).len(), 64);
        }));
    }
    for times in [&fwd, &back] {
        let min = *times.iter().min().unwrap();
        let max = *times.iter().max().unwrap();
        assert!(
            max <= min * 10 + Duration::from_millis(20),
            "page time depends on position: {times:?}"
        );
        assert!(max < Duration::from_millis(500), "too slow: {times:?}");
    }
}

// ------------------------------------------------ text from binaries is bounded

#[test]
fn clip_cuts_on_a_character_boundary() {
    assert_eq!(clip("short"), "short");
    let exact = "a".repeat(MAX_TEXT_BYTES);
    assert_eq!(clip(&exact), exact, "exactly at the limit: unchanged");
    let over = "a".repeat(MAX_TEXT_BYTES + 1);
    let c = clip(&over);
    assert_eq!(c.len(), MAX_TEXT_BYTES + '…'.len_utf8());
    assert!(c.ends_with('…'));
    for ch in ['é', 'я', '日', '😀'] {
        let long: String = std::iter::repeat_n(ch, MAX_TEXT_BYTES).collect();
        let c = clip(&long);
        assert!(c.ends_with('…'));
        assert!(c.len() <= MAX_TEXT_BYTES + 3);
        assert!(
            c.trim_end_matches('…').chars().all(|x| x == ch),
            "no split character"
        );
    }
}

#[test]
fn huge_strings_are_clipped_in_rows_and_tables() {
    const BASE: u64 = 0x1000;
    let len = 1 << 20;
    let value = "я".repeat(len / 2);
    let base = snapshot_of(vec![region(BASE, vec![b'x'; len + 1])], 64);
    let mut results = AnalysisResults::default();
    results.apply(AnalysisDelta {
        upsert_strings: vec![dasm_core::StringLiteral {
            address: Address(BASE),
            encoding: dasm_core::StringEncoding::Utf8,
            byte_len: len as u64,
            value: value.clone(),
        }],
        ..AnalysisDelta::default()
    });
    let snap = base.with_analysis(results);
    let rows = rows_from(&snap, Address(BASE), 1);
    assert_eq!(rows[0].kind, 1);
    assert!(rows[0].tokens[0].text.len() < MAX_TEXT_BYTES * 2 + 16);
    let table = strings(&snap);
    assert_eq!(
        table[0].value.len(),
        MAX_TEXT_BYTES + 3 - (MAX_TEXT_BYTES % 2)
    );
    assert!(table[0].value.ends_with('…'));
}

#[test]
fn long_user_comment_is_clipped() {
    let (session, _) = synthetic();
    ui(
        &session,
        Operation::Comment {
            address: Address(0x40_1011),
            text: Some("é".repeat(30_000)),
        },
    );
    let r = &rows_from(&session.snapshot(), Address(0x40_1011), 1)[0];
    assert!(r.comment.len() <= MAX_TEXT_BYTES + 3);
    assert!(r.comment.ends_with('…'));
}
