#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Contract tests for the `analyze --json` document, on the mock session.

use dasm_core::report::{AnalyzeReport, ReportOptions};
use dasm_core::testing::mock_session;
use dasm_tests::schema;
use serde_json::Value;

fn report(insns: bool) -> AnalyzeReport {
    let session = mock_session().unwrap();
    AnalyzeReport::from_snapshot(
        &session.snapshot(),
        &ReportOptions {
            path: "./synthetic".into(),
            include_instructions: insns,
            analysis_ms: 3,
        },
    )
}

fn json(insns: bool) -> Value {
    serde_json::to_value(report(insns)).unwrap()
}

#[test]
fn schema_valid_with_instructions() {
    let problems = schema::validate(&json(true), true);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn schema_valid_without_instructions() {
    let doc = json(false);
    let problems = schema::validate(&doc, false);
    assert!(problems.is_empty(), "{problems:#?}");
    for f in doc["functions"].as_array().unwrap() {
        assert!(
            f.get("instructions").is_none(),
            "key must be absent without --insns"
        );
    }
}

#[test]
fn validator_detects_violations() {
    // The validator itself must not be vacuous: break the document in
    // several ways and expect each to be reported.
    let good = json(true);
    let mutate = |f: &dyn Fn(&mut Value)| {
        let mut d = good.clone();
        f(&mut d);
        schema::validate(&d, true)
    };
    assert!(
        !mutate(&|d| d["binary"]["base"] = "0x0400000".into()).is_empty(),
        "leading zero"
    );
    assert!(
        !mutate(&|d| d["binary"]["base"] = "0X400000".into()).is_empty(),
        "upper-case"
    );
    assert!(!mutate(&|d| d["schema_version"] = 2.into()).is_empty());
    assert!(
        !mutate(&|d| {
            d["functions"].as_array_mut().unwrap().swap(0, 1);
        })
        .is_empty(),
        "unsorted functions"
    );
    assert!(
        !mutate(&|d| d["functions"][0]["instructions"][0]["bytes"] = "ab".into()).is_empty(),
        "len mismatch"
    );
    assert!(
        !mutate(&|d| {
            d["functions"][0]["instructions"][0]["operands"] = "zzz".into();
        })
        .is_empty(),
        "tokens vs operands"
    );
    assert!(!mutate(&|d| d["stats"]["function_count"] = 99.into()).is_empty());
    assert!(
        !mutate(&|d| {
            d["binary"].as_object_mut().unwrap().remove("build_id");
        })
        .is_empty(),
        "null keys must be present"
    );
    assert!(
        !mutate(&|d| d["xrefs"].as_array_mut().unwrap().reverse()).is_empty(),
        "unsorted xrefs"
    );
}

#[test]
fn addresses_are_hex_strings_and_sizes_are_numbers() {
    let doc = json(true);
    assert_eq!(doc["binary"]["entry"], "0x401000");
    assert_eq!(doc["binary"]["base"], "0x0");
    assert!(doc["functions"][0]["size"].is_u64());
    assert!(doc["segments"][0]["file_offset"].is_u64());
    assert!(doc["strings"][0]["byte_len"].is_u64());
    assert_eq!(doc["schema_version"], 1);
    // sha256 is 64 lower-case hex chars
    assert_eq!(doc["binary"]["sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn mock_program_content_matches_documented_example() {
    let r = report(true);
    let names: Vec<&str> = r.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["_start", "main", "sub_401040", "puts@plt"]);
    let main = r.functions.iter().find(|f| f.name == "main").unwrap();
    assert_eq!(main.blocks.len(), 3);
    let call = main
        .instructions
        .as_ref()
        .unwrap()
        .iter()
        .find(|i| i.address.get() == 0x40101b)
        .unwrap();
    assert_eq!(
        (call.mnemonic.as_str(), call.operands.as_str()),
        ("call", "puts@plt")
    );
    assert_eq!(call.bytes, "e830000000");
    assert_eq!(call.tokens[0].target.map(|a| a.get()), Some(0x401050));
    assert_eq!(r.stats.function_count, 4);
    assert_eq!(r.strings.len(), 3);
}

#[test]
fn typed_roundtrip_and_determinism() {
    let a = serde_json::to_string(&report(true)).unwrap();
    let b = serde_json::to_string(&report(true)).unwrap();
    assert_eq!(
        a, b,
        "two runs must serialise identically (analysis_ms fixed)"
    );
    let back: AnalyzeReport = serde_json::from_str(&a).unwrap();
    assert_eq!(back, report(true));
}

#[test]
fn unknown_fields_are_ignored_by_clients() {
    let mut doc = json(true);
    doc["future_top_level"] = serde_json::json!({"x": 1});
    doc["binary"]["future"] = 5.into();
    doc["functions"][0]["future"] = "y".into();
    doc["functions"][0]["instructions"][0]["future"] = true.into();
    let back: AnalyzeReport = serde_json::from_value(doc).unwrap();
    assert_eq!(back, report(true));
}

#[test]
fn memory_and_flags_details() {
    let r = report(true);
    let start = &r.functions[0];
    assert!(start.flags.noreturn);
    let plt = r.functions.iter().find(|f| f.name == "puts@plt").unwrap();
    assert!(plt.flags.plt && plt.flags.thunk);
    assert_eq!(r.imports.len(), 1);
    assert_eq!(r.imports[0].name, "puts");
    assert_eq!(r.imports[0].version.as_deref(), Some("GLIBC_2.2.5"));
}
