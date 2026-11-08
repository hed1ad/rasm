//! CLI logic on the mock backends (the real loader and scheduler are wired
//! in during wave C; see `INTEGRATION(wave C)` in `services.rs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dasm_cli::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, Env, Services, run};
use dasm_core::report::AnalyzeReport;
use dasm_core::testing::{
    MockArch, StaticDriver, addrs, reference_analysis, synthetic_file, synthetic_image,
    synthetic_program, synthetic_source,
};
use dasm_core::{
    AnalysisDriver, AnalysisState, Change, Focus, JOURNAL_FORMAT_VERSION, LoadError, LoadOptions,
    Loader, NoAnalysis, OpSource, Operation, ProjectStore, Registry, Session, SharedBytes,
    SnapshotHub, SourceContent, StoredSource,
};
use dasm_db::SqliteStore;

struct MockLoader;
impl Loader for MockLoader {
    fn name(&self) -> &'static str {
        "mock"
    }
    fn probe(&self, bytes: &[u8]) -> bool {
        bytes == synthetic_file().as_slice()
    }
    fn load(
        &self,
        _file: SharedBytes,
        _o: &LoadOptions,
    ) -> Result<dasm_core::LoadedImage, LoadError> {
        synthetic_image().map_err(|e| LoadError::Unsupported(e.to_string()))
    }
}

/// Finishes the analysis from another thread after a delay, so the CLI
/// really has to wait for the notification.
struct SlowDriver;
impl AnalysisDriver for SlowDriver {
    fn start(&self, hub: Arc<SnapshotHub>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            hub.update(|s| {
                let r = reference_analysis(s);
                s.with_analysis(r)
            });
        });
    }
    fn invalidate(&self, _: &[Change]) {}
    fn set_focus(&self, _: Focus) {}
    fn cancel(&self) {}
}

fn services(driver: fn() -> Arc<dyn AnalysisDriver>) -> Services {
    Services {
        registry: Registry::new()
            .with_loader(Arc::new(MockLoader))
            .with_arch(Arc::new(MockArch)),
        driver: Box::new(driver),
    }
}

fn static_services() -> Services {
    services(|| Arc::new(StaticDriver::default()))
}

struct Outcome {
    code: i32,
    out: String,
    err: String,
}

fn dasm(services: &Services, env: &Env, args: &[&str]) -> Outcome {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let argv: Vec<OsString> = std::iter::once("dasm")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    let code = run(argv, services, env, &mut out, &mut err);
    Outcome {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

fn binary(dir: &Path) -> PathBuf {
    let p = dir.join("synthetic");
    std::fs::write(&p, synthetic_file()).unwrap();
    p
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn json_report_parses_and_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let sv = static_services();
    let a = dasm(&sv, &Env::default(), &["analyze", s(&bin), "--json"]);
    let b = dasm(&sv, &Env::default(), &["analyze", s(&bin), "--json"]);
    assert_eq!((a.code, b.code), (EXIT_OK, EXIT_OK), "{}", a.err);
    assert!(a.out.ends_with('\n'));
    let mut ra: AnalyzeReport = serde_json::from_str(&a.out).unwrap();
    let mut rb: AnalyzeReport = serde_json::from_str(&b.out).unwrap();
    assert_eq!(ra.stats.analysis_state, AnalysisState::Done);
    assert!(ra.stats.function_count > 0);
    assert_eq!(ra.binary.path, s(&bin));
    ra.stats.analysis_ms = 0;
    rb.stats.analysis_ms = 0;
    assert_eq!(ra, rb);
    assert!(ra.functions.iter().all(|f| f.instructions.is_none()));
}

#[test]
fn insns_flag_adds_instructions() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let o = dasm(
        &static_services(),
        &Env::default(),
        &["analyze", s(&bin), "--json", "--insns"],
    );
    let r: AnalyzeReport = serde_json::from_str(&o.out).unwrap();
    assert!(r.functions.iter().all(|f| f.instructions.is_some()));
}

#[test]
fn plain_output_is_a_summary() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let o = dasm(&static_services(), &Env::default(), &["analyze", s(&bin)]);
    assert_eq!(o.code, EXIT_OK);
    assert!(o.out.contains("functions:"), "{}", o.out);
}

#[test]
fn waits_for_a_driver_that_finishes_later() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let sv = services(|| Arc::new(SlowDriver));
    let o = dasm(&sv, &Env::default(), &["analyze", s(&bin), "--json"]);
    assert_eq!(o.code, EXIT_OK, "{}", o.err);
    let r: AnalyzeReport = serde_json::from_str(&o.out).unwrap();
    assert_eq!(r.stats.analysis_state, AnalysisState::Done);
    assert!(r.stats.analysis_ms >= 90, "{}", r.stats.analysis_ms);
}

#[test]
fn project_is_created_and_reopened_with_user_names() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let sv = static_services();
    let args = ["analyze", s(&bin), "--json", "--project", s(&proj)];
    let first = dasm(&sv, &Env::default(), &args);
    assert_eq!(first.code, EXIT_OK, "{}", first.err);

    // A user rename lands in the journal and shows up on the next run.
    {
        let session = Session::open(
            synthetic_program().unwrap(),
            synthetic_source(),
            Box::new(SqliteStore::open(&proj).unwrap()),
            Arc::new(NoAnalysis),
            "ada",
        )
        .unwrap();
        session
            .apply(
                Operation::Rename {
                    address: addrs::MAIN,
                    name: Some("my_main".into()),
                },
                OpSource::Cli,
            )
            .unwrap();
    }
    let second = dasm(&sv, &Env::default(), &args);
    assert_eq!(second.code, EXIT_OK, "{}", second.err);
    let r: AnalyzeReport = serde_json::from_str(&second.out).unwrap();
    assert!(r.functions.iter().any(|f| f.name == "my_main"));
}

#[test]
fn link_mode_stores_path_and_detects_changes() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let sv = static_services();
    let args = ["analyze", s(&bin), "--json", "--project", s(&proj)];
    let mut linked = args.to_vec();
    linked.push("--link");
    let o = dasm(&sv, &Env::default(), &linked);
    assert_eq!(o.code, EXIT_OK, "{}", o.err);
    let src = SqliteStore::open(&proj)
        .unwrap()
        .load_source()
        .unwrap()
        .unwrap();
    assert!(matches!(src.content, SourceContent::Linked { .. }));
    // Reopening works while the file is unchanged ...
    assert_eq!(dasm(&sv, &Env::default(), &args).code, EXIT_OK);
    // ... and fails with a clear message once it changed.
    std::fs::write(&bin, b"changed").unwrap();
    let o = dasm(&sv, &Env::default(), &args);
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.out.is_empty());
    assert!(o.err.contains("not"), "{}", o.err);
}

#[test]
fn base_is_persisted_and_checked() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let sv = static_services();
    let first = [
        "analyze",
        s(&bin),
        "--project",
        s(&proj),
        "--base",
        "0x10000",
    ];
    assert_eq!(dasm(&sv, &Env::default(), &first).code, EXIT_OK);
    let src = SqliteStore::open(&proj)
        .unwrap()
        .load_source()
        .unwrap()
        .unwrap();
    assert_eq!(src.options.base, Some(dasm_core::Address(0x10000)));
    let other = [
        "analyze",
        s(&bin),
        "--project",
        s(&proj),
        "--base",
        "0x20000",
    ];
    let o = dasm(&sv, &Env::default(), &other);
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.err.contains("load base"), "{}", o.err);
}

#[test]
fn wrong_binary_for_project_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let sv = static_services();
    assert_eq!(
        dasm(
            &sv,
            &Env::default(),
            &["analyze", s(&bin), "--project", s(&proj)]
        )
        .code,
        EXIT_OK
    );
    let other = dir.path().join("other");
    std::fs::write(&other, b"not the same").unwrap();
    let o = dasm(
        &sv,
        &Env::default(),
        &["analyze", s(&other), "--project", s(&proj)],
    );
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.out.is_empty());
    assert!(o.err.contains("project mismatch"), "{}", o.err);
}

#[test]
fn newer_project_format_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let sv = static_services();
    let args = ["analyze", s(&bin), "--project", s(&proj)];
    assert_eq!(dasm(&sv, &Env::default(), &args).code, EXIT_OK);
    SqliteStore::open(&proj)
        .unwrap()
        .set_format_version(JOURNAL_FORMAT_VERSION + 1)
        .unwrap();
    let o = dasm(&sv, &Env::default(), &args);
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.err.contains("upgrade dasm"), "{}", o.err);
}

#[test]
fn load_errors_exit_1_with_empty_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk");
    std::fs::write(&junk, b"hello").unwrap();
    let o = dasm(
        &static_services(),
        &Env::default(),
        &["analyze", s(&junk), "--json"],
    );
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.out.is_empty());
    assert!(o.err.contains("unrecognised file format"), "{}", o.err);

    let missing = dir.path().join("missing");
    let o = dasm(
        &static_services(),
        &Env::default(),
        &["analyze", s(&missing)],
    );
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.err.starts_with("dasm: error:"));

    // The production registry is empty until wave C.
    let o = dasm(
        &dasm_cli::build_services(),
        &Env::default(),
        &["analyze", s(&junk)],
    );
    assert_eq!(o.code, EXIT_ERROR);
}

#[test]
fn failed_first_run_leaves_no_project_file() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk");
    std::fs::write(&junk, b"hello").unwrap();
    let proj = dir.path().join("p.dasm");
    let o = dasm(
        &static_services(),
        &Env::default(),
        &["analyze", s(&junk), "--project", s(&proj)],
    );
    assert_eq!(o.code, EXIT_ERROR);
    assert!(!proj.exists());
}

#[test]
fn usage_errors_exit_2() {
    let sv = static_services();
    let env = Env::default();
    for args in [
        &["analyze"][..],
        &["analyze", "x", "--link"],
        &["analyze", "x", "--base", "zz"],
        &["analyze", "x", "--nope"],
        &["bogus"],
        &[],
    ] {
        let o = dasm(&sv, &env, args);
        assert_eq!(o.code, EXIT_USAGE, "{args:?}");
        assert!(o.out.is_empty());
        assert!(!o.err.is_empty());
    }
    let o = dasm(&sv, &env, &["--help"]);
    assert_eq!(o.code, EXIT_OK);
    assert!(o.out.contains("analyze"));
}

#[test]
fn stored_link_path_is_never_opened() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let sv = static_services();
    let args = [
        "analyze",
        s(&bin),
        "--json",
        "--project",
        s(&proj),
        "--link",
    ];
    assert_eq!(dasm(&sv, &Env::default(), &args).code, EXIT_OK);
    // A tampered project points elsewhere; a regression must fail with an
    // ordinary error (a missing path), not hang on a device like /dev/zero.
    let mut store = SqliteStore::open(&proj).unwrap();
    let mut src = store.load_source().unwrap().unwrap();
    src.content = SourceContent::Linked {
        path: PathBuf::from("/nonexistent/dasm-tampered-link"),
    };
    store.save_source(&src).unwrap();
    drop(store);
    let o = dasm(&sv, &Env::default(), &args);
    assert_eq!(o.code, EXIT_OK, "{}", o.err);
    let r: AnalyzeReport = serde_json::from_str(&o.out).unwrap();
    assert_eq!(r.stats.analysis_state, AnalysisState::Done);
}

#[test]
fn preexisting_empty_project_file_survives_a_failed_run() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk");
    std::fs::write(&junk, b"hello").unwrap();
    let proj = dir.path().join("p.dasm");
    std::fs::write(&proj, b"").unwrap();
    let o = dasm(
        &static_services(),
        &Env::default(),
        &["analyze", s(&junk), "--project", s(&proj)],
    );
    assert_eq!(o.code, EXIT_ERROR);
    assert!(proj.exists());
}

#[test]
fn link_on_an_embedded_project_warns() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let sv = static_services();
    let args = ["analyze", s(&bin), "--project", s(&proj)];
    assert_eq!(dasm(&sv, &Env::default(), &args).code, EXIT_OK);
    let mut again = args.to_vec();
    again.push("--link");
    let o = dasm(&sv, &Env::default(), &again);
    assert_eq!(o.code, EXIT_OK);
    assert!(o.err.contains("--link ignored"), "{}", o.err);
}

/// Ends the analysis in the `Failed` state.
struct FailingDriver;
impl AnalysisDriver for FailingDriver {
    fn start(&self, hub: Arc<SnapshotHub>) {
        hub.update(|s| {
            let mut r = reference_analysis(s);
            r.progress.state = AnalysisState::Failed;
            r.progress.error = Some("pass functions panicked: boom".into());
            s.with_analysis(r)
        });
    }
    fn invalidate(&self, _: &[Change]) {}
    fn set_focus(&self, _: Focus) {}
    fn cancel(&self) {}
}

#[test]
fn failed_analysis_exits_1_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let sv = services(|| Arc::new(FailingDriver));
    let o = dasm(&sv, &Env::default(), &["analyze", s(&bin), "--json"]);
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.out.is_empty());
    assert!(o.err.contains("analysis failed"), "{}", o.err);
    assert!(o.err.contains("boom"), "{}", o.err);
}

#[test]
fn control_characters_from_a_project_are_escaped_in_messages() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let proj = dir.path().join("p.dasm");
    let mut store = SqliteStore::create(&proj).unwrap();
    store.set_format_version(JOURNAL_FORMAT_VERSION).unwrap();
    let evil = StoredSource::embedded(
        "evil\u{1b}[2Jname",
        SharedBytes::from(b"other".to_vec()),
        LoadOptions::default(),
    );
    store.save_source(&evil).unwrap();
    drop(store);
    let o = dasm(
        &static_services(),
        &Env::default(),
        &["analyze", s(&bin), "--project", s(&proj)],
    );
    assert_eq!(o.code, EXIT_ERROR);
    assert!(!o.err.contains('\u{1b}'), "{:?}", o.err);
    assert!(o.err.contains("\\u{1b}"), "{:?}", o.err);
}

#[test]
fn non_regular_inputs_are_rejected_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let sv = static_services();
    let o = dasm(&sv, &Env::default(), &["analyze", s(dir.path())]);
    assert_eq!(o.code, EXIT_ERROR);
    assert!(o.err.contains("not a regular file"), "{}", o.err);

    let fifo = dir.path().join("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|st| st.success());
    if made {
        let o = dasm(&sv, &Env::default(), &["analyze", s(&fifo)]);
        assert_eq!(o.code, EXIT_ERROR);
        assert!(o.err.contains("not a regular file"), "{}", o.err);
    }
}

#[test]
fn symlinked_project_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let bin = binary(dir.path());
    let real = dir.path().join("real.dasm");
    let sv = static_services();
    assert_eq!(
        dasm(
            &sv,
            &Env::default(),
            &["analyze", s(&bin), "--project", s(&real)]
        )
        .code,
        EXIT_OK
    );
    let link = dir.path().join("link.dasm");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let o = dasm(
        &sv,
        &Env::default(),
        &["analyze", s(&bin), "--project", s(&link)],
    );
    assert_eq!(o.code, EXIT_ERROR);
}
