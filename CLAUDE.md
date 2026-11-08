# dasm — Linux-first disassembler

Design: `docs/design.md`. Decisions: `docs/adr/`. JSON contract: `docs/api/analyze-json.md`.
Apache-2.0. Core: Rust (cargo workspace). UI: C++ Qt 6 Widgets + Qt Advanced Docking System, bridged with cxx-qt.

Local-only files (git-ignored): `docs/internal/` holds the plan, handoff, review reports and `KNOWN_ISSUES.md`; `.claude/` holds agent role definitions.

## Layout and ownership

| Path | Owner |
|---|---|
| `Cargo.toml` (workspace), `docs/adr/`, `docs/api/`, `.github/`, `crates/dasm-core/` | Architect |
| `crates/dasm-elf/` | Backend (loader) |
| `crates/dasm-x86/`, `crates/dasm-analysis/` | Backend (analysis) |
| `crates/dasm-db/`, `crates/dasm-cli/` | Backend (storage, CLI) |
| `crates/dasm-qt/`, `ui/` | Frontend |
| `tests/`, `benches/`, `scripts/fixtures/` | QA |
| `fuzz/`, `SECURITY.md`, `deny.toml`, `docs/security/` | Security |
| `CLAUDE.md`, merging into `main` | Team Lead |

If a change belongs to another zone, do not make it; describe it in your report and the Team Lead routes it to the owner.
Changes to the public `dasm-core` API go through the Architect and an ADR.

## Git

- Only the Team Lead changes `main`. Each agent works on its own `<role>/<task>` branch.
- Non-UI roles verify without Qt: `cargo test` and `cargo clippy --all-targets -- -D warnings` (`dasm-qt` and `tests` are outside `default-members`).
- Merging into `main` requires: `cargo test --workspace --all-features` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass, the UI builds, Security has no critical/high findings, and Code Review approved.
- Commits are atomic, in English, in the imperative mood.

## Code rules

- Parsing untrusted binaries: no `panic!`, `unwrap` or unchecked indexing on input data, only `Result`. `unsafe` only in the FFI bridge, with a `// SAFETY:` comment.
- The UI never waits for analysis: it reads snapshots (`Snapshot`) only.
- The model changes only through operations (`Operation`), which go to the journal and undo.
- Test binaries are not committed; `scripts/fixtures/build.sh` builds them.

## Commands

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cmake -S ui -B build -G Ninja && cmake --build build && QT_QPA_PLATFORM=offscreen ctest --test-dir build
scripts/fixtures/build.sh
DASM_BIN=target/release/dasm DASM_STRICT=1 cargo test -p dasm-tests --test golden
```
