# dasm fuzzing harness

Owner: Security. Threat model: `docs/security/threat-model.md`.

A separate cargo workspace (own `Cargo.lock`): the root workspace never
builds libFuzzer. Each target is a plain `dasm_fuzz::<target>::run(&[u8])`;
`fuzz_targets/*.rs` only wrap it with `fuzz_target!`.

| Target | Under test | Status |
|---|---|---|
| `journal_replay` | `Journal::replay` of a JSON journal + undo/redo/apply; oracle: live state == replay of the persisted store | active |
| `memory_read` | `MemoryMap::{new, read, read_up_to, with_patch, region_at}` vs. a byte model | active |
| `operation_json` | JSON → `Operation` → `UserState::apply` → inverse → redo; JSON round trip | active |
| `elf_load` | `ElfLoader::load` on raw bytes + `Limits` and image invariants + listing | `--features elf` |
| `eh_frame` | the input as `.eh_frame` of a valid ELF (`src/elf_image.rs`) | `--features elf` |
| `dwarf` | the input split into the `.debug_*` sections (`src/dwarf.rs`) | `--features elf` |
| `x86_decode` | `X86_64::{decode, render, is_prologue, is_padding}` contract | `--features x86` after Backend #2 lands |

The generic halves (`loader::run_with`, `arch::run_with`) are already
exercised on stable with a stand-in loader and `MockArch`.

## Coverage-guided fuzzing (cargo-fuzz)

No rustup/nightly is needed: the system stable `rustc` accepts the nightly
flags cargo-fuzz passes when `RUSTC_BOOTSTRAP=1` is set. AddressSanitizer
works with the Arch `rust` package (checked with rustc 1.99.1, cargo-fuzz
0.13.2).

```sh
# from the repository root
cargo run --release --manifest-path fuzz/Cargo.toml --example seed_corpus 500   # optional seeds
RUSTC_BOOTSTRAP=1 DASM_FUZZ_IGNORE_KNOWN=1 cargo fuzz run journal_replay -- \
    -max_total_time=3600 -timeout=10 -rss_limit_mb=2048 -dict=fuzz/dict/json.dict
RUSTC_BOOTSTRAP=1 DASM_FUZZ_IGNORE_KNOWN=1 cargo fuzz run memory_read -- -max_total_time=3600 -timeout=10
# ELF targets (seed them first, needs gcc/objcopy):
fuzz/seed_elf_corpus.sh
RUSTC_BOOTSTRAP=1 cargo fuzz run --features elf elf_load -- -max_total_time=3600 -timeout=10 -max_len=262144
# after Backend #2 lands:
RUSTC_BOOTSTRAP=1 cargo fuzz run --features x86 x86_decode -- -max_total_time=3600
```

To keep going after the first crash and collect them all, add
`-fork=3 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1`.

If a toolchain without ASan runtime is used, add `--sanitizer none`
(panics, overflows in debug-assertion builds, hangs and OOM are still found).

`DASM_FUZZ_IGNORE_KNOWN=1` skips oracle violations of already filed
findings (`src/report.rs`, `KNOWN`) so a long campaign keeps searching.
Panics inside dasm itself are never skipped.

## Stable smoke run

```sh
cd fuzz && cargo test --release            # 100 000 generated inputs per target
cargo test --release --features elf        # also the ELF targets
DASM_FUZZ_ITERS=1000000 cargo test --release
cargo test --release -- --ignored          # demonstrators of open findings (fail until fixed)
```

## Crashes and regressions

- A crash found by either runner is a bug: minimise it
  (`cargo fuzz tmin <target> <file>`), file it with an id `SEC-…`, and copy
  the input to `regressions/<target>/`.
- `regressions/<target>/known-<ID>-*` must still reproduce `<ID>` while the
  id is in `KNOWN`. When the fix lands: remove the id from `KNOWN` and the
  `known-<ID>-` prefix from the file name; from then on it must pass.
- `artifacts/` and `corpus/` are not committed.
