# rasm

A Linux-first reverse-engineering tool (binaries: `dasm`, `dasm-gui`): a native disassembler with a headless core, written in Rust with a Qt 6 interface.

> **Status: early preview (0.1).** It analyses x86-64 ELF binaries and opens them in a desktop UI, but it is not hardened yet. **Do not open untrusted or malicious files with this version.**

## What works

- **ELF loading** with a bounds-checked parser: segments, sections, symbols, relocations, PLT/GOT, TLS, DWARF names and `.eh_frame` function boundaries.
- **x86-64 analysis**: recursive descent, control-flow graphs, cross-references, strings, tail calls and `noreturn` detection, running in the background.
- **`dasm` CLI**: headless analysis with stable JSON output.
- **`dasm-gui`**: a virtualized listing, function, string and import lists, a Ctrl+K command palette, navigation history, inline rename and comments, and undo/redo.
- **Projects**: edits are stored in a SQLite journal and survive restarts.

## Known limitations

- x86-64 only. No decompiler, graph view, hex view or plugins yet.
- C++ and Rust names are not demangled.
- `switch` jump tables are not resolved directly; code in functions without a known size may be missed.
- Analysis of a hostile file can be very slow, and incremental re-analysis after edits can differ from a full analysis.
- The interface is functional but unpolished; a redesign is planned.

## Building

You need Rust 1.88+, Qt 6.8+, CMake, Ninja and a C++ compiler. The UI build downloads Qt Advanced Docking System unless a system package is installed.

```bash
cargo build --release -p dasm-cli
cmake -S ui -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Usage

```bash
target/release/dasm analyze /usr/bin/ls
target/release/dasm analyze /usr/bin/ls --json | jq .stats
target/release/dasm analyze /usr/bin/ls --project ls.dasm

build/dasm-gui /usr/bin/ls
```

In the GUI:

| Key | Action |
|---|---|
| Ctrl+K | Command palette: go to a function, address or string, or run a command |
| Alt+← / Alt+→ | Navigate back and forward |
| Enter or click | Follow a reference |
| N | Rename |
| ; | Comment |
| Ctrl+Z / Ctrl+Shift+Z | Undo / redo |

## Development

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
QT_QPA_PLATFORM=offscreen ctest --test-dir build

scripts/fixtures/build.sh
DASM_BIN=target/release/dasm DASM_STRICT=1 cargo test -p dasm-tests --test golden
```

The golden tests compare results against `readelf`, `objdump` and `nm`. Fuzz targets are in [`fuzz/`](fuzz/README.md). Architecture decisions are in [`docs/adr/`](docs/adr/README.md) and the design document is [`docs/design.md`](docs/design.md); both are currently in Russian.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0, see [`LICENSE`](LICENSE). The UI links against Qt (LGPL-3.0) and Qt Advanced Docking System (LGPL-2.1).
