# Security Policy

dasm is a disassembler: it is built to open hostile files. A crash, hang,
memory exhaustion or misleading output caused by a crafted binary or
project file is a security bug, not just a bug.

## Supported versions

dasm is pre-release (stage 1). Only the latest commit of `main` receives
security fixes.

## Reporting a vulnerability

Please report privately — do **not** open a public issue for:

- code execution, memory corruption, or a panic/abort reachable from an
  input file (ELF, DWARF, `.eh_frame`, project `.dasm`);
- unbounded memory/CPU use or a hang from an input file;
- reading or writing files outside what the user asked for (e.g. through
  a project's linked source path);
- output that hides or misrepresents code (e.g. bytes shown differ from
  bytes mapped).

Use GitHub's "Report a vulnerability" (private security advisory) on this
repository. Include the dasm commit, the command or UI steps, and the
smallest input that reproduces the problem (attach it zipped with a
password given in the report; never attach live malware unpacked).

We aim to acknowledge reports within 3 working days and to ship a fix or a
mitigation within 30 days for high/critical issues. Reporters are credited
in the advisory unless they ask otherwise.

## Scope and trust model

Summary of `docs/security/threat-model.md`:

| Input | Trusted? |
|---|---|
| Binaries being analysed | **No** — any byte sequence |
| Project files (`.dasm`, SQLite + JSON journal) | **No** — treat like a binary from the internet |
| Linked source path stored in a project | **No** |
| Command-line arguments, `$XDG_CONFIG_HOME/dasm/config.toml` | Yes (the local user) |
| Plugins and Python scripts (future) | Yes — run in-process with the user's rights, **no sandbox**. Only install plugins you trust. |

Out of scope: attacks that require a malicious plugin or script, local
attackers who can already modify the user's files or dasm itself, and
denial of service through deliberately huge but legitimate inputs within
the configured `Limits`.

## Hardening in the code base

- Parsers never panic on input; resource limits (`dasm_core::Limits`,
  `MAX_READ_LEN`, `MAX_PATCH_LEN`, ...) bound allocations.
- `unsafe` is denied workspace-wide except in the Qt bridge, where each
  block carries a `// SAFETY:` justification.
- Every parser of untrusted data has a fuzz target (`fuzz/`); crashes
  become regression inputs in `fuzz/regressions/`.
- Dependencies are checked by `cargo deny check` (`deny.toml`): RustSec
  advisories, Apache-2.0-compatible licenses, crates.io only.
