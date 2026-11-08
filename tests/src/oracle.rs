//! Reference data: runs `readelf`/`objdump`/`nm` and parses their output.
//!
//! The parsers are pure functions over `&str` so they are unit-tested
//! without the tools; the `run_*` helpers invoke the tools.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// A section header row of `readelf -SW`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RSection {
    /// Section name.
    pub name: String,
    /// `sh_type` name (`PROGBITS`, `NOBITS`, ...).
    pub ty: String,
    /// `sh_addr`.
    pub addr: u64,
    /// `sh_offset`.
    pub offset: u64,
    /// `sh_size`.
    pub size: u64,
    /// Flag letters (`AX`, `WA`, ...); empty if none.
    pub flags: String,
}

impl RSection {
    /// `SHF_ALLOC`.
    pub fn alloc(&self) -> bool {
        self.flags.contains('A')
    }
}

/// A program header row of `readelf -lW`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RSegment {
    /// Type (`LOAD`, `GNU_STACK`, ...).
    pub ty: String,
    /// `p_offset`.
    pub offset: u64,
    /// `p_vaddr`.
    pub vaddr: u64,
    /// `p_filesz`.
    pub filesz: u64,
    /// `p_memsz`.
    pub memsz: u64,
    /// Permissions as `r-x`.
    pub perms: String,
}

/// A symbol line of `nm -S`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NmSymbol {
    /// Name without `@version`.
    pub name: String,
    /// Address.
    pub addr: u64,
    /// Size if printed.
    pub size: Option<u64>,
    /// nm type letter.
    pub ty: char,
}

/// Parses a `0x`-prefixed or bare hex number.
pub fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// Parses `readelf -SW`.
pub fn parse_sections(text: &str) -> Vec<RSection> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim_start();
        let Some(rest) = l.strip_prefix('[') else {
            continue;
        };
        let Some((idx, rest)) = rest.split_once(']') else {
            continue;
        };
        let Ok(idx) = idx.trim().parse::<u32>() else {
            continue;
        };
        if idx == 0 {
            continue;
        }
        let t: Vec<&str> = rest.split_whitespace().collect();
        // name type addr off size es [flg] lk inf al
        if t.len() < 9 {
            continue;
        }
        let (Some(addr), Some(offset), Some(size)) = (hex(t[2]), hex(t[3]), hex(t[4])) else {
            continue;
        };
        let flags = if t.len() >= 10 {
            t[6].to_string()
        } else {
            String::new()
        };
        out.push(RSection {
            name: t[0].into(),
            ty: t[1].into(),
            addr,
            offset,
            size,
            flags,
        });
    }
    out
}

/// Parses `readelf -lW` program headers.
pub fn parse_segments(text: &str) -> Vec<RSegment> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 8 || !t[1].starts_with("0x") || !t[2].starts_with("0x") {
            continue;
        }
        let (Some(offset), Some(vaddr), Some(filesz), Some(memsz)) =
            (hex(t[1]), hex(t[2]), hex(t[4]), hex(t[5]))
        else {
            continue;
        };
        // flags: tokens between memsz and the trailing alignment
        let flg = &t[6..t.len() - 1];
        let joined: String = flg.concat();
        let has = |c: &str| joined.contains(c);
        let perms = format!(
            "{}{}{}",
            if has("R") { 'r' } else { '-' },
            if has("W") { 'w' } else { '-' },
            if has("E") { 'x' } else { '-' }
        );
        out.push(RSegment {
            ty: t[0].into(),
            offset,
            vaddr,
            filesz,
            memsz,
            perms,
        });
    }
    out
}

/// Parses `readelf --debug-dump=frames` into FDE `(start, end)` ranges.
pub fn parse_fdes(text: &str) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains(" FDE ") {
            continue;
        }
        let Some(pc) = line.split("pc=").nth(1) else {
            continue;
        };
        let Some((a, b)) = pc
            .split_whitespace()
            .next()
            .and_then(|p| p.split_once(".."))
        else {
            continue;
        };
        if let (Some(a), Some(b)) = (hex(a), hex(b)) {
            out.push((a, b));
        }
    }
    out
}

/// Parses `objdump -d -w` into `address -> bytes` (instruction lines only).
pub fn parse_objdump(text: &str) -> BTreeMap<u64, Vec<u8>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, '\t');
        let (Some(addr), Some(bytes)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(addr) = addr.trim().strip_suffix(':').and_then(hex) else {
            continue;
        };
        let b: Option<Vec<u8>> = bytes
            .split_whitespace()
            .map(|x| u8::from_str_radix(x, 16).ok())
            .collect();
        match b {
            Some(b) if !b.is_empty() => {
                out.insert(addr, b);
            }
            _ => {}
        }
    }
    out
}

/// Parses `nm -S --defined-only` (with or without `-n`).
pub fn parse_nm(text: &str) -> Vec<NmSymbol> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        let (addr, size, ty, name) = match t.len() {
            4 => (t[0], Some(t[1]), t[2], t[3]),
            3 => (t[0], None, t[1], t[2]),
            _ => continue,
        };
        let (Some(addr), Some(c)) = (hex(addr), ty.chars().next()) else {
            continue;
        };
        let size = size.and_then(hex);
        let name = name.split('@').next().unwrap_or(name).to_string();
        out.push(NmSymbol {
            name,
            addr,
            size,
            ty: c,
        });
    }
    out
}

fn run(tool: &str, args: &[&str], path: &Path) -> Result<String, String> {
    let o = Command::new(tool)
        .args(args)
        .arg(path)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("{tool}: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "{tool} {args:?} {} failed ({}): {}",
            path.display(),
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Like [`run`], but accepts a failed exit status when stdout is non-empty
/// and stderr only complains about unreliable NOBITS section contents.
fn run_tolerant(tool: &str, args: &[&str], path: &Path) -> Result<String, String> {
    let o = Command::new(tool)
        .args(args)
        .arg(path)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("{tool}: {e}"))?;
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    let benign = stderr
        .lines()
        .all(|l| l.trim().is_empty() || l.contains("NOBITS"));
    if o.status.success() || (!stdout.is_empty() && benign) {
        Ok(stdout)
    } else {
        Err(format!(
            "{tool} {args:?} {} failed ({}): {}",
            path.display(),
            o.status,
            stderr.trim()
        ))
    }
}

/// ELF header facts from `readelf -h`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RHeader {
    /// Report-style kind: `executable`, `pie_executable`, `shared_library`, ...
    pub kind: &'static str,
    /// `e_entry`.
    pub entry: u64,
}

/// Parses `readelf -h`.
pub fn parse_header(text: &str) -> Option<RHeader> {
    let ty = text.lines().find(|l| l.trim_start().starts_with("Type:"))?;
    let kind = if ty.contains("EXEC (") {
        "executable"
    } else if ty.contains("Position-Independent Executable") {
        "pie_executable"
    } else if ty.contains("DYN") {
        "shared_library"
    } else if ty.contains("REL (") {
        "relocatable"
    } else if ty.contains("CORE") {
        "core"
    } else {
        "other"
    };
    let entry = text
        .lines()
        .find(|l| l.trim_start().starts_with("Entry point address:"))?
        .split(':')
        .nth(1)
        .and_then(|v| hex(v.trim()))?;
    Some(RHeader { kind, entry })
}

/// Names of imported symbols from `readelf -rW` (JUMP_SLOT / GLOB_DAT with a
/// symbol carrying a `@version`: definite imports), without the version, deduplicated and sorted.
pub fn parse_import_names(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .lines()
        .filter(|l| l.contains("JUMP_SLOT") || l.contains("GLOB_DAT"))
        .filter_map(|l| {
            // offset info type sym_value sym_name [+ addend]
            let name = l.split_whitespace().nth(4)?;
            let n = name.split_once('@')?.0;
            (!n.is_empty() && n != "+").then(|| n.to_string())
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// `readelf -h`.
pub fn header(p: &Path) -> Result<RHeader, String> {
    let t = run("readelf", &["-h"], p)?;
    parse_header(&t).ok_or_else(|| format!("cannot parse readelf -h of {}", p.display()))
}
/// Imported symbol names from relocations.
pub fn import_names(p: &Path) -> Result<Vec<String>, String> {
    run("readelf", &["-rW"], p).map(|t| parse_import_names(&t))
}
/// `readelf -SW`.
pub fn sections(p: &Path) -> Result<Vec<RSection>, String> {
    run("readelf", &["-SW"], p).map(|t| parse_sections(&t))
}
/// `readelf -lW`.
pub fn segments(p: &Path) -> Result<Vec<RSegment>, String> {
    run("readelf", &["-lW"], p).map(|t| parse_segments(&t))
}
/// FDE ranges from `.eh_frame` (empty if the binary has no `.eh_frame`,
/// e.g. Go, whose `.debug_frame` readelf would otherwise mix in).
pub fn fdes(p: &Path) -> Result<Vec<(u64, u64)>, String> {
    if !sections(p)?
        .iter()
        .any(|s| s.name == ".eh_frame" && s.size > 0)
    {
        return Ok(Vec::new());
    }
    // readelf (binutils 2.47+) exits 1 when a dumped section is NOBITS
    // ("contents are unreliable") although the dump itself is complete.
    run_tolerant("readelf", &["--debug-dump=frames"], p).map(|t| parse_fdes(&t))
}
/// Instructions from `objdump -d -w`.
pub fn insns(p: &Path) -> Result<BTreeMap<u64, Vec<u8>>, String> {
    run("objdump", &["-d", "-w"], p).map(|t| parse_objdump(&t))
}
/// Static symbols (`nm -S --defined-only`).
pub fn nm_static(p: &Path) -> Result<Vec<NmSymbol>, String> {
    run("nm", &["-S", "--defined-only"], p).map(|t| parse_nm(&t))
}
/// Dynamic symbols (`nm -D -S --defined-only`).
pub fn nm_dynamic(p: &Path) -> Result<Vec<NmSymbol>, String> {
    run("nm", &["-D", "-S", "--defined-only"], p).map(|t| parse_nm(&t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_parse() {
        let t = "  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0\n\
                 [ 1] .note.gnu.build-id NOTE            0000000000000388 000388 000024 00   A  0   0  4\n\
                 [20] .tbss             NOBITS          0000000000003d90 002d90 000008 00 WAT  0   0  8\n\
                 [21] .foo              PROGBITS        0000000000000000 002d90 000008 00      0   0  8\n";
        let s = parse_sections(t);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].name, ".note.gnu.build-id");
        assert_eq!(
            (s[0].addr, s[0].size, s[0].flags.as_str()),
            (0x388, 0x24, "A")
        );
        assert!(s[1].alloc());
        assert_eq!(s[2].flags, "");
    }

    #[test]
    fn segments_parse() {
        let t = "  LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x0006c1 0x0006c1 R E 0x1000\n\
                 GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10\n";
        let s = parse_segments(t);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].perms, "r-x");
        assert_eq!(s[1].perms, "rw-");
        assert_eq!(s[0].memsz, 0x6c1);
    }

    #[test]
    fn fde_objdump_nm_parse() {
        let f = "00000018 0000000000000014 0000001c FDE cie=00000000 pc=0000000000001200..0000000000001226";
        assert_eq!(parse_fdes(f), vec![(0x1200, 0x1226)]);
        let o = "  401004:\t48 83 ec 08          \tsub    $0x8,%rsp\n  40100f:\t48 85 c0             \ttest   %rax,%rax\nDisassembly of section .init:\n";
        let m = parse_objdump(o);
        assert_eq!(m.get(&0x401004), Some(&vec![0x48, 0x83, 0xec, 0x08]));
        assert_eq!(m.len(), 2);
        let n = parse_nm(
            "0000000000001300 0000000000000008 t classify\n0000000000004040 B __bss_start\n0000000000004040 0000000000000008 B stderr@GLIBC_2.2.5\n",
        );
        assert_eq!(n.len(), 3);
        assert_eq!(n[0].size, Some(8));
        assert_eq!(n[1].size, None);
        assert_eq!(n[2].name, "stderr");
    }
}
