//! Structural validator for the `dasm analyze --json` document
//! (schema version 1, `docs/api/analyze-json.md`). Works on raw
//! `serde_json::Value`, i.e. checks what is on the wire, not what the
//! typed structs would accept.

use serde_json::Value;

/// Keys whose string value must be an address (`"0x..."`).
const ADDR_KEYS: &[&str] = &[
    "address", "start", "end", "entry", "base", "from", "to", "target", "plt", "got",
];

/// Is `s` a canonical address: `0x` + lower-case hex without leading zeros?
pub fn is_addr(s: &str) -> bool {
    let Some(h) = s.strip_prefix("0x") else {
        return false;
    };
    !h.is_empty()
        && h.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && (h == "0" || !h.starts_with('0'))
}

/// Parses a canonical address.
pub fn addr(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    if !is_addr(s) {
        return None;
    }
    u64::from_str_radix(&s[2..], 16).ok()
}

#[allow(clippy::manual_is_multiple_of)] // MSRV 1.88
fn is_hex(s: &str) -> bool {
    s.len() % 2 == 0
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn is_snake(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Validates a whole report; returns all violations (empty = valid).
/// `expect_insns` states whether `--insns` was requested.
pub fn validate(doc: &Value, expect_insns: bool) -> Vec<String> {
    let mut v = Vec::new();
    check(doc, expect_insns, &mut v);
    v
}

fn arr<'a>(doc: &'a Value, key: &str, v: &mut Vec<String>) -> &'a [Value] {
    match doc.get(key).and_then(Value::as_array) {
        Some(a) => a,
        None => {
            v.push(format!("`{key}` missing or not an array"));
            &[]
        }
    }
}

fn walk_addresses(path: &str, val: &Value, v: &mut Vec<String>) {
    match val {
        Value::Object(m) => {
            for (k, x) in m {
                let p = format!("{path}.{k}");
                if ADDR_KEYS.contains(&k.as_str()) {
                    match x {
                        Value::String(s) if is_addr(s) => {}
                        Value::Null | Value::Bool(_) if k == "plt" && path.ends_with(".flags") => {}
                        Value::Null => {}
                        // `entry`/`address` also appear as non-address keys
                        // only inside objects we never descend into.
                        other => v.push(format!("{p}: not a canonical address: {other}")),
                    }
                } else {
                    walk_addresses(&p, x, v);
                }
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                walk_addresses(&format!("{path}[{i}]"), x, v);
            }
        }
        _ => {}
    }
}

fn sorted_by<T: PartialOrd>(name: &str, keys: &[T], v: &mut Vec<String>) {
    if keys.windows(2).any(|w| w[0] > w[1]) {
        v.push(format!("{name} not sorted"));
    }
}

fn a(x: &Value, k: &str) -> u64 {
    x.get(k).and_then(addr).unwrap_or(0)
}

fn check(doc: &Value, expect_insns: bool, v: &mut Vec<String>) {
    if doc.get("schema_version") != Some(&Value::from(1)) {
        v.push("schema_version != 1".into());
    }
    if doc.pointer("/tool/name") != Some(&Value::from("dasm")) {
        v.push("tool.name != dasm".into());
    }
    if doc
        .pointer("/tool/version")
        .and_then(Value::as_str)
        .is_none()
    {
        v.push("tool.version missing".into());
    }
    walk_addresses("$", doc, v);

    // binary
    let b = doc.get("binary").unwrap_or(&Value::Null);
    match b.get("sha256").and_then(Value::as_str) {
        Some(s) if s.len() == 64 && is_hex(s) => {}
        other => v.push(format!("binary.sha256 invalid: {other:?}")),
    }
    for k in ["format", "kind", "endian"] {
        if !b.get(k).and_then(Value::as_str).is_some_and(is_snake) {
            v.push(format!("binary.{k} not a snake_case string"));
        }
    }
    if !matches!(b.get("bits").and_then(Value::as_u64), Some(32 | 64)) {
        v.push("binary.bits not 32/64".into());
    }
    for k in ["entry", "build_id", "interpreter"] {
        if b.get(k).is_none() {
            v.push(format!("binary.{k} key missing (must be null)"));
        }
    }
    if let Some(Value::String(s)) = b.get("build_id")
        && !is_hex(s)
    {
        v.push("binary.build_id not hex".into());
    }
    if !b.get("needed").is_some_and(Value::is_array) {
        v.push("binary.needed missing".into());
    }
    if b.get("arch")
        .is_none_or(|x| !(x.is_object() || x.as_str().is_some_and(is_snake)))
    {
        v.push("binary.arch invalid".into());
    }

    // segments / sections
    let segs = arr(doc, "segments", v);
    let starts: Vec<u64> = segs.iter().map(|s| a(s, "start")).collect();
    sorted_by("segments", &starts, v);
    for s in segs {
        ranges_ok("segment", s, v);
        perms_ok(s, v);
    }
    for s in arr(doc, "sections", v) {
        ranges_ok("section", s, v);
        perms_ok(s, v);
        if s.get("file_offset").is_none() {
            v.push("section.file_offset key missing".into());
        }
    }

    // symbols
    let syms = arr(doc, "symbols", v);
    let keys: Vec<(u64, String)> = syms
        .iter()
        .map(|s| {
            (
                a(s, "address"),
                s.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    sorted_by("symbols (address, name)", &keys, v);
    for s in syms {
        for k in ["demangled", "size"] {
            if s.get(k).is_none() {
                v.push(format!("symbol.{k} key missing"));
            }
        }
        for k in ["kind", "binding", "source"] {
            if !s.get(k).and_then(Value::as_str).is_some_and(is_snake) {
                v.push(format!("symbol.{k} invalid"));
            }
        }
    }
    for i in arr(doc, "imports", v) {
        for k in ["version", "library", "plt", "got"] {
            if i.get(k).is_none() {
                v.push(format!("import.{k} key missing"));
            }
        }
    }

    // functions
    let funcs = arr(doc, "functions", v);
    let entries: Vec<u64> = funcs.iter().map(|f| a(f, "entry")).collect();
    sorted_by("functions", &entries, v);
    if entries.windows(2).any(|w| w[0] == w[1]) {
        v.push("duplicate function entries".into());
    }
    let mut insn_total = 0u64;
    for f in funcs {
        function_ok(f, expect_insns, v);
        insn_total += f.get("insn_count").and_then(Value::as_u64).unwrap_or(0);
    }

    // xrefs
    let xr = arr(doc, "xrefs", v);
    let keys: Vec<(u64, u64, String)> = xr
        .iter()
        .map(|x| {
            (
                a(x, "from"),
                a(x, "to"),
                x.get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    sorted_by("xrefs (from, to, kind)", &keys, v);
    if keys.windows(2).any(|w| w[0] == w[1]) {
        v.push("duplicate xrefs".into());
    }
    for x in xr {
        let k = x.get("kind").and_then(Value::as_str).unwrap_or("");
        if !["call", "jump", "read", "write", "read_write", "data_ptr"].contains(&k) {
            v.push(format!("xref.kind `{k}` unknown"));
        }
    }

    // strings
    let st = arr(doc, "strings", v);
    let addrs: Vec<u64> = st.iter().map(|s| a(s, "address")).collect();
    sorted_by("strings", &addrs, v);
    for s in st {
        let e = s.get("encoding").and_then(Value::as_str).unwrap_or("");
        if ![
            "ascii", "utf8", "utf16_le", "utf16_be", "utf32_le", "utf32_be",
        ]
        .contains(&e)
        {
            v.push(format!("string.encoding `{e}` unknown"));
        }
        if s.get("byte_len").and_then(Value::as_u64).is_none()
            || s.get("value").and_then(Value::as_str).is_none()
        {
            v.push("string byte_len/value invalid".into());
        }
    }

    // stats
    let n = |k: &str| doc.pointer(&format!("/stats/{k}")).and_then(Value::as_u64);
    if n("function_count") != Some(funcs.len() as u64) {
        v.push("stats.function_count != functions.len()".into());
    }
    if n("xref_count") != Some(xr.len() as u64) {
        v.push("stats.xref_count != xrefs.len()".into());
    }
    if n("string_count") != Some(st.len() as u64) {
        v.push("stats.string_count != strings.len()".into());
    }
    if n("insn_count") != Some(insn_total) {
        v.push("stats.insn_count != sum(functions.insn_count)".into());
    }
    if n("analysis_ms").is_none() {
        v.push("stats.analysis_ms missing".into());
    }
    let state = doc.pointer("/stats/analysis_state").and_then(Value::as_str);
    if !state.is_some_and(|s| ["idle", "running", "done", "cancelled"].contains(&s)) {
        v.push(format!("stats.analysis_state invalid: {state:?}"));
    }
}

fn ranges_ok(what: &str, s: &Value, v: &mut Vec<String>) {
    if a(s, "start") > a(s, "end") {
        v.push(format!("{what} {:?}: start > end", s.get("name")));
    }
}

fn perms_ok(s: &Value, v: &mut Vec<String>) {
    let p = s.get("perms").and_then(Value::as_str).unwrap_or("");
    let b = p.as_bytes();
    let ok = b.len() == 3
        && matches!(b[0], b'r' | b'-')
        && matches!(b[1], b'w' | b'-')
        && matches!(b[2], b'x' | b'-');
    if !ok {
        v.push(format!("perms `{p}` invalid"));
    }
}

fn function_ok(f: &Value, expect_insns: bool, v: &mut Vec<String>) {
    let entry = a(f, "entry");
    let name = f.get("name").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() {
        v.push(format!("function {entry:#x}: empty name"));
    }
    let blocks = f
        .get("blocks")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let starts: Vec<u64> = blocks.iter().map(|b| a(b, "start")).collect();
    sorted_by("blocks", &starts, v);
    let mut size = 0u64;
    let mut count = 0u64;
    for b in blocks {
        let (s, e) = (a(b, "start"), a(b, "end"));
        if s >= e {
            v.push(format!(
                "function {entry:#x}: empty/inverted block {s:#x}..{e:#x}"
            ));
        }
        size += e.saturating_sub(s);
        count += b.get("insn_count").and_then(Value::as_u64).unwrap_or(0);
        for edge in b
            .get("successors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let k = edge.get("kind").and_then(Value::as_str).unwrap_or("");
            if ![
                "fallthrough",
                "jump",
                "conditional_taken",
                "conditional_not_taken",
                "switch",
                "tail_call",
            ]
            .contains(&k)
            {
                v.push(format!("edge.kind `{k}` unknown"));
            }
            if edge.get("target").is_none() {
                v.push("edge.target key missing (must be null)".into());
            }
        }
    }
    if f.get("size").and_then(Value::as_u64) != Some(size) {
        v.push(format!("function {entry:#x}: size != sum of block sizes"));
    }
    if f.get("insn_count").and_then(Value::as_u64) != Some(count) {
        v.push(format!(
            "function {entry:#x}: insn_count != sum of block insn_count"
        ));
    }
    if f.pointer("/source/type").and_then(Value::as_str).is_none() {
        v.push(format!("function {entry:#x}: source.type missing"));
    }
    for k in ["noreturn", "thunk", "plt", "library"] {
        if f.pointer(&format!("/flags/{k}"))
            .and_then(Value::as_bool)
            .is_none()
        {
            v.push(format!("function {entry:#x}: flags.{k} missing"));
        }
    }
    match (f.get("instructions"), expect_insns) {
        (None, false) => {}
        (Some(_), false) => v.push(format!(
            "function {entry:#x}: `instructions` present without --insns"
        )),
        (None, true) => v.push(format!(
            "function {entry:#x}: `instructions` missing with --insns"
        )),
        (Some(ins), true) => insns_ok(entry, ins, count, v),
    }
}

fn insns_ok(entry: u64, ins: &Value, expected: u64, v: &mut Vec<String>) {
    let list = ins.as_array().map_or(&[][..], Vec::as_slice);
    if list.len() as u64 != expected {
        v.push(format!(
            "function {entry:#x}: instructions.len != insn_count"
        ));
    }
    let mut prev_end = 0u64;
    for i in list {
        let ad = a(i, "address");
        let bytes = i.get("bytes").and_then(Value::as_str).unwrap_or("");
        let len = i.get("len").and_then(Value::as_u64).unwrap_or(0);
        if !is_hex(bytes) || bytes.is_empty() || bytes.len() as u64 != 2 * len {
            v.push(format!(
                "insn {ad:#x}: bytes/len inconsistent ({bytes}, {len})"
            ));
        }
        if i.get("mnemonic")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            v.push(format!("insn {ad:#x}: empty mnemonic"));
        }
        let ops = i.get("operands").and_then(Value::as_str).unwrap_or("\u{0}");
        let toks = i
            .get("tokens")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let joined: String = toks
            .iter()
            .filter_map(|t| t.get("text").and_then(Value::as_str))
            .collect();
        if joined != ops {
            v.push(format!(
                "insn {ad:#x}: tokens `{joined}` != operands `{ops}`"
            ));
        }
        for t in toks {
            let k = t.get("kind").and_then(Value::as_str).unwrap_or("");
            if ![
                "mnemonic",
                "register",
                "immediate",
                "address",
                "symbol",
                "keyword",
                "punctuation",
                "whitespace",
                "string",
                "comment",
            ]
            .contains(&k)
            {
                v.push(format!("insn {ad:#x}: token kind `{k}` unknown"));
            }
        }
        if ad < prev_end {
            v.push(format!("insn {ad:#x}: overlaps/unsorted"));
        }
        prev_end = ad + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_rules() {
        assert!(is_addr("0x0") && is_addr("0x401000") && is_addr("0xffffffffffffffff"));
        for bad in ["0x", "0x0401000", "0X10", "401000", "0xABC", "0x1g", ""] {
            assert!(!is_addr(bad), "{bad}");
        }
    }
}
