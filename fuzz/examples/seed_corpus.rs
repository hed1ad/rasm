//! Writes a seed corpus for the JSON targets from the structured
//! generator: `cargo run --release --example seed_corpus [count]`
//! (from `fuzz/`), then `cargo fuzz run <target> corpus/<target>`.

use std::path::Path;

use dasm_fuzz::generate::Rng;

fn main() -> std::io::Result<()> {
    let count: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(500);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let mut rng = Rng::new(1);
    for (target, make) in [
        (
            "operation_json",
            (|r: &mut Rng| serde_json::to_vec(&r.operation(3))) as fn(&mut Rng) -> _,
        ),
        ("journal_replay", |r: &mut Rng| {
            serde_json::to_vec(&r.journal())
        }),
        ("memory_read", |r: &mut Rng| {
            let len = r.below(300) as usize;
            Ok(r.bytes(len))
        }),
    ] {
        let dir = root.join(target);
        std::fs::create_dir_all(&dir)?;
        for i in 0..count {
            let bytes = make(&mut rng).map_err(std::io::Error::other)?;
            std::fs::write(dir.join(format!("seed-{i:05}")), bytes)?;
        }
    }
    Ok(())
}
