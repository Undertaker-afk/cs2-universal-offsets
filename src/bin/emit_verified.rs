// Standalone helper: emit verified_features.{json,md,hpp} into output/sdk/
// without needing a live cs2.exe attach. Useful when only the curated
// catalogue changes and we want to refresh what cs2-sdk.com pulls.
#[path = "../output/verified.rs"]
mod verified;

use std::fs;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let out_dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("output/sdk"));
    fs::create_dir_all(&out_dir)?;

    fs::write(
        out_dir.join("verified_features.json"),
        verified::render_json(None),
    )?;
    fs::write(
        out_dir.join("verified_features.md"),
        verified::render_md(None),
    )?;
    fs::write(
        out_dir.join("verified_features.hpp"),
        verified::render_hpp(None),
    )?;

    println!(
        "emitted verified_features.{{json,md,hpp}} -> {}",
        out_dir.display()
    );
    Ok(())
}
