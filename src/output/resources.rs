use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use anyhow::Result;
use crate::analysis::ResourceTree;

pub fn dump(out_dir: &Path, tree: &ResourceTree) -> Result<()> {
    let mut s = String::new();
    s.push_str("Resources\n");
    for (category, items) in tree {
        s.push_str(&format!("- {}\n", category));
        for item in items {
            s.push_str(&format!("   |- {}\n", item));
        }
        s.push('\n');
    }
    fs::write(out_dir.join("resources.txt"), s)?;
    Ok(())
}
