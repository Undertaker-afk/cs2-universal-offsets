use std::fs;
use std::path::Path;
use anyhow::Result;
use crate::analysis::SchemaMap;

pub fn generate(out_dir: &Path, schemas: &SchemaMap) -> Result<()> {
    let mut dot = String::new();
    dot.push_str("digraph CS2Hierarchy {\n");
    dot.push_str("  node [shape=box];\n");

    for (_module, (classes, _)) in schemas {
        for class in classes {
            if let Some(parent) = &class.parent_name {
                dot.push_str(&format!("  \"{}\" -> \"{}\";\n", parent, class.name));
            }
        }
    }

    dot.push_str("}\n");
    fs::write(out_dir.join("hierarchy.dot"), dot)?;
    Ok(())
}
