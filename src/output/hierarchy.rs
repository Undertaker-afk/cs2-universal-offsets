use std::fs;
use std::path::Path;
use anyhow::Result;
use crate::analysis::SchemaMap;

pub fn generate(out_dir: &Path, schemas: &SchemaMap) -> Result<()> {
    // Generate .dot file
    let mut dot = String::new();
    dot.push_str("digraph CS2Hierarchy {\n");
    dot.push_str("  node [shape=box, style=filled, fillcolor=lightblue];\n");
    dot.push_str("  rankdir=LR;\n");

    for (_module, (classes, _)) in schemas {
        for class in classes {
            if let Some(parent) = &class.parent_name {
                dot.push_str(&format!("  \"{}\" -> \"{}\";\n", parent, class.name));
            }
        }
    }

    dot.push_str("}\n");
    fs::write(out_dir.join("hierarchy.dot"), dot)?;

    // Generate simple HTML tree view
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><title>CS2 Entity Hierarchy</title></head><body>");
    html.push_str("<h1>CS2 Entity Hierarchy</h1><ul>");

    // This is a naive flat list for now, ideally it would be a recursive tree
    for (module, (classes, _)) in schemas {
        html.push_str(&format!("<li><b>{}</b><ul>", module));
        for class in classes {
            let parent_info = class.parent_name.as_ref().map(|p| format!(" (parent: {})", p)).unwrap_or_default();
            html.push_str(&format!("<li>{}{}</li>", class.name, parent_info));
        }
        html.push_str("</ul></li>");
    }

    html.push_str("</ul></body></html>");
    fs::write(out_dir.join("hierarchy.html"), html)?;

    Ok(())
}
