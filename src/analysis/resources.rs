use std::collections::BTreeMap;
use anyhow::Result;
use memflow::prelude::v1::*;

pub type ResourceTree = BTreeMap<String, Vec<String>>;

pub fn resources<P: Process + MemoryView>(process: &mut P) -> Result<ResourceTree> {
    // Logic to walk IResourceSystem and extract loaded/registered resources.
    let mut tree = BTreeMap::new();
    // Example: tree.insert("Maps".to_string(), vec!["Inferno".to_string(), "Mirage".to_string()]);
    Ok(tree)
}
