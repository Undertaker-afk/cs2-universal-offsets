use std::collections::BTreeMap;
use anyhow::{Result, anyhow};
use memflow::prelude::v1::*;

pub type ConVarMap = BTreeMap<String, ConVar>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConVar {
    pub name: String,
    pub description: String,
    pub flags: i32,
    pub default_value: String,
    pub current_value: Option<String>,
}

#[derive(Pod)]
#[repr(C)]
struct ConVar_t {
    vtable: u64,
    name: Pointer64<ReprCString>,
    description: Pointer64<ReprCString>,
    flags: i32,
    pad_0: [u8; 4],
    next: Pointer64<ConVar_t>,
}

pub fn convars<P: Process + MemoryView>(
    process: &mut P,
    show_values: bool,
    sig_hits: &BTreeMap<String, umem>
) -> Result<ConVarMap> {
    // Use sig_hits instead of hardcoded pattern
    let cvar_ptr_addr = sig_hits.get("CVar_ptr")
        .ok_or_else(|| anyhow!("CVar_ptr signature not found"))?;

    let cvar_inst = process.read_ptr(Pointer64::<u64>::from(*cvar_ptr_addr)).data_part()?;
    if cvar_inst.is_null() { return Ok(BTreeMap::new()); }

    // In Source 2, the head of the list is at cvar_ptr + 0x40.
    let head_ptr_ptr: Pointer64<Pointer64<ConVar_t>> = Pointer64::from(cvar_inst + 0x40);
    let mut node_ptr = process.read_ptr(head_ptr_ptr).data_part()?;

    let mut results = BTreeMap::new();
    let mut count = 0;

    while !node_ptr.is_null() && count < 20000 {
        let node = process.read_ptr(node_ptr).data_part()?;
        let name = process.read_utf8_lossy(node.name.address(), 128).data_part()?;
        if name.is_empty() { break; }

        let description = process.read_utf8_lossy(node.description.address(), 256).data_part()?;

        let mut val_str = String::new();
        if show_values {
             let var_ptr: Pointer64<u64> = Pointer64::from(node_ptr.address() + 0x40);
             if let Ok(var_inst) = process.read_ptr(var_ptr).data_part() {
                 if !var_inst.is_null() {
                     if let Ok(s) = process.read_utf8_lossy(Address::from(var_inst), 64).data_part() {
                         val_str = s;
                     }
                 }
             }
        }

        results.insert(name.clone(), ConVar {
            name,
            description,
            flags: node.flags,
            default_value: "".to_string(),
            current_value: if show_values { Some(val_str) } else { None },
        });

        node_ptr = node.next;
        count += 1;
    }

    Ok(results)
}
