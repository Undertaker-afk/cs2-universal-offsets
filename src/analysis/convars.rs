use std::collections::BTreeMap;
use anyhow::Result;
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

pub fn convars<P: Process + MemoryView>(process: &mut P, show_values: bool) -> Result<ConVarMap> {
    let tier0 = process.module_by_name("tier0.dll")?;

    // Find CCvar head using pattern
    let buf = process.read_raw(tier0.base, tier0.size as usize).data_part()?;
    let mut save = [0u32; 2];
    let view = pelite::pe64::PeView::from_bytes(&buf)?;

    use pelite::pe64::Pe;
    if !view.scanner().finds_code(pelite::pattern!("48 8b 0d ${'} 48 85 c9 74 1d 48 8b 01 ff 50 10"), &mut save) {
        // Fallback pattern
        if !view.scanner().finds_code(pelite::pattern!("48 8b 0d ${'} 48 85 c9 0f 84 ? ? ? ? 48 8b 01 ff 50 10"), &mut save) {
             return Ok(BTreeMap::new());
        }
    }

    let cvar_ptr: Pointer64<u64> = Pointer64::from(tier0.base + save[1]);
    let cvar_inst = process.read_ptr(cvar_ptr).data_part()?;
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
             // In CS2, the actual value is often reached through another pointer at node + 0x40.
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
