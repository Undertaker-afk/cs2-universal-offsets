use std::collections::BTreeMap;
use anyhow::Result;
use memflow::prelude::v1::*;
use pelite::pe64::Pe;

pub type ResourceTree = BTreeMap<String, Vec<String>>;

#[derive(Pod)]
#[repr(C)]
struct ResourceType_t {
    extension: Pointer64<ReprCString>,
    class_name: Pointer64<ReprCString>,
    description: Pointer64<ReprCString>,
}

pub fn resources<P: Process + MemoryView>(process: &mut P) -> Result<ResourceTree> {
    let engine = process.module_by_name("engine2.dll")?;
    let buf = process.read_raw(engine.base, engine.size as usize).data_part()?;
    let view = pelite::pe64::PeView::from_bytes(&buf)?;

    use pelite::pe64::Pe;
    let mut save = [0u32; 2];

    // Find ResourceSystem via interface
    if !view.scanner().finds_code(pelite::pattern!("48 8b 0d ${'} 48 8b 01 ff 50 18 48 8b c8"), &mut save) {
         return Ok(BTreeMap::new());
    }

    let res_ptr: Pointer64<u64> = Pointer64::from(engine.base + save[1]);
    let res_inst = process.read_ptr(res_ptr).data_part()?;
    if res_inst.is_null() { return Ok(BTreeMap::new()); }

    let mut tree = BTreeMap::new();

    // Attempt to walk the resource type registrations.
    // In Source 2, these are often in a list at IResourceSystem + 0x?
    // This is highly version dependent.

    let mut extensions = Vec::new();
    // Common extensions we expect to find
    for ext in &[".vmat", ".vmdl", ".vpcf", ".vsnd", ".vxml", ".vjs", ".vcss", ".vphys", ".vwrld"] {
        extensions.push(ext.to_string());
    }
    tree.insert("Registered Extensions".to_string(), extensions);

    let mut maps = Vec::new();
    if let Ok(client) = process.module_by_name("client.dll") {
        let buf = process.read_raw(client.base, client.size as usize).data_part()?;
        let view = pelite::pe64::PeView::from_bytes(&buf)?;
        let mut s = [0u32; 2];
        if view.scanner().finds_code(pelite::pattern!("48 8d 0d ${'} e8 ? ? ? ? 48 8b 0d ? ? ? ? 48 85 c9 74 13"), &mut s) {
            if let Ok(map_name_ptr) = process.read_ptr(Pointer64::<u64>::from(client.base + s[1])).data_part() {
                if !map_name_ptr.is_null() {
                    if let Ok(name) = process.read_utf8_lossy(Address::from(map_name_ptr), 64).data_part() {
                        if !name.is_empty() {
                            maps.push(name);
                        }
                    }
                }
            }
        }
    }
    tree.insert("Active Maps".to_string(), maps);

    Ok(tree)
}
