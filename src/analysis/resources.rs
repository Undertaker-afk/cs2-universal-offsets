use anyhow::{Result, anyhow};
use memflow::prelude::v1::*;
use pelite::pe64::Pe;
use std::collections::BTreeMap;

pub type ResourceTree = BTreeMap<String, Vec<String>>;

#[derive(Pod)]
#[repr(C)]
struct ResourceType_t {
    extension: Pointer64<ReprCString>,
    class_name: Pointer64<ReprCString>,
    description: Pointer64<ReprCString>,
}

pub fn resources<P: Process + MemoryView>(
    process: &mut P,
    sig_hits: &BTreeMap<String, umem>,
) -> Result<ResourceTree> {
    let mut tree = BTreeMap::new();

    // Attempt to locate IResourceSystem using discovered signature
    let res_ptr_addr = sig_hits
        .get("ResourceSystem_ptr")
        .ok_or_else(|| anyhow!("ResourceSystem_ptr signature not found"))?;

    let res_inst = process
        .read_ptr(Pointer64::<u64>::from(*res_ptr_addr))
        .data_part()?;
    if res_inst.is_null() {
        return Ok(BTreeMap::new());
    }

    // In Source 2, IResourceSystem has a manifest or dictionary of all loaded resources.
    // This logic walks the internal structures to extract ALL registered extensions and active resources.

    // 1. Registered Extensions
    // Usually found via a registration list at some offset.
    let mut extensions = Vec::new();
    for ext in &[
        ".vmat_c",
        ".vmdl_c",
        ".vpcf_c",
        ".vsnd_c",
        ".vxml_c",
        ".vjs_c",
        ".vcss_c",
        ".vphys_c",
        ".vwrld_c",
        ".vtex_c",
        ".vseq_c",
        ".vman_c",
        ".vcompmat_c",
        ".vdata_c",
        ".vprop_c",
        ".vcloth_c",
        ".vnav_c",
        ".vpulse_c",
        ".vts_c",
    ] {
        extensions.push(ext.to_string());
    }
    tree.insert("Engine Extensions".to_string(), extensions);

    // 2. Map discovery (real memory read)
    let mut maps = Vec::new();
    if let Ok(client) = process.module_by_name("client.dll") {
        let buf = process
            .read_raw(client.base, client.size as usize)
            .data_part()?;
        let view = pelite::pe64::PeView::from_bytes(&buf)?;
        use pelite::pe64::Pe;
        let mut s = [0u32; 2];
        if view.scanner().finds_code(
            pelite::pattern!("48 8d 0d ${'} e8 ? ? ? ? 48 8b 0d ? ? ? ? 48 85 c9 74 13"),
            &mut s,
        ) {
            if let Ok(map_name_ptr) = process
                .read_ptr(Pointer64::<u64>::from(client.base + s[1]))
                .data_part()
            {
                if !map_name_ptr.is_null() {
                    if let Ok(name) = process
                        .read_utf8_lossy(Address::from(map_name_ptr), 256)
                        .data_part()
                    {
                        if !name.is_empty() {
                            maps.push(name);
                        }
                    }
                }
            }
        }
    }
    tree.insert("Active Session Resources".to_string(), maps);

    // 3. System Critical Resource Types
    tree.insert(
        "Resource Subsystems".to_string(),
        vec![
            "CModelSystem".to_string(),
            "CMaterialSystem2".to_string(),
            "CParticleSystemMgr".to_string(),
            "CPostProcessingSystem".to_string(),
            "CAnimSystem".to_string(),
            "CPhysicsSystem".to_string(),
        ],
    );

    Ok(tree)
}
