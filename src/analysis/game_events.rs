use anyhow::{Result, anyhow};
use memflow::prelude::v1::*;
use std::collections::BTreeMap;

pub type GameEventMap = BTreeMap<String, GameEvent>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GameEvent {
    pub name: String,
    pub fields: Vec<GameEventField>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GameEventField {
    pub name: String,
    pub type_id: i32,
}

#[derive(Pod)]
#[repr(C)]
struct GameEventDescriptor_t {
    vtable: u64,
    name: Pointer64<ReprCString>,
    id: i32,
    pad_0: [u8; 4],
    fields: Pointer64<[GameEventFieldDescriptor_t]>,
    field_count: i32,
    pad_1: [u8; 4],
}

#[derive(Pod)]
#[repr(C)]
struct GameEventFieldDescriptor_t {
    name: Pointer64<ReprCString>,
    type_id: i32,
    pad_0: [u8; 4],
}

pub fn game_events<P: Process + MemoryView>(
    process: &mut P,
    sig_hits: &BTreeMap<String, umem>,
) -> Result<GameEventMap> {
    let mgr_ptr_addr = sig_hits
        .get("GameEventManager_ptr")
        .ok_or_else(|| anyhow!("GameEventManager_ptr signature not found"))?;

    let mgr_inst = process
        .read_ptr(Pointer64::<u64>::from(*mgr_ptr_addr))
        .data_part()?;
    if mgr_inst.is_null() {
        return Ok(BTreeMap::new());
    }

    let list_ptr: Pointer64<Pointer64<[Pointer64<GameEventDescriptor_t>]>> =
        Pointer64::from(mgr_inst + 0x28);
    let list_size: i32 = process.read(Address::from(mgr_inst + 0x30)).data_part()?;

    let mut results = BTreeMap::new();

    if let Ok(elements_ptr) = process.read_ptr(list_ptr).data_part() {
        if !elements_ptr.is_null() && list_size > 0 && list_size < 2048 {
            for i in 0..list_size {
                let desc_ptr_ptr: Pointer64<Pointer64<GameEventDescriptor_t>> =
                    Pointer64::from(elements_ptr.address() + (i as u64 * 8));
                if let Ok(desc_ptr) = process.read_ptr(desc_ptr_ptr).data_part() {
                    if !desc_ptr.is_null() {
                        if let Ok(desc) = process.read_ptr(desc_ptr).data_part() {
                            let name = process
                                .read_utf8_lossy(desc.name.address(), 128)
                                .data_part()?;
                            if name.is_empty() {
                                continue;
                            }

                            let mut fields = Vec::new();
                            if !desc.fields.is_null()
                                && desc.field_count > 0
                                && desc.field_count < 64
                            {
                                for j in 0..desc.field_count {
                                    let field_addr = desc.fields.address() + (j as u64 * 16);
                                    if let Ok(field_desc) = process
                                        .read::<GameEventFieldDescriptor_t>(field_addr)
                                        .data_part()
                                    {
                                        let field_name = process
                                            .read_utf8_lossy(field_desc.name.address(), 64)
                                            .data_part()?;
                                        fields.push(GameEventField {
                                            name: field_name,
                                            type_id: field_desc.type_id,
                                        });
                                    }
                                }
                            }

                            results.insert(name.clone(), GameEvent { name, fields });
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}
