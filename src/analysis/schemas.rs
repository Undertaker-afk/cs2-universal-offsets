use std::collections::BTreeMap;
use std::ffi::CStr;

use anyhow::{Result, bail};

use log::debug;

use memflow::prelude::v1::*;

use pelite::pattern;
use pelite::pe64::{Pe, PeView};

use serde::{Deserialize, Serialize};

use crate::source2::*;

pub type SchemaMap = BTreeMap<String, (Vec<Class>, Vec<Enum>)>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ClassMetadata {
    Unknown { name: String },
    NetworkChangeCallback { name: String },
    NetworkVarNames { name: String, type_name: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Class {
    pub name: String,
    pub module_name: String,
    pub parent_name: Option<String>,
    pub metadata: Vec<ClassMetadata>,
    pub fields: Vec<ClassField>,
    pub size: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClassField {
    pub name: String,
    pub type_name: String,
    pub offset: i32,
    pub size: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Enum {
    pub name: String,
    pub alignment: u8,
    pub size: u16,
    pub members: Vec<EnumMember>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnumMember {
    pub name: String,
    pub value: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TypeScope {
    pub module_name: String,
    pub classes: Vec<Class>,
    pub enums: Vec<Enum>,
}

pub fn schemas<P: Process + MemoryView>(process: &mut P) -> Result<SchemaMap> {
    let schema_system = read_schema_system(process)?;
    let type_scopes = read_type_scopes(process, &schema_system)?;

    Ok(type_scopes
        .into_iter()
        .map(|type_scope| {
            (
                type_scope.module_name,
                (type_scope.classes, type_scope.enums),
            )
        })
        .collect())
}

fn read_class_binding(
    mem: &mut impl MemoryView,
    binding_ptr: Pointer64<SchemaClassBinding>,
) -> Result<Class> {
    let binding = mem.read_ptr(binding_ptr).data_part()?;

    let module_name = mem
        .read_utf8_lossy(binding.module_name.address(), 128)
        .data_part()
        .map(|m| format!("{}.dll", m))?;

    let name = mem
        .read_utf8_lossy(binding.name.address(), 128)
        .data_part()?;

    if name.is_empty() {
        bail!("invalid class name");
    }

    let parent_name = binding.base_classes.non_null().and_then(|ptr| {
        let base_class = mem.read_ptr(ptr).data_part().ok()?;
        let parent_class = mem.read_ptr(base_class.class).data_part().ok()?;

        let parent_name = mem
            .read_utf8_lossy(parent_class.name.address(), 128)
            .data_part()
            .ok()?;

        (!parent_name.is_empty()).then_some(parent_name)
    });

    let fields = read_class_binding_fields(mem, &binding)?;
    let metadata = read_class_binding_metadata(mem, &binding)?;

    Ok(Class {
        name,
        module_name,
        parent_name,
        metadata,
        fields,
        size: binding.size,
    })
}

fn read_class_binding_fields(
    mem: &mut impl MemoryView,
    binding: &SchemaClassBinding,
) -> Result<Vec<ClassField>> {
    if binding.fields.is_null() {
        return Ok(Vec::new());
    }

    (0..binding.field_count).try_fold(Vec::new(), |mut acc, i| {
        let field = mem.read_ptr(binding.fields.at(i as _)).data_part()?;

        if field.r#type.is_null() {
            return Ok(acc);
        }

        let name = mem.read_utf8_lossy(field.name.address(), 128).data_part()?;
        let type_ptr = field.r#type;
        let r#type = mem.read_ptr(type_ptr).data_part()?;

        let type_name = mem
            .read_utf8_lossy(r#type.name.address(), 128)
            .data_part()?
            .replace(" ", "");

        let size = get_type_size(mem, type_ptr).unwrap_or(0);

        acc.push(ClassField {
            name,
            type_name,
            offset: field.offset,
            size,
        });

        Ok(acc)
    })
}

fn get_type_size(mem: &mut impl MemoryView, type_ptr: Pointer64<SchemaType>) -> Result<i32> {
    let r#type = mem.read_ptr(type_ptr).data_part()?;
    match r#type.type_category {
        SchemaTypeCategory::BuiltIn => {
            let name = mem.read_utf8_lossy(r#type.name.address(), 128).data_part()?;
            Ok(match name.as_str() {
                "int8" | "uint8" | "bool" | "char" => 1,
                "int16" | "uint16" => 2,
                "int32" | "uint32" | "float32" => 4,
                "int64" | "uint64" | "float64" => 8,
                _ => 4,
            })
        }
        SchemaTypeCategory::Ptr => Ok(8),
        SchemaTypeCategory::Bitfield => Ok(4),
        SchemaTypeCategory::FixedArray => unsafe {
            let array = r#type.value.array;
            let element_size = get_type_size(mem, array.element)?;
            Ok(array.array_size as i32 * element_size)
        },
        SchemaTypeCategory::Atomic => match r#type.atomic_category {
            SchemaAtomicCategory::TF => unsafe { Ok(r#type.value.atomic_tf.size) },
            SchemaAtomicCategory::TTF => unsafe { Ok(r#type.value.atomic_ttf.size) },
            _ => {
                let name = mem.read_utf8_lossy(r#type.name.address(), 128).data_part()?;
                Ok(match name.split('<').next().unwrap() {
                    "CHandle" => 4,
                    "CUtlVector" | "CNetworkUtlVectorBase" | "CUtlVectorEmbeddedNetworkVar" => 24,
                    "CUtlString" => 8,
                    "CUtlSymbolLarge" => 8,
                    "CUtlLeanVector" => 16,
                    "CAnimNetVar" => unsafe { get_type_size(mem, r#type.value.atomic.element)? },
                    _ => 0,
                })
            }
        },
        SchemaTypeCategory::DeclaredClass => unsafe {
            let binding = mem.read_ptr(r#type.value.class_binding).data_part()?;
            Ok(binding.size)
        },
        SchemaTypeCategory::DeclaredEnum => unsafe {
            let binding = mem.read_ptr(r#type.value.enum_binding).data_part()?;
            Ok(match binding.alignment {
                1 => 1,
                2 => 2,
                4 => 4,
                8 => 8,
                _ => 4,
            })
        },
        _ => Ok(0),
    }
}

fn read_class_binding_metadata(
    mem: &mut impl MemoryView,
    binding: &SchemaClassBinding,
) -> Result<Vec<ClassMetadata>> {
    if binding.static_metadata.is_null() {
        return Ok(Vec::new());
    }

    (0..binding.static_metadata_count).try_fold(Vec::new(), |mut acc, i| {
        let metadata = mem
            .read_ptr(binding.static_metadata.at(i as _))
            .data_part()?;

        if metadata.network_value.is_null() {
            return Ok(acc);
        }

        let name = mem
            .read_utf8_lossy(metadata.name.address(), 128)
            .data_part()?;

        let network_value = mem.read_ptr(metadata.network_value).data_part()?;

        let metadata = match name.as_str() {
            "MNetworkChangeCallback" => unsafe {
                let name = mem
                    .read_utf8_lossy(network_value.value.name_ptr.address(), 128)
                    .data_part()?;

                ClassMetadata::NetworkChangeCallback { name }
            },
            "MNetworkVarNames" => unsafe {
                let var_value = network_value.value.var_value;

                let name = mem
                    .read_utf8_lossy(var_value.name.address(), 128)
                    .data_part()?;

                let type_name = mem
                    .read_utf8_lossy(var_value.type_name.address(), 128)
                    .data_part()?
                    .replace(" ", "");

                ClassMetadata::NetworkVarNames { name, type_name }
            },
            _ => ClassMetadata::Unknown { name },
        };

        acc.push(metadata);

        Ok(acc)
    })
}

fn read_enum_binding(
    mem: &mut impl MemoryView,
    binding_ptr: Pointer64<SchemaEnumBinding>,
) -> Result<Enum> {
    let binding = mem.read_ptr(binding_ptr).data_part()?;

    let name = mem
        .read_utf8_lossy(binding.name.address(), 128)
        .data_part()?;

    if name.is_empty() {
        bail!("invalid enum name");
    }

    let members = read_enum_binding_members(mem, &binding)?;

    Ok(Enum {
        name,
        alignment: binding.alignment,
        size: binding.enumerator_count,
        members,
    })
}

fn read_enum_binding_members(
    mem: &mut impl MemoryView,
    binding: &SchemaEnumBinding,
) -> Result<Vec<EnumMember>> {
    if binding.enumerators.is_null() {
        return Ok(Vec::new());
    }

    (0..binding.enumerator_count).try_fold(Vec::new(), |mut acc, i| {
        let r#enum = mem.read_ptr(binding.enumerators.at(i as _)).data_part()?;

        let name = mem
            .read_utf8_lossy(r#enum.name.address(), 128)
            .data_part()?;

        acc.push(EnumMember {
            name,
            value: unsafe { r#enum.value.ulong } as i64,
        });

        Ok(acc)
    })
}

fn read_schema_system<P: Process + MemoryView>(process: &mut P) -> Result<SchemaSystem> {
    let module = process.module_by_name("schemasystem.dll")?;

    let buf = process
        .read_raw(module.base, module.size as _)
        .data_part()?;

    let view = PeView::from_bytes(&buf)?;

    let mut save = [0; 2];

    if !view
        .scanner()
        .finds_code(pattern!("4c8d35${'} 0f2845"), &mut save)
    {
        bail!("outdated schema system pattern");
    }

    let schema_system: SchemaSystem = process.read(module.base + save[1]).data_part()?;

    if schema_system.registration_count == 0 {
        bail!("no schema registrations");
    }

    Ok(schema_system)
}

fn read_type_scopes(
    mem: &mut impl MemoryView,
    schema_system: &SchemaSystem,
) -> Result<Vec<TypeScope>> {
    let type_scopes = &schema_system.type_scopes;

    (0..type_scopes.count).try_fold(Vec::new(), |mut acc, i| {
        let type_scope_ptr = type_scopes.element(mem, i as _)?;
        let type_scope = mem.read_ptr(type_scope_ptr).data_part()?;

        let module_name = unsafe { CStr::from_ptr(type_scope.name.as_ptr()) }
            .to_string_lossy()
            .to_string();

        let classes: Vec<_> = type_scope
            .class_bindings
            .elements(mem)
            .iter()
            .filter_map(|ptr| read_class_binding(mem, *ptr).ok())
            .collect();

        let enums: Vec<_> = type_scope
            .enum_bindings
            .elements(mem)
            .iter()
            .filter_map(|ptr| read_enum_binding(mem, *ptr).ok())
            .collect();

        if classes.is_empty() && enums.is_empty() {
            return Ok(acc);
        }

        debug!(
            "module \"{}\" contains {} class(es) and {} enum(s)",
            module_name,
            classes.len(),
            enums.len(),
        );

        acc.push(TypeScope {
            module_name,
            classes,
            enums,
        });

        Ok(acc)
    })
}
