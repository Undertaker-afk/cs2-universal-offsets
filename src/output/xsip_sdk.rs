use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;

use super::ident::slugify;
use crate::analysis::{Class, Enum, SchemaMap};
use anyhow::Result;

use crate::ui;

pub fn dump(out_dir: &Path, schemas: &SchemaMap) -> Result<()> {
    let xsip_sdk_dir = out_dir.join("SDK");
    fs::create_dir_all(&xsip_sdk_dir)?;

    write_global_types(&xsip_sdk_dir)?;

    let type_to_module = build_type_to_module_map(schemas);

    let total_modules = schemas.len();
    for (i, (module_name, (classes, enums))) in schemas.iter().enumerate() {
        ui::progress(
            i,
            total_modules,
            &format!("dumping xsip-sdk: {}", module_name),
        );
        let module_slug = slugify(&module_name.replace('.', "_"));
        let module_dir = xsip_sdk_dir.join(&module_slug);
        fs::create_dir_all(&module_dir)?;

        for class in classes {
            write_class_header(&module_dir, &module_slug, class, &type_to_module)?;
        }

        for enm in enums {
            write_enum_header(&module_dir, &module_slug, enm)?;
        }
    }

    ui::progress(total_modules, total_modules, "dumping xsip-sdk: done");
    println!();
    Ok(())
}

fn build_type_to_module_map(schemas: &SchemaMap) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (module_name, (classes, enums)) in schemas {
        let module_slug = slugify(&module_name.replace('.', "_"));
        for class in classes {
            map.insert(class.name.clone(), module_slug.clone());
        }
        for enm in enums {
            map.insert(enm.name.clone(), module_slug.clone());
        }
    }
    map
}

fn write_global_types(dir: &Path) -> Result<()> {
    let content = r#"#pragma once

#include <cstdint>
#include <cstddef>

namespace GlobalTypes {
    using uint8 = uint8_t;
    using uint16 = uint16_t;
    using uint32 = uint32_t;
    using uint64 = uint64_t;
    using int8 = int8_t;
    using int16 = int16_t;
    using int32 = int32_t;
    using int64 = int64_t;

    template <typename T>
    struct CHandle {
        uint32 m_Index;
    };

    template <typename T>
    struct CStrongHandle {
        uint64 m_Value;
    };

    template <typename T>
    struct CUtlVector {
        T* m_pElements;
        int32 m_Size;
        int32 m_Capacity;
    };

    struct CUtlString {
        char* m_pString;
    };

    struct CUtlSymbolLarge {
        const char* m_pString;
    };

    struct CUtlStringToken {
        uint32 m_nHashCode;
    };

    struct CSplitScreenSlot {
        int32 m_nSlot;
    };

    struct Vector { float x, y, z; };
    struct Vector2D { float x, y; };
    struct Vector4D { float x, y, z, w; };
    struct QAngle { float x, y, z; };
    struct Quaternion { float x, y, z, w; };
    struct Color { uint8 r, g, b, a; };

    using CEntityIndex = uint32;
}

#define S2_PAD(size) char pad_##__LINE__[size]
"#;
    fs::write(dir.join("GlobalTypes.hpp"), content)?;
    Ok(())
}

fn write_class_header(
    module_dir: &Path,
    module_slug: &str,
    class: &Class,
    type_to_module: &BTreeMap<String, String>,
) -> Result<()> {
    let mut s = String::new();
    writeln!(s, "#pragma once")?;
    writeln!(s)?;
    writeln!(s, "#include <cstdint>")?;
    writeln!(s)?;
    writeln!(s, "// /////////////////////////////////////////////////////////////")?;
    writeln!(s, "// Module: {}", module_slug)?;
    writeln!(s, "// Created using cs2-universal-dumper")?;
    writeln!(s, "// /////////////////////////////////////////////////////////////")?;
    writeln!(s)?;
    writeln!(s, "#ifndef CUSTOM_GLOBAL_TYPES")?;
    writeln!(s, "    #include \"../GlobalTypes.hpp\"")?;
    writeln!(s, "#else")?;
    writeln!(s, "    #include <Custom/GlobalTypes.hpp>")?;
    writeln!(s, "#endif")?;
    writeln!(s)?;

    let mut includes = BTreeSet::new();
    if let Some(parent) = &class.parent_name {
        if let Some(module) = type_to_module.get(parent) {
            if module == module_slug {
                includes.insert(format!("{}.hpp", parent));
            } else {
                writeln!(s, "#include \"../../{}/{}.hpp\"", module, parent)?;
            }
        }
    }

    for inc in includes {
        writeln!(s, "#include \"{}\"", inc)?;
    }

    writeln!(s)?;
    // Forward declarations
    let mut forward_decls = BTreeMap::new();
    for field in &class.fields {
        let clean_type = field
            .type_name
            .split('<')
            .next()
            .unwrap()
            .split('[')
            .next()
            .unwrap();
        if let Some(module) = type_to_module.get(clean_type) {
            forward_decls
                .entry(module.clone())
                .or_insert_with(BTreeSet::new)
                .insert(clean_type.to_string());
        }
    }

    for (module, types) in forward_decls {
        writeln!(s, "namespace CS2 {{")?;
        writeln!(s, "    namespace {} {{", module)?;
        for ty in types {
            if ty != class.name {
                writeln!(s, "        class {};", ty)?;
            }
        }
        writeln!(s, "    }}")?;
        writeln!(s, "}}")?;
    }

    writeln!(s)?;
    writeln!(s, "using namespace GlobalTypes;")?;
    writeln!(s, "namespace CS2 {{")?;
    writeln!(s, "    namespace {} {{", module_slug)?;

    let parent_str = if let Some(parent) = &class.parent_name {
        let parent_module = type_to_module
            .get(parent)
            .map(|s| s.as_str())
            .unwrap_or(module_slug);
        format!(" : public CS2::{}::{}", parent_module, parent)
    } else {
        "".to_string()
    };

    writeln!(s, "        class {}{} {{", class.name, parent_str)?;
    writeln!(s, "        public:")?;

    let mut current_offset = 0;
    let mut sorted_fields = class.fields.clone();
    sorted_fields.sort_by_key(|f| f.offset);

    for field in sorted_fields {
        if field.offset > current_offset {
            writeln!(
                s,
                "            S2_PAD({:#X});",
                field.offset - current_offset
            )?;
        }

        writeln!(s, "            // {} : {}", field.name, field.type_name)?;
        writeln!(s, "            // Offset: {:#X}", field.offset)?;
        writeln!(s, "            // Size: {:#X}", field.size)?;
        writeln!(s, "            // Category: {}", field.category)?;
        writeln!(s, "            // Type: {}", field.type_name)?;
        let cpp_type = map_type(
            &field.type_name,
            &field.category,
            module_slug,
            type_to_module,
        );
        writeln!(
            s,
            "            {} {}; // {:#X}",
            cpp_type, field.name, field.offset
        )?;
        writeln!(s)?;

        current_offset = field.offset + field.size;
    }

    if (class.size as i32) > current_offset {
        writeln!(s, "            // End padding")?;
        writeln!(
            s,
            "            S2_PAD({:#X});",
            class.size - current_offset
        )?;
    }

    writeln!(s, "        }};")?;

    writeln!(s, "#ifdef USE_STATIC_ASSERTS")?;
    for field in &class.fields {
        writeln!(
            s,
            "        static_assert(offsetof(CS2::{}::{}, {}) == {:#X}, \"{} in {} should be at offset {:#X}\");",
            module_slug, class.name, field.name, field.offset, field.name, class.name, field.offset
        )?;
    }
    writeln!(
        s,
        "        static_assert(sizeof(CS2::{}::{}) == {:#X}, \"{} size should be {:#X}\");",
        module_slug, class.name, class.size, class.name, class.size
    )?;
    writeln!(s, "#endif")?;

    writeln!(s, "    }}")?;
    writeln!(s, "}}")?;

    fs::write(module_dir.join(format!("{}.hpp", class.name)), s)?;
    Ok(())
}

fn write_enum_header(module_dir: &Path, module_slug: &str, enm: &Enum) -> Result<()> {
    let mut s = String::new();
    writeln!(s, "// generated - do not edit!")?;
    writeln!(s, "#pragma once")?;
    writeln!(s)?;
    writeln!(s, "#include <cstdint>")?;
    writeln!(s)?;
    writeln!(s, "namespace CS2 {{")?;
    writeln!(s, "    namespace {} {{", module_slug)?;

    let underlying = match enm.alignment {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "uint32_t",
    };

    writeln!(s, "        enum class {} : {} {{", enm.name, underlying)?;
    for member in &enm.members {
        writeln!(s, "            {} = {:#X},", member.name, member.value)?;
    }
    writeln!(s, "        }};")?;
    writeln!(s, "    }}")?;
    writeln!(s, "}}")?;

    fs::write(module_dir.join(format!("{}.hpp", enm.name)), s)?;
    Ok(())
}

fn map_type(
    raw: &str,
    category: &str,
    current_module: &str,
    type_to_module: &BTreeMap<String, String>,
) -> String {
    if raw.starts_with("CHandle<") {
        let inner = raw[8..raw.len() - 1].trim();
        let mapped_inner = map_type(inner, "Schema_Builtin", current_module, type_to_module);
        return format!("GlobalTypes::CHandle<{}>", mapped_inner);
    }
    if raw.starts_with("CStrongHandle<") {
        let inner = raw[14..raw.len() - 1].trim();
        let mapped_inner = map_type(inner, "Schema_Builtin", current_module, type_to_module);
        return format!("GlobalTypes::CStrongHandle<{}>", mapped_inner);
    }
    if raw.starts_with("CUtlVector<") {
        let inner = raw[11..raw.len() - 1].trim();
        let mapped_inner = map_type(inner, "Schema_Builtin", current_module, type_to_module);
        return format!("GlobalTypes::CUtlVector<{}>", mapped_inner);
    }

    let mut result = match raw {
        "int32" => "int32".into(),
        "uint32" => "uint32".into(),
        "int16" => "int16".into(),
        "uint16" => "uint16".into(),
        "int8" => "int8".into(),
        "uint8" => "uint8".into(),
        "int64" => "int64".into(),
        "uint64" => "uint64".into(),
        "float32" => "float".into(),
        "float64" => "double".into(),
        "bool" => "bool".into(),
        "char" => "char".into(),
        "Vector" | "Vector2D" | "Vector4D" | "QAngle" | "Quaternion" | "Color"
        | "CUtlString" | "CUtlSymbolLarge" | "CUtlStringToken" | "CSplitScreenSlot" => {
            format!("GlobalTypes::{}", raw)
        }
        _ => {
            if let Some(module) = type_to_module.get(raw) {
                format!("CS2::{}::{}", module, raw)
            } else {
                raw.to_string()
            }
        }
    };

    if category == "Schema_Ptr" && !result.ends_with('*') {
        result.push('*');
    }

    result
}
