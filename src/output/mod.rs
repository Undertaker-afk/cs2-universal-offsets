use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write};
use std::fs;
use std::path::Path;

use anyhow::Result;

use chrono::{DateTime, Utc};

use memflow::prelude::v1::*;

use formatter::Formatter;

use crate::analysis::*;

mod buttons;
mod formatter;

// SDK-style emitters — every disk output the dumper produces is now
// expressed in typed, cheat-developer-friendly form.
pub mod amalgamation;
pub mod ident;
pub mod interfaces_sdk;
pub mod netvars;
pub mod sdk_classes;
pub mod verified;
pub mod vtables;
pub mod xsip_interfaces;
pub mod xsip_sdk;
pub mod hierarchy;
pub mod reports;

enum Item<'a> {
    Buttons(&'a ButtonMap),
}

impl<'a> Item<'a> {
    fn write(&self, fmt: &mut Formatter<'a>, file_type: &str) -> fmt::Result {
        match file_type {
            "cs" => self.write_cs(fmt),
            "hpp" => self.write_hpp(fmt),
            "json" => self.write_json(fmt),
            "rs" => self.write_rs(fmt),
            "zig" => self.write_zig(fmt),
            _ => unimplemented!(),
        }
    }
}

trait CodeWriter {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
}

impl<'a> CodeWriter for Item<'a> {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_cs(fmt),
        }
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_hpp(fmt),
        }
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_json(fmt),
        }
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_rs(fmt),
        }
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_zig(fmt),
        }
    }
}

pub struct Output<'a> {
    file_types: &'a [String],
    indent_size: usize,
    out_dir: &'a Path,
    result: &'a AnalysisResult,
    timestamp: DateTime<Utc>,
}

impl<'a> Output<'a> {
    pub fn new(
        file_types: &'a [String],
        indent_size: usize,
        out_dir: &'a Path,
        result: &'a AnalysisResult,
    ) -> Result<Self> {
        fs::create_dir_all(&out_dir)?;

        Ok(Self {
            file_types,
            indent_size,
            out_dir,
            result,
            timestamp: Utc::now(),
        })
    }

    /// Emit the cheat-developer-friendly SDK files into `self.out_dir`
    /// (which is the session's `sdk/` directory):
    ///
    /// * `cs2sdk_macros.hpp`         — SCHEMA_FIELD macros
    /// * `<module>.hpp`              — typed schema classes
    /// * `netvars.{json,hpp}`        — split networked fields
    /// * `interfaces_sdk.hpp`        — typed accessor stubs
    /// * `cs2sdk.hpp`                — single-include amalgamation
    /// * `cs2sdk.rs`                 — Rust amalgamation module
    /// * `verified_features.{json,md,hpp}` — verified-working catalogue
    ///
    /// `build_number` is pinned into every emitted file as `CS2_BUILD`
    /// so internal cheats can `static_assert` against the running game.
    pub fn dump_sdk_extras(&self, build_number: Option<u32>) -> Result<()> {
        let ts = self.timestamp.to_rfc3339();

        // 0. xsip-style expanded SDK
        xsip_sdk::dump(self.out_dir, &self.result.schemas)?;
        xsip_interfaces::dump(self.out_dir, &self.result.interfaces)?;

        // 1. shared SCHEMA_FIELD macros
        // Render module headers first so we can iterate and write them below
        let module_data = sdk_classes::render_module_headers(&self.result.schemas, &self.result.buttons, build_number, &ts);

        // Render base macros (includes a rich set of global forward-decls / minimal types)
        let macros_path = self.out_dir.join("cs2sdk_macros.hpp");
        let mut macros = sdk_classes::render_macros_header();

        // Scan all module bodies for cross-module ::sdk::NAMESPACE::Type references
        // and for enum definitions so we can emit safe forward-declarations in the
        // macros header. Forward-declarations avoid ordering problems between
        // per-module headers when included together.
        let mut namespace_blocks: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut enum_underlying: BTreeMap<(String, String), String> = BTreeMap::new();

        for (_file_name, body) in &module_data {
            // Parse the current module namespace from the header preamble
            let mut current_ns = String::new();
            if let Some(ns_pos) = body.find("namespace sdk::") {
                let ns_start = ns_pos + "namespace sdk::".len();
                let mut ns_end = ns_start;
                while ns_end < body.len() {
                    let c = body.as_bytes()[ns_end] as char;
                    if c.is_whitespace() || c == '{' { break; }
                    ns_end += 1;
                }
                current_ns = body[ns_start..ns_end].to_string();
            }

            // Collect enum definitions and their underlying types scoped to this module
            let mut scan_idx = 0usize;
            let bytes = body.as_bytes();
            while let Some(found) = body[scan_idx..].find("enum class") {
                let pos = scan_idx + found;
                let mut name_start = pos + "enum class".len();
                // skip whitespace
                while name_start < bytes.len() && (bytes[name_start] as char).is_whitespace() {
                    name_start += 1;
                }
                let mut name_end = name_start;
                while name_end < bytes.len() {
                    let c = bytes[name_end] as char;
                    if c.is_ascii_alphanumeric() || c == '_' { name_end += 1; } else { break; }
                }
                if name_end > name_start {
                    let name = body[name_start..name_end].trim().to_string();
                    // Look for ':' and '{' to extract underlying type
                    let rest = &body[name_end..];
                    if let Some(colon_rel) = rest.find(':') {
                        if let Some(brace_rel) = rest.find('{') {
                            if brace_rel > colon_rel {
                                let underlying = rest[colon_rel + 1..brace_rel].trim().to_string();
                                enum_underlying.insert((current_ns.clone(), name), underlying);
                            }
                        }
                    }
                }
                scan_idx = pos + 1;
            }

            // Collect explicit cross-module qualified uses like ::sdk::resourcesystem::Type
            let mut search_idx = 0usize;
            while let Some(found) = body[search_idx..].find("::sdk::") {
                let pos = search_idx + found + "::sdk::".len();
                if let Some(ns_end_rel) = body[pos..].find("::") {
                    let ns = &body[pos..pos + ns_end_rel];
                    let type_start = pos + ns_end_rel + 2;
                    let mut type_end = type_start;
                    while type_end < body.len() {
                        let c = body.as_bytes()[type_end] as char;
                        if c.is_ascii_alphanumeric() || c == '_' { type_end += 1; } else { break; }
                    }
                    if type_end > type_start {
                        let ty = &body[type_start..type_end];
                        namespace_blocks
                            .entry(ns.to_string())
                            .or_insert_with(BTreeSet::new)
                            .insert(ty.to_string());
                    }
                    search_idx = type_end;
                } else { break; }
            }
        }

        macros.push_str("\n// ============================================================================\n");
        macros.push_str("// Cross-module forward declarations (auto-generated)\n");
        macros.push_str("// These provide declaration-only stubs for types referenced across\n");
        macros.push_str("// different sdk::<module> namespaces so headers can be included in any\n");
        macros.push_str("// order. They are intentionally declaration-only; the real definitions\n");
        macros.push_str("// live in the per-module headers.\n\n");

        for (ns, types_set) in &namespace_blocks {
            macros.push_str(&format!("namespace sdk {{ namespace {} {{\n", ns));
            for ty in types_set {
                if let Some(under) = enum_underlying.get(&(ns.clone(), ty.clone())) {
                    macros.push_str(&format!("    enum class {} : {};\n", ty, under));
                } else {
                    macros.push_str(&format!("    class {};\n", ty));
                }
            }
            macros.push_str("} }\n\n");
        }

        fs::write(macros_path, macros)?;

        // 2. per-module SDK class headers (skip modules with 0 classes
        //    AND 0 enums to avoid emitting empty/useless headers like
        //    host_dll.hpp).
        let mut module_stems = Vec::new();
        for (file_name, body) in module_data {
            // Cheap heuristic: an "empty" module body has no `class ` or
            // `enum class ` definitions — only the namespace shell.
            // We still keep client.dll because of the buttons enum.
            let is_empty = !body.contains("class ") && !body.contains("enum class ");
            if is_empty { continue; }
            fs::write(self.out_dir.join(&file_name), body)?;
            if let Some(stem) = file_name.strip_suffix(".hpp") {
                module_stems.push(stem.to_string());
            }
        }


        // 3. netvars (split from schema). Only emit if we actually got
        //    any networked fields — the schema walker can come back
        //    empty on builds where metadata layout drifted.
        let nvs = netvars::extract(&self.result.schemas);
        if !nvs.is_empty() {
            fs::write(self.out_dir.join("netvars.json"), netvars::render_json(&nvs))?;
            fs::write(self.out_dir.join("netvars.hpp"), netvars::render_hpp(&nvs, build_number))?;
        }

        // 4. interface accessor stubs
        fs::write(
            self.out_dir.join("interfaces_sdk.hpp"),
            interfaces_sdk::render_hpp(&self.result.interfaces, build_number),
        )?;

        // 5. amalgamation (C++ only; Rust amalgamation dropped —
        //    repo is C++-only output now).
        // Try to reorder module_stems using the emitted module_order.txt
        // file in the output `sdk/` directory so the single-include
        // amalgamation includes modules in a stable dependency order.
        let mut ordered_stems = module_stems.clone();
        let order_paths = [self.out_dir.join("sdk/module_order.txt"), self.out_dir.join("module_order.txt")];
        for p in &order_paths {
            if let Ok(txt) = std::fs::read_to_string(p) {
                let mut idx_map: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
                for line in txt.lines() {
                    if let Some((idxs, name)) = line.split_once(':') {
                        if let Ok(idx) = idxs.parse::<usize>() {
                            let stem = name.trim().trim_end_matches(".dll").to_string();
                            idx_map.insert(stem, idx);
                        }
                    }
                }
                if !idx_map.is_empty() {
                    ordered_stems.sort_by_key(|m| idx_map.get(m).cloned().unwrap_or(usize::MAX));
                    break;
                }
            }
        }

        fs::write(
            self.out_dir.join("cs2sdk.hpp"),
            amalgamation::render_hpp(&ordered_stems, build_number),
        )?;

        // 6. hand-curated "verified working features" catalogue.
        // Lives next to the auto-generated outputs so cheat developers
        // can copy a single file (.md / .hpp / .json) and know which
        // offsets are confirmed working in a live internal cheat plus
        // the gotchas (skybox tint moved to +0xE8, mat_fullbright needs
        // both ConVar slots written, etc).
        fs::write(
            self.out_dir.join("verified_features.json"),
            verified::render_json(build_number),
        )?;
        fs::write(
            self.out_dir.join("verified_features.md"),
            verified::render_md(build_number),
        )?;
        fs::write(
            self.out_dir.join("verified_features.hpp"),
            verified::render_hpp(build_number),
        )?;

        Ok(())
    }

    pub fn dump_buttons(&self) -> Result<()> {
        if self.result.buttons.is_empty() {
            return Ok(());
        }
        self.dump_item("buttons", &Item::Buttons(&self.result.buttons))
    }

    pub fn dump_all<P: MemoryView + Process>(&self, _process: &mut P) -> Result<()> {
        // The legacy `a2x/cs2-dumper`-style raw flat-offset emitters
        // (`offsets.{hpp,cs,...}`, `interfaces.{hpp,cs,...}`,
        // `<schema>.{hpp,cs,...}`, the skinchanger pattern dump) have
        // been retired — every value they exposed is now reachable in a
        // typed form through the SDK headers (`sdk_classes`, netvars
        // split-out, interface accessor stubs, `cs2sdk.hpp`
        // amalgamation), and the per-file pattern dump is superseded by
        // the dedicated `signatures/` directory.
        //
        // Buttons are now emitted as an enum in client_dll.hpp.

        Ok(())
    }

    fn dump_item(&self, file_name: &str, item: &Item) -> Result<()> {
        for file_type in self.file_types {
            let mut out = String::new();
            let mut fmt = Formatter::new(&mut out, self.indent_size);

            if file_type != "json" {
                self.write_banner(&mut fmt)?;
            }

            item.write(&mut fmt, file_type)?;

            let file_path = self.out_dir.join(format!("{}.{}", file_name, file_type));

            fs::write(&file_path, out)?;
        }

        Ok(())
    }

    fn write_banner(&self, fmt: &mut Formatter<'_>) -> Result<()> {
        writeln!(fmt, "// Generated by cs2-sdk v{} — https://cs2-sdk.com", env!("CARGO_PKG_VERSION"))?;
        writeln!(fmt, "// {}\n", self.timestamp)?;

        Ok(())
    }
}

/// Free-standing emitter for the `buttons` table.
///
/// Writes `<out_dir>/buttons.hpp` and `<out_dir>/buttons.json`.
/// Repo policy is C++-only output — .rs / .zig / .cs variants are
/// no longer emitted (the buttons enum also lives inside
/// `client_dll.hpp` for the typed-SDK consumers).
pub fn write_buttons(
    out_dir: &Path,
    buttons: &ButtonMap,
    _file_types: &[String],
) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    let item = Item::Buttons(buttons);
    let timestamp = Utc::now().to_rfc3339();
    for file_type in ["hpp", "json"] {
        let mut out = String::new();
        let mut fmt = Formatter::new(&mut out, 4);
        if file_type != "json" {
            writeln!(
                fmt,
                "// Generated by cs2-sdk v{} — https://cs2-sdk.com",
                env!("CARGO_PKG_VERSION")
            )?;
            writeln!(fmt, "// {}\n", timestamp)?;
        }
        item.write(&mut fmt, file_type)?;
        fs::write(out_dir.join(format!("buttons.{}", file_type)), out)?;
    }
    Ok(())
}

#[inline]
fn slugify(input: &str) -> String {
    input.replace(|c: char| !c.is_alphanumeric(), "_")
}

#[inline]
fn zig_ident(input: &str) -> String {
    if is_zig_identifier(input) && !is_zig_keyword(input) {
        input.to_string()
    } else {
        let escaped = input.replace('\\', "\\\\").replace('"', "\\\"");

        format!("@\"{}\"", escaped)
    }
}

#[inline]
fn is_zig_identifier(input: &str) -> bool {
    let mut chars = input.chars();

    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[inline]
fn is_zig_keyword(input: &str) -> bool {
    matches!(
        input,
        "addrspace"
            | "align"
            | "allowzero"
            | "and"
            | "anyframe"
            | "anytype"
            | "asm"
            | "async"
            | "await"
            | "break"
            | "callconv"
            | "catch"
            | "comptime"
            | "const"
            | "continue"
            | "defer"
            | "else"
            | "enum"
            | "errdefer"
            | "error"
            | "export"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "inline"
            | "linksection"
            | "noalias"
            | "noinline"
            | "nosuspend"
            | "null"
            | "opaque"
            | "or"
            | "orelse"
            | "packed"
            | "pub"
            | "resume"
            | "return"
            | "struct"
            | "suspend"
            | "switch"
            | "test"
            | "threadlocal"
            | "true"
            | "try"
            | "union"
            | "unreachable"
            | "usingnamespace"
            | "var"
            | "volatile"
            | "while"
    )
}
