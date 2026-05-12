//! Multi-language emitters for resolved signatures.
//!
//! We already emit a hand-formatted [`signatures.json`].  This module adds
//! sibling files in the same set of languages the offset pass produces
//! (`.hpp`, `.rs`) so consumers can drop the file straight into
//! their project without writing a converter.
//!
//! Output is intentionally minimal — one constant per signature, named
//! after the signature, valued with the IDA-style byte **pattern**
//! (auto-synthesised at the resolved RVA when available, otherwise the
//! database pattern).  Consumers do their own pattern scanning at
//! runtime, which is build-portable and avoids leaking absolute
//! addresses into compiled artefacts.

use std::collections::BTreeMap;

use super::SignatureHit;

/// Group resolved signatures by module so each emitter can render them as
/// nested namespaces / modules / classes. Excludes RIPREL signatures.
fn grouped<'a>(hits: &'a [SignatureHit]) -> BTreeMap<&'a str, Vec<&'a SignatureHit>> {
    let mut out: BTreeMap<&'a str, Vec<&'a SignatureHit>> = BTreeMap::new();
    for h in hits.iter().filter(|h| h.found && h.resolve != "riprel") {
        out.entry(h.module.as_str()).or_default().push(h);
    }
    for v in out.values_mut() {
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v.dedup_by(|a, b| a.name == b.name);
    }
    out
}

fn ident(name: &str) -> String {
    let mut s = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    if s.chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        s.insert(0, '_');
    }
    s
}

fn module_ident(module: &str) -> String {
    ident(module.trim_end_matches(".dll"))
}

fn display_name(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if let Some(idx) = raw.rfind("::") {
        return raw[idx + 2..].to_string();
    }
    if raw.starts_with("m_") || raw.starts_with("dw") || raw.starts_with("g_") {
        return raw.to_string();
    }
    let parts: Vec<&str> = raw.split('_').filter(|p| !p.is_empty()).collect();
    if parts.len() > 1 {
        let head = parts[0];
        let tail = parts[parts.len() - 1];
        let bad_tail = matches!(tail, "fn" | "ptr" | "call" | "func" | "function");
        if (head.starts_with('C')
            || head.starts_with("CCS")
            || head.starts_with("CS")
            || head.starts_with("CBase")
            || head.starts_with("C_"))
            && !bad_tail
        {
            return tail.to_string();
        }
    }
    raw.to_string()
}

/// Convert a signature prototype into a C function-pointer body that is
/// guaranteed to compile in downstream consumers.
///
/// We only preserve a fully-typed signature when we explicitly know it is
/// safe.  Everything else falls back to the generic variadic form so we do
/// not leak IDA-only aliases like `_QWORD` / `_DWORD` / project-specific
/// class names into consumer builds.
fn proto_to_fnptr(sig_name: &str, _proto: &str) -> String {
    if sig_name == "CreateMove" {
        return "bool(__fastcall*)(void* pthis, int nSlot, float flInputSampleTime, bool bActive)"
            .to_string();
    }
    "void(__fastcall*)(void*, ...)".to_string()
}

/// Heuristic: is this signature's `name` actually a *type / data / vtable*
/// label rather than a function? We treat the following as types and
/// suppress the `using <name>_t = ...;` typedef for them, since a
/// function-pointer alias on a class name (`using C_BaseEntity_t =
/// void(__fastcall*)(...);`) is nonsensical and confuses consumers.
///
/// Names matched as types:
///   * starts with `C_`     (CS2 client-side classes — `C_BaseEntity`)
///   * starts with `CCS`    (CS-specific classes — `CCSPlayerPawn`)
///   * starts with `CBase`  (engine base classes)
///   * starts with `CSchemaSystem`, `CGameRules`, ...
///   * starts with `dw`     (vtable / global pointers — `dwLocalPlayer`)
///   * starts with `m_`     (member offsets exposed as sigs)
///   * starts with `I` followed by another uppercase  (interface — `IGameSystem`)
///   * ends with `_t`       (typedef-style label — `Trace_t`)
fn is_type_name(name: &str) -> bool {
    if name.starts_with("C_")
        || name.starts_with("CCS")
        || name.starts_with("CBase")
        || name.starts_with("CGame")
        || name.starts_with("CSchema")
        || name.starts_with("dw")
        || name.starts_with("m_")
    {
        return true;
    }
    if name.ends_with("_t") {
        return true;
    }
    let mut chars = name.chars();
    if let (Some(a), Some(b)) = (chars.next(), chars.next())
        && a == 'I'
        && b.is_ascii_uppercase()
    {
        return true;
    }
    false
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('\r', "")
        .replace('\n', "\\n")
        .replace('|', "\\|")
        .replace('`', "'")
}

/// Pick the pattern string we want to emit for a given hit.  We prefer
/// the auto-synthesised IDA pattern at the resolved RVA (handles
/// `StringRef` entries whose database `pattern` is text, not bytes),
/// and fall back to the database pattern when `.text` was outside the
/// scanned range (rare).
fn emit_pattern(h: &SignatureHit) -> Option<&str> {
    if let Some(p) = h.pattern_synth.as_deref() {
        return Some(p);
    }
    // Skip StringRef when no synth — its `pattern` field is the literal
    // string, not a byte pattern, so it would never scan-match.
    if h.resolve == "StringRef" {
        return None;
    }
    Some(h.pattern.as_str())
}

/// C++ header with one `inline constexpr` IDA-style pattern per
/// signature, namespaced per module.  In addition to the pattern
/// strings we emit a sibling `using <Name>_t = void(__fastcall*)(...);`
/// function-pointer typedef for every signature so consumers can write
/// `auto fn = reinterpret_cast<cs2::fn::client_dll::CreateMove_t>(scan(...));`
/// without re-typing the calling convention.  We don't know the real
/// argument list (this would require type recovery from IDA / a
/// debugger), so the typedef is intentionally generic
/// (`void __fastcall(void*, ...)`) and the consumer can
/// `reinterpret_cast` it to a more specific shape when they hook.
pub fn render_hpp(hits: &[SignatureHit]) -> String {
    let mut s = String::new();
    s.push_str("// Generated by cs2-sdk — https://cs2-sdk.com\n");
    s.push_str("// Each constant is an IDA-style byte pattern; scan it at\n");
    s.push_str("// runtime with your favourite pattern scanner. Function\n");
    s.push_str("// signatures get a sibling `sdk::sigs_fn::<module>::<Name>_t`\n");
    s.push_str("// generic __fastcall function-pointer alias; type / vtable /\n");
    s.push_str("// data signatures (names like `C_BaseEntity`, `dwLocalPlayer`,\n");
    s.push_str("// `IFoo`, `*_t`) intentionally do NOT get a fn-ptr typedef.\n");
    s.push_str("//\n");
    s.push_str("// PROTOTYPE NOTE: most function prototypes in the database are\n");
    s.push_str("// placeholders — argument types and counts have NOT been\n");
    s.push_str("// reverse-engineered. The emitted typedef is therefore the\n");
    s.push_str("// generic variadic `void(__fastcall*)(void*, ...)` shape; cast\n");
    s.push_str("// it to the real signature after you've audited the function\n");
    s.push_str("// in IDA / Ghidra.\n");
    s.push_str("#pragma once\n\n#include <string_view>\n\n");
    s.push_str("namespace sdk::sigs {\n");
    for (module, items) in grouped(hits) {
        s.push_str(&format!("    namespace {} {{\n", module_ident(&module)));
        for h in &items {
            let Some(pattern) = emit_pattern(h) else {
                continue;
            };
            s.push_str(&format!(
                "        inline constexpr std::string_view {} = \"{}\";\n",
                ident(&h.name),
                pattern,
            ));
        }
        s.push_str("    }\n");
    }
    s.push_str("}\n\n");

    // Function-pointer typedef table. Mirrors `sdk::sigs::<module>` but
    // lives under `sdk::sigs_fn::<module>` and ONLY contains entries for
    // signatures whose name looks like a function — type / data / vtable
    // sigs are skipped.
    s.push_str("namespace sdk::sigs_fn {\n");
    for (module, items) in grouped(hits) {
        s.push_str(&format!("    namespace {} {{\n", module_ident(&module)));
        for h in &items {
            if emit_pattern(h).is_none() {
                continue;
            }
            if is_type_name(&h.name) {
                continue;
            }
            // Always a placeholder fn-ptr until prototypes are audited.
            if let Some(proto) = h.prototype.as_deref().filter(|p| !p.is_empty()) {
                s.push_str(&format!(
                    "        // PROTOTYPE: {} (placeholder — verify in IDA)\n        using {}_t = {};\n",
                    proto,
                    ident(&h.name),
                    proto_to_fnptr(&h.name, proto),
                ));
            } else {
                s.push_str(&format!(
                    "        // PROTOTYPE: not yet reverse-engineered (placeholder)\n        using {}_t = void(__fastcall*)(void*, ...);\n",
                    ident(&h.name),
                ));
            }
        }
        s.push_str("    }\n");
    }
    s.push_str("}\n");
    s
}

/// Rust module per game module, with `pub const &str` patterns.
pub fn render_rs(hits: &[SignatureHit]) -> String {
    let mut s = String::new();
    s.push_str("// Generated by cs2-sdk - https://cs2-sdk.com\n");
    s.push_str("// Each constant is an IDA-style byte pattern; scan it at\n");
    s.push_str("// runtime with your favourite pattern scanner.\n");
    s.push_str("#![allow(non_upper_case_globals, non_snake_case, dead_code)]\n\n");
    for (module, items) in grouped(hits) {
        s.push_str(&format!("pub mod {} {{\n", module_ident(module)));
        for h in items {
            let Some(pattern) = emit_pattern(h) else {
                continue;
            };
            if let Some(proto) = h.prototype.as_deref() {
                s.push_str(&format!("    /// `{}`\n", proto.replace('\n', " "),));
            }
            s.push_str(&format!(
                "    pub const {}: &str = \"{}\";\n",
                ident(&h.name),
                pattern,
            ));
        }
        s.push_str("}\n\n");
    }
    s
}

/// Compact human-readable summary used by `SIGNATURES.md`.
pub fn render_markdown(hits: &[SignatureHit]) -> String {
    let mut s = String::new();
    s.push_str("# CS2 Signatures\n\n");
    s.push_str("_This file is regenerated on every successful run of `cs2-sdk`._\n\n");
    let groups = grouped(hits);
    let total_found = hits.iter().filter(|h| h.found).count();
    let total = hits.len();
    s.push_str(&format!(
        "**{}/{} signatures resolved across {} module(s).**\n\n",
        total_found,
        total,
        groups.len(),
    ));
    for (module, items) in groups {
        s.push_str(&format!("## `{}`\n\n", module));
        s.push_str("| Name | Prototype | Resolve | VA | RVA | Pattern |\n");
        s.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for h in items {
            s.push_str(&format!(
                "| `{}` | `{}` | `{}` | `0x{:X}` | `0x{:X}` | `{}` |\n",
                markdown_cell(&h.name),
                markdown_cell(h.prototype.as_deref().unwrap_or("")),
                markdown_cell(&h.resolve),
                h.va.unwrap_or(0),
                h.rva.unwrap_or(0),
                markdown_cell(&h.pattern),
            ));
        }
        s.push('\n');
    }
    s
}
