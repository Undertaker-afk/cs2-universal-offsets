use crate::analysis::ConVarMap;
use std::fmt::Write;

pub fn render_hpp(convars: &ConVarMap, show_values: bool) -> String {
    let mut s = String::new();
    writeln!(s, "// generated - do not edit!").ok();
    writeln!(s, "#pragma once").ok();
    writeln!(s, "#include <cstdint>").ok();
    writeln!(s).ok();
    writeln!(s, "namespace CS2 {{").ok();
    writeln!(s, "    namespace ConVars {{").ok();

    for (name, cv) in convars {
        let comment = if show_values {
            format!(" // Value: {}", cv.current_value.as_deref().unwrap_or("?"))
        } else {
            "".to_string()
        };
        writeln!(s, "        // {}", cv.description.replace("\n", " ")).ok();
        writeln!(
            s,
            "        constexpr int32_t {}_flags = {:#X};{}",
            name, cv.flags, comment
        )
        .ok();
    }

    writeln!(s, "    }}").ok();
    writeln!(s, "}}").ok();
    s
}
