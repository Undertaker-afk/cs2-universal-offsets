use crate::analysis::AnalysisResult;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn generate(out_dir: &Path, analysis: &AnalysisResult) -> Result<()> {
    let mut s = String::new();
    s.push_str("# LLM Instruction Set for CS2 SDK Consumption\n\n");

    s.push_str("## Core System Overview\n");
    s.push_str("You are assisting in the development of tools for Counter-Strike 2. This directory contains a complete, type-safe SDK generated from the game's schema system and memory. The SDK is organized into several distinct tiers of data.\n\n");

    s.push_str("## Data Tiers\n");
    s.push_str("1. **Precise Memory Layouts (`xsip_sdk/`)**: Use these headers when you need exact byte-alignment. They use `S2_PAD` for gaps between members. This is the source of truth for struct sizes and member offsets.\n");
    s.push_str("2. **Ergonomic Accessors (`sdk/`)**: Use headers in `sdk/` for internal cheat development. The `SCHEMA_FIELD` macros provide inline accessors that handle address calculation automatically.\n");
    s.push_str("3. **Interface Registry (`xsip_interfaces/`)**: Provides RVAs for `CreateInterface` targets. Use these to find engine singletons (e.g., `CGameEventManager`).\n");
    s.push_str("4. **Engine Signatures (`signatures/`)**: Contains IDA-style patterns for non-schema functions. Use these to find hook locations for game logic.\n\n");

    s.push_str("## How to Analyze a Request\n");
    s.push_str("- **If asked about a class**: Look for the class file in `xsip_sdk/<module>/<ClassName>.hpp`. Check inheritance and field offsets.\n");
    s.push_str("- **If asked about an offset**: Cross-reference `sdk/offsets.json` and the signature report in `report.json`.\n");
    s.push_str("- **If asked about a GameEvent**: Search the `game_events` object in `report.json` to find its field names and types.\n");
    s.push_str(
        "- **If asked about a ConVar**: Check `sdk/convars.hpp` for flags and descriptions.\n\n",
    );

    s.push_str("## Technical Constraints\n");
    s.push_str("- All pointers are **64-bit** (`uintptr_t` or `void*`).\n");
    s.push_str("- The engine is **Source 2**, which uses a heavily networked schema system.\n");
    s.push_str("- Use `static_assert` blocks found in `xsip_sdk/` to verify your assumptions about memory layout.\n\n");

    s.push_str("## Engine Stats\n");
    s.push_str(&format!(
        "- Classes: {}\n",
        analysis
            .schemas
            .values()
            .map(|(c, _)| c.len())
            .sum::<usize>()
    ));
    s.push_str(&format!("- ConVars: {}\n", analysis.convars.len()));
    s.push_str(&format!(
        "- Interfaces: {}\n",
        analysis.interfaces.values().map(|i| i.len()).sum::<usize>()
    ));

    fs::write(out_dir.join("llm.txt"), s)?;
    Ok(())
}
