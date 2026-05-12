# cs2-sdk

External CS2 SDK generator. Reads a live `cs2.exe` and emits a C++ `include/`
tree containing schema headers, signatures, offsets, interfaces, vtables and
buttons.

Public mirror of the latest output: <https://cs2-sdk.com>.

## What you get

```
include/
├── manifest.json                 # build number, module fingerprints, stage status
├── sdk/
│   ├── cs2sdk.hpp                # single-include amalgamation
│   ├── cs2sdk_macros.hpp         # SCHEMA_FIELD / SCHEMA_PAD macros
│   ├── client_dll.hpp            # per-module schema classes
│   ├── server_dll.hpp
│   ├── engine2_dll.hpp
│   ├── …                         # one .hpp per non-empty schema module
│   ├── interfaces_sdk.hpp        # CreateInterface accessor stubs
│   ├── offsets.{hpp,json}        # dwXxx static globals (a2x-compatible)
│   ├── buttons.{hpp,json}        # kbutton table
│   ├── netvars.{hpp,json}        # networked field index (omitted if empty)
│   ├── vtables.{hpp,json}        # vtable layouts + RTTI names
│   └── verified_features.{hpp,json,md}
├── signatures/
│   ├── signatures.json           # canonical IDA-style patterns + RVAs
│   ├── signatures.hpp
│   └── SIGNATURES.md
└── logs/cs2-sdk.log
```

The repo is laid out so you can drop it in as a git submodule and
`#include "cs2-sdk/sdk/cs2sdk.hpp"` from your project.

## Build

```
cargo build --release
```

Requires Rust 1.83+ (uses `let … && …` chains). Windows-only by default
(uses `memflow-native`); pass `--connector` for cross-platform / DMA setups.

## Run

```
.\target\release\cs2-sdk.exe
```

Useful flags:

| flag | default | what it does |
|---|---|---|
| `-o, --output <DIR>` | `include` | output root |
| `-p, --process-name <NAME>` | `cs2.exe` | target process |
| `--skip-offsets` | off | skip the schema/offsets pass |
| `--skip-signatures` | off | skip the signatures pass |
| `--cache <FILE>` | none | warm-start from a previous `signatures.json` |
| `--no-sound` | off | silence the UI cues |
| `--show-convar-values` | off | include current values of ConVars in dump |
| `--use-mem-walk` | off | use real memory walking for advanced scanning |
| `--html-report` | off | generate an interactive HTML report of the dump |
| `-v / -vv / -vvv` | warn | terminal log verbosity (file log is always trace) |

## New Features (v1.5)

* **Expanded xsip-style SDK**: Generates a file-per-class C++ SDK in `include/xsip_sdk`.
* **Interface Dumper**: Per-module `constexpr` interface offsets in `include/xsip_interfaces`.
* **Confidence Scoring**: Each signature hit now includes a confidence score (0-100%).
* **Hierarchy Visualization**: Generates a Graphviz `hierarchy.dot` of the engine's class tree.
* **Advanced Reporting**: Comprehensive reports in JSON, Markdown, and HTML formats.
* **Skeleton Analysers**: Added groundwork for ConVar, GameEvent, and ResourceSystem dumping.

CI publishes a release binary on every `v*` tag — see the latest under
[Releases](../../releases).

## Output guarantees

* `signatures.json` schema and `sdk/*.hpp` paths are the public contract
  consumed by cs2-sdk.com — these will not break in a minor version.
* Per-module `.hpp` files with no classes or enums are skipped, so the
  tree only contains files that have actual content for the current build.
* C++ is the only output language. Older Rust / Zig / C# emitters were
  removed in 1.22 — use the `.json` files if you need to consume the
  data from another language.

## License

MIT.
