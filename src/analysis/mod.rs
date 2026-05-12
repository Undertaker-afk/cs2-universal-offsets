//! Offset / interface / schema / button extraction pipeline.
//!
//! Ports the pelite-based scanners from [a2x's `cs2-dumper`] and exposes a
//! single [`analyze_all`] entry point that the binary's main loop calls.
//! Errors in any individual scanner are downgraded to a warning so a
//! partial run still produces a useful set of files.
//!
//! [a2x's `cs2-dumper`]: https://github.com/a2x/cs2-dumper

use std::any::type_name;

use anyhow::Result;
use log::{error, info};
use memflow::prelude::v1::*;

mod buttons;
mod interfaces;
mod offsets;
mod rtti;
mod schemas;
mod convars;
mod game_events;
mod resources;
mod skinchanger;
mod vtables;

pub use buttons::*;
pub use convars::*;
pub use game_events::*;
pub use interfaces::*;
pub use offsets::*;
pub use resources::*;
pub use schemas::*;
pub use skinchanger::*;
pub use vtables::*;

/// Aggregated output of every analysis stage.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AnalysisResult {
    pub buttons: ButtonMap,
    pub interfaces: InterfaceMap,
    pub offsets: OffsetMap,
    pub schemas: SchemaMap,
    #[serde(skip)]
    pub skinchanger: SkinchangerMap,
    pub vtables: VTableMap,
    pub convars: ConVarMap,
    pub game_events: GameEventMap,
    pub resources: ResourceTree,
}

/// Run every static analyser against the live process.
///
/// Each stage is independent — a failure in one (e.g. a missing module) is
/// logged and replaced with that stage's [`Default`] value so subsequent
/// stages can still complete.
use crate::ui;

pub fn analyze_all<P: Process + MemoryView>(
    process: &mut P,
    show_convar_values: bool,
) -> Result<AnalysisResult> {
    ui::progress(10, 100, "dumping buttons");
    let buttons = analyze(process, buttons);
    info!("found {} buttons", buttons.len());

    ui::progress(20, 100, "dumping convars");
    let convars = match convars(process, show_convar_values) {
        Ok(c) => {
            info!("found {} convars", c.len());
            c
        }
        Err(e) => {
            log::error!("convar walk failed: {}", e);
            Default::default()
        }
    };

    ui::progress(40, 100, "dumping game events");
    let game_events = match game_events(process) {
        Ok(ge) => {
            info!("found {} game events", ge.len());
            ge
        }
        Err(e) => {
            log::error!("game event walk failed: {}", e);
            Default::default()
        }
    };

    ui::progress(60, 100, "dumping resources");
    let resources = match resources(process) {
        Ok(r) => {
            info!("found {} resource types", r.len());
            r
        }
        Err(e) => {
            log::error!("resource walk failed: {}", e);
            Default::default()
        }
    };

    ui::progress(80, 100, "dumping interfaces");
    let interfaces = analyze(process, interfaces);
    info!(
        "found {} interfaces across {} modules",
        interfaces.iter().map(|(_, ifaces)| ifaces.len()).sum::<usize>(),
        interfaces.len(),
    );

    let offsets = analyze(process, offsets);
    info!(
        "found {} offsets across {} modules",
        offsets.iter().map(|(_, offsets)| offsets.len()).sum::<usize>(),
        offsets.len(),
    );

    ui::progress(90, 100, "dumping schemas");
    let schemas = analyze(process, schemas);
    let (class_count, enum_count) = schemas
        .values()
        .fold((0, 0), |(c, e), (cv, ev)| (c + cv.len(), e + ev.len()));
    info!(
        "found {} classes and {} enums across {} modules",
        class_count,
        enum_count,
        schemas.len(),
    );

    let skinchanger = analyze(process, skinchanger);
    info!(
        "found {} skinchanger patterns across {} modules",
        skinchanger.iter().map(|(_, p)| p.len()).sum::<usize>(),
        skinchanger.len(),
    );

    // VTable walk depends on the resolved interface table; run it
    // inline rather than through `analyze` so we can pass `&interfaces`.
    let vtables = match vtables::vtables(process, &interfaces) {
        Ok(v) => {
            let total: usize = v.values().map(|m| m.len()).sum();
            let methods: usize = v.values().flat_map(|m| m.values()).map(|i| i.methods.len()).sum();
            let rtti: usize = v
                .values()
                .flat_map(|m| m.values())
                .filter(|i| i.rtti_class.is_some())
                .count();
            info!(
                "dumped {} interface vtables ({} method slots, {} class names recovered via RTTI) across {} modules",
                total, methods, rtti, v.len()
            );
            v
        }
        Err(err) => {
            error!("vtable walk failed: {}", err);
            Default::default()
        }
    };

    Ok(AnalysisResult {
        buttons,
        interfaces,
        offsets,
        schemas,
        skinchanger,
        vtables,
        convars,
        game_events,
        resources,
    })
}

/// Run a single analyser and convert any failure into the type's default.
fn analyze<P, F, T>(process: &mut P, f: F) -> T
where
    P: Process + MemoryView,
    F: FnOnce(&mut P) -> Result<T>,
    T: Default,
{
    let name = type_name::<F>();
    match f(process) {
        Ok(v) => v,
        Err(err) => {
            error!("failed to read {name}: {err}");
            T::default()
        }
    }
}
