use std::collections::BTreeMap;
use anyhow::Result;
use memflow::prelude::v1::*;

pub type GameEventMap = BTreeMap<String, GameEvent>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct GameEvent {
    pub name: String,
    pub fields: Vec<GameEventField>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GameEventField {
    pub name: String,
    pub type_id: i32,
}

pub fn game_events<P: Process + MemoryView>(process: &mut P) -> Result<GameEventMap> {
    // Similar to ConVars, needs CGameEventManager address.
    let mut results = BTreeMap::new();
    Ok(results)
}
