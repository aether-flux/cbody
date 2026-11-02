use std::{collections::HashMap, path::Path};

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub settings: Settings,
    pub exemptions: Exemptions,
    pub default: Ruleset,
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

#[derive(Deserialize, Debug)]
pub struct Settings {
    pub default_action: String,
    pub enable_ring_buffer_telemetry: bool,
}

#[derive(Deserialize, Debug)]
pub struct Exemptions {
    pub uids: Vec<u32>,
}

#[derive(Deserialize, Debug)]
pub struct Ruleset {
    #[serde(default)]
    pub allow_exec: Vec<String>,
    #[serde(default)]
    pub block_outbound_ports: Vec<u16>,
}

#[derive(Deserialize, Debug)]
pub struct Profile {
    pub uids: Vec<u32>,
    #[serde(default)]
    pub allow_exec: Vec<String>,
    #[serde(default)]
    pub block_outbound_ports: Vec<u16>,
}

pub fn load_config<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
