use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub settings: Settings,
    // pub exemptions: Exemptions,
    pub default: Ruleset,
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

#[derive(Deserialize, Debug)]
pub struct Settings {
    pub action: String,
    // pub enable_ring_buffer_telemetry: bool,
}

#[derive(Deserialize, Debug)]
pub struct Exemptions {
    pub uids: Vec<u32>,
}

#[derive(Deserialize, Debug)]
pub struct Ruleset {
    #[serde(default)]
    pub deny_exec: Vec<String>,
    #[serde(default)]
    pub block_outbound_ports: Vec<u16>,
    #[serde(default)]
    pub readonly: Vec<String>,
    #[serde(default)]
    pub noaccess: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct Profile {
    pub uids: Vec<u32>,
    #[serde(default)]
    pub deny_exec: Vec<String>,
    #[serde(default)]
    pub block_outbound_ports: Vec<u16>,
    #[serde(default)]
    pub readonly: Vec<String>,
    #[serde(default)]
    pub noaccess: Vec<String>,
}

pub fn load_config() -> anyhow::Result<Config> {
    // let base = PathBuf::from(".");
    let base = PathBuf::from("/etc/cbody");
    let path = base.join("config.toml");

    let contents = std::fs::read_to_string(path)
        .context("Config file does not exist at /etc/cbody/config.toml")?;
    let config: Config = toml::from_str(&contents)?;

    Ok(config)
}
