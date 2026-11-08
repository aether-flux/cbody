use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::Context;
use cbody_common::Config;
use serde::Deserialize;

pub fn get_config_path() -> &'static str {
    if cfg!(debug_assertions) {
        "."
    } else {
        "/etc/cbody"
    }
}

pub fn load_config() -> anyhow::Result<Config> {
    // let base = PathBuf::from(".");
    // let base = PathBuf::from("/etc/cbody");

    let base = PathBuf::from(get_config_path());
    let path = base.join("config.toml");

    let contents = std::fs::read_to_string(path)
        .context("Config file does not exist at /etc/cbody/config.toml")?;
    let config: Config = toml::from_str(&contents)?;

    Ok(config)
}
