use std::path::PathBuf;

use cbody_common::Config;

pub fn config_path() -> &'static str {
    if cfg!(debug_assertions) {
        "."
    } else {
        "/etc/cbody"
    }
}

pub fn load_config() -> anyhow::Result<Config> {
    let config_file_path = PathBuf::from(config_path()).join("config.toml");
    let contents = std::fs::read_to_string(&config_file_path)?;
    let config: Config = toml::from_str(&contents)?;

    Ok(config)
}
