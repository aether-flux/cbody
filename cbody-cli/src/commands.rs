use std::{io::Write, path::PathBuf};

use crate::{
    cli::{Args, Commands},
    config::{config_path, load_config},
};

const DEFAULT_CONFIG: &str = r#"
[settings]
action = "deny_and_log" # Options: deny, log, deny_and_log

[exemptions]
uids = [0] # Root is exempt by default

[default]
deny_exec = [
    "/usr/bin/nc",
    "/usr/bin/ncat"
]
block_outbound_ports = [4444, 1337]
readonly = []
noaccess = [
    "/etc/shadow",
    "/etc/gshadow"
]

[profiles.restricted]
uids = [1001]
deny_exec = ["/usr/bin/curl"]
block_outbound_ports = [80, 443]
readonly = []
noaccess = []
"#;

pub fn handle_commands(args: &Args) -> anyhow::Result<()> {
    match &args.command {
        Commands::Init => {
            let config_file = PathBuf::from(config_path()).join("config.toml");

            if config_file.exists() {
                let mut stdin = std::io::stdin();
                let mut choice = String::new();

                print!(
                    "Config file already exists at {}. Do you want to overwrite existing config? (y/N)",
                    config_file.display()
                );
                std::io::stdout().flush()?;
                stdin.read_line(&mut choice)?;

                let choice = choice.trim().to_lowercase();
                if choice.is_empty() || choice == "n" || choice == "no" {
                    println!("Config file was not overwritten.");
                    return Ok(());
                }
            }

            println!("Creating sample config file...");

            std::fs::write(&config_file, DEFAULT_CONFIG)?;

            println!("Config file created!");
            println!(
                "Read the full guide about the config at https://github.com/aether-flux/cbody/blob/main/CONFIG.md"
            );
        }
        Commands::Set { property, value } => {
            println!("cbody set {} {}", property, value);
        }
        Commands::Add { property, value } => {
            println!("cbody add {} {}", property, value);
        }
        Commands::Get { property } => {
            let config = load_config()?;

            match property.as_str() {
                "settings.action" => println!("{}", config.settings.action),

                "exemptions.uids" => {
                    if let Some(exemptions) = config.exemptions {
                        exemptions.uids.iter().for_each(|u| println!("{}", u));
                    } else {
                        println!("No exemptions section present in config.");
                    }
                }

                // Default
                // d if d.starts_with("default.")

                // Profiles
                // p if p.starts_with("profiles.")
                _ => eprintln!("Unknown config property: {}", property),
            }
        }
        Commands::Check => {
            let path = PathBuf::from(config_path()).canonicalize()?;
            match load_config() {
                Ok(_) => println!("Valid config file at {}/", path.display()),
                Err(_) => println!(
                    "Invalid config file at {}/\nGenerate a sample using 'cbody init'",
                    path.display()
                ),
            }
        }
        Commands::Install => {
            println!("cbody install");
        }
    }

    Ok(())
}
