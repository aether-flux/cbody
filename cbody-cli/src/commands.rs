use std::{
    ffi::c_int,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use cbody_common::Exemptions;

use crate::{
    cli::{Args, Commands},
    config::{config_path, load_config, save_config},
};

const DEFAULT_CONFIG: &str = r#"[settings]
action = "deny_and_log" # Options: deny, log, deny_and_log

[exemptions]
uids = [0] # Root is exempt by default

[default]
deny_exec = [
    "/usr/bin/nc",
    "/usr/bin/ncat"
]
outbound_ports = [4444, 1337]
readonly = []
noaccess = [
    "/etc/shadow",
    "/etc/gshadow"
]

[profiles.restricted]
uids = [1001]
deny_exec = ["/usr/bin/curl"]
outbound_ports = [80, 443]
readonly = []
noaccess = []
"#;

const SERVICE_FILE: &str = r#"[Unit]
Description=cbody Security Daemon
After=network.target

[Service]
type=simple
ExecStart=/usr/bin/cbodyd
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
"#;

pub fn handle_commands(args: &Args) -> anyhow::Result<()> {
    match &args.command {
        Commands::Init => {
            // Check for root
            if !is_root() {
                println!("cbody must be run as root.");
                return Ok(());
            }

            let config_dir = PathBuf::from(config_path());
            if !config_dir.exists() {
                std::fs::create_dir_all(&config_dir)?;
            }

            let config_file = config_dir.join("config.toml");

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
        Commands::Get { property } => {
            let config = load_config()?;

            match property.as_str() {
                v if v.is_empty() || v == "_" => {
                    // settings
                    println!("[settings]");
                    println!("action = {}\n", &config.settings.action);

                    // exemptions
                    if let Some(exemptions) = &config.exemptions {
                        println!("[exemptions]");
                        println!("uids = [");
                        exemptions.uids.iter().for_each(|u| println!("\t{u},"));
                        println!("]\n");
                    }

                    // default
                    println!("[default]");
                    println!("exec = [");
                    &config.default.exec.iter().for_each(|e| println!("\t{e},"));
                    println!("]");
                    println!("outbound_ports = [");
                    &config
                        .default
                        .outbound_ports
                        .iter()
                        .for_each(|p| println!("\t{p},"));
                    println!("]");
                    println!("readonly = [");
                    &config
                        .default
                        .readonly
                        .iter()
                        .for_each(|r| println!("\t{r},"));
                    println!("]");
                    println!("noaccess = [");
                    &config
                        .default
                        .noaccess
                        .iter()
                        .for_each(|n| println!("\t{n},"));
                    println!("]\n");

                    // profiles
                    for (p_name, profile) in &config.profiles {
                        println!("[profiles.{p_name}]");
                        println!("uids = [");
                        profile.uids.iter().for_each(|u| println!("\t{u},"));
                        println!("]");
                        println!("exec = [");
                        profile.exec.iter().for_each(|e| println!("\t{e},"));
                        println!("]");
                        println!("outbound_ports = [");
                        profile
                            .outbound_ports
                            .iter()
                            .for_each(|p| println!("\t{p},"));
                        println!("]");
                        println!("readonly = [");
                        profile.readonly.iter().for_each(|r| println!("\t{r},"));
                        println!("]");
                        println!("noaccess = [");
                        profile.noaccess.iter().for_each(|n| println!("\t{n},"));
                        println!("]\n");
                    }
                }

                "settings.action" => println!("{}", config.settings.action),

                "exemptions.uids" => {
                    if let Some(exemptions) = config.exemptions {
                        exemptions.uids.iter().for_each(|u| println!("{}", u));
                    } else {
                        println!("No exemptions section present in config.");
                    }
                }

                d if d.starts_with("default.") => {
                    let parts: Vec<&str> = d.split('.').collect();
                    let field = parts.get(1).context("No field name specified")?;

                    match *field {
                        "exec" => config.default.exec.iter().for_each(|e| println!("{}", e)),
                        "outbound_ports" => config
                            .default
                            .outbound_ports
                            .iter()
                            .for_each(|p| println!("{}", p)),
                        "readonly" => config
                            .default
                            .readonly
                            .iter()
                            .for_each(|r| println!("{}", r)),
                        "noaccess" => config
                            .default
                            .noaccess
                            .iter()
                            .for_each(|n| println!("{}", n)),
                        _ => eprintln!("Unknown field: {}", d),
                    }
                }

                p if p.starts_with("profiles.") => {
                    let parts: Vec<&str> = p.split('.').collect();
                    let p_name = parts.get(1).context("No profile name specified")?;
                    let field = parts.get(2).context("No field name specified")?;

                    if let Some(profile) = config.profiles.get(*p_name) {
                        match *field {
                            "uids" => profile.uids.iter().for_each(|u| println!("{}", u)),
                            "exec" => profile.exec.iter().for_each(|e| println!("{}", e)),
                            "outbound_ports" => profile
                                .outbound_ports
                                .iter()
                                .for_each(|p| println!("{}", p)),
                            "readonly" => profile.readonly.iter().for_each(|r| println!("{}", r)),
                            "noaccess" => profile.noaccess.iter().for_each(|n| println!("{}", n)),
                            _ => eprintln!("Unknown field: {}", p),
                        }
                    } else {
                        eprintln!("Unknown profile name: {}", p_name);
                    }
                }

                _ => eprintln!("Unknown config property: {}", property),
            }
        }
        Commands::Set { property, value } => {
            // Check for root
            if !is_root() {
                println!("cbody must be run as root.");
                return Ok(());
            }

            let mut config = load_config()?;

            match property.as_str() {
                "settings.action" => {
                    let value_str = value.trim().to_lowercase();
                    if value_str != "deny" && value_str != "log" && value_str != "deny_and_log" {
                        println!(
                            "WARN: Setting action to {} which is neither 'deny' nor 'log'.",
                            value_str
                        );
                        println!(
                            "This would result in the action behaving equivalent to 'deny_and_log'."
                        );
                    }
                    config.settings.action = value_str.to_string();
                }

                "exemptions.uids" => {
                    let uids: Vec<&str> = value.split(',').collect();
                    let mut exemptions = config
                        .exemptions
                        .get_or_insert(Exemptions { uids: Vec::new() });
                    exemptions.uids = Vec::new();
                    uids.iter()
                        .for_each(|u| exemptions.uids.push(u.parse().unwrap()));
                }

                d if d.starts_with("default.") => {
                    let parts: Vec<&str> = d.split('.').collect();
                    let field = parts.get(1).context("No field name specified")?;

                    let values: Vec<&str> = value.split(',').collect();

                    match *field {
                        "exec" => {
                            config.default.exec = Vec::new();
                            values
                                .iter()
                                .for_each(|&v| config.default.exec.push(v.to_string()));
                        }
                        "outbound_ports" => {
                            config.default.outbound_ports = Vec::new();
                            values.iter().for_each(|&v| {
                                config.default.outbound_ports.push(v.parse().unwrap())
                            });
                        }
                        "readonly" => {
                            config.default.readonly = Vec::new();
                            values
                                .iter()
                                .for_each(|&v| config.default.readonly.push(v.to_string()));
                        }
                        "noaccess" => {
                            config.default.noaccess = Vec::new();
                            values
                                .iter()
                                .for_each(|&v| config.default.noaccess.push(v.to_string()));
                        }
                        _ => eprintln!("Unknown field: {}", d),
                    }
                }

                p if p.starts_with("profiles.") => {
                    let parts: Vec<&str> = p.split('.').collect();
                    let p_name = parts.get(1).context("No profile name specified")?;
                    let field = parts.get(2).context("No field name specified")?;

                    let values: Vec<&str> = value.split(',').collect();

                    if let Some(profile) = config.profiles.get_mut(*p_name) {
                        match *field {
                            "uids" => {
                                profile.uids = Vec::new();
                                values
                                    .iter()
                                    .for_each(|&v| profile.uids.push(v.parse().unwrap()));
                            }
                            "exec" => {
                                profile.exec = Vec::new();
                                values
                                    .iter()
                                    .for_each(|&v| profile.exec.push(v.to_string()));
                            }
                            "outbound_ports" => {
                                profile.outbound_ports = Vec::new();
                                values
                                    .iter()
                                    .for_each(|&v| profile.outbound_ports.push(v.parse().unwrap()));
                            }
                            "readonly" => {
                                profile.readonly = Vec::new();
                                values
                                    .iter()
                                    .for_each(|&v| profile.readonly.push(v.to_string()));
                            }
                            "noaccess" => {
                                profile.noaccess = Vec::new();
                                values
                                    .iter()
                                    .for_each(|&v| profile.noaccess.push(v.to_string()));
                            }
                            _ => eprintln!("Unknown field: {}", p),
                        }
                    } else {
                        eprintln!("Unknown profile name: {}", p_name);
                    }
                }

                _ => eprintln!("Unknown config property: {}", property),
            }

            match save_config(&config) {
                Ok(_) => println!(
                    "Config updated successfully! Check out config at {}/config.toml.",
                    config_path()
                ),
                Err(e) => eprintln!("Error when updating config file: {}", e),
            }
        }
        Commands::Add { property, value } => {
            // Check for root
            if !is_root() {
                println!("cbody must be run as root.");
                return Ok(());
            }

            let mut config = load_config()?;

            match property.as_str() {
                "settings.action" => {
                    let value_str = value.trim().to_lowercase();
                    if value_str != "deny" && value_str != "log" && value_str != "deny_and_log" {
                        println!(
                            "WARN: Setting action to {} which is neither 'deny' nor 'log'.",
                            value_str
                        );
                        println!(
                            "This would result in the action behaving equivalent to 'deny_and_log'."
                        );
                    }
                    config.settings.action = value_str.to_string();
                }

                "exemptions.uids" => {
                    let uids: Vec<&str> = value.split(',').collect();
                    let mut exemptions = config
                        .exemptions
                        .get_or_insert(Exemptions { uids: Vec::new() });
                    uids.iter()
                        .for_each(|u| exemptions.uids.push(u.parse().unwrap()));
                }

                d if d.starts_with("default.") => {
                    let parts: Vec<&str> = d.split('.').collect();
                    let field = parts.get(1).context("No field name specified")?;

                    let values: Vec<&str> = value.split(',').collect();

                    match *field {
                        "exec" => values
                            .iter()
                            .for_each(|&v| config.default.exec.push(v.to_string())),
                        "outbound_ports" => values
                            .iter()
                            .for_each(|&v| config.default.outbound_ports.push(v.parse().unwrap())),
                        "readonly" => values
                            .iter()
                            .for_each(|&v| config.default.readonly.push(v.to_string())),
                        "noaccess" => values
                            .iter()
                            .for_each(|&v| config.default.noaccess.push(v.to_string())),
                        _ => eprintln!("Unknown field: {}", d),
                    }
                }

                p if p.starts_with("profiles.") => {
                    let parts: Vec<&str> = p.split('.').collect();
                    let p_name = parts.get(1).context("No profile name specified")?;
                    let field = parts.get(2).context("No field name specified")?;

                    let values: Vec<&str> = value.split(',').collect();

                    if let Some(profile) = config.profiles.get_mut(*p_name) {
                        match *field {
                            "uids" => values
                                .iter()
                                .for_each(|&v| profile.uids.push(v.parse().unwrap())),
                            "exec" => values
                                .iter()
                                .for_each(|&v| profile.exec.push(v.to_string())),
                            "outbound_ports" => values
                                .iter()
                                .for_each(|&v| profile.outbound_ports.push(v.parse().unwrap())),
                            "readonly" => values
                                .iter()
                                .for_each(|&v| profile.readonly.push(v.to_string())),
                            "noaccess" => values
                                .iter()
                                .for_each(|&v| profile.noaccess.push(v.to_string())),
                            _ => eprintln!("Unknown field: {}", p),
                        }
                    } else {
                        eprintln!("Unknown profile name: {}", p_name);
                    }
                }

                _ => eprintln!("Unknown config property: {}", property),
            }

            match save_config(&config) {
                Ok(_) => println!(
                    "Config updated successfully! Check out config at {}/config.toml.",
                    config_path()
                ),
                Err(e) => eprintln!("Error when updating config file: {}", e),
            }
        }
        Commands::Remove { property, value } => {
            // Check for root
            if !is_root() {
                println!("cbody must be run as root.");
                return Ok(());
            }

            let mut config = load_config()?;

            match property.as_str() {
                "settings.action" => {
                    println!(
                        "settings.action cannot be removed/empty. Run `sudo cbody get settings.action` to get its value or `set` to set it."
                    );
                    return Ok(());
                }

                "exemptions.uids" => {
                    let uids: Vec<&str> = value.split(',').collect();
                    let mut exemptions = config
                        .exemptions
                        .get_or_insert(Exemptions { uids: Vec::new() });
                    uids.iter().for_each(|u| {
                        let uid: u32 = u.parse().expect("Unable to parse uid");
                        for i in 0..exemptions.uids.len() {
                            if exemptions.uids.get(i).unwrap() == &uid {
                                let _ = exemptions.uids.swap_remove(i);
                                break;
                            }
                        }
                    });
                }

                d if d.starts_with("default.") => {
                    let parts: Vec<&str> = d.split('.').collect();
                    let field = parts.get(1).context("No field name specified")?;

                    let values: Vec<&str> = value.split(',').collect();

                    match *field {
                        "exec" => values.iter().for_each(|&v| {
                            for i in 0..config.default.exec.len() {
                                if config.default.exec.get(i).unwrap() == v {
                                    let _ = config.default.exec.swap_remove(i);
                                    break;
                                }
                            }
                        }),
                        "outbound_ports" => values.iter().for_each(|&v| {
                            let p: u16 = v.parse().expect("Unable to parse port number");
                            for i in 0..config.default.outbound_ports.len() {
                                if config.default.outbound_ports.get(i).unwrap() == &p {
                                    let _ = config.default.outbound_ports.swap_remove(i);
                                    break;
                                }
                            }
                        }),
                        "readonly" => values.iter().for_each(|&v| {
                            for i in 0..config.default.readonly.len() {
                                if config.default.readonly.get(i).unwrap() == v {
                                    let _ = config.default.readonly.swap_remove(i);
                                    break;
                                }
                            }
                        }),
                        "noaccess" => values.iter().for_each(|&v| {
                            for i in 0..config.default.noaccess.len() {
                                if config.default.noaccess.get(i).unwrap() == v {
                                    let _ = config.default.noaccess.swap_remove(i);
                                    break;
                                }
                            }
                        }),
                        _ => eprintln!("Unknown field: {}", d),
                    }
                }

                p if p.starts_with("profiles.") => {
                    let parts: Vec<&str> = p.split('.').collect();
                    let p_name = parts.get(1).context("No profile name specified")?;
                    let field = parts.get(2).context("No field name specified")?;

                    let values: Vec<&str> = value.split(',').collect();

                    if let Some(profile) = config.profiles.get_mut(*p_name) {
                        match *field {
                            "uids" => values.iter().for_each(|&v| {
                                let u: u32 = v.parse().expect("Unable to parse uid");
                                for i in 0..profile.uids.len() {
                                    if profile.uids.get(i).unwrap() == &u {
                                        let _ = profile.exec.swap_remove(i);
                                        break;
                                    }
                                }
                            }),
                            "exec" => values.iter().for_each(|&v| {
                                for i in 0..profile.exec.len() {
                                    if profile.exec.get(i).unwrap() == v {
                                        let _ = profile.exec.swap_remove(i);
                                        break;
                                    }
                                }
                            }),
                            "outbound_ports" => values.iter().for_each(|&v| {
                                let p: u16 = v.parse().expect("Unable to parse port number");
                                for i in 0..profile.outbound_ports.len() {
                                    if profile.outbound_ports.get(i).unwrap() == &p {
                                        let _ = profile.outbound_ports.swap_remove(i);
                                        break;
                                    }
                                }
                            }),
                            "readonly" => values.iter().for_each(|&v| {
                                for i in 0..profile.readonly.len() {
                                    if profile.readonly.get(i).unwrap() == v {
                                        let _ = profile.readonly.swap_remove(i);
                                        break;
                                    }
                                }
                            }),
                            "noaccess" => values.iter().for_each(|&v| {
                                for i in 0..profile.noaccess.len() {
                                    if profile.noaccess.get(i).unwrap() == v {
                                        let _ = profile.noaccess.swap_remove(i);
                                        break;
                                    }
                                }
                            }),
                            _ => eprintln!("Unknown field: {}", p),
                        }
                    } else {
                        eprintln!("Unknown profile name: {}", p_name);
                    }
                }

                _ => eprintln!("Unknown config property: {}", property),
            }

            match save_config(&config) {
                Ok(_) => println!(
                    "Config updated successfully! Check out config at {}/config.toml.",
                    config_path()
                ),
                Err(e) => eprintln!("Error when updating config file: {}", e),
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
        Commands::Enable_Service => {
            // Check for root
            if !is_root() {
                println!("cbody must be run as root.");
                return Ok(());
            }

            // Validate config directory path
            let config_dir = Path::new(config_path());
            if !config_dir.exists() {
                std::fs::create_dir_all(&config_dir)?;
            }

            // Validate config file path
            let config_file = config_dir.join("config.toml");
            if !config_file.exists() {
                let mut stdin = std::io::stdin();
                let mut choice = String::new();

                print!("No config file found. Generate a sample? (Y/n)");
                std::io::stdout().flush()?;
                stdin.read_line(&mut choice)?;

                let choice = choice.trim().to_lowercase();
                if choice == "n" || choice == "no" {
                    println!(
                        "Skipping creation of service. Create a config file at {} and re-run this command.",
                        config_file.display()
                    );
                    return Ok(());
                }

                std::fs::write(&config_file, &DEFAULT_CONFIG)?;
                println!("Default config generated at {}\n", config_file.display());
            }

            // Validate daemon binary
            let target_bin = Path::new("/usr/bin/cbodyd");
            if !target_bin.exists() {
                println!(
                    "Install the daemon binary first. Refer to https://github.com/aether-flux/cbody"
                );
                return Ok(());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(target_bin, std::fs::Permissions::from_mode(0755))?;
            }

            // Write service file
            let service_path = Path::new("/etc/systemd/system/cbodyd.service");
            // let service_path = Path::new("./cbodyd.service");
            std::fs::write(&service_path, SERVICE_FILE)?;
            println!("Created service file at {}\n", service_path.display());

            // Helpful logs
            println!("Run these commands to reload systemd and enable/start cbodyd:");
            println!("  sudo systemctl daemon-reload");
            println!("  sudo systemctl enable --now cbodyd\n");

            // Optionally run `sudo systemctl daemon-reload`
            let mut stdin = std::io::stdin();
            let mut choice = String::new();
            print!("Run 'sudo systemctl daemon-reload'? (Y/n)");
            std::io::stdout().flush()?;
            stdin.read_line(&mut choice)?;

            let choice = choice.trim().to_lowercase();
            if choice == "n" || choice == "no" {
                return Ok(());
            }

            let status = std::process::Command::new("systemctl")
                .arg("daemon-reload")
                .status()?;

            if status.success() {
                // Optionally run 'sudo systemctl enable --now cbodyd'
                let mut choice = String::new();
                print!("Run 'sudo systemctl enable --now cbodyd'? (Y/n)");
                std::io::stdout().flush()?;
                stdin.read_line(&mut choice)?;

                let choice = choice.trim().to_lowercase();
                if choice == "n" || choice == "no" {
                    return Ok(());
                }

                let status = std::process::Command::new("systemctl")
                    .arg("enable")
                    .arg("--now")
                    .arg("cbodyd")
                    .status()?;

                if status.success() {
                    println!("All commands run successfully!");
                    println!("cbodyd should be running now.");
                } else {
                    println!(
                        "Failed to run 'sudo systemctl enable --now cbodyd'. Please run the commands manually."
                    );
                }
            } else {
                println!(
                    "Failed to run 'sudo systemctl daemon-reload'. Please run the commands manually."
                );
            }
        }
    }

    Ok(())
}

unsafe extern "C" {
    fn geteuid() -> c_int;
}

fn is_root() -> bool {
    unsafe { geteuid() == 0 }
}
