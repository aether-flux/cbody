use std::path::PathBuf;

use crate::{
    cli::{Args, Commands},
    config::{config_path, load_config},
};

pub fn handle_commands(args: &Args) -> anyhow::Result<()> {
    match &args.command {
        Commands::Init => {
            println!("cbody init");
        }
        Commands::Set { property, value } => {
            println!("cbody set {} {}", property, value);
        }
        Commands::Get { property } => {
            println!("cbody get {}", property);
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
