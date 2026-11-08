use crate::{cli::Args, commands::handle_commands};
use clap::Parser;

mod cli;
mod commands;
mod config;

fn main() -> anyhow::Result<()> {
    let args = Args::try_parse().unwrap_or_else(|e| e.exit());
    handle_commands(&args)?;

    Ok(())
}
