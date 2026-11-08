use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cbody",
    author,
    version,
    about = "Manage the cbody daemon from the terminal"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init,

    Set { property: String, value: String },

    Get { property: String },

    Check,

    Install,
}
