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

    Get { property: String },

    Set { property: String, value: String },

    Add { property: String, value: String },

    Remove { property: String, value: String },

    Check,

    Enable_Service,
}
