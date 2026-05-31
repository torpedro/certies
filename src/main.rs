mod ca_signer;
mod cert_reader;
mod cli;
mod commands;
mod store;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use store::Store;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let root = cli.store.unwrap_or_else(Store::default_path);
    let store = Store::new(root);

    match cli.command {
        Commands::Init { name, validity_days } => {
            commands::init_ca::run(&store, name, validity_days)
        }
        Commands::New { client, device, validity_days, key_password, p12_password } => {
            commands::new::run(&store, client, device, validity_days, key_password, p12_password)
        }
        Commands::Revoke { client, device } => commands::revoke::run(&store, client, device),
        Commands::Status => commands::status::run(&store),
        Commands::RenewCrl { validity_days } => commands::renew_crl::run(&store, validity_days),
        Commands::Migrate => commands::migrate::run(&store),
        Commands::Reset => commands::reset::run(&store),
    }
}
