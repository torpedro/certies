use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "certies", about = "SSL certificate manager for user authentication")]
pub struct Cli {
    /// Path to certificate store (default: ~/.certies)
    #[arg(short, long, global = true)]
    pub store: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialise a new Certificate Authority
    Init {
        /// Common name for the CA certificate (prompted if omitted)
        #[arg(long)]
        name: Option<String>,

        /// Validity period in days (prompted if omitted, default 3650)
        #[arg(long)]
        validity_days: Option<u32>,
    },

    /// Create a new client certificate
    New {
        /// Client (user) name
        client: String,

        /// Device name
        device: String,

        /// Validity period in days
        #[arg(long, default_value_t = 365)]
        validity_days: u32,

        /// Password to encrypt the private key (unencrypted if omitted)
        #[arg(long)]
        key_password: Option<String>,

        /// Password for the generated .p12 bundle (prompted if omitted)
        #[arg(long)]
        p12_password: Option<String>,
    },

    /// Revoke a client certificate
    Revoke {
        /// Client (user) name
        client: String,

        /// Device name
        device: String,
    },

    /// Show a summary of all certificates
    Status,

    /// Renew the Certificate Revocation List
    RenewCrl {
        /// CRL validity period in days (prompted if omitted, default 30)
        #[arg(long)]
        validity_days: Option<u32>,
    },

    /// Migrate a legacy store.json store to serial, crlnumber, and index.txt
    Migrate,

    /// Delete all certificates and reset the store
    Reset,
}
