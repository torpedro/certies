use anyhow::{Context, Result};
use std::io::{self, Write};

use crate::store::Store;

pub fn run(store: &Store) -> Result<()> {
    store.require_initialized()?;

    println!("This will permanently delete the store at:");
    println!("  {}", store.root.display());
    println!();
    println!("  ca/       — CA key and certificate");
    println!("  crl/      — Certificate Revocation List");
    println!("  clients/  — all client keys and certificates");
    println!("  serial");
    println!("  crlnumber");
    println!("  index.txt");
    println!("  store.json.legacy");
    println!();
    print!("Type \"yes\" to confirm: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim() != "yes" {
        println!("Aborted.");
        return Ok(());
    }

    for entry in [
        "ca",
        "crl",
        "clients",
        "serial",
        "crlnumber",
        "index.txt",
        "store.json.legacy",
    ] {
        let path = store.root.join(entry);
        if path.is_dir() {
            std::fs::remove_dir_all(&path)
                .with_context(|| format!("cannot remove {}", path.display()))?;
        } else if path.is_file() {
            std::fs::remove_file(&path)
                .with_context(|| format!("cannot remove {}", path.display()))?;
        }
    }

    println!("Store reset. Run `certies init-ca` to start fresh.");
    Ok(())
}
