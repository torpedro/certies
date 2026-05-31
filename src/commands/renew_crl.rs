use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Write};

use crate::ca_signer::{CaSigner, CrlEntry};
use crate::store::Store;

const DEFAULT_VALIDITY_DAYS: u32 = 30;

pub fn run(store: &Store, validity_days: Option<u32>) -> Result<()> {
    let validity_days = match validity_days {
        Some(d) => d,
        None => {
            print!("Validity in days [{}]: ", DEFAULT_VALIDITY_DAYS);
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            if input.is_empty() {
                DEFAULT_VALIDITY_DAYS
            } else {
                input.parse::<u32>().context("invalid number of days")?
            }
        }
    };
    run_with_extra(store, validity_days)
}

/// Regenerates the CRL from index.txt.
pub fn run_with_extra(store: &Store, validity_days: u32) -> Result<()> {
    store.require_initialized()?;

    let signer = CaSigner::load(store)?;

    let entries: Vec<CrlEntry> = store
        .revoked_entries()?
        .into_iter()
        .filter_map(|entry| {
            entry.revoked_at.map(|revoked_at| CrlEntry { serial: entry.serial, revoked_at })
        })
        .collect();

    let crl_number = store.take_next_crl_number()?;

    let crl_pem = signer
        .sign_crl(&entries, validity_days, crl_number)
        .context("failed to sign CRL")?;

    let crl_path = store.crl_path();
    fs::write(&crl_path, &crl_pem)
        .with_context(|| format!("cannot write {}", crl_path.display()))?;

    let next_update_chrono = chrono::DateTime::from_timestamp(
        (time::OffsetDateTime::now_utc()
            + time::Duration::days(validity_days as i64))
        .unix_timestamp(),
        0,
    )
    .unwrap();

    println!("CRL #{crl_number} written to {}", crl_path.display());
    println!("  Revoked entries: {}", entries.len());
    println!("  Valid until:     {}", next_update_chrono.format("%Y-%m-%d"));

    Ok(())
}
