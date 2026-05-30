use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::io::{self, Write};

use crate::ca_signer::{CaSigner, CrlEntry};
use crate::cert_reader;
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
    run_with_extra(store, validity_days, None)
}

/// Regenerates the CRL, optionally appending a newly revoked serial.
pub fn run_with_extra(
    store: &Store,
    validity_days: u32,
    new_revocation: Option<(u64, DateTime<Utc>)>,
) -> Result<()> {
    store.require_initialized()?;

    let signer = CaSigner::load(store)?;

    // Carry forward entries from the existing CRL.
    let mut entries: Vec<CrlEntry> = cert_reader::read_crl_info(store)?
        .map(|crl| {
            crl.entries
                .into_iter()
                .map(|e| CrlEntry { serial: e.serial, revoked_at: e.revoked_at })
                .collect()
        })
        .unwrap_or_default();

    if let Some((serial, revoked_at)) = new_revocation {
        entries.push(CrlEntry { serial, revoked_at });
    }

    let crl_number = parse_crl_number(store).unwrap_or(0) + 1;

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

fn parse_crl_number(store: &Store) -> Option<u64> {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::*;

    let pem_str = std::fs::read_to_string(store.crl_path()).ok()?;
    let (_, pem) = parse_x509_pem(pem_str.as_bytes()).ok()?;
    let (_, crl) = CertificateRevocationList::from_der(&pem.contents).ok()?;
    let n = crl.crl_number()?;
    let digits = n.to_u64_digits();
    digits.last().copied()
}
