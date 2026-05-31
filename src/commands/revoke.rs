use anyhow::{bail, Context, Result};

use crate::cert_reader;
use crate::commands::renew_crl;
use crate::store::Store;

pub fn run(store: &Store, client: String, device: String) -> Result<()> {
    store.require_initialized()?;

    let cert_path = store.client_dir(&client, &device).join(format!("{device}.crt"));
    if !cert_path.exists() {
        bail!("No certificate found for {client}/{device}.");
    }

    let serial = cert_reader::read_client_serial(&cert_path)
        .with_context(|| format!("cannot read serial from {}", cert_path.display()))?;

    if store
        .revoked_entries()?
        .iter()
        .any(|entry| entry.serial == serial)
    {
        bail!("Certificate #{serial} for {client}/{device} is already revoked.");
    }

    println!("Revoked certificate #{serial} for {client}/{device}.");
    println!("Regenerating CRL...");

    store.mark_revoked(serial, chrono::Utc::now())?;
    renew_crl::run_with_extra(store, 30)?;

    Ok(())
}
