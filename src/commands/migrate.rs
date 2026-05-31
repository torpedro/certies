use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use crate::cert_reader;
use crate::store::{IndexEntry, Store};

#[derive(Deserialize)]
struct LegacyMeta {
    next_serial: u64,
}

pub fn run(store: &Store) -> Result<()> {
    let legacy_meta_path = store.legacy_meta_path();
    if store.is_initialized() {
        bail!("Store at {} already uses the OpenSSL-style database.", store.root.display());
    }
    if !legacy_meta_path.exists() {
        bail!(
            "No legacy store.json found at {}.",
            legacy_meta_path.display()
        );
    }
    if !store.ca_cert_path().exists() || !store.ca_key_path().exists() {
        bail!("Legacy store is missing ca/ca.crt or ca/ca.key.");
    }
    let backup_path = store.root.join("store.json.legacy");
    if backup_path.exists() {
        bail!("Backup file already exists at {}.", backup_path.display());
    }

    let legacy_meta: LegacyMeta = serde_json::from_str(
        &std::fs::read_to_string(&legacy_meta_path)
            .with_context(|| format!("cannot read {}", legacy_meta_path.display()))?,
    )
    .context("cannot parse legacy store.json")?;

    let crl = cert_reader::read_crl_info(store)?;
    let revoked: HashMap<_, _> = crl
        .as_ref()
        .map(|crl| {
            crl.entries
                .iter()
                .map(|entry| (entry.serial, entry.revoked_at))
                .collect()
        })
        .unwrap_or_default();

    let mut entries = collect_client_index_entries(store, &revoked)?;
    entries.sort_by_key(|entry| entry.serial);

    let next_crl_number = crl.and_then(|crl| crl.number).unwrap_or(0) + 1;
    store.init_database(legacy_meta.next_serial, next_crl_number)?;
    store.write_index(&entries)?;

    std::fs::rename(&legacy_meta_path, &backup_path).with_context(|| {
        format!(
            "cannot rename {} to {}",
            legacy_meta_path.display(),
            backup_path.display()
        )
    })?;

    println!("Migrated store at {}", store.root.display());
    println!("  serial:    next certificate serial #{:X}", legacy_meta.next_serial);
    println!("  crlnumber: next CRL number #{:X}", next_crl_number);
    println!("  index.txt: {} certificate entries", entries.len());
    println!("  backup:    {}", backup_path.display());

    Ok(())
}

fn collect_client_index_entries(
    store: &Store,
    revoked: &HashMap<u64, chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<IndexEntry>> {
    let clients_dir = store.root.join("clients");
    if !clients_dir.exists() {
        return Ok(vec![]);
    }

    let mut result = vec![];
    let mut client_entries: Vec<_> = std::fs::read_dir(&clients_dir)?.collect::<Result<_, _>>()?;
    client_entries.sort_by_key(|entry| entry.file_name());

    for client_entry in client_entries {
        if !client_entry.file_type()?.is_dir() {
            continue;
        }
        let client = client_entry.file_name().to_string_lossy().to_string();

        let mut device_entries: Vec<_> =
            std::fs::read_dir(client_entry.path())?.collect::<Result<_, _>>()?;
        device_entries.sort_by_key(|entry| entry.file_name());

        for device_entry in device_entries {
            if !device_entry.file_type()?.is_dir() {
                continue;
            }
            let device = device_entry.file_name().to_string_lossy().to_string();
            let cert_path = device_entry.path().join(format!("{device}.crt"));
            if !cert_path.exists() {
                continue;
            }

            let cert = cert_reader::read_cert_index_info(&cert_path)?;
            let revoked_at = revoked.get(&cert.serial).copied();
            result.push(IndexEntry {
                status: if revoked_at.is_some() { 'R' } else { 'V' },
                expires_at: cert.not_after,
                revoked_at,
                serial: cert.serial,
                filename: "unknown".to_string(),
                subject: format!("/CN={client}/{device}"),
            });
        }
    }

    Ok(result)
}
