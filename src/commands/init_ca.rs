use anyhow::{bail, Context, Result};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::fs;
use std::io::{self, Write};
use time::Duration;

use crate::commands::renew_crl;
use crate::store::Store;

const DEFAULT_VALIDITY_DAYS: u32 = 3650;

pub fn run(store: &Store, name: Option<String>, validity_days: Option<u32>) -> Result<()> {
    if store.has_any_database() {
        bail!("Store at {} is already initialised.", store.root.display());
    }

    let name = match name {
        Some(n) => n,
        None => prompt("CA name: ")?,
    };

    let validity_days = match validity_days {
        Some(d) => d,
        None => {
            let input = prompt(&format!("Validity in days [{}]: ", DEFAULT_VALIDITY_DAYS))?;
            if input.is_empty() {
                DEFAULT_VALIDITY_DAYS
            } else {
                input.parse::<u32>().context("invalid number of days")?
            }
        }
    };

    fs::create_dir_all(store.ca_dir()).context("cannot create ca/ directory")?;
    fs::create_dir_all(store.crl_dir()).context("cannot create crl/ directory")?;
    fs::create_dir_all(store.root.join("clients")).context("cannot create clients/ directory")?;

    let key_pair = KeyPair::generate()?;

    let now = time::OffsetDateTime::now_utc();
    let mut params = CertificateParams::new(vec![])?;
    params.distinguished_name.push(rcgen::DnType::CommonName, &name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = now;
    params.not_after = now + Duration::days(validity_days as i64);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));

    let cert = params.self_signed(&key_pair)?;

    let key_path = store.ca_key_path();
    let cert_path = store.ca_cert_path();
    write_private(&key_path, &key_pair.serialize_pem())?;
    fs::write(&cert_path, cert.pem())
        .with_context(|| format!("cannot write {}", cert_path.display()))?;

    store.init_database(2, 1)?;

    let expires = chrono::DateTime::from_timestamp(
        (now + Duration::days(validity_days as i64)).unix_timestamp(),
        0,
    )
    .unwrap();

    println!("CA '{}' initialised at {}", name, store.root.display());
    println!("  Certificate: {}", cert_path.display());
    println!("  Private key: {}", key_path.display());
    println!("  Valid until: {}", expires.format("%Y-%m-%d"));
    println!();
    renew_crl::run(store, Some(30))?;

    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn write_private(path: &std::path::Path, pem: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(pem.as_bytes())
            })
            .with_context(|| format!("cannot write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, pem).with_context(|| format!("cannot write {}", path.display()))?;
    }
    Ok(())
}
