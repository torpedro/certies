use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rcgen::{
    CertificateParams, CertificateRevocationListParams, KeyPair, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use std::fs;
use time::Duration;

use crate::cert_reader;
use crate::store::Store;

pub fn run(store: &Store, validity_days: u32) -> Result<()> {
    run_with_extra(store, validity_days, None)
}

/// Regenerates the CRL, optionally appending a newly revoked serial.
pub fn run_with_extra(
    store: &Store,
    validity_days: u32,
    new_revocation: Option<(u64, DateTime<Utc>)>,
) -> Result<()> {
    store.require_initialized()?;

    let ca_cert_pem = store.read_ca_cert_pem()?;
    let ca_key_pem = store.read_ca_key_pem()?;
    let ca_key_pair = KeyPair::from_pem(&ca_key_pem).context("cannot load CA key")?;
    let ca_params =
        CertificateParams::from_ca_cert_pem(&ca_cert_pem).context("cannot load CA cert")?;
    let ca_cert = ca_params.self_signed(&ca_key_pair)?;

    let now = time::OffsetDateTime::now_utc();
    let next_update = now + Duration::days(validity_days as i64);

    // Start from the existing CRL's revoked entries so revocations are preserved.
    let mut revoked: Vec<RevokedCertParams> = cert_reader::read_crl_info(store)?
        .map(|crl| {
            crl.entries
                .into_iter()
                .map(|e| RevokedCertParams {
                    serial_number: SerialNumber::from(e.serial),
                    revocation_time: time::OffsetDateTime::from_unix_timestamp(
                        e.revoked_at.timestamp(),
                    )
                    .unwrap(),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect()
        })
        .unwrap_or_default();

    if let Some((serial, revoked_at)) = new_revocation {
        revoked.push(RevokedCertParams {
            serial_number: SerialNumber::from(serial),
            revocation_time: time::OffsetDateTime::from_unix_timestamp(revoked_at.timestamp())
                .unwrap(),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        });
    }

    // Derive the CRL number from the current CRL (increment by 1), or start at 1.
    let crl_number = cert_reader::read_crl_info(store)?
        .and_then(|_| {
            // We re-read because read_crl_info was consumed above — parse CRL number from file.
            parse_crl_number(store).ok()
        })
        .unwrap_or(0)
        + 1;

    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update,
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs: revoked,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = crl_params.signed_by(&ca_cert, &ca_key_pair)?;
    let crl_path = store.crl_path();
    fs::write(&crl_path, crl.pem()?)
        .with_context(|| format!("cannot write {}", crl_path.display()))?;

    let next_update_chrono =
        chrono::DateTime::from_timestamp(next_update.unix_timestamp(), 0).unwrap();

    // Count revoked entries from the freshly written CRL.
    let revoked_count = cert_reader::read_crl_info(store)?
        .map(|c| c.entries.len())
        .unwrap_or(0);

    println!("CRL #{crl_number} written to {}", crl_path.display());
    println!("  Revoked entries: {revoked_count}");
    println!("  Valid until:     {}", next_update_chrono.format("%Y-%m-%d"));

    Ok(())
}

fn parse_crl_number(store: &Store) -> Result<u64> {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::*;

    let pem_str = std::fs::read_to_string(store.crl_path())?;
    let (_, pem) = parse_x509_pem(pem_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("CRL PEM: {e:?}"))?;
    let (_, crl) = CertificateRevocationList::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("CRL DER: {e:?}"))?;

    Ok(crl
        .crl_number()
        .map(|n| {
            let digits = n.to_u64_digits();
            *digits.last().unwrap_or(&0)
        })
        .unwrap_or(0))
}
