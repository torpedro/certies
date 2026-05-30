use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::path::Path;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

use crate::store::Store;

pub struct CaInfo {
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

pub struct CrlEntry {
    pub serial: u64,
    pub revoked_at: DateTime<Utc>,
}

pub struct CrlInfo {
    pub last_update: DateTime<Utc>,
    pub next_update: Option<DateTime<Utc>>,
    pub entries: Vec<CrlEntry>,
}

pub struct ClientInfo {
    pub client: String,
    pub device: String,
    pub serial: u64,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub fn read_ca_info(store: &Store) -> Result<CaInfo> {
    let pem_str = store.read_ca_cert_pem()?;
    let (_, pem) = parse_x509_pem(pem_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to parse CA PEM: {e:?}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("failed to parse CA cert DER: {e:?}"))?;

    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("(unknown)")
        .to_string();

    Ok(CaInfo {
        subject,
        not_before: ts(cert.validity().not_before.timestamp()),
        not_after: ts(cert.validity().not_after.timestamp()),
    })
}

pub fn read_crl_info(store: &Store) -> Result<Option<CrlInfo>> {
    let path = store.crl_path();
    if !path.exists() {
        return Ok(None);
    }
    let pem_str = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let (_, pem) = parse_x509_pem(pem_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to parse CRL PEM: {e:?}"))?;
    let (_, crl) = CertificateRevocationList::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("failed to parse CRL DER: {e:?}"))?;

    let entries = crl
        .iter_revoked_certificates()
        .map(|r| CrlEntry {
            serial: bytes_to_serial(r.raw_serial()),
            revoked_at: ts(r.revocation_date.timestamp()),
        })
        .collect();

    Ok(Some(CrlInfo {
        last_update: ts(crl.last_update().timestamp()),
        next_update: crl.next_update().map(|t| ts(t.timestamp())),
        entries,
    }))
}

pub fn read_client_serial(cert_path: &Path) -> Result<u64> {
    let pem_str = std::fs::read_to_string(cert_path)
        .with_context(|| format!("cannot read {}", cert_path.display()))?;
    let (_, pem) = parse_x509_pem(pem_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to parse cert PEM: {e:?}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("failed to parse cert DER: {e:?}"))?;
    Ok(bytes_to_serial(cert.raw_serial()))
}

pub fn list_clients(store: &Store, crl: Option<&CrlInfo>) -> Result<Vec<ClientInfo>> {
    let clients_dir = store.root.join("clients");
    if !clients_dir.exists() {
        return Ok(vec![]);
    }

    let mut result = vec![];
    let mut client_entries: Vec<_> = std::fs::read_dir(&clients_dir)?.collect::<Result<_, _>>()?;
    client_entries.sort_by_key(|e| e.file_name());

    for client_entry in client_entries {
        if !client_entry.file_type()?.is_dir() {
            continue;
        }
        let client_name = client_entry.file_name().to_string_lossy().to_string();

        let mut device_entries: Vec<_> =
            std::fs::read_dir(client_entry.path())?.collect::<Result<_, _>>()?;
        device_entries.sort_by_key(|e| e.file_name());

        for device_entry in device_entries {
            if !device_entry.file_type()?.is_dir() {
                continue;
            }
            let device_name = device_entry.file_name().to_string_lossy().to_string();
            let cert_path = device_entry.path().join(format!("{device_name}.crt"));
            if !cert_path.exists() {
                continue;
            }

            let info = read_cert_info(&cert_path, &client_name, &device_name, crl)?;
            result.push(info);
        }
    }

    Ok(result)
}

fn read_cert_info(
    cert_path: &Path,
    client: &str,
    device: &str,
    crl: Option<&CrlInfo>,
) -> Result<ClientInfo> {
    let pem_str = std::fs::read_to_string(cert_path)
        .with_context(|| format!("cannot read {}", cert_path.display()))?;
    let (_, pem) = parse_x509_pem(pem_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to parse PEM: {e:?}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("failed to parse DER: {e:?}"))?;

    let serial = bytes_to_serial(cert.raw_serial());
    let revocation = crl.and_then(|c| c.entries.iter().find(|e| e.serial == serial));

    Ok(ClientInfo {
        client: client.to_string(),
        device: device.to_string(),
        serial,
        not_before: ts(cert.validity().not_before.timestamp()),
        not_after: ts(cert.validity().not_after.timestamp()),
        revoked: revocation.is_some(),
        revoked_at: revocation.map(|e| e.revoked_at),
    })
}

fn bytes_to_serial(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

fn ts(unix: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(unix, 0).unwrap_or_default()
}
