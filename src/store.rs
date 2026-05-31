use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub status: char,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub serial: u64,
    pub filename: String,
    pub subject: String,
}

pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(root: PathBuf) -> Self {
        Store { root }
    }

    pub fn default_path() -> PathBuf {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".certies")
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.root.join("ca")
    }

    pub fn crl_dir(&self) -> PathBuf {
        self.root.join("crl")
    }

    pub fn client_dir(&self, client: &str, device: &str) -> PathBuf {
        self.root.join("clients").join(client).join(device)
    }

    pub fn ca_key_path(&self) -> PathBuf {
        self.ca_dir().join("ca.key")
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_dir().join("ca.crt")
    }

    pub fn crl_path(&self) -> PathBuf {
        self.crl_dir().join("crl.pem")
    }

    pub fn serial_path(&self) -> PathBuf {
        self.root.join("serial")
    }

    pub fn crl_number_path(&self) -> PathBuf {
        self.root.join("crlnumber")
    }

    pub fn index_path(&self) -> PathBuf {
        self.root.join("index.txt")
    }

    pub fn legacy_meta_path(&self) -> PathBuf {
        self.root.join("store.json")
    }

    pub fn is_initialized(&self) -> bool {
        self.ca_cert_path().exists()
            && self.ca_key_path().exists()
            && self.serial_path().exists()
            && self.crl_number_path().exists()
            && self.index_path().exists()
    }

    pub fn has_legacy_database(&self) -> bool {
        self.legacy_meta_path().exists()
            && self.ca_cert_path().exists()
            && self.ca_key_path().exists()
            && !self.is_initialized()
    }

    pub fn has_any_database(&self) -> bool {
        self.is_initialized() || self.has_legacy_database()
    }

    pub fn require_initialized(&self) -> Result<()> {
        if !self.is_initialized() {
            if self.has_legacy_database() {
                bail!(
                    "Store at {} uses the legacy store.json format. Run `certies migrate` first.",
                    self.root.display()
                );
            }
            bail!(
                "Store at {} is not initialised. Run `certies init-ca` first.",
                self.root.display()
            );
        }
        Ok(())
    }

    pub fn init_database(&self, next_serial: u64, next_crl_number: u64) -> Result<()> {
        write_hex_counter(&self.serial_path(), next_serial)?;
        write_hex_counter(&self.crl_number_path(), next_crl_number)?;
        std::fs::write(self.index_path(), "").context("cannot write index.txt")
    }

    pub fn take_next_serial(&self) -> Result<u64> {
        take_hex_counter(&self.serial_path())
    }

    pub fn take_next_crl_number(&self) -> Result<u64> {
        take_hex_counter(&self.crl_number_path())
    }

    pub fn read_index(&self) -> Result<Vec<IndexEntry>> {
        let path = self.index_path();
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;

        data.lines()
            .filter(|line| !line.trim().is_empty())
            .map(parse_index_line)
            .collect()
    }

    pub fn write_index(&self, entries: &[IndexEntry]) -> Result<()> {
        let data = entries
            .iter()
            .map(format_index_line)
            .collect::<Vec<_>>()
            .join("\n");
        let data = if data.is_empty() { data } else { format!("{data}\n") };
        std::fs::write(self.index_path(), data).context("cannot write index.txt")
    }

    pub fn record_issued(
        &self,
        client: &str,
        device: &str,
        serial: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut entries = self.read_index()?;
        entries.push(IndexEntry {
            status: 'V',
            expires_at,
            revoked_at: None,
            serial,
            filename: "unknown".to_string(),
            subject: format!("/CN={client}/{device}"),
        });
        self.write_index(&entries)
    }

    pub fn mark_revoked(&self, serial: u64, revoked_at: DateTime<Utc>) -> Result<()> {
        let mut entries = self.read_index()?;
        let entry = entries
            .iter_mut()
            .find(|entry| entry.serial == serial)
            .with_context(|| format!("serial #{} is missing from index.txt", serial))?;
        if entry.status == 'R' {
            bail!("Certificate #{serial} is already revoked.");
        }
        entry.status = 'R';
        entry.revoked_at = Some(revoked_at);
        self.write_index(&entries)
    }

    pub fn revoked_entries(&self) -> Result<Vec<IndexEntry>> {
        Ok(self
            .read_index()?
            .into_iter()
            .filter(|entry| entry.status == 'R')
            .collect())
    }

    pub fn read_ca_cert_pem(&self) -> Result<String> {
        std::fs::read_to_string(self.ca_cert_path()).context("cannot read CA certificate")
    }

    pub fn read_ca_key_pem(&self) -> Result<String> {
        std::fs::read_to_string(self.ca_key_path()).context("cannot read CA private key")
    }
}

pub fn serial_to_hex(serial: u64) -> String {
    format!("{serial:02X}")
}

fn take_hex_counter(path: &std::path::Path) -> Result<u64> {
    let current = read_hex_counter(path)?;
    write_hex_counter(path, current + 1)?;
    Ok(current)
}

fn read_hex_counter(path: &std::path::Path) -> Result<u64> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    u64::from_str_radix(data.trim(), 16)
        .with_context(|| format!("cannot parse hex counter in {}", path.display()))
}

fn write_hex_counter(path: &std::path::Path, value: u64) -> Result<()> {
    std::fs::write(path, format!("{}\n", serial_to_hex(value)))
        .with_context(|| format!("cannot write {}", path.display()))
}

fn parse_index_line(line: &str) -> Result<IndexEntry> {
    let fields: Vec<_> = line.split('\t').collect();
    if fields.len() != 6 {
        bail!("invalid index.txt line: {line}");
    }

    let status = fields[0]
        .chars()
        .next()
        .with_context(|| format!("missing status in index.txt line: {line}"))?;
    let expires_at = parse_index_time(fields[1])?;
    let revoked_at_value = fields[2].split(',').next().unwrap_or_default();
    let revoked_at = if revoked_at_value.is_empty() {
        None
    } else {
        Some(parse_index_time(revoked_at_value)?)
    };
    let serial = u64::from_str_radix(fields[3], 16)
        .with_context(|| format!("invalid serial in index.txt line: {line}"))?;

    Ok(IndexEntry {
        status,
        expires_at,
        revoked_at,
        serial,
        filename: fields[4].to_string(),
        subject: fields[5].to_string(),
    })
}

fn format_index_line(entry: &IndexEntry) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        entry.status,
        format_index_time(entry.expires_at),
        entry.revoked_at.map(format_index_time).unwrap_or_default(),
        serial_to_hex(entry.serial),
        entry.filename,
        entry.subject
    )
}

fn parse_index_time(value: &str) -> Result<DateTime<Utc>> {
    let naive = NaiveDateTime::parse_from_str(value, "%y%m%d%H%M%SZ")
        .with_context(|| format!("invalid index.txt timestamp: {value}"))?;
    Ok(DateTime::from_naive_utc_and_offset(naive, Utc))
}

fn format_index_time(value: DateTime<Utc>) -> String {
    value.format("%y%m%d%H%M%SZ").to_string()
}
