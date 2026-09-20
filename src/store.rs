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
                "Store at {} is not initialised. Run `certies init` first.",
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
        let data = if data.is_empty() {
            data
        } else {
            format!("{data}\n")
        };
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
    let data =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Minimal self-cleaning temp directory, so the tests need no dev-dependency.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "certies-test-{}-{}-{}",
                std::process::id(),
                tag,
                n
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    fn entry(serial: u64, revoked_at: Option<DateTime<Utc>>) -> IndexEntry {
        IndexEntry {
            status: if revoked_at.is_some() { 'R' } else { 'V' },
            expires_at: utc(2030, 6, 15, 12, 30, 45),
            revoked_at,
            serial,
            filename: "unknown".to_string(),
            subject: "/CN=alice/laptop".to_string(),
        }
    }

    fn assert_same(left: &IndexEntry, right: &IndexEntry) {
        assert_eq!(left.status, right.status, "status");
        assert_eq!(left.expires_at, right.expires_at, "expires_at");
        assert_eq!(left.revoked_at, right.revoked_at, "revoked_at");
        assert_eq!(left.serial, right.serial, "serial");
        assert_eq!(left.filename, right.filename, "filename");
        assert_eq!(left.subject, right.subject, "subject");
    }

    // ── index.txt line round-trip ─────────────────────────────────────────────

    #[test]
    fn index_line_round_trips_valid_entry() {
        let original = entry(3, None);
        let parsed = parse_index_line(&format_index_line(&original)).unwrap();
        assert_same(&original, &parsed);
    }

    #[test]
    fn index_line_round_trips_revoked_entry() {
        let original = entry(3, Some(utc(2027, 1, 2, 3, 4, 5)));
        let parsed = parse_index_line(&format_index_line(&original)).unwrap();
        assert_same(&original, &parsed);
    }

    #[test]
    fn index_line_round_trips_across_serial_widths() {
        for serial in [1u64, 15, 255, 256, 4096, u32::MAX as u64, u64::MAX] {
            let original = entry(serial, None);
            let line = format_index_line(&original);
            let parsed = parse_index_line(&line).unwrap();
            assert_eq!(parsed.serial, serial, "serial {serial} via line {line:?}");
        }
    }

    #[test]
    fn index_line_round_trips_subject_with_spaces_and_equals() {
        let mut original = entry(7, None);
        original.subject = "/CN=Ada Lovelace/O=Analytical Engine=1".to_string();
        let parsed = parse_index_line(&format_index_line(&original)).unwrap();
        assert_same(&original, &parsed);
    }

    #[test]
    fn index_line_reads_openssl_revocation_reason_suffix() {
        // `openssl ca` writes "<date>,<reason>" in the revocation column; we keep
        // the date and drop the reason.
        let line = "R\t300615123045Z\t270102030405Z,keyCompromise\t03\tunknown\t/CN=alice/laptop";
        let parsed = parse_index_line(line).unwrap();
        assert_eq!(parsed.status, 'R');
        assert_eq!(parsed.revoked_at, Some(utc(2027, 1, 2, 3, 4, 5)));
    }

    #[test]
    fn index_line_rejects_wrong_field_count() {
        assert!(parse_index_line("V\t300615123045Z\t\t03\tunknown").is_err());
        assert!(parse_index_line("V\t300615123045Z\t\t03\tunknown\t/CN=a\textra").is_err());
    }

    #[test]
    fn index_line_rejects_malformed_serial_and_timestamp() {
        assert!(parse_index_line("V\t300615123045Z\t\tZZ\tunknown\t/CN=a").is_err());
        assert!(parse_index_line("V\tnot-a-date\t\t03\tunknown\t/CN=a").is_err());
    }

    #[test]
    fn index_time_round_trips_until_2069() {
        for year in [2026, 2036, 2049, 2069] {
            let value = utc(year, 1, 2, 3, 4, 5);
            let parsed = parse_index_time(&format_index_time(value)).unwrap();
            assert_eq!(parsed, value, "year {year}");
        }
    }

    #[test]
    fn index_time_wraps_after_2069() {
        // KNOWN BUG: the index.txt timestamp uses a two-digit year (%y), which
        // chrono maps 70..=99 to 19xx. A certificate expiring in 2070 or later
        // reads back as expired in the 1970s. `openssl ca` switches to a
        // four-digit year past 2049; this test pins today's behaviour so that
        // fixing it is a deliberate, visible change.
        let value = utc(2070, 1, 2, 3, 4, 5);
        let parsed = parse_index_time(&format_index_time(value)).unwrap();
        assert_eq!(parsed, utc(1970, 1, 2, 3, 4, 5));
    }

    // ── serial formatting ─────────────────────────────────────────────────────

    #[test]
    fn serial_to_hex_pads_small_values_to_two_digits() {
        assert_eq!(serial_to_hex(0), "00");
        assert_eq!(serial_to_hex(1), "01");
        assert_eq!(serial_to_hex(255), "FF");
    }

    #[test]
    fn serial_to_hex_emits_odd_width_above_one_byte() {
        // KNOWN BUG: `{:02X}` pads only to two digits, so serials that need an
        // odd number of digits are written as-is. `openssl ca` expects an even
        // number of hex digits in serial/index.txt, so a store handed to
        // OpenSSL after serial 255 is rejected. certies parses its own output
        // back correctly (see the round-trip tests), so this only affects
        // interop; the assertion records the current shape.
        assert_eq!(serial_to_hex(256), "100");
        assert_eq!(serial_to_hex(4096), "1000");
    }

    // ── hex counters ──────────────────────────────────────────────────────────

    #[test]
    fn take_next_serial_returns_current_then_increments() {
        let dir = TempDir::new("serial");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();

        assert_eq!(store.take_next_serial().unwrap(), 1);
        assert_eq!(store.take_next_serial().unwrap(), 2);
        assert_eq!(store.take_next_serial().unwrap(), 3);
    }

    #[test]
    fn counters_are_independent_and_persist_across_store_handles() {
        let dir = TempDir::new("counters");
        Store::new(dir.0.clone()).init_database(1, 1).unwrap();

        assert_eq!(Store::new(dir.0.clone()).take_next_serial().unwrap(), 1);
        assert_eq!(Store::new(dir.0.clone()).take_next_serial().unwrap(), 2);
        // Bumping the serial must not disturb the CRL number.
        assert_eq!(Store::new(dir.0.clone()).take_next_crl_number().unwrap(), 1);
        assert_eq!(Store::new(dir.0.clone()).take_next_serial().unwrap(), 3);
    }

    #[test]
    fn counter_survives_a_round_trip_above_one_byte() {
        let dir = TempDir::new("counter-wide");
        let store = Store::new(dir.0.clone());
        store.init_database(255, 1).unwrap();

        assert_eq!(store.take_next_serial().unwrap(), 255);
        assert_eq!(store.take_next_serial().unwrap(), 256);
        assert_eq!(store.take_next_serial().unwrap(), 257);
    }

    #[test]
    fn counter_file_is_hex_with_trailing_newline() {
        let dir = TempDir::new("counter-format");
        let store = Store::new(dir.0.clone());
        store.init_database(26, 1).unwrap();
        assert_eq!(
            std::fs::read_to_string(store.serial_path()).unwrap(),
            "1A\n"
        );
    }

    #[test]
    fn malformed_counter_reports_an_error_rather_than_panicking() {
        let dir = TempDir::new("counter-bad");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();
        std::fs::write(store.serial_path(), "not-hex\n").unwrap();

        let err = store.take_next_serial().unwrap_err();
        assert!(
            err.to_string().contains("cannot parse hex counter"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_counter_reports_an_error_rather_than_panicking() {
        let dir = TempDir::new("counter-missing");
        let store = Store::new(dir.0.clone());
        let err = store.take_next_serial().unwrap_err();
        assert!(
            err.to_string().contains("cannot read"),
            "unexpected error: {err}"
        );
    }

    // ── index file read/write ─────────────────────────────────────────────────

    #[test]
    fn index_file_round_trips_through_the_store() {
        let dir = TempDir::new("index");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();

        let entries = vec![entry(1, None), entry(2, Some(utc(2027, 1, 2, 3, 4, 5)))];
        store.write_index(&entries).unwrap();
        let read_back = store.read_index().unwrap();

        assert_eq!(read_back.len(), 2);
        assert_same(&entries[0], &read_back[0]);
        assert_same(&entries[1], &read_back[1]);
    }

    #[test]
    fn empty_index_reads_as_no_entries() {
        let dir = TempDir::new("index-empty");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();

        assert!(store.read_index().unwrap().is_empty());
        store.write_index(&[]).unwrap();
        assert_eq!(std::fs::read_to_string(store.index_path()).unwrap(), "");
        assert!(store.read_index().unwrap().is_empty());
    }

    #[test]
    fn non_empty_index_ends_with_exactly_one_newline() {
        let dir = TempDir::new("index-newline");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();
        store.write_index(&[entry(1, None)]).unwrap();

        let data = std::fs::read_to_string(store.index_path()).unwrap();
        assert!(data.ends_with('\n'));
        assert!(!data.ends_with("\n\n"));
        assert_eq!(data.lines().count(), 1);
    }

    #[test]
    fn mark_revoked_flips_status_and_records_the_time() {
        let dir = TempDir::new("revoke");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();
        store
            .write_index(&[entry(1, None), entry(2, None)])
            .unwrap();

        let when = utc(2027, 1, 2, 3, 4, 5);
        store.mark_revoked(2, when).unwrap();

        let entries = store.read_index().unwrap();
        assert_eq!(entries[0].status, 'V');
        assert_eq!(entries[0].revoked_at, None);
        assert_eq!(entries[1].status, 'R');
        assert_eq!(entries[1].revoked_at, Some(when));
    }

    #[test]
    fn mark_revoked_rejects_a_second_revocation() {
        let dir = TempDir::new("revoke-twice");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();
        store.write_index(&[entry(1, None)]).unwrap();

        let when = utc(2027, 1, 2, 3, 4, 5);
        store.mark_revoked(1, when).unwrap();
        let err = store.mark_revoked(1, when).unwrap_err();
        assert!(
            err.to_string().contains("already revoked"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mark_revoked_rejects_an_unknown_serial() {
        let dir = TempDir::new("revoke-unknown");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();
        store.write_index(&[entry(1, None)]).unwrap();

        let err = store
            .mark_revoked(99, utc(2027, 1, 2, 3, 4, 5))
            .unwrap_err();
        assert!(
            err.to_string().contains("missing from index.txt"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn revoked_entries_returns_only_revoked_rows() {
        let dir = TempDir::new("revoked-list");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();
        store
            .write_index(&[
                entry(1, None),
                entry(2, Some(utc(2027, 1, 2, 3, 4, 5))),
                entry(3, None),
            ])
            .unwrap();

        let revoked = store.revoked_entries().unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].serial, 2);
    }

    #[test]
    fn record_issued_appends_without_disturbing_existing_rows() {
        let dir = TempDir::new("record");
        let store = Store::new(dir.0.clone());
        store.init_database(1, 1).unwrap();
        store.write_index(&[entry(1, None)]).unwrap();

        let expires = utc(2031, 3, 4, 5, 6, 7);
        store.record_issued("bob", "phone", 2, expires).unwrap();

        let entries = store.read_index().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].serial, 1);
        assert_eq!(entries[1].serial, 2);
        assert_eq!(entries[1].status, 'V');
        assert_eq!(entries[1].expires_at, expires);
        assert_eq!(entries[1].subject, "/CN=bob/phone");
    }
}
