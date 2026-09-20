use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use openssl::base64;
use openssl::sha::sha256;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

use crate::store::Store;

struct Remote {
    host: String,
    path: String,
}

enum Target {
    Local(PathBuf),
    Remote(Remote),
}

impl Target {
    fn display(&self) -> String {
        match self {
            Target::Local(path) => path.display().to_string(),
            Target::Remote(remote) => format!("{}:{}", remote.host, remote.path),
        }
    }

    fn file_display(&self, name: &str) -> String {
        match self {
            Target::Local(path) => path.join(name).display().to_string(),
            Target::Remote(remote) => format!("{}:{}", remote.host, remote_file_path(remote, name)),
        }
    }
}

struct SyncFile {
    label: &'static str,
    store_name: &'static str,
    source: Vec<u8>,
    target: Option<Vec<u8>>,
}

pub fn run(source: Option<String>, target: String) -> Result<()> {
    let source = match source {
        Some(source) => parse_target(&source)?,
        None => Target::Local(Store::default_path()),
    };
    let target = parse_target(&target)?;

    let mut files = vec![
        SyncFile {
            label: "ca.crt",
            store_name: "ca/ca.crt",
            source: vec![],
            target: None,
        },
        SyncFile {
            label: "crl.pem",
            store_name: "crl/crl.pem",
            source: vec![],
            target: None,
        },
    ];

    load_source_files(&source, &mut files)?;

    println!("Source: {}", source.display());
    println!("Target: {}", target.display());
    println!("Comparing ca.crt and crl.pem...");
    println!();

    for file in &files {
        println!("Checking source {}", source.file_display(file.store_name));
        println!("Checking target {}", target.file_display(file.store_name));
    }
    let target_files = read_target_files(&target, &files)?;
    println!();

    let mut out_of_sync = false;
    for file in &mut files {
        file.target = target_files.get(file.store_name).cloned().unwrap_or(None);
        print_comparison(file);
        if file.target.as_ref() != Some(&file.source) {
            out_of_sync = true;
            print_diff(file);
        }
    }

    if !out_of_sync {
        println!("Target files are up to date.");
        return Ok(());
    }

    let can_download = files.iter().all(|file| file.target.is_some());

    println!("Options:");
    println!("  1. Deploy source ca.crt and crl.pem to the target path");
    if can_download {
        println!("  2. Download target ca.crt and crl.pem into the source store");
        println!("  3. Leave unchanged");
        print!("Choose [1/2/3]: ");
    } else {
        println!("  2. Leave unchanged");
        print!("Choose [1/2]: ");
    }
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if can_download {
        match input.trim() {
            "1" | "a" | "A" => deploy_source_to_target(&target, &files),
            "2" | "b" | "B" => download_target_to_source(&source, &files),
            "3" | "" => {
                println!("No changes made.");
                Ok(())
            }
            other => bail!("invalid choice: {other}"),
        }
    } else {
        match input.trim() {
            "1" | "a" | "A" => deploy_source_to_target(&target, &files),
            "2" | "" => {
                println!("No changes made.");
                Ok(())
            }
            other => bail!("invalid choice: {other}"),
        }
    }
}

fn parse_target(value: &str) -> Result<Target> {
    if value.contains(':') {
        return parse_remote(value).map(Target::Remote);
    }
    if looks_local(value) {
        return Ok(Target::Local(expand_local_path(value)));
    }
    Ok(Target::Remote(Remote {
        host: value.to_string(),
        path: "~/.certies".to_string(),
    }))
}

fn parse_remote(value: &str) -> Result<Remote> {
    let (host, path) = match value.split_once(':') {
        Some((host, path)) => (host, path),
        None => (value, "~/.certies"),
    };
    if host.is_empty() || path.is_empty() {
        bail!("remote must be in the form [user@]server[:/path]");
    }
    Ok(Remote {
        host: host.to_string(),
        path: path.to_string(),
    })
}

fn looks_local(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value == "."
        || value == ".."
        || value.starts_with("~/")
        || Path::new(value).exists()
}

fn expand_local_path(value: &str) -> PathBuf {
    if value == "~" {
        home_dir()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home_dir().join(rest)
    } else {
        PathBuf::from(value)
    }
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn backup_path(path: &Path, stamp: &str) -> PathBuf {
    path.with_extension(format!(
        "{}.bak.{}",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("pem"),
        stamp
    ))
}

fn read_target_files(
    target: &Target,
    files: &[SyncFile],
) -> Result<HashMap<String, Option<Vec<u8>>>> {
    match target {
        Target::Local(path) => read_local_files(path, files),
        Target::Remote(remote) => read_remote_files(remote, files),
    }
}

fn load_source_files(source: &Target, files: &mut [SyncFile]) -> Result<()> {
    let source_files = read_target_files(source, files)?;
    for file in files {
        file.source = source_files
            .get(file.store_name)
            .cloned()
            .flatten()
            .with_context(|| {
                format!("source {} is missing", source.file_display(file.store_name))
            })?;
    }
    Ok(())
}

fn read_local_files(root: &Path, files: &[SyncFile]) -> Result<HashMap<String, Option<Vec<u8>>>> {
    let mut result = HashMap::new();
    for file in files {
        let path = root.join(file.store_name);
        let contents = if path.exists() {
            Some(std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?)
        } else {
            None
        };
        result.insert(file.store_name.to_string(), contents);
    }
    Ok(result)
}

fn read_remote_files(
    remote: &Remote,
    files: &[SyncFile],
) -> Result<HashMap<String, Option<Vec<u8>>>> {
    let mut command = String::from(
        "read_one() { name=$1; path=$2; printf 'CERTIES_FILE\\t%s\\t' \"$name\"; if test -f \"$path\"; then printf 'present\\n'; base64 \"$path\"; printf '\\nCERTIES_END\\t%s\\n' \"$name\"; else printf 'missing\\n'; fi; };",
    );
    for file in files {
        command.push_str(&format!(
            " read_one {} {};",
            shell_quote(file.store_name),
            remote_shell_path(&remote_file_path(remote, file.store_name))
        ));
    }

    let output = Command::new("ssh")
        .arg(&remote.host)
        .arg(command)
        .output()
        .with_context(|| format!("failed to run ssh for {}", remote.host))?;

    if output.status.success() {
        return parse_remote_files(&output.stdout);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!("failed to read remote files: {}", stderr.trim())
}

fn deploy_source_to_target(target: &Target, files: &[SyncFile]) -> Result<()> {
    match target {
        Target::Local(path) => deploy_local_files(path, files),
        Target::Remote(remote) => deploy_remote_files(remote, files),
    }
}

fn deploy_local_files(root: &Path, files: &[SyncFile]) -> Result<()> {
    std::fs::create_dir_all(root.join("ca"))
        .with_context(|| format!("cannot create {}", root.join("ca").display()))?;
    std::fs::create_dir_all(root.join("crl"))
        .with_context(|| format!("cannot create {}", root.join("crl").display()))?;
    for file in files {
        let path = root.join(file.store_name);
        std::fs::write(&path, &file.source)
            .with_context(|| format!("cannot write {}", path.display()))?;
        println!("Deployed {}", file.label);
    }
    Ok(())
}

fn deploy_remote_files(remote: &Remote, files: &[SyncFile]) -> Result<()> {
    let mut script = format!(
        "set -e\nmkdir -p {} {}\n",
        remote_shell_path(&remote_file_path(remote, "ca")),
        remote_shell_path(&remote_file_path(remote, "crl"))
    );
    for file in files {
        let path = remote_file_path(remote, file.store_name);
        script.push_str(&format!(
            "base64 --decode > {} <<'CERTIES_{}'\n{}\nCERTIES_{}\n",
            remote_shell_path(&path),
            file.label.replace('.', "_").to_uppercase(),
            base64::encode_block(&file.source),
            file.label.replace('.', "_").to_uppercase(),
        ));
    }
    write_remote_command(remote, "sh -s", Some(script.as_bytes()))
        .context("cannot deploy files")?;
    for file in files {
        println!("Deployed {}", file.label);
    }
    Ok(())
}

fn download_target_to_source(source: &Target, files: &[SyncFile]) -> Result<()> {
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    println!("Warning: downloading ca.crt can make the local CA certificate disagree with ca.key.");
    print!("Type \"download\" to continue: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim() != "download" {
        println!("No changes made.");
        return Ok(());
    }

    let downloaded: Vec<_> = files
        .iter()
        .map(|file| {
            file.target
                .as_ref()
                .map(|contents| (file.label, file.store_name, contents.as_slice()))
                .with_context(|| format!("target {} is missing; cannot download it", file.label))
        })
        .collect::<Result<_>>()?;

    write_downloaded_files(source, &downloaded, &stamp)
}

fn write_downloaded_files(
    source: &Target,
    files: &[(&str, &str, &[u8])],
    stamp: &str,
) -> Result<()> {
    match source {
        Target::Local(root) => {
            for file in files {
                let path = root.join(file.1);
                let backup = backup_path(&path, stamp);
                if path.exists() {
                    std::fs::copy(&path, &backup)
                        .with_context(|| format!("cannot back up {}", path.display()))?;
                }
                std::fs::write(&path, file.2)
                    .with_context(|| format!("cannot write {}", path.display()))?;
                println!("Downloaded {} (backup: {})", file.0, backup.display());
            }
        }
        Target::Remote(remote) => {
            let remote_files = files
                .iter()
                .map(|file| (file.1, file.2))
                .collect::<Vec<_>>();
            deploy_bytes_remote(remote, &remote_files)
                .context("cannot download target files into remote source")?;
            for file in files {
                println!("Downloaded {} into remote source", file.0);
            }
        }
    }
    Ok(())
}

fn deploy_bytes_remote(remote: &Remote, files: &[(&str, &[u8])]) -> Result<()> {
    let mut script = format!(
        "set -e\nmkdir -p {} {}\n",
        remote_shell_path(&remote_file_path(remote, "ca")),
        remote_shell_path(&remote_file_path(remote, "crl"))
    );
    for (name, contents) in files {
        script.push_str(&format!(
            "base64 --decode > {} <<'CERTIES_FILE'\n{}\nCERTIES_FILE\n",
            remote_shell_path(&remote_file_path(remote, name)),
            base64::encode_block(contents),
        ));
    }
    write_remote_command(remote, "sh -s", Some(script.as_bytes()))
}

fn write_remote_command(remote: &Remote, command: &str, input: Option<&[u8]>) -> Result<()> {
    let mut child = Command::new("ssh")
        .arg(&remote.host)
        .arg(command)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run ssh for {}", remote.host))?;

    if let Some(input) = input {
        child
            .stdin
            .as_mut()
            .context("failed to open ssh stdin")?
            .write_all(input)?;
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
    }
}

fn parse_remote_files(output: &[u8]) -> Result<HashMap<String, Option<Vec<u8>>>> {
    let text = String::from_utf8_lossy(output);
    let mut result = HashMap::new();
    let mut lines = text.lines();

    while let Some(line) = lines.next() {
        let Some(rest) = line.strip_prefix("CERTIES_FILE\t") else {
            continue;
        };
        let mut parts = rest.splitn(2, '\t');
        let name = parts.next().unwrap_or_default().to_string();
        let status = parts.next().unwrap_or_default();

        match status {
            "missing" => {
                result.insert(name, None);
            }
            "present" => {
                let mut encoded = String::new();
                for line in lines.by_ref() {
                    if line == format!("CERTIES_END\t{name}") {
                        break;
                    }
                    encoded.push_str(line);
                }
                let decoded = base64::decode_block(&encoded)
                    .with_context(|| format!("cannot decode remote {}", name))?;
                result.insert(name, Some(decoded));
            }
            _ => bail!("unexpected remote sync response for {}", name),
        }
    }

    Ok(result)
}

fn print_comparison(file: &SyncFile) {
    println!("{}", file.label);
    println!(
        "  source: {} bytes, sha256 {}",
        file.source.len(),
        hex(&sha256(&file.source))
    );
    match &file.target {
        Some(target) => println!(
            "  target: {} bytes, sha256 {}",
            target.len(),
            hex(&sha256(target))
        ),
        None => println!("  target: missing"),
    }
    if file.target.as_ref() == Some(&file.source) {
        println!("  status: up to date");
    } else {
        println!("  status: out of sync");
    }
}

fn print_diff(file: &SyncFile) {
    let Some(target) = &file.target else {
        println!();
        return;
    };

    println!("  semantic differences:");
    let result = match file.label {
        "ca.crt" => print_cert_diff(&file.source, target),
        "crl.pem" => print_crl_diff(&file.source, target),
        _ => Err(anyhow::anyhow!(
            "no semantic diff available for {}",
            file.label
        )),
    };

    if let Err(err) = result {
        println!("    cannot parse semantic diff: {err}");
    }
    println!();
}

struct CertSummary {
    subject: String,
    issuer: String,
    serial: u64,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    public_key_algorithm: String,
}

struct CrlSummary {
    issuer: String,
    last_update: DateTime<Utc>,
    next_update: Option<DateTime<Utc>>,
    number: Option<u64>,
    revoked: BTreeMap<u64, DateTime<Utc>>,
}

fn print_cert_diff(local: &[u8], remote: &[u8]) -> Result<()> {
    let local = parse_cert_summary(local)?;
    let remote = parse_cert_summary(remote)?;

    print_field_diff("subject", &local.subject, &remote.subject);
    print_field_diff("issuer", &local.issuer, &remote.issuer);
    print_field_diff(
        "serial",
        &serial_hex(local.serial),
        &serial_hex(remote.serial),
    );
    print_field_diff(
        "not before",
        &fmt_time(local.not_before),
        &fmt_time(remote.not_before),
    );
    print_field_diff(
        "not after",
        &fmt_time(local.not_after),
        &fmt_time(remote.not_after),
    );
    print_field_diff(
        "public key algorithm",
        &local.public_key_algorithm,
        &remote.public_key_algorithm,
    );

    Ok(())
}

fn print_crl_diff(local: &[u8], remote: &[u8]) -> Result<()> {
    let local = parse_crl_summary(local)?;
    let remote = parse_crl_summary(remote)?;

    print_field_diff("issuer", &local.issuer, &remote.issuer);
    print_field_diff(
        "last update",
        &fmt_time(local.last_update),
        &fmt_time(remote.last_update),
    );
    print_field_diff(
        "next update",
        &local
            .next_update
            .map(fmt_time)
            .unwrap_or_else(|| "(none)".to_string()),
        &remote
            .next_update
            .map(fmt_time)
            .unwrap_or_else(|| "(none)".to_string()),
    );
    print_field_diff(
        "CRL number",
        &local
            .number
            .map(serial_hex)
            .unwrap_or_else(|| "(none)".to_string()),
        &remote
            .number
            .map(serial_hex)
            .unwrap_or_else(|| "(none)".to_string()),
    );

    for (serial, local_revoked_at) in &local.revoked {
        match remote.revoked.get(serial) {
            None => println!(
                "    revoked only local:  {} at {}",
                serial_hex(*serial),
                fmt_time(*local_revoked_at)
            ),
            Some(remote_revoked_at) if remote_revoked_at != local_revoked_at => {
                println!(
                    "    revoked date differs for {}: local {}, remote {}",
                    serial_hex(*serial),
                    fmt_time(*local_revoked_at),
                    fmt_time(*remote_revoked_at)
                );
            }
            Some(_) => {}
        }
    }
    for (serial, remote_revoked_at) in &remote.revoked {
        if !local.revoked.contains_key(serial) {
            println!(
                "    revoked only remote: {} at {}",
                serial_hex(*serial),
                fmt_time(*remote_revoked_at)
            );
        }
    }

    Ok(())
}

fn parse_cert_summary(pem: &[u8]) -> Result<CertSummary> {
    let (_, pem) = parse_x509_pem(pem)
        .map_err(|err| anyhow::anyhow!("failed to parse certificate PEM: {err:?}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|err| anyhow::anyhow!("failed to parse certificate DER: {err:?}"))?;

    Ok(CertSummary {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: bytes_to_serial(cert.raw_serial()),
        not_before: ts(cert.validity().not_before.timestamp()),
        not_after: ts(cert.validity().not_after.timestamp()),
        public_key_algorithm: cert.public_key().algorithm.algorithm.to_id_string(),
    })
}

fn parse_crl_summary(pem: &[u8]) -> Result<CrlSummary> {
    let (_, pem) =
        parse_x509_pem(pem).map_err(|err| anyhow::anyhow!("failed to parse CRL PEM: {err:?}"))?;
    let (_, crl) = CertificateRevocationList::from_der(&pem.contents)
        .map_err(|err| anyhow::anyhow!("failed to parse CRL DER: {err:?}"))?;

    let revoked = crl
        .iter_revoked_certificates()
        .map(|entry| {
            (
                bytes_to_serial(entry.raw_serial()),
                ts(entry.revocation_date.timestamp()),
            )
        })
        .collect();

    Ok(CrlSummary {
        issuer: crl.issuer().to_string(),
        last_update: ts(crl.last_update().timestamp()),
        next_update: crl.next_update().map(|time| ts(time.timestamp())),
        number: crl
            .crl_number()
            .and_then(|number| number.to_u64_digits().last().copied()),
        revoked,
    })
}

fn print_field_diff(label: &str, local: &str, remote: &str) {
    if local != remote {
        println!("    {label}: local {local}, remote {remote}");
    }
}

fn bytes_to_serial(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |acc, &byte| (acc << 8) | byte as u64)
}

fn serial_hex(serial: u64) -> String {
    format!("#{serial:X}")
}

fn fmt_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%SZ").to_string()
}

fn ts(unix: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(unix, 0).unwrap_or_default()
}

fn remote_file_path(remote: &Remote, name: &str) -> String {
    format!("{}/{}", remote.path.trim_end_matches('/'), name)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn remote_shell_path(value: &str) -> String {
    if value == "~" {
        "$HOME".to_string()
    } else if let Some(rest) = value.strip_prefix("~/") {
        format!("$HOME/{}", shell_quote(rest))
    } else {
        shell_quote(value)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(target: &Target) -> &Path {
        match target {
            Target::Local(path) => path,
            Target::Remote(remote) => panic!("expected local, got {}:{}", remote.host, remote.path),
        }
    }

    fn remote(target: &Target) -> &Remote {
        match target {
            Target::Remote(remote) => remote,
            Target::Local(path) => panic!("expected remote, got {}", path.display()),
        }
    }

    // ── target parsing ────────────────────────────────────────────────────────

    #[test]
    fn absolute_and_relative_paths_are_local() {
        for value in ["/srv/certies", "./certies", "../certies", ".", ".."] {
            let target = parse_target(value).unwrap();
            assert_eq!(local(&target), Path::new(value), "{value}");
        }
    }

    #[test]
    fn a_bare_hostname_is_remote_with_the_default_store() {
        let target = parse_target("server").unwrap();
        assert_eq!(remote(&target).host, "server");
        assert_eq!(remote(&target).path, "~/.certies");
    }

    #[test]
    fn host_and_path_are_split_at_the_first_colon() {
        let target = parse_target("user@server:/srv/certies").unwrap();
        assert_eq!(remote(&target).host, "user@server");
        assert_eq!(remote(&target).path, "/srv/certies");
    }

    #[test]
    fn parse_target_rejects_an_empty_host_or_path() {
        assert!(parse_target(":/srv/certies").is_err());
        assert!(parse_target("server:").is_err());
    }

    #[test]
    fn windows_drive_paths_are_misread_as_remote() {
        // KNOWN BUG: `parse_target` tests for ':' *before* `looks_local`, so a
        // Windows absolute path becomes host "C". Mirrors the same bug in
        // `main.rs::is_remote_store`; both need to learn about drive letters.
        let target = parse_target(r"C:\certies").unwrap();
        assert_eq!(remote(&target).host, "C");
        assert_eq!(remote(&target).path, r"\certies");
    }

    #[test]
    fn unc_paths_fall_through_to_a_remote_hostname() {
        // KNOWN BUG: no ':' and not an existing path, so a UNC share is taken
        // for a hostname rather than a local directory.
        let target = parse_target(r"\\server\share").unwrap();
        assert_eq!(remote(&target).host, r"\\server\share");
    }

    #[test]
    fn looks_local_recognises_path_shapes() {
        for value in ["/abs", "./rel", "../up", ".", "..", "~/store"] {
            assert!(looks_local(value), "{value} should look local");
        }
        for value in ["server", "user@server", "certies"] {
            assert!(!looks_local(value), "{value} should not look local");
        }
    }

    #[test]
    fn looks_local_accepts_any_path_that_exists() {
        // A bare name that happens to exist on disk wins over the host reading.
        assert!(looks_local("Cargo.toml"));
    }

    // ── tilde expansion ───────────────────────────────────────────────────────

    #[test]
    fn expand_local_path_leaves_ordinary_paths_alone() {
        assert_eq!(
            expand_local_path("/srv/certies"),
            PathBuf::from("/srv/certies")
        );
        assert_eq!(expand_local_path("./certies"), PathBuf::from("./certies"));
        // Only a leading "~/" is special; a tilde inside the path is literal.
        assert_eq!(expand_local_path("/srv/~/x"), PathBuf::from("/srv/~/x"));
    }

    #[test]
    fn expand_local_path_expands_a_leading_tilde() {
        let home = home_dir();
        assert_eq!(expand_local_path("~"), home);
        assert_eq!(expand_local_path("~/.certies"), home.join(".certies"));
    }

    #[test]
    fn home_dir_falls_back_to_the_current_directory() {
        // KNOWN GAP: `home_dir` reads only $HOME, which is unset on Windows
        // (it uses %USERPROFILE%), so "~/.certies" silently resolves to
        // "./.certies" there instead of failing or finding the real home.
        if std::env::var("HOME").is_err() {
            assert_eq!(home_dir(), PathBuf::from("."));
        } else {
            assert!(home_dir().is_absolute());
        }
    }

    // ── serial rendering ──────────────────────────────────────────────────────

    #[test]
    fn bytes_to_serial_reads_big_endian() {
        assert_eq!(bytes_to_serial(&[]), 0);
        assert_eq!(bytes_to_serial(&[0x03]), 3);
        assert_eq!(bytes_to_serial(&[0x01, 0x00]), 256);
        assert_eq!(bytes_to_serial(&[0xDE, 0xAD, 0xBE, 0xEF]), 0xDEAD_BEEF);
        assert_eq!(bytes_to_serial(&[0xFF; 8]), u64::MAX);
    }

    #[test]
    fn bytes_to_serial_silently_truncates_long_serials() {
        // KNOWN BUG: the fold shifts left without checking width, so anything
        // past 8 bytes falls off the top. Real CAs issue 20-byte random
        // serials, and `sync` renders serials from a *remote* CA that certies
        // did not issue, so two unrelated certificates can be reported under
        // the same serial in a diff. Only the low 8 bytes survive:
        let long = [0xAA, 0xBB, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(bytes_to_serial(&long), 0x1122_3344_5566_7788);
        // ...which makes these two distinct serials indistinguishable.
        let other = [0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(bytes_to_serial(&long), bytes_to_serial(&other));
    }

    #[test]
    fn serial_hex_is_prefixed_and_uppercase() {
        assert_eq!(serial_hex(3), "#3");
        assert_eq!(serial_hex(255), "#FF");
        assert_eq!(serial_hex(0xDEAD), "#DEAD");
    }

    #[test]
    fn hex_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    // ── backup naming ─────────────────────────────────────────────────────────

    #[test]
    fn backup_path_keeps_the_original_extension() {
        assert_eq!(
            backup_path(Path::new("/srv/certies/ca.crt"), "20260920-2100"),
            PathBuf::from("/srv/certies/ca.crt.bak.20260920-2100")
        );
    }

    #[test]
    fn backup_path_defaults_the_extension_when_there_is_none() {
        assert_eq!(
            backup_path(Path::new("/srv/certies/ca"), "20260920-2100"),
            PathBuf::from("/srv/certies/ca.pem.bak.20260920-2100")
        );
    }

    #[test]
    fn backups_of_the_same_file_at_different_stamps_do_not_collide() {
        let path = Path::new("/srv/certies/crl.pem");
        assert_ne!(backup_path(path, "a"), backup_path(path, "b"));
    }

    // ── remote command construction ───────────────────────────────────────────

    #[test]
    fn remote_file_path_joins_and_trims_a_trailing_slash() {
        let remote = Remote {
            host: "server".to_string(),
            path: "/srv/certies/".to_string(),
        };
        assert_eq!(remote_file_path(&remote, "ca.crt"), "/srv/certies/ca.crt");
    }

    #[test]
    fn shell_quote_neutralises_metacharacters() {
        for value in ["a b", "a;rm -rf /", "a$(id)", "a`id`", "a|b", "a\nb"] {
            let quoted = shell_quote(value);
            assert!(
                quoted.starts_with('\'') && quoted.ends_with('\''),
                "{quoted}"
            );
            assert!(!quoted[1..quoted.len() - 1].contains('\''), "{quoted}");
        }
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn remote_shell_path_expands_tilde_and_quotes_the_tail() {
        assert_eq!(remote_shell_path("~"), "$HOME");
        assert_eq!(remote_shell_path("~/.certies"), "$HOME/'.certies'");
        assert_eq!(remote_shell_path("~/a$(id)"), "$HOME/'a$(id)'");
        assert_eq!(remote_shell_path("/srv/certies"), "'/srv/certies'");
    }

    // ── remote tar listing ────────────────────────────────────────────────────

    #[test]
    fn parse_remote_files_reads_a_present_file() {
        let encoded = base64::encode_block(b"hello");
        let output = format!("CERTIES_FILE\tca.crt\tpresent\n{encoded}\nCERTIES_END\tca.crt\n");
        let files = parse_remote_files(output.as_bytes()).unwrap();
        assert_eq!(files.get("ca.crt").unwrap().as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn parse_remote_files_reads_a_missing_file_as_none() {
        let files = parse_remote_files(b"CERTIES_FILE\tcrl.pem\tmissing\n").unwrap();
        assert!(files.contains_key("crl.pem"));
        assert_eq!(files.get("crl.pem").unwrap(), &None);
    }

    #[test]
    fn parse_remote_files_reassembles_wrapped_base64() {
        // `base64` wraps at 76 columns, so a real payload spans many lines.
        let payload: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let encoded = base64::encode_block(&payload);
        let wrapped: Vec<String> = encoded
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        assert!(wrapped.len() > 1, "test needs a multi-line payload");
        let output = format!(
            "CERTIES_FILE\tca.crt\tpresent\n{}\nCERTIES_END\tca.crt\n",
            wrapped.join("\n")
        );

        let files = parse_remote_files(output.as_bytes()).unwrap();
        assert_eq!(files.get("ca.crt").unwrap().as_deref(), Some(&payload[..]));
    }

    #[test]
    fn parse_remote_files_handles_several_files_in_one_response() {
        let encoded = base64::encode_block(b"pem");
        let output = format!(
            "CERTIES_FILE\tca.crt\tpresent\n{encoded}\nCERTIES_END\tca.crt\n\
             CERTIES_FILE\tcrl.pem\tmissing\n"
        );
        let files = parse_remote_files(output.as_bytes()).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files.get("ca.crt").unwrap().as_deref(), Some(&b"pem"[..]));
        assert_eq!(files.get("crl.pem").unwrap(), &None);
    }

    #[test]
    fn parse_remote_files_ignores_unrelated_shell_chatter() {
        // Login banners and stderr noise share the stream; only tagged lines count.
        let encoded = base64::encode_block(b"hi");
        let output = format!(
            "Welcome to the server\nLast login: today\n\
             CERTIES_FILE\tca.crt\tpresent\n{encoded}\nCERTIES_END\tca.crt\n"
        );
        let files = parse_remote_files(output.as_bytes()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files.get("ca.crt").unwrap().as_deref(), Some(&b"hi"[..]));
    }

    #[test]
    fn parse_remote_files_reads_an_empty_listing() {
        assert!(parse_remote_files(b"").unwrap().is_empty());
        assert!(parse_remote_files(b"\n").unwrap().is_empty());
    }

    #[test]
    fn parse_remote_files_rejects_an_unknown_status() {
        let err = parse_remote_files(b"CERTIES_FILE\tca.crt\tconfused\n").unwrap_err();
        assert!(
            err.to_string().contains("unexpected remote sync response"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_remote_files_rejects_undecodable_payload() {
        let output = "CERTIES_FILE\tca.crt\tpresent\n!!!!\nCERTIES_END\tca.crt\n";
        let err = parse_remote_files(output.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("cannot decode remote"),
            "unexpected error: {err}"
        );
    }
}
