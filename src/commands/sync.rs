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
    local_path: PathBuf,
    remote_name: &'static str,
    local: Vec<u8>,
    remote: Option<Vec<u8>>,
}

pub fn run(store: &Store, target: String) -> Result<()> {
    store.require_initialized()?;
    let target = parse_target(&target)?;

    let mut files = vec![
        SyncFile {
            label: "ca.crt",
            local_path: store.ca_cert_path(),
            remote_name: "ca/ca.crt",
            local: std::fs::read(store.ca_cert_path()).context("cannot read local ca.crt")?,
            remote: None,
        },
        SyncFile {
            label: "crl.pem",
            local_path: store.crl_path(),
            remote_name: "crl/crl.pem",
            local: std::fs::read(store.crl_path()).context("cannot read local crl.pem")?,
            remote: None,
        },
    ];

    println!("Target: {}", target.display());
    println!("Comparing ca.crt and crl.pem...");
    println!();

    for file in &files {
        println!("Checking target {}", target.file_display(file.remote_name));
    }
    let target_files = read_target_files(&target, &files)?;
    println!();

    let mut out_of_sync = false;
    for file in &mut files {
        file.remote = target_files.get(file.remote_name).cloned().unwrap_or(None);
        print_comparison(file);
        if file.remote.as_ref() != Some(&file.local) {
            out_of_sync = true;
            print_diff(file);
        }
    }

    if !out_of_sync {
        println!("Target files are up to date.");
        return Ok(());
    }

    let can_download = files.iter().all(|file| file.remote.is_some());

    println!("Options:");
    println!("  1. Deploy local ca.crt and crl.pem to the target path");
    if can_download {
        println!("  2. Download target ca.crt and crl.pem into the local store");
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
            "1" | "a" | "A" => deploy_local(&target, &files),
            "2" | "b" | "B" => download_target(&files),
            "3" | "" => {
                println!("No changes made.");
                Ok(())
            }
            other => bail!("invalid choice: {other}"),
        }
    } else {
        match input.trim() {
            "1" | "a" | "A" => deploy_local(&target, &files),
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
    Ok(Target::Remote(Remote { host: value.to_string(), path: "~/.certies".to_string() }))
}

fn parse_remote(value: &str) -> Result<Remote> {
    let (host, path) = match value.split_once(':') {
        Some((host, path)) => (host, path),
        None => (value, "~/.certies"),
    };
    if host.is_empty() || path.is_empty() {
        bail!("remote must be in the form [user@]server[:/path]");
    }
    Ok(Remote { host: host.to_string(), path: path.to_string() })
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
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

fn read_target_files(target: &Target, files: &[SyncFile]) -> Result<HashMap<String, Option<Vec<u8>>>> {
    match target {
        Target::Local(path) => read_local_files(path, files),
        Target::Remote(remote) => read_remote_files(remote, files),
    }
}

fn read_local_files(root: &Path, files: &[SyncFile]) -> Result<HashMap<String, Option<Vec<u8>>>> {
    let mut result = HashMap::new();
    for file in files {
        let path = root.join(file.remote_name);
        let contents = if path.exists() {
            Some(std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?)
        } else {
            None
        };
        result.insert(file.remote_name.to_string(), contents);
    }
    Ok(result)
}

fn read_remote_files(remote: &Remote, files: &[SyncFile]) -> Result<HashMap<String, Option<Vec<u8>>>> {
    let mut command = String::from(
        "read_one() { name=$1; path=$2; printf 'CERTIES_FILE\\t%s\\t' \"$name\"; if test -f \"$path\"; then printf 'present\\n'; base64 \"$path\"; printf '\\nCERTIES_END\\t%s\\n' \"$name\"; else printf 'missing\\n'; fi; };",
    );
    for file in files {
        command.push_str(&format!(
            " read_one {} {};",
            shell_quote(file.remote_name),
            remote_shell_path(&remote_file_path(remote, file.remote_name))
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

fn deploy_local(target: &Target, files: &[SyncFile]) -> Result<()> {
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
        let path = root.join(file.remote_name);
        std::fs::write(&path, &file.local)
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
        let path = remote_file_path(remote, file.remote_name);
        script.push_str(&format!(
            "base64 --decode > {} <<'CERTIES_{}'\n{}\nCERTIES_{}\n",
            remote_shell_path(&path),
            file.label.replace('.', "_").to_uppercase(),
            base64::encode_block(&file.local),
            file.label.replace('.', "_").to_uppercase(),
        ));
    }
    write_remote_command(remote, "sh -s", Some(script.as_bytes())).context("cannot deploy files")?;
    for file in files {
        println!("Deployed {}", file.label);
    }
    Ok(())
}

fn download_target(files: &[SyncFile]) -> Result<()> {
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

    for file in files {
        let remote = file.remote.as_ref().with_context(|| {
            format!("target {} is missing; cannot download it", file.label)
        })?;
        let backup = file.local_path.with_extension(format!(
            "{}.bak.{}",
            file.local_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("pem"),
            stamp
        ));
        std::fs::copy(&file.local_path, &backup)
            .with_context(|| format!("cannot back up {}", file.local_path.display()))?;
        std::fs::write(&file.local_path, remote)
            .with_context(|| format!("cannot write {}", file.local_path.display()))?;
        println!("Downloaded {} (backup: {})", file.label, backup.display());
    }
    Ok(())
}

fn write_remote_command(remote: &Remote, command: &str, input: Option<&[u8]>) -> Result<()> {
    let mut child = Command::new("ssh")
        .arg(&remote.host)
        .arg(command)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
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
        "  local:  {} bytes, sha256 {}",
        file.local.len(),
        hex(&sha256(&file.local))
    );
    match &file.remote {
        Some(remote) => println!(
            "  remote: {} bytes, sha256 {}",
            remote.len(),
            hex(&sha256(remote))
        ),
        None => println!("  remote: missing"),
    }
    if file.remote.as_ref() == Some(&file.local) {
        println!("  status: up to date");
    } else {
        println!("  status: out of sync");
    }
}

fn print_diff(file: &SyncFile) {
    let Some(remote) = &file.remote else {
        println!();
        return;
    };

    println!("  semantic differences:");
    let result = match file.label {
        "ca.crt" => print_cert_diff(&file.local, remote),
        "crl.pem" => print_crl_diff(&file.local, remote),
        _ => Err(anyhow::anyhow!("no semantic diff available for {}", file.label)),
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
    print_field_diff("serial", &serial_hex(local.serial), &serial_hex(remote.serial));
    print_field_diff("not before", &fmt_time(local.not_before), &fmt_time(remote.not_before));
    print_field_diff("not after", &fmt_time(local.not_after), &fmt_time(remote.not_after));
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
    print_field_diff("last update", &fmt_time(local.last_update), &fmt_time(remote.last_update));
    print_field_diff(
        "next update",
        &local.next_update.map(fmt_time).unwrap_or_else(|| "(none)".to_string()),
        &remote.next_update.map(fmt_time).unwrap_or_else(|| "(none)".to_string()),
    );
    print_field_diff(
        "CRL number",
        &local.number.map(serial_hex).unwrap_or_else(|| "(none)".to_string()),
        &remote.number.map(serial_hex).unwrap_or_else(|| "(none)".to_string()),
    );

    for (serial, local_revoked_at) in &local.revoked {
        match remote.revoked.get(serial) {
            None => println!("    revoked only local:  {} at {}", serial_hex(*serial), fmt_time(*local_revoked_at)),
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
            println!("    revoked only remote: {} at {}", serial_hex(*serial), fmt_time(*remote_revoked_at));
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
    let (_, pem) = parse_x509_pem(pem)
        .map_err(|err| anyhow::anyhow!("failed to parse CRL PEM: {err:?}"))?;
    let (_, crl) = CertificateRevocationList::from_der(&pem.contents)
        .map_err(|err| anyhow::anyhow!("failed to parse CRL DER: {err:?}"))?;

    let revoked = crl
        .iter_revoked_certificates()
        .map(|entry| (bytes_to_serial(entry.raw_serial()), ts(entry.revocation_date.timestamp())))
        .collect();

    Ok(CrlSummary {
        issuer: crl.issuer().to_string(),
        last_update: ts(crl.last_update().timestamp()),
        next_update: crl.next_update().map(|time| ts(time.timestamp())),
        number: crl.crl_number().and_then(|number| number.to_u64_digits().last().copied()),
        revoked,
    })
}

fn print_field_diff(label: &str, local: &str, remote: &str) {
    if local != remote {
        println!("    {label}: local {local}, remote {remote}");
    }
}

fn bytes_to_serial(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &byte| (acc << 8) | byte as u64)
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
