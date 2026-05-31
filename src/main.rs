mod ca_signer;
mod cert_reader;
mod cli;
mod commands;
mod store;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use store::Store;

struct RemoteStore {
    host: String,
    path: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sync { target } => commands::sync::run(cli.store, target),
        command => run_store_command(command, cli.store),
    }
}

fn run_store_command(command: Commands, store: Option<String>) -> Result<()> {
    match store {
        Some(value) if is_remote_store(&value) => run_remote_store_command(command, &value),
        Some(value) => {
            let store = Store::new(PathBuf::from(value));
            run_local_command(command, &store)
        }
        None => {
            let store = Store::new(Store::default_path());
            run_local_command(command, &store)
        }
    }
}

fn run_local_command(command: Commands, store: &Store) -> Result<()> {
    match command {
        Commands::Init { name, validity_days } => {
            commands::init_ca::run(&store, name, validity_days)
        }
        Commands::New { client, device, validity_days, key_password, p12_password } => {
            commands::new::run(&store, client, device, validity_days, key_password, p12_password)
        }
        Commands::Revoke { client, device } => commands::revoke::run(&store, client, device),
        Commands::Status => commands::status::run(&store),
        Commands::RenewCrl { validity_days } => commands::renew_crl::run(&store, validity_days),
        Commands::Sync { .. } => unreachable!(),
        Commands::Migrate => commands::migrate::run(&store),
        Commands::Reset => commands::reset::run(&store),
    }
}

fn run_remote_store_command(command: Commands, remote: &str) -> Result<()> {
    let remote = parse_remote_store(remote)?;
    let temp_root = remote_temp_dir()?;
    download_remote_store(&remote, &temp_root)?;

    let should_upload = !matches!(command, Commands::Status);
    let store = Store::new(temp_root.clone());
    let result = run_local_command(command, &store);

    match result {
        Ok(()) => {
            if should_upload {
                upload_remote_store(&remote, &temp_root)?;
            }
            let _ = std::fs::remove_dir_all(&temp_root);
            Ok(())
        }
        Err(err) => {
            let _ = std::fs::remove_dir_all(&temp_root);
            Err(err)
        }
    }
}

fn is_remote_store(value: &str) -> bool {
    value.contains('@') || value.contains(':')
}

fn parse_remote_store(value: &str) -> Result<RemoteStore> {
    let (host, path) = match value.split_once(':') {
        Some((host, path)) => (host, path),
        None => (value, "~/.certies"),
    };
    if host.is_empty() || path.is_empty() {
        bail!("remote store must be in the form [user@]server[:/path]");
    }
    Ok(RemoteStore { host: host.to_string(), path: path.to_string() })
}

fn remote_temp_dir() -> Result<PathBuf> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "certies-remote-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    Ok(path)
}

fn download_remote_store(remote: &RemoteStore, local: &Path) -> Result<()> {
    let command = format!(
        "if test -d {path}; then tar -C {path} -cf - .; fi",
        path = remote_shell_path(&remote.path)
    );
    let output = Command::new("ssh")
        .arg(&remote.host)
        .arg(command)
        .output()
        .with_context(|| format!("failed to run ssh for {}", remote.host))?;

    if !output.status.success() {
        bail!(
            "failed to read remote store: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.is_empty() {
        return Ok(());
    }

    let mut tar = Command::new("tar")
        .arg("-C")
        .arg(local)
        .arg("-xf")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run tar to unpack remote store")?;
    tar.stdin
        .as_mut()
        .context("failed to open tar stdin")?
        .write_all(&output.stdout)?;
    let output = tar.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
    }
}

fn upload_remote_store(remote: &RemoteStore, local: &Path) -> Result<()> {
    let archive = Command::new("tar")
        .arg("-C")
        .arg(local)
        .arg("-cf")
        .arg("-")
        .arg(".")
        .output()
        .context("failed to run tar to pack local store")?;
    if !archive.status.success() {
        bail!("{}", String::from_utf8_lossy(&archive.stderr).trim());
    }

    let command = format!(
        "rm -rf {path} && mkdir -p {path} && tar -C {path} -xf -",
        path = remote_shell_path(&remote.path)
    );
    let mut child = Command::new("ssh")
        .arg(&remote.host)
        .arg(command)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run ssh for {}", remote.host))?;
    child
        .stdin
        .as_mut()
        .context("failed to open ssh stdin")?
        .write_all(&archive.stdout)?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "failed to write remote store: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
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
