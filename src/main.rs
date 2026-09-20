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
        Commands::Init {
            name,
            validity_days,
        } => commands::init_ca::run(store, name, validity_days),
        Commands::New {
            client,
            device,
            validity_days,
            key_password,
            p12_password,
        } => commands::new::run(
            store,
            client,
            device,
            validity_days,
            key_password,
            p12_password,
        ),
        Commands::Revoke { client, device } => commands::revoke::run(store, client, device),
        Commands::Status => commands::status::run(store),
        Commands::RenewCrl { validity_days } => commands::renew_crl::run(store, validity_days),
        Commands::Sync { .. } => unreachable!(),
        Commands::Migrate => commands::migrate::run(store),
        Commands::Reset => commands::reset::run(store),
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
    Ok(RemoteStore {
        host: host.to_string(),
        path: path.to_string(),
    })
}

fn remote_temp_dir() -> Result<PathBuf> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "certies-remote-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&path).with_context(|| format!("cannot create {}", path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── local vs. remote store dispatch ───────────────────────────────────────

    #[test]
    fn plain_paths_are_local() {
        for value in ["/abs/path", "./rel", "../up", ".", "~/.certies", "certies"] {
            assert!(!is_remote_store(value), "{value} should be local");
        }
    }

    #[test]
    fn ssh_style_values_are_remote() {
        for value in [
            "user@server",
            "server:/srv/certies",
            "user@server:/srv/certies",
            "user@server:~/.certies",
        ] {
            assert!(is_remote_store(value), "{value} should be remote");
        }
    }

    #[test]
    fn a_bare_hostname_without_a_colon_is_not_detected_as_remote() {
        // KNOWN GAP: `certies -s server status` (no '@' and no ':') is treated
        // as a local relative directory named "server". `sync::parse_target`
        // takes the opposite view and treats a bare word as a host. The two
        // dispatchers disagree; this pins the `main.rs` side.
        assert!(!is_remote_store("server"));
    }

    #[test]
    fn windows_drive_paths_are_misread_as_remote() {
        // KNOWN BUG: dispatch keys off a bare ':' , so a Windows absolute path
        // parses as host "C" plus path "\\certies" and certies shells out to
        // ssh instead of opening the local store. Windows is a supported CI
        // target, so this is live. Pinned here; fixing it means teaching
        // `is_remote_store` about drive letters (and UNC paths, below).
        assert!(is_remote_store(r"C:\certies"));
        assert_eq!(parse_remote_store(r"C:\certies").unwrap().host, "C");
        assert_eq!(parse_remote_store(r"C:\certies").unwrap().path, r"\certies");
    }

    #[test]
    fn unc_paths_are_treated_as_local() {
        // No ':' and no '@', so this one happens to land on the local path.
        assert!(!is_remote_store(r"\\server\share\certies"));
    }

    // ── remote store parsing ──────────────────────────────────────────────────

    #[test]
    fn remote_without_a_path_defaults_to_the_home_store() {
        let remote = parse_remote_store("user@server").unwrap();
        assert_eq!(remote.host, "user@server");
        assert_eq!(remote.path, "~/.certies");
    }

    #[test]
    fn remote_splits_host_from_path_at_the_first_colon() {
        let remote = parse_remote_store("user@server:/srv/certies").unwrap();
        assert_eq!(remote.host, "user@server");
        assert_eq!(remote.path, "/srv/certies");
    }

    #[test]
    fn remote_keeps_later_colons_in_the_path() {
        let remote = parse_remote_store("server:/srv/odd:name").unwrap();
        assert_eq!(remote.host, "server");
        assert_eq!(remote.path, "/srv/odd:name");
    }

    #[test]
    fn remote_rejects_an_empty_host_or_path() {
        assert!(parse_remote_store(":/srv/certies").is_err());
        assert!(parse_remote_store("server:").is_err());
    }

    // ── shell quoting for the ssh command line ────────────────────────────────

    #[test]
    fn shell_quote_wraps_plain_values() {
        assert_eq!(shell_quote("/srv/certies"), "'/srv/certies'");
    }

    #[test]
    fn shell_quote_neutralises_metacharacters() {
        for value in [
            "a b",
            "a;rm -rf /",
            "a$(id)",
            "a`id`",
            "a&b",
            "a|b",
            "a\nb",
            "a*b",
        ] {
            let quoted = shell_quote(value);
            assert!(
                quoted.starts_with('\'') && quoted.ends_with('\''),
                "{quoted}"
            );
            // Nothing between the outer quotes may close them.
            assert!(!quoted[1..quoted.len() - 1].contains('\''), "{quoted}");
        }
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("'"), r"''\'''");
    }

    #[test]
    fn remote_shell_path_expands_a_bare_tilde_unquoted() {
        // Must stay unquoted so the remote shell expands it.
        assert_eq!(remote_shell_path("~"), "$HOME");
    }

    #[test]
    fn remote_shell_path_expands_tilde_and_quotes_only_the_tail() {
        assert_eq!(remote_shell_path("~/.certies"), "$HOME/'.certies'");
        assert_eq!(remote_shell_path("~/my certies"), "$HOME/'my certies'");
        assert_eq!(remote_shell_path("~/a$(id)"), "$HOME/'a$(id)'");
    }

    #[test]
    fn remote_shell_path_quotes_absolute_paths_whole() {
        assert_eq!(remote_shell_path("/srv/certies"), "'/srv/certies'");
        assert_eq!(remote_shell_path("/srv/a b"), "'/srv/a b'");
    }

    #[test]
    fn remote_shell_path_does_not_expand_a_tilde_inside_the_path() {
        assert_eq!(remote_shell_path("/srv/~/certies"), "'/srv/~/certies'");
    }
}
