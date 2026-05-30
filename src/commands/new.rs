use anyhow::{bail, Context, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::X509;
use rcgen::KeyPair;
use std::fs;
use time::Duration;

use crate::ca_signer::CaSigner;
use crate::store::Store;

pub fn run(
    store: &Store,
    client: String,
    device: String,
    validity_days: u32,
    key_password: Option<String>,
    p12_password: Option<String>,
) -> Result<()> {
    store.require_initialized()?;
    let mut meta = store.load_meta()?;

    let client_dir = store.client_dir(&client, &device);
    if client_dir.exists() {
        bail!("Certificate for {client}/{device} already exists. Revoke it first.");
    }
    fs::create_dir_all(&client_dir)
        .with_context(|| format!("cannot create {}", client_dir.display()))?;

    let signer = CaSigner::load(store)?;
    let serial = meta.next_serial;

    let client_key_pair = KeyPair::generate()?;
    let key_pem = client_key_pair.serialize_pem();

    let cert_pem = signer
        .sign_client_cert(&format!("{client}/{device}"), &key_pem, serial, validity_days)
        .context("failed to sign client certificate")?;

    let key_password = match key_password {
        Some(pw) => Some(pw),
        None => {
            let pw = rpassword::prompt_password(format!(
                "Key password for {client}/{device} (Enter to skip): "
            ))
            .context("failed to read key password")?;
            if pw.is_empty() { None } else { Some(pw) }
        }
    };

    let key_bytes = match key_password {
        Some(ref pw) => {
            let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
                .context("cannot parse private key")?;
            pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pw.as_bytes())
                .context("cannot encrypt private key")?
        }
        None => key_pem.as_bytes().to_vec(),
    };

    let p12_password = match p12_password {
        Some(p) => p,
        None => rpassword::prompt_password(format!("P12 password for {client}/{device}: "))
            .context("failed to read P12 password")?,
    };

    let p12_der =
        build_p12(&device, &key_pem, &cert_pem, signer.ca_cert_pem(), &p12_password)
            .context("failed to build P12")?;

    let key_path = client_dir.join(format!("{device}.key"));
    let cert_path = client_dir.join(format!("{device}.crt"));
    let p12_path = client_dir.join(format!("{device}.p12"));

    write_private_bytes(&key_path, &key_bytes)?;
    fs::write(&cert_path, &cert_pem)
        .with_context(|| format!("cannot write {}", cert_path.display()))?;
    write_private_bytes(&p12_path, &p12_der)?;

    meta.next_serial += 1;
    store.save_meta(&meta)?;

    let expires = chrono::DateTime::from_timestamp(
        (time::OffsetDateTime::now_utc() + Duration::days(validity_days as i64)).unix_timestamp(),
        0,
    )
    .unwrap();

    println!("Certificate issued for {client}/{device}");
    println!("  Certificate: {}", cert_path.display());
    println!("  Private key: {}", key_path.display());
    println!("  P12 bundle:  {}", p12_path.display());
    println!("  Serial:      #{serial}");
    println!("  Valid until: {}", expires.format("%Y-%m-%d"));

    Ok(())
}

fn build_p12(
    friendly_name: &str,
    key_pem: &str,
    cert_pem: &str,
    ca_cert_pem: &str,
    password: &str,
) -> Result<Vec<u8>> {
    let pkey =
        PKey::private_key_from_pem(key_pem.as_bytes()).context("cannot parse private key")?;
    let cert = X509::from_pem(cert_pem.as_bytes()).context("cannot parse certificate")?;
    let ca = X509::from_pem(ca_cert_pem.as_bytes()).context("cannot parse CA certificate")?;

    let mut ca_chain = Stack::new().context("cannot create cert stack")?;
    ca_chain.push(ca).context("cannot push CA onto stack")?;

    let p12 = Pkcs12::builder()
        .name(friendly_name)
        .pkey(&pkey)
        .cert(&cert)
        .ca(ca_chain)
        .build2(password)
        .context("cannot build P12")?;

    p12.to_der().context("cannot serialise P12 to DER")
}

fn write_private_bytes(path: &std::path::Path, data: &[u8]) -> Result<()> {
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
                f.write_all(data)
            })
            .with_context(|| format!("cannot write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).with_context(|| format!("cannot write {}", path.display()))?;
    }
    Ok(())
}
