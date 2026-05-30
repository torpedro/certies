use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct StoreMeta {
    pub next_serial: u64,
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

    fn meta_path(&self) -> PathBuf {
        self.root.join("store.json")
    }

    pub fn is_initialized(&self) -> bool {
        self.meta_path().exists()
    }

    pub fn require_initialized(&self) -> Result<()> {
        if !self.is_initialized() {
            bail!(
                "Store at {} is not initialised. Run `certies init-ca` first.",
                self.root.display()
            );
        }
        Ok(())
    }

    pub fn load_meta(&self) -> Result<StoreMeta> {
        let path = self.meta_path();
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_str(&data).context("cannot parse store.json")
    }

    pub fn save_meta(&self, meta: &StoreMeta) -> Result<()> {
        let path = self.meta_path();
        let data = serde_json::to_string_pretty(meta)?;
        std::fs::write(&path, data)
            .with_context(|| format!("cannot write {}", path.display()))
    }

    pub fn read_ca_cert_pem(&self) -> Result<String> {
        std::fs::read_to_string(self.ca_cert_path()).context("cannot read CA certificate")
    }

    pub fn read_ca_key_pem(&self) -> Result<String> {
        std::fs::read_to_string(self.ca_key_path()).context("cannot read CA private key")
    }
}
