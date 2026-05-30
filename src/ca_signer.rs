use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use rcgen::{CertificateParams, KeyPair};

use crate::store::Store;

pub struct CrlEntry {
    pub serial: u64,
    pub revoked_at: DateTime<Utc>,
}

pub enum CaSigner {
    Ecdsa {
        ca_cert: rcgen::Certificate,
        ca_key_pair: KeyPair,
        ca_cert_pem: String,
    },
    Rsa {
        ca_pkey: PKey<Private>,
        ca_x509: X509,
        ca_cert_pem: String,
    },
}

impl CaSigner {
    pub fn load(store: &Store) -> Result<Self> {
        let ca_cert_pem = store.read_ca_cert_pem()?;
        let ca_key_pem = store.read_ca_key_pem()?;

        let pkey = PKey::private_key_from_pem(ca_key_pem.as_bytes())
            .context("cannot parse CA private key")?;

        match pkey.id() {
            Id::RSA => {
                let ca_x509 = X509::from_pem(ca_cert_pem.as_bytes())
                    .context("cannot parse CA certificate")?;
                Ok(CaSigner::Rsa { ca_pkey: pkey, ca_x509, ca_cert_pem })
            }
            _ => {
                let ca_key_pair =
                    KeyPair::from_pem(&ca_key_pem).context("cannot load CA key into rcgen")?;
                let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)
                    .context("cannot load CA cert into rcgen")?;
                let ca_cert = ca_params.self_signed(&ca_key_pair)?;
                Ok(CaSigner::Ecdsa { ca_cert, ca_key_pair, ca_cert_pem })
            }
        }
    }

    pub fn ca_cert_pem(&self) -> &str {
        match self {
            CaSigner::Ecdsa { ca_cert_pem, .. } => ca_cert_pem,
            CaSigner::Rsa { ca_cert_pem, .. } => ca_cert_pem,
        }
    }

    pub fn key_type(&self) -> String {
        match self {
            CaSigner::Ecdsa { .. } => "ECDSA P-256".to_string(),
            CaSigner::Rsa { ca_pkey, .. } => format!("RSA-{}", ca_pkey.bits()),
        }
    }

    /// Sign a client certificate. Returns the certificate PEM.
    /// The client key is always generated as ECDSA P-256 by the caller.
    pub fn sign_client_cert(
        &self,
        cn: &str,
        client_key_pem: &str,
        serial: u64,
        validity_days: u32,
    ) -> Result<String> {
        match self {
            CaSigner::Ecdsa { ca_cert, ca_key_pair, .. } => {
                ecdsa_sign_client_cert(ca_cert, ca_key_pair, cn, client_key_pem, serial, validity_days)
            }
            CaSigner::Rsa { ca_pkey, ca_x509, .. } => {
                rsa_sign_client_cert(ca_pkey, ca_x509, cn, client_key_pem, serial, validity_days)
            }
        }
    }

    /// Sign a CRL. Returns the CRL PEM.
    pub fn sign_crl(
        &self,
        entries: &[CrlEntry],
        validity_days: u32,
        crl_number: u64,
    ) -> Result<String> {
        match self {
            CaSigner::Ecdsa { ca_cert, ca_key_pair, .. } => {
                ecdsa_sign_crl(ca_cert, ca_key_pair, entries, validity_days, crl_number)
            }
            CaSigner::Rsa { ca_pkey, ca_x509, .. } => {
                rsa_sign_crl(ca_pkey, ca_x509, entries, validity_days, crl_number)
            }
        }
    }
}

// ── ECDSA path (rcgen) ────────────────────────────────────────────────────────

fn ecdsa_sign_client_cert(
    ca_cert: &rcgen::Certificate,
    ca_key_pair: &KeyPair,
    cn: &str,
    client_key_pem: &str,
    serial: u64,
    validity_days: u32,
) -> Result<String> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, SerialNumber};
    use time::Duration;

    let client_key_pair = KeyPair::from_pem(client_key_pem)?;
    let now = time::OffsetDateTime::now_utc();

    let mut params = CertificateParams::new(vec![])?;
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.not_before = now;
    params.not_after = now + Duration::days(validity_days as i64);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.serial_number = Some(SerialNumber::from(serial));

    let cert = params.signed_by(&client_key_pair, ca_cert, ca_key_pair)?;
    Ok(cert.pem())
}

fn ecdsa_sign_crl(
    ca_cert: &rcgen::Certificate,
    ca_key_pair: &KeyPair,
    entries: &[CrlEntry],
    validity_days: u32,
    crl_number: u64,
) -> Result<String> {
    use rcgen::{
        CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
        SerialNumber,
    };
    use time::Duration;

    let now = time::OffsetDateTime::now_utc();
    let next_update = now + Duration::days(validity_days as i64);

    let revoked_certs = entries
        .iter()
        .map(|e| RevokedCertParams {
            serial_number: SerialNumber::from(e.serial),
            revocation_time: time::OffsetDateTime::from_unix_timestamp(e.revoked_at.timestamp())
                .unwrap(),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();

    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update,
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };

    let crl = crl_params.signed_by(ca_cert, ca_key_pair)?;
    Ok(crl.pem()?)
}

// ── RSA path (openssl) ────────────────────────────────────────────────────────

fn rsa_sign_client_cert(
    ca_pkey: &PKey<Private>,
    ca_x509: &X509,
    cn: &str,
    client_key_pem: &str,
    serial: u64,
    validity_days: u32,
) -> Result<String> {
    let client_pkey = PKey::private_key_from_pem(client_key_pem.as_bytes())
        .context("cannot parse client key")?;

    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", cn)?;
    let subject = subject.build();

    let serial_bn = BigNum::from_slice(&serial.to_be_bytes())?;
    let serial_asn1 = Asn1Integer::from_bn(&serial_bn)?;

    let not_before = Asn1Time::from_unix(Utc::now().timestamp())?;
    let not_after = Asn1Time::from_unix(
        (Utc::now() + chrono::Duration::days(validity_days as i64)).timestamp(),
    )?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial_asn1)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(ca_x509.subject_name())?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(&client_pkey)?;
    builder.append_extension(BasicConstraints::new().build()?)?;
    builder.append_extension(KeyUsage::new().digital_signature().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
    builder.sign(ca_pkey, MessageDigest::sha256())?;

    let cert = builder.build();
    Ok(String::from_utf8(cert.to_pem()?)?)
}

fn rsa_sign_crl(
    ca_pkey: &PKey<Private>,
    ca_x509: &X509,
    entries: &[CrlEntry],
    validity_days: u32,
    crl_number: u64,
) -> Result<String> {
    use foreign_types_shared::ForeignType;
    use openssl_sys as ffi;

    let now_ts = Utc::now().timestamp();
    let next_ts = (Utc::now() + chrono::Duration::days(validity_days as i64)).timestamp();
    let this_update = Asn1Time::from_unix(now_ts)?;
    let next_update = Asn1Time::from_unix(next_ts)?;

    unsafe {
        let crl = ffi::X509_CRL_new();
        if crl.is_null() {
            bail!("X509_CRL_new failed");
        }

        // Version 2 (value 1)
        ffi::X509_CRL_set_version(crl, 1);

        // Issuer name from CA cert
        let issuer = ffi::X509_get_subject_name(ca_x509.as_ptr() as *const _);
        ffi::X509_CRL_set_issuer_name(crl, issuer);

        // Timestamps
        ffi::X509_CRL_set1_lastUpdate(crl, this_update.as_ptr());
        ffi::X509_CRL_set1_nextUpdate(crl, next_update.as_ptr());

        // Revoked entries
        for entry in entries {
            let rev = ffi::X509_REVOKED_new();
            if rev.is_null() {
                ffi::X509_CRL_free(crl);
                bail!("X509_REVOKED_new failed");
            }

            let serial_bn = BigNum::from_slice(&entry.serial.to_be_bytes())?;
            let serial_asn1 = Asn1Integer::from_bn(&serial_bn)?;
            ffi::X509_REVOKED_set_serialNumber(rev, serial_asn1.as_ptr());

            let rev_time = Asn1Time::from_unix(entry.revoked_at.timestamp())?;
            ffi::X509_REVOKED_set_revocationDate(rev, rev_time.as_ptr());

            // add0 transfers ownership of rev to the CRL
            ffi::X509_CRL_add0_revoked(crl, rev);
        }

        // CRL number extension
        let crl_num_bn = BigNum::from_slice(&crl_number.to_be_bytes())?;
        let crl_num_asn1 = Asn1Integer::from_bn(&crl_num_bn)?;
        ffi::X509_CRL_add1_ext_i2d(
            crl,
            ffi::NID_crl_number,
            crl_num_asn1.as_ptr() as *mut _,
            0,
            0u64,
        );

        ffi::X509_CRL_sort(crl);

        // Sign
        let signed = ffi::X509_CRL_sign(crl, ca_pkey.as_ptr(), MessageDigest::sha256().as_ptr());
        if signed == 0 {
            ffi::X509_CRL_free(crl);
            bail!("X509_CRL_sign failed");
        }

        // Write to PEM via BIO
        let bio = ffi::BIO_new(ffi::BIO_s_mem());
        if bio.is_null() {
            ffi::X509_CRL_free(crl);
            bail!("BIO_new failed");
        }

        ffi::PEM_write_bio_X509_CRL(bio, crl);

        let mut buf_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
        let len = ffi::BIO_get_mem_data(bio, &mut buf_ptr);
        let pem =
            std::slice::from_raw_parts(buf_ptr as *const u8, len as usize).to_vec();

        ffi::BIO_free_all(bio);
        ffi::X509_CRL_free(crl);

        Ok(String::from_utf8(pem).context("CRL PEM was not valid UTF-8")?)
    }
}
