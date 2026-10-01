//! A local certificate authority used by MITM mode to mint per-host leaf
//! certificates on demand, signed by a CA the operator has installed in client
//! trust stores. Generated `ServerConfig`s are cached per host name.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

pub struct CertAuthority {
    /// Reconstructed CA certificate, used as the issuer when signing leaves.
    ca_cert: rcgen::Certificate,
    /// The CA private key.
    ca_key: KeyPair,
    /// The original CA certificate DER, included in served chains.
    ca_der: CertificateDer<'static>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("reading CA cert {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("reading CA key {}", key_path.display()))?;

        let ca_key = KeyPair::from_pem(&key_pem).context("parsing CA private key")?;
        let ca_params =
            CertificateParams::from_ca_cert_pem(&cert_pem).context("parsing CA certificate")?;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("reconstructing CA certificate for signing")?;

        let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
        let ca_der = rustls_pemfile::certs(&mut reader)
            .next()
            .context("no certificate found in CA cert file")?
            .context("decoding CA certificate DER")?;

        Ok(CertAuthority {
            ca_cert,
            ca_key,
            ca_der,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Return a `ServerConfig` presenting a certificate valid for `host`,
    /// generating and caching one on first use.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if let Some(cfg) = self.cache.lock().unwrap().get(host) {
            return Ok(cfg.clone());
        }
        let cfg = self.build_server_config(host)?;
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    fn build_server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let leaf_key = KeyPair::generate().context("generating leaf key")?;

        let mut params =
            CertificateParams::new(vec![host.to_string()]).context("building leaf params")?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::ExplicitNoCa;
        params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .context("signing leaf certificate")?;

        let leaf_der: CertificateDer<'static> = leaf.der().clone();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let chain = vec![leaf_der, self.ca_der.clone()];

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .context("building rustls ServerConfig")?;

        Ok(Arc::new(config))
    }
}
