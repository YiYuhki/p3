//! TLS support: SNI extraction (transparent mode) and a local certificate
//! authority for on-the-fly cert generation (MITM mode).

pub mod ca;
pub mod sni;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ClientConfig;

/// Build a shared rustls client config (for upstream connections in MITM mode)
/// that trusts the Mozilla root set bundled via `webpki-roots`, plus any extra
/// roots supplied by the operator.
pub fn upstream_client_config(extra_ca: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = extra_ca {
        let pem = std::fs::read(path)
            .with_context(|| format!("reading extra upstream CA {}", path.display()))?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.context("decoding extra upstream CA certificate")?;
            roots
                .add(cert)
                .context("adding extra upstream CA to root store")?;
        }
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}
