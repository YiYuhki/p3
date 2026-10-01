//! p3 — a high-performance web proxy with hierarchical domain access control.
//!
//! Usage: `p3 [path/to/config.toml]` (defaults to `config.toml`).

mod config;
mod http1;
mod ipmap;
mod policy;
mod proxy;
mod resolver;
mod tls;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, Mode};
use crate::resolver::Engine;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Install the ring crypto provider as the process default for rustls.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config_path: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string())
        .into();

    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading configuration from {}", config_path.display()))?;

    let engine = Arc::new(Engine::from_config(&cfg));
    info!(
        "policy loaded: {} departments, {} CIDR blocks, {} individual rules, default={:?}",
        engine.department_count(),
        engine.cidr_count(),
        engine.individual_count(),
        cfg.server.default_action,
    );

    let listener = TcpListener::bind(&cfg.server.listen)
        .await
        .with_context(|| format!("binding to {}", cfg.server.listen))?;

    let server = async {
        match cfg.server.mode {
            Mode::Forward => proxy::forward::run(listener, engine).await,
            Mode::Transparent => proxy::transparent::run(listener, engine).await,
            Mode::Mitm => {
                let mitm = cfg
                    .mitm
                    .as_ref()
                    .expect("validated: mitm mode requires [mitm]");
                let ca = Arc::new(
                    tls::ca::CertAuthority::load(&mitm.ca_cert, &mitm.ca_key)
                        .context("loading MITM certificate authority")?,
                );
                let client_config =
                    tls::upstream_client_config(mitm.extra_upstream_ca.as_deref())?;
                proxy::mitm::run(listener, engine, ca, client_config).await
            }
        }
    };

    tokio::select! {
        res = server => res?,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received, exiting");
        }
    }

    Ok(())
}
