//! Configuration file schema (TOML) and loading.
//!
//! The config is read once at startup and is immutable thereafter, so the hot
//! path needs no locking. Changing rules requires a restart (by design).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

use crate::policy::RawRules;

/// Which proxy engine to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Explicit forward proxy (clients set a proxy). HTTP by Host, HTTPS by the
    /// CONNECT target host — no decryption.
    Forward,
    /// Transparent interception (iptables REDIRECT). Filters by SNI / Host.
    Transparent,
    /// Man-in-the-middle: terminates TLS with a locally-signed cert to inspect
    /// full URLs. Requires a CA.
    Mitm,
}

/// Default action when no level expresses an opinion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

fn default_action() -> Action {
    Action::Deny
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub mode: Mode,
    pub listen: String,
    #[serde(default = "default_action")]
    pub default_action: Action,
}

#[derive(Debug, Deserialize)]
pub struct MitmConfig {
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    /// Optional PEM file of extra root certificates to trust when connecting to
    /// upstreams (e.g. internal services signed by a corporate CA). Added on top
    /// of the bundled public root set.
    #[serde(default)]
    pub extra_upstream_ca: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct DepartmentConfig {
    pub name: String,
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
    #[serde(flatten)]
    pub rules: RawRules,
}

#[derive(Debug, Deserialize)]
pub struct IndividualConfig {
    pub ip: IpAddr,
    #[serde(flatten)]
    pub rules: RawRules,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub mitm: Option<MitmConfig>,
    #[serde(default)]
    pub global: RawRules,
    #[serde(default)]
    pub departments: Vec<DepartmentConfig>,
    #[serde(default)]
    pub individuals: Vec<IndividualConfig>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config file {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.server.mode == Mode::Mitm && self.mitm.is_none() {
            anyhow::bail!("mode = \"mitm\" requires a [mitm] section with ca_cert and ca_key");
        }
        Ok(())
    }
}
