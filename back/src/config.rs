use crate::crypto::MasterKey;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::env;

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    pub ui_dir: String,
    pub service_key: String,
    pub portal_url: String,
    pub client_id: String,
    /// Vault key-encryption key. Absent: the vault is sealed and every vault route returns 503.
    pub master_key: Option<MasterKey>,
    /// Behind a reverse proxy: take the client IP from its X-Forwarded-For.
    pub trust_proxy: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let value = |key: &str, fallback: &str| {
            env::var(key)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| fallback.into())
        };
        let config = Self {
            bind: value("KEYSTONE_BIND", "127.0.0.1:8090"),
            database_url: value("KEYSTONE_DATABASE_URL", "sqlite://data/keystone.db"),
            ui_dir: value("KEYSTONE_UI_DIR", "ui/dist/keystone-ui/browser"),
            service_key: value("KEYSTONE_SERVICE_KEY", ""),
            portal_url: value("PORTAL_URL", ""),
            client_id: value("PORTAL_CLIENT_ID", ""),
            master_key: master_key(&value("KEYSTONE_MASTER_KEY", ""))?,
            trust_proxy: matches!(
                value("KEYSTONE_TRUST_PROXY", "false").as_str(),
                "true" | "1"
            ),
        };
        if !config.service_key.is_empty() && config.service_key.len() < 32 {
            anyhow::bail!("KEYSTONE_SERVICE_KEY must contain at least 32 characters");
        }
        if !config.portal_url.is_empty() {
            validate_url(&config.portal_url)?;
            anyhow::ensure!(
                !config.portal_url.ends_with('/'),
                "PORTAL_URL must match the issuer exactly, without a trailing slash"
            );
        }
        Ok(config)
    }
    pub fn sso_configured(&self) -> bool {
        !self.portal_url.is_empty() && !self.client_id.is_empty()
    }
}

fn validate_url(raw: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(raw)?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "Use HTTPS (HTTP is allowed only on loopback)"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "URLs must not contain credentials or fragments"
    );
    Ok(())
}

/// `KEYSTONE_MASTER_KEY`: 32 random bytes, base64 (`openssl rand -base64 32`).
pub fn master_key(raw: &str) -> anyhow::Result<Option<MasterKey>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let bytes: [u8; 32] = STANDARD
        .decode(raw.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "KEYSTONE_MASTER_KEY must be 32 bytes, base64 encoded (openssl rand -base64 32)"
            )
        })?;
    Ok(Some(MasterKey::from_bytes(bytes)))
}
