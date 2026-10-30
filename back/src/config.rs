use serde::Deserialize;
use std::env;

#[derive(Clone, Deserialize)]
pub struct Monitor {
    pub name: String,
    pub url: String,
}

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    pub ui_dir: String,
    pub service_key: String,
    pub portal_url: String,
    pub client_id: String,
    pub monitors: Vec<Monitor>,
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
            monitors: serde_json::from_str(&value("KEYSTONE_MONITORS_JSON", "[]"))?,
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
        anyhow::ensure!(
            config.monitors.len() <= 20,
            "At most 20 monitors are supported"
        );
        for monitor in &config.monitors {
            validate_url(&monitor.url)?;
            anyhow::ensure!(
                !monitor.name.is_empty() && monitor.name.len() <= 80,
                "Invalid monitor name"
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
