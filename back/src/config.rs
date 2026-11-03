//! Configuration, in the same shape as Portal SSO's: one properties file in the Keystone home
//! (written, fully commented, on first start), overridden by environment variables, overridden by
//! command-line flags. Nothing is required to start; Portal SSO is required to sign in.
use crate::crypto::MasterKey;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

pub const TEMPLATE: &str = include_str!("../keystone.properties.template");
pub const VERSION: &str = match option_env!("KEYSTONE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Clone)]
pub struct Config {
    pub home: PathBuf,
    pub config_file: Option<PathBuf>,
    pub bind: String,
    pub database_url: String,
    /// Serve the console from this directory instead of the copy embedded in the binary.
    pub ui_dir: Option<String>,
    pub service_key: String,
    pub portal_url: String,
    pub client_id: String,
    /// Vault key-encryption key. Absent: the vault is sealed and every vault route returns 503.
    pub master_key: Option<MasterKey>,
    /// Where the master key came from, for the console (never the key itself).
    pub master_key_source: String,
    /// Behind a reverse proxy: take the client IP from its X-Forwarded-For.
    pub trust_proxy: bool,
    pub backup_dir: PathBuf,
    pub backup_interval_hours: u64,
    pub backup_keep: usize,
    pub failed_token_limit: u32,
    pub lockout_minutes: u64,
    pub rotation_days: i64,
    pub token_expiry_warning_days: i64,
    pub alerts_webhook_url: Option<String>,
    pub log_level: String,
    /// Local accounts (email + password), with or without Portal SSO.
    pub local_auth: bool,
    pub session_hours: i64,
    /// Unattended setup: accept the license from configuration (Docker, automation).
    pub accept_license: bool,
    /// Unattended setup: create this first local administrator if no local account exists.
    pub bootstrap_admin: Option<(String, String)>,
    /// Settings fixed by environment variables or flags, which the setup wizard cannot change.
    pub fixed: Vec<String>,
}

impl Default for Config {
    /// In-memory settings for tests and embedding; `load` is what the binary uses.
    fn default() -> Self {
        Self {
            home: env::temp_dir().join(format!("keystone-{}", uuid::Uuid::new_v4().simple())),
            config_file: None,
            bind: "127.0.0.1:8090".into(),
            database_url: "sqlite::memory:".into(),
            ui_dir: None,
            service_key: String::new(),
            portal_url: String::new(),
            client_id: String::new(),
            master_key: None,
            master_key_source: "none".into(),
            trust_proxy: false,
            backup_dir: PathBuf::from("backups"),
            backup_interval_hours: 0,
            backup_keep: 14,
            failed_token_limit: 10,
            lockout_minutes: 15,
            rotation_days: 90,
            token_expiry_warning_days: 14,
            alerts_webhook_url: None,
            log_level: "info".into(),
            local_auth: false,
            session_hours: 12,
            accept_license: true,
            bootstrap_admin: None,
            fixed: vec![],
        }
    }
}

/// Every setting: property key, legacy environment names still honoured, and a default.
const SETTINGS: &[(&str, &[&str])] = &[
    ("server.address", &[]),
    ("server.port", &[]),
    ("server.trust-proxy", &["KEYSTONE_TRUST_PROXY"]),
    ("portal.url", &["PORTAL_URL"]),
    ("portal.client-id", &["PORTAL_CLIENT_ID"]),
    ("vault.master-key", &["KEYSTONE_MASTER_KEY"]),
    ("vault.master-key-file", &[]),
    ("storage.database-url", &["KEYSTONE_DATABASE_URL"]),
    ("backup.dir", &[]),
    ("backup.interval-hours", &[]),
    ("backup.keep", &[]),
    ("security.failed-token-limit", &[]),
    ("security.lockout-minutes", &[]),
    ("security.rotation-days", &[]),
    ("security.token-expiry-warning-days", &[]),
    ("alerts.webhook-url", &[]),
    ("log.level", &[]),
    ("auth.local", &[]),
    ("auth.session-hours", &[]),
    ("setup.accept-license", &[]),
    ("bootstrap.admin-email", &[]),
    ("bootstrap.admin-password", &[]),
    ("ui.dir", &["KEYSTONE_UI_DIR"]),
    ("blog.service-key", &["KEYSTONE_SERVICE_KEY"]),
];

/// `server.port` → `KEYSTONE_SERVER_PORT`.
pub fn env_name(key: &str) -> String {
    format!(
        "KEYSTONE_{}",
        key.to_ascii_uppercase().replace(['.', '-'], "_")
    )
}

/// Portal-style flags kept for familiarity.
fn flag_alias(flag: &str) -> Option<&'static str> {
    match flag {
        "httpPort" => Some("server.port"),
        "httpListenAddress" => Some("server.address"),
        _ => None,
    }
}

pub struct Args {
    pub command: Option<String>,
    pub positional: Vec<String>,
    pub overrides: BTreeMap<String, String>,
    pub config: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub flags: BTreeMap<String, String>,
}

/// `keystone [command] [--key=value | --flag value]... [positional]...`
pub fn parse_args(raw: impl IntoIterator<Item = String>) -> anyhow::Result<Args> {
    let mut args = Args {
        command: None,
        positional: vec![],
        overrides: BTreeMap::new(),
        config: None,
        home: None,
        flags: BTreeMap::new(),
    };
    let mut iter = raw.into_iter().peekable();
    let mut passthrough = false;
    while let Some(arg) = iter.next() {
        if passthrough {
            args.positional.push(arg);
            continue;
        }
        if arg == "--" {
            passthrough = true;
            continue;
        }
        if let Some(flag) = arg.strip_prefix("--") {
            let (name, value) = match flag.split_once('=') {
                Some((n, v)) => (n.to_owned(), v.to_owned()),
                None => {
                    let takes_value = iter.peek().is_some_and(|next| !next.starts_with("--"));
                    let boolean =
                        matches!(flag, "help" | "version" | "replace" | "dry-run" | "force");
                    if takes_value && !boolean {
                        (flag.to_owned(), iter.next().unwrap_or_default())
                    } else {
                        (flag.to_owned(), "true".to_owned())
                    }
                }
            };
            match name.as_str() {
                "config" => args.config = Some(PathBuf::from(value)),
                "home" => args.home = Some(PathBuf::from(value)),
                n if flag_alias(n).is_some() => {
                    args.overrides
                        .insert(flag_alias(n).unwrap().to_owned(), value);
                }
                n if SETTINGS.iter().any(|(key, _)| *key == n) => {
                    args.overrides.insert(n.to_owned(), value);
                }
                _ => {
                    args.flags.insert(name, value);
                }
            }
        } else if args.command.is_none() && args.positional.is_empty() {
            args.command = Some(arg);
        } else {
            args.positional.push(arg);
        }
    }
    Ok(args)
}

pub fn default_home() -> PathBuf {
    if let Ok(home) = env::var("KEYSTONE_HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home);
    }
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(|h| PathBuf::from(h).join(".keystone"))
        .unwrap_or_else(|| PathBuf::from(".keystone"))
}

fn restrict(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    let _ = (path, mode);
}

impl Config {
    /// Resolves the home, writes the commented template on first start, and merges
    /// file < environment < command line. `prepare` creates folders and the master key.
    pub fn load(args: &Args, prepare: bool) -> anyhow::Result<Self> {
        let home = args.home.clone().unwrap_or_else(default_home);
        let explicit = args.config.clone().or_else(|| {
            env::var("KEYSTONE_CONFIG")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        });
        let file = explicit
            .clone()
            .unwrap_or_else(|| home.join("keystone.properties"));
        if prepare {
            fs::create_dir_all(home.join("data"))?;
            fs::create_dir_all(home.join("secrets"))?;
            restrict(&home.join("secrets"), 0o700);
            if explicit.is_none() && !file.exists() {
                fs::write(&file, TEMPLATE)?;
                restrict(&file, 0o600);
            }
        }
        let from_file = if file.exists() {
            crate::props::parse_properties(&fs::read_to_string(&file)?)
        } else {
            anyhow::ensure!(
                explicit.is_none(),
                "Config file {} does not exist",
                file.display()
            );
            Default::default()
        };
        let get = |key: &str| -> Option<String> {
            if let Some(v) = args.overrides.get(key) {
                return Some(v.clone());
            }
            let (_, legacy) = SETTINGS.iter().find(|(k, _)| *k == key)?;
            for name in std::iter::once(env_name(key)).chain(legacy.iter().map(|s| s.to_string())) {
                if let Ok(v) = env::var(&name)
                    && !v.is_empty()
                {
                    return Some(v);
                }
            }
            from_file.get(key).filter(|v| !v.is_empty()).cloned()
        };
        let number = |key: &str, default: u64| -> anyhow::Result<u64> {
            get(key).map_or(Ok(default), |v| {
                v.trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{key} must be a whole number, got {v:?}"))
            })
        };
        let bool_of =
            |key: &str| get(key).is_some_and(|v| matches!(v.trim(), "true" | "1" | "yes"));

        let legacy_bind = env::var("KEYSTONE_BIND").ok().filter(|v| !v.is_empty());
        let bind = match (get("server.address"), get("server.port"), legacy_bind) {
            (None, None, Some(bind)) => bind,
            (address, port, _) => format!(
                "{}:{}",
                address.unwrap_or_else(|| "127.0.0.1".into()),
                port.unwrap_or_else(|| "8090".into())
            ),
        };
        let database_url = get("storage.database-url").unwrap_or_else(|| {
            format!(
                "sqlite://{}",
                home.join("data").join("keystone.db").display()
            )
        });

        // Master key: inline value, a file, or generated into the home on first start.
        let (master_key, master_key_source) = if let Some(inline) = get("vault.master-key") {
            (master_key(&inline)?, "configured value".to_owned())
        } else {
            let path = get("vault.master-key-file")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("secrets").join("master.key"));
            if path.exists() {
                let raw = fs::read_to_string(&path)?;
                (master_key(raw.trim())?, format!("file {}", path.display()))
            } else if prepare && get("vault.master-key-file").is_none() {
                let generated = generate_master_key();
                fs::write(&path, format!("{generated}\n"))?;
                restrict(&path, 0o600);
                eprintln!(
                    "\n  Keystone generated a new master key: {}\n  BACK IT UP NOW, separately from the data folder. Without it, nothing in the vault can be decrypted.\n",
                    path.display()
                );
                (master_key(&generated)?, format!("file {}", path.display()))
            } else {
                (None, "none".to_owned())
            }
        };

        let config = Self {
            config_file: file.exists().then(|| file.clone()),
            bind,
            database_url,
            ui_dir: get("ui.dir"),
            service_key: get("blog.service-key").unwrap_or_default(),
            portal_url: get("portal.url").unwrap_or_default(),
            client_id: get("portal.client-id").unwrap_or_default(),
            master_key,
            master_key_source,
            trust_proxy: bool_of("server.trust-proxy"),
            backup_dir: get("backup.dir")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("backups")),
            backup_interval_hours: number("backup.interval-hours", 24)?,
            backup_keep: number("backup.keep", 14)? as usize,
            failed_token_limit: number("security.failed-token-limit", 10)? as u32,
            lockout_minutes: number("security.lockout-minutes", 15)?,
            rotation_days: number("security.rotation-days", 90)? as i64,
            token_expiry_warning_days: number("security.token-expiry-warning-days", 14)? as i64,
            alerts_webhook_url: get("alerts.webhook-url"),
            log_level: get("log.level").unwrap_or_else(|| "info".into()),
            local_auth: bool_of("auth.local")
                || (get("bootstrap.admin-email").is_some()
                    && get("bootstrap.admin-password").is_some()),
            session_hours: number("auth.session-hours", 12)?.clamp(1, 720) as i64,
            accept_license: bool_of("setup.accept-license"),
            bootstrap_admin: match (
                get("bootstrap.admin-email"),
                get("bootstrap.admin-password"),
            ) {
                (Some(email), Some(password)) => Some((email, password)),
                _ => None,
            },
            fixed: SETTINGS
                .iter()
                .filter(|(key, legacy)| {
                    args.overrides.contains_key(*key)
                        || std::iter::once(env_name(key))
                            .chain(legacy.iter().map(|s| s.to_string()))
                            .any(|name| env::var(name).is_ok_and(|v| !v.is_empty()))
                })
                .map(|(key, _)| key.to_string())
                .collect(),
            home,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.service_key.is_empty() && self.service_key.len() < 32 {
            anyhow::bail!("blog.service-key must contain at least 32 characters");
        }
        if !self.portal_url.is_empty() {
            validate_url(&self.portal_url)?;
            anyhow::ensure!(
                !self.portal_url.ends_with('/'),
                "portal.url must match the issuer exactly, without a trailing slash"
            );
        }
        if let Some(url) = &self.alerts_webhook_url {
            validate_url(url)?;
        }
        crate::db::Dialect::of_url(&self.database_url)?;
        Ok(())
    }

    pub fn sso_configured(&self) -> bool {
        !self.portal_url.is_empty() && !self.client_id.is_empty()
    }
    /// Where the setup wizard writes its choices.
    pub fn writable_config_file(&self) -> PathBuf {
        self.config_file
            .clone()
            .unwrap_or_else(|| self.home.join("keystone.properties"))
    }
}

/// Sets keys in a properties file in place: an active `key=` line is replaced, a commented
/// `# key=` template line is uncommented, anything else is appended. Comments and order are kept.
pub fn set_in_file(path: &Path, entries: &[(&str, &str)]) -> anyhow::Result<()> {
    let text = fs::read_to_string(path).unwrap_or_else(|_| TEMPLATE.to_owned());
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    for (key, value) in entries {
        anyhow::ensure!(!value.contains(['\n', '\r']), "Invalid value for {key}");
        let line = format!("{key}={value}");
        let matches = |l: &str, commented: bool| {
            let t = l.trim_start();
            let t = if commented {
                t.strip_prefix('#').map(str::trim_start).unwrap_or("")
            } else {
                t
            };
            t.strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        };
        if let Some(i) = lines.iter().position(|l| matches(l, false)) {
            lines[i] = line;
        } else if let Some(i) = lines.iter().position(|l| matches(l, true)) {
            lines[i] = line;
        } else {
            lines.push(line);
        }
    }
    fs::write(path, lines.join("\n") + "\n")?;
    restrict(path, 0o600);
    Ok(())
}

pub fn generate_master_key() -> String {
    use aes_gcm::aead::{OsRng, rand_core::RngCore};
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    STANDARD.encode(key)
}

pub fn validate_url(raw: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(raw)?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "Use HTTPS (HTTP is allowed only on loopback): {raw}"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "URLs must not contain credentials or fragments"
    );
    Ok(())
}

/// 32 random bytes, base64 (`openssl rand -base64 32`).
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
                "The master key must be 32 bytes, base64 encoded (openssl rand -base64 32)"
            )
        })?;
    Ok(Some(MasterKey::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Args {
        parse_args(list.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn precedence_is_flags_then_env_then_file_then_defaults() {
        let home = env::temp_dir().join(format!("keystone-cfg-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).unwrap();
        fs::write(
            home.join("keystone.properties"),
            "server.port=7000\nportal.url=https://sso.example.com\nbackup.keep=3\n",
        )
        .unwrap();
        let mut a = args(&["--home", home.to_str().unwrap(), "--httpPort=7100"]);
        let config = Config::load(&a, true).unwrap();
        assert_eq!(config.bind, "127.0.0.1:7100");
        assert_eq!(config.portal_url, "https://sso.example.com");
        assert_eq!(config.backup_keep, 3);
        // First start generated a master key and kept it.
        assert!(config.master_key.is_some());
        let key = fs::read_to_string(home.join("secrets/master.key")).unwrap();
        a.overrides.clear();
        let again = Config::load(&a, true).unwrap();
        assert_eq!(again.bind, "127.0.0.1:7000");
        assert_eq!(
            fs::read_to_string(home.join("secrets/master.key")).unwrap(),
            key
        );
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn parses_commands_flags_and_passthrough() {
        let a = args(&[
            "run",
            "--token",
            "ksv_x",
            "--server.port=1",
            "--",
            "java",
            "-jar",
            "app.jar",
        ]);
        assert_eq!(a.command.as_deref(), Some("run"));
        assert_eq!(a.flags["token"], "ksv_x");
        assert_eq!(a.overrides["server.port"], "1");
        assert_eq!(a.positional, ["java", "-jar", "app.jar"]);
        assert_eq!(
            env_name("security.failed-token-limit"),
            "KEYSTONE_SECURITY_FAILED_TOKEN_LIMIT"
        );
    }
}
