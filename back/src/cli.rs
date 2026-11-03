//! `keystone <command>`: server operations (backup, restore, key rotation, Portal connection) and
//! a client for applications and CI (`pull`, `get`, `run`) that uses the same read-only tokens.
use crate::config;
use anyhow::{Context, bail, ensure};
use std::{fs, path::Path, process::Command, time::Duration};

pub const HELP: &str = "\
Keystone Vault: encrypted secrets and configuration for the Portal SSO suite

USAGE
  keystone [serve] [--config=FILE] [--home=DIR] [--server.port=8090] [--<setting>=VALUE]...

SERVER
  init                        Create the home folder, master key and config file, then exit
  serve                       Start the server (the default). Settings: see keystone.properties
  connect-portal ISSUER       Register Keystone with Portal SSO (an admin approves it) and save it
  config                      Show the effective configuration (secrets redacted)
  backup [DIR]                Write a consistent, still-encrypted snapshot of the database
  restore FILE                Replace the data with a backup, .db or .json (stop the server first)
  migrate --to URL            Copy everything into another database (e.g. MySQL) and switch to it
  rotate-master-key           Re-wrap every application key under a new master key
  gen-master-key              Print a new random master key (32 bytes, base64)
  healthcheck                 Exit 0 if the local server is ready (for container health checks)
  version                     Print the version

APPLICATIONS AND CI (read-only token; KEYSTONE_URL and KEYSTONE_TOKEN, or --url / --token)
  pull [--format=json|properties|env|shell] [--out=FILE]
                              Print or write the merged configuration
  get key NAME | get file NAME [--out=FILE]
                              One key's value or one whole file
  run -- COMMAND [ARGS]...    Start COMMAND with every key as an environment variable
                              (spring.datasource.url -> SPRING_DATASOURCE_URL)
  whoami                      Which application and environment the token reads

Docs: http://127.0.0.1:8090/docs (or /docs on your server)
";

/// Client commands talk to a running server; they never read local configuration.
struct Remote {
    url: String,
    token: String,
    http: reqwest::blocking::Client,
}

impl Remote {
    fn new(args: &config::Args) -> anyhow::Result<Self> {
        let url = args
            .flags
            .get("url")
            .cloned()
            .or_else(|| std::env::var("KEYSTONE_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:8090".into());
        let token = args
            .flags
            .get("token")
            .cloned()
            .or_else(|| std::env::var("KEYSTONE_TOKEN").ok())
            .filter(|t| !t.is_empty())
            .context(
                "Set KEYSTONE_TOKEN (or --token) to an application token from the Keystone console",
            )?;
        Ok(Self {
            url: url.trim_end_matches('/').to_owned(),
            token,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent(format!("keystone-cli/{}", config::VERSION))
                .build()?,
        })
    }
    fn get(&self, path: &str) -> anyhow::Result<reqwest::blocking::Response> {
        let response = self
            .http
            .get(format!("{}{path}", self.url))
            .bearer_auth(&self.token)
            .send()
            .with_context(|| format!("Could not reach Keystone at {}", self.url))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
                .unwrap_or(body);
            bail!("Keystone answered {status}: {message}");
        }
        Ok(response)
    }
}

fn write_or_print(bytes: &[u8], out: Option<&String>) -> anyhow::Result<()> {
    match out {
        Some(path) => {
            fs::write(path, bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
            eprintln!("Wrote {path}");
        }
        None => {
            use std::io::Write;
            std::io::stdout().write_all(bytes)?;
        }
    }
    Ok(())
}

pub fn pull(args: &config::Args) -> anyhow::Result<()> {
    let remote = Remote::new(args)?;
    let format = args
        .flags
        .get("format")
        .map(String::as_str)
        .unwrap_or("properties");
    let body = remote
        .get(&format!("/api/v1/vault/config?format={format}"))?
        .bytes()?;
    write_or_print(&body, args.flags.get("out"))
}

pub fn get(args: &config::Args) -> anyhow::Result<()> {
    let remote = Remote::new(args)?;
    let (kind, name) = match args.positional.as_slice() {
        [kind, name] if kind == "key" || kind == "file" => (format!("{kind}s"), name),
        _ => bail!("Usage: keystone get key NAME | keystone get file NAME [--out=FILE]"),
    };
    let body = remote
        .get(&format!("/api/v1/vault/{kind}/{name}"))?
        .bytes()?;
    write_or_print(&body, args.flags.get("out"))
}

pub fn whoami(args: &config::Args) -> anyhow::Result<()> {
    let remote = Remote::new(args)?;
    println!("{}", remote.get("/api/v1/vault/whoami")?.text()?);
    Ok(())
}

/// Fetches the configuration, then runs the command with it in the environment. Existing
/// variables win, so a deployment can still override a single value.
pub fn run(args: &config::Args) -> anyhow::Result<()> {
    ensure!(
        !args.positional.is_empty(),
        "Usage: keystone run -- COMMAND [ARGS]..."
    );
    let remote = Remote::new(args)?;
    let config: std::collections::BTreeMap<String, String> =
        remote.get("/api/v1/vault/config?format=json")?.json()?;
    let mut command = Command::new(&args.positional[0]);
    command.args(&args.positional[1..]);
    for (key, value) in &config {
        let name = crate::props::env_name(key);
        if std::env::var_os(&name).is_none() {
            command.env(name, value);
        }
    }
    // The token has done its job; the child does not need it.
    command.env_remove("KEYSTONE_TOKEN");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        bail!("Could not start {}: {error}", args.positional[0]);
    }
    #[cfg(not(unix))]
    {
        let status = command.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Prepares a home (and an explicitly named config file) without starting the server, so an
/// installer or an operator can review keystone.properties before the first start.
pub fn init(args: &config::Args) -> anyhow::Result<()> {
    let explicit = args.config.clone().or_else(|| {
        std::env::var("KEYSTONE_CONFIG")
            .ok()
            .filter(|v| !v.is_empty())
            .map(Into::into)
    });
    if let Some(file) = &explicit
        && !file.exists()
    {
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(file, config::TEMPLATE)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
        }
    }
    let cfg = config::Config::load(args, true)?;
    println!("Keystone Vault is ready to start.");
    println!("  home         {}", cfg.home.display());
    println!(
        "  config file  {}",
        cfg.config_file
            .as_ref()
            .map_or("(none)".into(), |p| p.display().to_string())
    );
    println!("  master key   {}", cfg.master_key_source);
    println!();
    println!(
        "Next: connect Portal SSO with  keystone connect-portal https://your-portal  (or set portal.url"
    );
    println!("and portal.client-id in the config file), then run  keystone");
    Ok(())
}

pub fn healthcheck(cfg: &config::Config) -> anyhow::Result<()> {
    let port = cfg.bind.rsplit(':').next().unwrap_or("8090");
    let host = cfg
        .bind
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or("127.0.0.1");
    let host = if host == "0.0.0.0" || host == "[::]" {
        "127.0.0.1"
    } else {
        host
    };
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?
        .get(format!("http://{host}:{port}/health/ready"))
        .send()?;
    ensure!(
        response.status().is_success(),
        "not ready: {}",
        response.status()
    );
    Ok(())
}

pub fn show_config(cfg: &config::Config) {
    let redact = |s: &str| {
        if s.is_empty() {
            "(not set)".to_owned()
        } else {
            s.to_owned()
        }
    };
    println!("Keystone Vault {}", config::VERSION);
    println!("  home                 {}", cfg.home.display());
    println!(
        "  config file          {}",
        cfg.config_file
            .as_ref()
            .map_or("(none)".into(), |p| p.display().to_string())
    );
    println!("  listen               {}", cfg.bind);
    println!("  database             {}", cfg.database_url);
    println!(
        "  console              {}",
        cfg.ui_dir
            .clone()
            .unwrap_or_else(|| if crate::ui::embedded() {
                "embedded".into()
            } else {
                "NOT BUILT".into()
            })
    );
    println!("  portal.url           {}", redact(&cfg.portal_url));
    println!("  portal.client-id     {}", redact(&cfg.client_id));
    println!("  master key           {}", cfg.master_key_source);
    println!("  trust proxy          {}", cfg.trust_proxy);
    println!(
        "  backups              every {}h, keep {}, in {}",
        cfg.backup_interval_hours,
        cfg.backup_keep,
        cfg.backup_dir.display()
    );
    println!(
        "  token lockout        {} failures / {} min",
        cfg.failed_token_limit, cfg.lockout_minutes
    );
    println!(
        "  alerts webhook       {}",
        if cfg.alerts_webhook_url.is_some() {
            "set in config"
        } else {
            "console or none"
        }
    );
}

async fn open_db(cfg: &config::Config) -> anyhow::Result<crate::db::Db> {
    crate::db::connect(&cfg.database_url).await
}

fn server_running(cfg: &config::Config) -> bool {
    use std::net::ToSocketAddrs;
    let address = cfg
        .bind
        .replace("0.0.0.0", "127.0.0.1")
        .replace("[::]", "[::1]");
    address
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .is_some_and(|a| {
            std::net::TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_ok()
        })
}

pub async fn backup(cfg: &config::Config, args: &config::Args) -> anyhow::Result<()> {
    let dir = args
        .positional
        .first()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cfg.backup_dir.clone());
    let db = open_db(cfg).await?;
    let path = crate::backup::snapshot(&db, &dir, "manual").await?;
    println!("Backup written: {}", path.display());
    println!(
        "It is encrypted with the master key ({}). Store the key separately.",
        cfg.master_key_source
    );
    Ok(())
}

/// Opens a backup: a SQLite snapshot (`.db`) read-only, or a portable export (`.json`).
async fn read_backup(file: &str) -> anyhow::Result<serde_json::Value> {
    if file.ends_with(".json") {
        return serde_json::from_slice(&fs::read(file)?)
            .context("The file is not a Keystone Vault export");
    }
    let snapshot = crate::db::open(&format!("sqlite://{file}"), true)
        .await
        .context("The file is not a readable Keystone backup")?;
    let data = crate::db::export(&snapshot).await?;
    snapshot.close().await;
    Ok(data)
}

/// The kek_check value or a wrapped app key from an export, checked against `master`.
fn verify_export(
    data: &serde_json::Value,
    master: &crate::crypto::MasterKey,
) -> anyhow::Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let tables = &data["tables"];
    if let Some(row) = tables["vault_meta"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r[0] == "kek_check"))
    {
        let check = STANDARD.decode(row[1].as_str().unwrap_or(""))?;
        ensure!(
            master.verify(&check),
            "This backup was written with a different master key"
        );
        return Ok(());
    }
    if let Some(app) = tables["vault_apps"]
        .as_array()
        .and_then(|rows| rows.first())
    {
        let wrapped = STANDARD.decode(app[4].as_str().unwrap_or(""))?;
        ensure!(
            master
                .unwrap_data_key(app[0].as_str().unwrap_or(""), &wrapped)
                .is_ok(),
            "This backup was written with a different master key"
        );
    }
    Ok(())
}

/// Replaces the configured database's contents with a backup (either engine, either format).
pub async fn restore(cfg: &config::Config, args: &config::Args) -> anyhow::Result<()> {
    let file = args
        .positional
        .first()
        .context("Usage: keystone restore FILE")?;
    ensure!(Path::new(file).exists(), "{file} does not exist");
    ensure!(
        !server_running(cfg) || args.flags.contains_key("force"),
        "Keystone is running on {}. Stop it first (or pass --force if that is a different server).",
        cfg.bind
    );
    let master = cfg.master_key.as_ref().context(
        "No master key is configured; restore needs the key the backup was written with",
    )?;
    // Prove the backup opens with this key before touching anything.
    let data = read_backup(file).await?;
    verify_export(&data, master)?;
    let db = open_db(cfg).await?;
    let saved = crate::backup::snapshot(&db, &cfg.backup_dir, "pre-restore").await?;
    println!("Current data saved as {}", saved.display());
    let rows = crate::db::import(&db, &data).await?;
    println!(
        "Restored {rows} rows from {file} into {}. Start Keystone to use it.",
        crate::db::redact(&cfg.database_url)
    );
    Ok(())
}

/// `keystone migrate --to mysql://user:pass@host:3306/keystone`: copies every table into another
/// database (created and migrated if empty), then points keystone.properties at it.
pub async fn migrate(cfg: &config::Config, args: &config::Args) -> anyhow::Result<()> {
    let target = args
        .flags
        .get("to")
        .context("Usage: keystone migrate --to mysql://user:password@host:3306/keystone")?;
    ensure!(
        !server_running(cfg) || args.flags.contains_key("force"),
        "Stop Keystone before migrating its database."
    );
    let from = open_db(cfg).await?;
    let to = crate::db::connect(target).await?;
    let (existing,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_apps")
        .fetch_one(&to)
        .await?;
    ensure!(
        existing == 0 || args.flags.contains_key("force"),
        "The target already holds {existing} applications. Use --force to replace them."
    );
    let rows = crate::db::copy_all(&from, &to).await?;
    if let Some(master) = &cfg.master_key {
        crate::verify_master_key(&to, master).await?;
    }
    let file = cfg
        .config_file
        .clone()
        .unwrap_or_else(|| cfg.home.join("keystone.properties"));
    config::set_in_file(&file, &[("storage.database-url", target)])?;
    println!("Copied {rows} rows into {}.", crate::db::redact(target));
    println!(
        "Saved storage.database-url to {}. Start Keystone to use it.",
        file.display()
    );
    println!("The previous database is untouched; keep it until you have checked the new one.");
    Ok(())
}

pub async fn rotate_master_key(cfg: &config::Config, args: &config::Args) -> anyhow::Result<()> {
    ensure!(
        !server_running(cfg) || args.flags.contains_key("force"),
        "Stop Keystone before rotating the master key (it holds the current key in memory)."
    );
    let old = cfg
        .master_key
        .as_ref()
        .context("No master key is configured")?;
    let db = open_db(cfg).await?;
    crate::verify_master_key(&db, old).await?;
    let encoded = config::generate_master_key();
    let next = config::master_key(&encoded)?.expect("generated key is valid");

    // Write the new key down before the database depends on it.
    let secrets = cfg.home.join("secrets");
    fs::create_dir_all(&secrets)?;
    let staged = secrets.join("master.key.next");
    fs::write(&staged, format!("{encoded}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
    }
    let pre = crate::backup::snapshot(&db, &cfg.backup_dir, "pre-rotation").await?;

    let mut tx = db.begin().await?;
    let apps: Vec<(String, Vec<u8>)> = sqlx::query_as("SELECT id, wrapped_key FROM vault_apps")
        .fetch_all(&mut *tx)
        .await?;
    for (app, wrapped) in &apps {
        let rewrapped = old
            .rewrap(&next, app, wrapped)
            .with_context(|| format!("Could not re-wrap {app}"))?;
        sqlx::query("UPDATE vault_apps SET wrapped_key = ? WHERE id = ?")
            .bind(rewrapped)
            .bind(app)
            .execute(&mut *tx)
            .await?;
    }
    let settings: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT `key`, value FROM vault_settings")
            .fetch_all(&mut *tx)
            .await?;
    for (key, sealed) in &settings {
        let plain = old.open_setting(key, sealed)?;
        sqlx::query("UPDATE vault_settings SET value = ? WHERE `key` = ?")
            .bind(next.seal_setting(key, &plain)?)
            .bind(key)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM vault_meta WHERE `key` = 'kek_check'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO vault_meta (`key`, value) VALUES ('kek_check', ?)")
        .bind(next.check_value()?)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO audit_events (subject, event, target, created_at) VALUES ('system:cli', 'vault.master-key.rotate', ?, ?)")
        .bind(format!("{} application keys re-wrapped", apps.len()))
        .bind(crate::now() as i64)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    println!(
        "Re-wrapped {} application keys under a new master key.",
        apps.len()
    );
    println!("A snapshot from before the rotation: {}", pre.display());
    if let Some(file) = cfg.master_key_source.strip_prefix("file ") {
        let current = Path::new(file);
        let retired = current.with_extension(format!("key.retired-{}", crate::now()));
        fs::rename(current, &retired)?;
        fs::rename(&staged, current)?;
        println!("New key installed at {}.", current.display());
        println!(
            "The old key is kept at {} (needed only to restore older backups).",
            retired.display()
        );
    } else {
        println!(
            "Your key comes from configuration. Replace vault.master-key (or KEYSTONE_VAULT_MASTER_KEY) with:"
        );
        println!("  {}", staged.display());
        println!("before starting Keystone again; the old key no longer opens this database.");
    }
    println!("Back up the new key now.");
    Ok(())
}

pub async fn connect_portal(cfg: &config::Config, args: &config::Args) -> anyhow::Result<()> {
    crate::connect::run(cfg, args).await
}
