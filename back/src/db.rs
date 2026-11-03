//! Storage on SQLite (built in, the default) or MySQL 8+ / MariaDB, through sqlx's
//! database-agnostic driver. SQL is written to the common subset of both; the few differences
//! (insert-or-ignore, upsert) go through [`Dialect`]. Timestamps are always bound from Rust, never
//! left to database defaults, so both engines record identical values.
//!
//! The portable copy below backs three features: backups and restores on MySQL (a JSON export),
//! restoring a SQLite snapshot into MySQL, and moving a running vault from SQLite to MySQL during
//! setup or with `keystone migrate`.
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use sqlx::{Any, AnyConnection, AnyPool, Row, pool::PoolOptions};
use std::time::Duration;

pub type Db = AnyPool;
pub type Conn = AnyConnection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    MySql,
}

impl Dialect {
    pub fn of_url(url: &str) -> anyhow::Result<Self> {
        if url.starts_with("sqlite:") {
            Ok(Self::Sqlite)
        } else if url.starts_with("mysql:") || url.starts_with("mariadb:") {
            Ok(Self::MySql)
        } else {
            bail!(
                "storage.database-url must start with sqlite:// or mysql:// (got {})",
                redact(url)
            )
        }
    }
    pub fn of(conn: &Conn) -> Self {
        if conn.backend_name().eq_ignore_ascii_case("mysql") {
            Self::MySql
        } else {
            Self::Sqlite
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Sqlite => "SQLite",
            Self::MySql => "MySQL",
        }
    }
    /// `INSERT … ` that silently skips a row whose key already exists.
    pub fn insert_ignore(self) -> &'static str {
        match self {
            Self::Sqlite => "INSERT OR IGNORE INTO",
            Self::MySql => "INSERT IGNORE INTO",
        }
    }
    /// Upsert clause. `take` columns get the new row's value; `set` are raw assignments that may
    /// use the existing row (`current_version = current_version + 1`) or bound parameters.
    pub fn upsert(self, conflict: &str, take: &[&str], set: &[&str]) -> String {
        let mut parts: Vec<String> = match self {
            Self::Sqlite => take.iter().map(|c| format!("{c} = excluded.{c}")).collect(),
            Self::MySql => take.iter().map(|c| format!("{c} = VALUES({c})")).collect(),
        };
        parts.extend(set.iter().map(|s| s.to_string()));
        match self {
            Self::Sqlite => format!(
                "ON CONFLICT ({conflict}) DO UPDATE SET {}",
                parts.join(", ")
            ),
            Self::MySql => format!("ON DUPLICATE KEY UPDATE {}", parts.join(", ")),
        }
    }
}

/// The URL with any password replaced, for logs and the console.
pub fn redact(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("****"));
            u.to_string()
        }
        _ => url.to_owned(),
    }
}

/// SQLite through the agnostic driver needs `mode=rwc` to create the file on first start, and an
/// in-memory database must be one named, shared database, or every pooled connection would get
/// its own empty one.
fn normalise(url: &str) -> String {
    if url.starts_with("sqlite:") && url.contains(":memory:") {
        format!(
            "sqlite:file:keystone-{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4().simple()
        )
    } else if url.starts_with("sqlite:") && !url.contains("mode=") {
        format!("{url}{}mode=rwc", if url.contains('?') { '&' } else { '?' })
    } else {
        url.to_owned()
    }
}

/// Opens a pool and applies the schema migrations for its engine.
pub async fn connect(url: &str) -> anyhow::Result<Db> {
    let db = open(url, false).await?;
    migrate(&db, Dialect::of_url(url)?).await?;
    Ok(db)
}

/// Opens a pool without migrating (read-only snapshots, connection tests).
pub async fn open(url: &str, read_only: bool) -> anyhow::Result<Db> {
    sqlx::any::install_default_drivers();
    let dialect = Dialect::of_url(url)?;
    let mut url = normalise(url);
    if read_only && dialect == Dialect::Sqlite {
        url = url.replace("mode=rwc", "mode=ro");
    }
    if let Some(path) = url
        .strip_prefix("sqlite://")
        .map(|p| p.split('?').next().unwrap_or(p))
        && !url.contains("mode=memory")
        && let Some(parent) = std::path::Path::new(path).parent()
        && !read_only
    {
        std::fs::create_dir_all(parent).ok();
    }
    let options = PoolOptions::<Any>::new()
        .max_connections(if dialect == Dialect::Sqlite { 5 } else { 10 })
        // A shared in-memory database lives only while a connection to it is open.
        .min_connections(u32::from(url.contains("mode=memory")))
        .acquire_timeout(Duration::from_secs(5));
    let options = if dialect == Dialect::Sqlite {
        options.after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("PRAGMA foreign_keys = ON")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("PRAGMA busy_timeout = 5000")
                    .execute(&mut *conn)
                    .await?;
                let _ = sqlx::query("PRAGMA journal_mode = WAL")
                    .execute(&mut *conn)
                    .await;
                Ok(())
            })
        })
    } else {
        options
    };
    options.connect(&url).await.with_context(|| {
        format!(
            "Could not open the {} database at {}",
            dialect.name(),
            redact(&url)
        )
    })
}

pub async fn migrate(db: &Db, dialect: Dialect) -> anyhow::Result<()> {
    match dialect {
        Dialect::Sqlite => sqlx::migrate!("./migrations/sqlite").run(db).await?,
        Dialect::MySql => sqlx::migrate!("./migrations/mysql").run(db).await?,
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Portable copy, export and import

#[derive(Clone, Copy)]
enum Col {
    Int,
    Text,
    Blob,
}
use Col::{Blob, Int, Text};

/// Every table that holds data worth keeping, parents before children. Sessions are not copied:
/// people sign in again after a restore.
const TABLES: &[(&str, &[(&str, Col)])] = &[
    ("vault_meta", &[("`key`", Text), ("value", Blob)]),
    (
        "keystone_state",
        &[("name", Text), ("value", Text), ("updated_at", Int)],
    ),
    (
        "vault_settings",
        &[
            ("`key`", Text),
            ("value", Blob),
            ("updated_by", Text),
            ("updated_at", Int),
        ],
    ),
    (
        "vault_apps",
        &[
            ("id", Text),
            ("name", Text),
            ("description", Text),
            ("portal_client_id", Text),
            ("wrapped_key", Blob),
            ("created_by", Text),
            ("created_at", Int),
            ("updated_at", Int),
        ],
    ),
    (
        "vault_environments",
        &[
            ("app_id", Text),
            ("name", Text),
            ("created_at", Int),
            ("protected", Int),
        ],
    ),
    (
        "vault_items",
        &[
            ("id", Int),
            ("app_id", Text),
            ("environment", Text),
            ("kind", Text),
            ("name", Text),
            ("current_version", Int),
            ("content_type", Text),
            ("updated_by", Text),
            ("updated_at", Int),
        ],
    ),
    (
        "vault_versions",
        &[
            ("item_id", Int),
            ("version", Int),
            ("ciphertext", Blob),
            ("size", Int),
            ("created_by", Text),
            ("created_at", Int),
        ],
    ),
    (
        "vault_tokens",
        &[
            ("id", Text),
            ("app_id", Text),
            ("environment", Text),
            ("name", Text),
            ("secret_hash", Blob),
            ("created_by", Text),
            ("created_at", Int),
            ("expires_at", Int),
            ("last_used_at", Int),
            ("revoked_at", Int),
            ("allowed_cidrs", Text),
        ],
    ),
    (
        "vault_change_requests",
        &[
            ("id", Int),
            ("ref", Text),
            ("app_id", Text),
            ("environment", Text),
            ("operation", Text),
            ("kind", Text),
            ("name", Text),
            ("payload", Blob),
            ("content_type", Text),
            ("summary", Text),
            ("requested_by", Text),
            ("created_at", Int),
            ("status", Text),
            ("decided_by", Text),
            ("decided_at", Int),
            ("note", Text),
        ],
    ),
    (
        "local_users",
        &[
            ("id", Int),
            ("email", Text),
            ("name", Text),
            ("password_hash", Text),
            ("roles", Text),
            ("disabled", Int),
            ("created_at", Int),
            ("updated_at", Int),
            ("last_login_at", Int),
        ],
    ),
    (
        "audit_events",
        &[
            ("id", Int),
            ("subject", Text),
            ("event", Text),
            ("created_at", Int),
            ("target", Text),
            ("ip", Text),
            ("user_agent", Text),
        ],
    ),
    (
        "reactions",
        &[
            ("slug", Text),
            ("visitor", Text),
            ("action", Text),
            ("bucket", Text),
            ("created_at", Int),
        ],
    ),
];

fn read_value(row: &sqlx::any::AnyRow, index: usize, col: Col) -> anyhow::Result<Value> {
    Ok(match col {
        Int => row
            .try_get::<Option<i64>, _>(index)?
            .map_or(Value::Null, Value::from),
        Text => row
            .try_get::<Option<String>, _>(index)?
            .map_or(Value::Null, Value::from),
        Blob => row
            .try_get::<Option<Vec<u8>>, _>(index)?
            .map_or(Value::Null, |b| Value::from(STANDARD.encode(b))),
    })
}

/// Every table as JSON rows (blobs base64), in dependency order.
pub async fn export(db: &Db) -> anyhow::Result<Value> {
    let mut tables = Map::new();
    for (table, cols) in TABLES {
        let names: Vec<&str> = cols.iter().map(|(n, _)| *n).collect();
        let rows = sqlx::query(&format!("SELECT {} FROM {table}", names.join(", ")))
            .fetch_all(db)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let mut values = Vec::with_capacity(cols.len());
            for (i, (_, col)) in cols.iter().enumerate() {
                values.push(read_value(row, i, *col)?);
            }
            out.push(Value::Array(values));
        }
        tables.insert(table.to_string(), Value::Array(out));
    }
    Ok(json!({
        "format": "keystone-vault-export",
        "formatVersion": 1,
        "createdAt": crate::now(),
        "keystoneVersion": crate::config::VERSION,
        "tables": tables,
    }))
}

/// Replaces every table's contents with `data` (an [`export`]) in one transaction.
pub async fn import(db: &Db, data: &Value) -> anyhow::Result<usize> {
    if data["format"] != "keystone-vault-export" {
        bail!("Not a Keystone Vault export");
    }
    let mut tx = db.begin().await?;
    let dialect = Dialect::of(&tx);
    sqlx::query("DELETE FROM local_sessions")
        .execute(&mut *tx)
        .await?;
    for (table, _) in TABLES.iter().rev() {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await?;
    }
    let mut copied = 0;
    for (table, cols) in TABLES {
        let names: Vec<&str> = cols.iter().map(|(n, _)| *n).collect();
        let sql = format!(
            "INSERT INTO {table} ({}) VALUES ({})",
            names.join(", "),
            vec!["?"; cols.len()].join(", ")
        );
        for row in data["tables"][*table]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let values = row.as_array().context("Malformed export row")?;
            let mut query = sqlx::query(&sql);
            for ((_, col), value) in cols.iter().zip(values) {
                query = match (col, value) {
                    (Int, v) => query.bind(v.as_i64()),
                    (Text, v) => query.bind(v.as_str().map(str::to_owned)),
                    (Blob, Value::Null) => query.bind(None::<Vec<u8>>),
                    (Blob, v) => query.bind(Some(STANDARD.decode(v.as_str().unwrap_or(""))?)),
                };
            }
            query
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Importing {table}"))?;
            copied += 1;
        }
    }
    // MySQL continues AUTO_INCREMENT after the largest id by itself; nothing else to adjust.
    let _ = dialect;
    tx.commit().await?;
    Ok(copied)
}

/// Copies everything from one database into another (which is emptied first).
pub async fn copy_all(from: &Db, to: &Db) -> anyhow::Result<usize> {
    let data = export(from).await?;
    import(to, &data).await
}

/// Test helper: a private database per test. With `KEYSTONE_TEST_MYSQL_URL`
/// (e.g. mysql://root:pw@127.0.0.1:3306) every test gets its own new MySQL schema, so CI runs the
/// whole suite against MySQL too; otherwise an in-memory SQLite database.
pub async fn test_url() -> String {
    match std::env::var("KEYSTONE_TEST_MYSQL_URL") {
        Ok(base) if !base.is_empty() => {
            sqlx::any::install_default_drivers();
            let name = format!("ks_test_{}", uuid::Uuid::new_v4().simple());
            let admin = PoolOptions::<Any>::new()
                .max_connections(1)
                .connect(&base)
                .await
                .expect("KEYSTONE_TEST_MYSQL_URL is not reachable");
            sqlx::query(&format!("CREATE DATABASE {name}"))
                .execute(&admin)
                .await
                .expect("create test database");
            admin.close().await;
            format!("{}/{name}", base.trim_end_matches('/'))
        }
        _ => "sqlite::memory:".into(),
    }
}
