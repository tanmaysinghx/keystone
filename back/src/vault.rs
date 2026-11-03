//! Vault storage and the administrator API (Portal SSO, `ROLE_ADMIN`).
use crate::{
    AppState,
    auth::Claims,
    client::Actor,
    crypto::{self, DataKey},
    error::ApiError,
    props,
};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{SqliteConnection, SqlitePool};

pub const MAX_VALUE: usize = 64 * 1024;
pub const MAX_FILE: usize = 512 * 1024;
const MAX_ITEMS_PER_ENV: i64 = 1000;
const MAX_ENVIRONMENTS: i64 = 50;
const MAX_TOKENS_PER_APP: i64 = 50;
const KEEP_VERSIONS: i64 = 20;

type AppRow = (
    String,
    String,
    String,
    Option<String>,
    i64,
    i64,
    String,
    i64,
    i64,
    i64,
);
type TokenRow = (
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);
pub const DEFAULT_ENV: &str = "default";

// ---------------------------------------------------------------------------------------------
// Validation and errors

fn bad(code: &'static str, message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, code, message)
}
fn missing(code: &'static str, message: &'static str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, code, message)
}
fn internal() -> ApiError {
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "vault_error",
        "The vault could not complete the operation",
    )
}
pub fn sealed() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "vault_sealed",
        "The vault is sealed: KEYSTONE_MASTER_KEY is not configured",
    )
}

fn slug(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
/// Same shape as a Portal SSO client_id slug.
pub fn valid_app_id(value: &str) -> bool {
    slug(value, 63)
}
pub fn valid_environment(value: &str) -> bool {
    slug(value, 40)
}
/// Property names: `spring.datasource.password`, `DB_PASSWORD`, `app.hosts[0]`.
pub fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-[]".contains(&b))
}
pub fn valid_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn check_app(app: &str) -> Result<(), ApiError> {
    if valid_app_id(app) {
        Ok(())
    } else {
        Err(bad(
            "invalid_app",
            "Application ids are lowercase letters, digits and hyphens (Portal client_id style)",
        ))
    }
}
fn check_environment(environment: &str) -> Result<(), ApiError> {
    if valid_environment(environment) {
        Ok(())
    } else {
        Err(bad(
            "invalid_environment",
            "Environment names are lowercase letters, digits and hyphens",
        ))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Key,
    File,
}
impl Kind {
    pub fn from_segment(segment: &str) -> Result<Self, ApiError> {
        match segment {
            "keys" => Ok(Self::Key),
            "files" => Ok(Self::File),
            _ => Err(missing("not_found", "Endpoint not found")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::File => "file",
        }
    }
    pub fn check_name(self, name: &str) -> Result<(), ApiError> {
        let ok = match self {
            Self::Key => valid_key(name),
            Self::File => valid_file(name),
        };
        if ok {
            Ok(())
        } else if self == Self::Key {
            Err(bad(
                "invalid_key",
                "Key names use letters, digits, '.', '_', '-', '[' and ']' (at most 200)",
            ))
        } else {
            Err(bad(
                "invalid_file_name",
                "File names use letters, digits, '.', '_' and '-' (at most 128)",
            ))
        }
    }
}

pub fn admin_subject(claims: &Claims) -> String {
    let who = claims
        .email
        .as_deref()
        .filter(|email| !email.is_empty())
        .unwrap_or(&claims.sub);
    format!("admin:{who}")
}

/// Audit is part of the operation: if the event cannot be recorded, the operation fails.
pub async fn audit(
    db: &SqlitePool,
    actor: &Actor,
    event: &str,
    target: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_events (subject, event, target, ip, user_agent) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&actor.subject)
    .bind(event)
    .bind(target)
    .bind(&actor.ip)
    .bind(&actor.user_agent)
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Storage

pub async fn data_key(state: &AppState, app: &str) -> Result<DataKey, ApiError> {
    let master = state.config.master_key.as_ref().ok_or_else(sealed)?;
    let (wrapped,): (Vec<u8>,) = sqlx::query_as("SELECT wrapped_key FROM vault_apps WHERE id = ?")
        .bind(app)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| missing("app_not_found", "Application not found"))?;
    master.unwrap_data_key(app, &wrapped).map_err(|_| {
        tracing::error!(
            app,
            "Data key could not be unwrapped; check KEYSTONE_MASTER_KEY"
        );
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault_key_mismatch",
            "The configured master key cannot open this application's data",
        )
    })
}

async fn ensure_environment(db: &SqlitePool, app: &str, environment: &str) -> Result<(), ApiError> {
    let found: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM vault_environments WHERE app_id = ? AND name = ?")
            .bind(app)
            .bind(environment)
            .fetch_optional(db)
            .await?;
    found
        .map(|_| ())
        .ok_or_else(|| missing("environment_not_found", "Environment not found"))
}

#[allow(clippy::too_many_arguments)]
pub async fn write_item(
    conn: &mut SqliteConnection,
    key: &DataKey,
    app: &str,
    environment: &str,
    kind: Kind,
    name: &str,
    bytes: &[u8],
    content_type: &str,
    actor: &str,
) -> Result<i64, ApiError> {
    let (count, exists): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(kind = ? AND name = ?), 0) FROM vault_items WHERE app_id = ? AND environment = ?",
    )
    .bind(kind.as_str())
    .bind(name)
    .bind(app)
    .bind(environment)
    .fetch_one(&mut *conn)
    .await?;
    if exists == 0 && count >= MAX_ITEMS_PER_ENV {
        return Err(bad(
            "too_many_items",
            "An environment holds at most 1000 keys and files",
        ));
    }
    let (id, version): (i64, i64) = sqlx::query_as(
        "INSERT INTO vault_items (app_id, environment, kind, name, current_version, content_type, updated_by)
         VALUES (?, ?, ?, ?, 1, ?, ?)
         ON CONFLICT (app_id, environment, kind, name) DO UPDATE SET
           current_version = current_version + 1, content_type = excluded.content_type,
           updated_by = excluded.updated_by, updated_at = unixepoch()
         RETURNING id, current_version",
    )
    .bind(app)
    .bind(environment)
    .bind(kind.as_str())
    .bind(name)
    .bind(content_type)
    .bind(actor)
    .fetch_one(&mut *conn)
    .await?;
    let location = crypto::location(app, environment, kind.as_str(), name, version);
    let sealed = key.seal(bytes, &location).map_err(|_| internal())?;
    sqlx::query(
        "INSERT INTO vault_versions (item_id, version, ciphertext, size, created_by) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(version)
    .bind(sealed)
    .bind(bytes.len() as i64)
    .bind(actor)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM vault_versions WHERE item_id = ? AND version <= ?")
        .bind(id)
        .bind(version - KEEP_VERSIONS)
        .execute(&mut *conn)
        .await?;
    Ok(version)
}

pub struct Stored {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub version: i64,
}

#[allow(clippy::too_many_arguments)]
pub async fn read_item(
    db: &SqlitePool,
    key: &DataKey,
    app: &str,
    environment: &str,
    kind: Kind,
    name: &str,
    version: Option<i64>,
) -> Result<Stored, ApiError> {
    let row: Option<(i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT v.version, i.content_type, v.ciphertext FROM vault_items i
         JOIN vault_versions v ON v.item_id = i.id
         WHERE i.app_id = ? AND i.environment = ? AND i.kind = ? AND i.name = ?
           AND v.version = COALESCE(?, i.current_version)",
    )
    .bind(app)
    .bind(environment)
    .bind(kind.as_str())
    .bind(name)
    .bind(version)
    .fetch_optional(db)
    .await?;
    let (version, content_type, ciphertext) =
        row.ok_or_else(|| missing("item_not_found", "No such key, file or version"))?;
    let location = crypto::location(app, environment, kind.as_str(), name, version);
    let bytes = key.open(&ciphertext, &location).map_err(|_| {
        tracing::error!(app, environment, name, "Stored value failed authentication");
        internal()
    })?;
    Ok(Stored {
        bytes,
        content_type,
        version,
    })
}

/// One configuration layer. Spring Cloud Config semantics: earlier layers win.
pub struct Layer {
    pub name: String,
    pub source: props::Map,
}

/// The configuration an application sees in `environment`, highest precedence first:
/// keys(env) > .properties files(env) > keys(default) > .properties files(default).
/// Files are merged in name order, so `application-z.properties` overrides `application.properties`.
pub async fn resolve(
    db: &SqlitePool,
    key: &DataKey,
    app: &str,
    environment: &str,
) -> Result<Vec<Layer>, ApiError> {
    let rows: Vec<(String, String, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT i.environment, i.kind, i.name, i.current_version, v.ciphertext FROM vault_items i
         JOIN vault_versions v ON v.item_id = i.id AND v.version = i.current_version
         WHERE i.app_id = ? AND i.environment IN (?, ?) ORDER BY i.name",
    )
    .bind(app)
    .bind(environment)
    .bind(DEFAULT_ENV)
    .fetch_all(db)
    .await?;
    let mut order = vec![environment];
    if environment != DEFAULT_ENV {
        order.push(DEFAULT_ENV);
    }
    let mut layers = Vec::new();
    for env in order {
        let mut keys = props::Map::new();
        let mut files = props::Map::new();
        for (row_env, kind, name, version, ciphertext) in &rows {
            if row_env != env || (kind == "file" && !name.ends_with(".properties")) {
                continue;
            }
            let location = crypto::location(app, env, kind, name, *version);
            let plain = key.open(ciphertext, &location).map_err(|_| internal())?;
            let text = String::from_utf8_lossy(&plain);
            if kind == "key" {
                keys.insert(name.clone(), text.into_owned());
            } else {
                files.extend(props::parse_properties(&text));
            }
        }
        for (suffix, source) in [("", keys), ("/files", files)] {
            if !source.is_empty() {
                layers.push(Layer {
                    name: format!("keystone:{app}/{env}{suffix}"),
                    source,
                });
            }
        }
    }
    Ok(layers)
}

pub fn flatten(layers: &[Layer]) -> props::Map {
    let mut out = props::Map::new();
    for layer in layers.iter().rev() {
        out.extend(layer.source.clone());
    }
    out
}

#[derive(Deserialize)]
pub struct FormatQuery {
    pub format: Option<String>,
}

pub fn render(map: &props::Map, format: Option<&str>, header: &str) -> Result<Response, ApiError> {
    let text = |body: String| {
        ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
    };
    Ok(match format.unwrap_or("json") {
        "json" => Json(map).into_response(),
        "properties" => text(props::render_properties(map, header)),
        "env" | "dotenv" => text(props::render_dotenv(map)),
        "shell" => text(props::render_shell(map)),
        _ => {
            return Err(bad(
                "invalid_format",
                "Use format json, properties, env or shell",
            ));
        }
    })
}

/// Raw item bytes. The sandbox CSP and attachment disposition keep an uploaded HTML or SVG file
/// from ever executing on Keystone's origin.
pub fn raw(stored: Stored, name: &str, kind: Kind) -> Response {
    let mut response = stored.bytes.into_response();
    let headers = response.headers_mut();
    let content_type = match kind {
        Kind::Key => "text/plain; charset=utf-8".to_owned(),
        Kind::File => stored.content_type,
    };
    if let Ok(value) = HeaderValue::from_str(&content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    if let Ok(value) = HeaderValue::from_str(&stored.version.to_string()) {
        headers.insert("x-keystone-version", value);
    }
    response
}

fn content_type(headers: &HeaderMap) -> String {
    let value = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let simple = !value.is_empty()
        && value.len() <= 100
        && value.contains('/')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/.+-; =".contains(&b));
    if simple {
        value.to_owned()
    } else {
        "application/octet-stream".into()
    }
}

// ---------------------------------------------------------------------------------------------
// Admin API: applications and environments

pub async fn status(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (apps, keys, files, tokens): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM vault_apps),
                (SELECT COUNT(*) FROM vault_items WHERE kind = 'key'),
                (SELECT COUNT(*) FROM vault_items WHERE kind = 'file'),
                (SELECT COUNT(*) FROM vault_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch()))",
    )
    .fetch_one(&state.db)
    .await?;
    Ok(Json(json!({
        "sealed": state.config.master_key.is_none(),
        "apps": apps, "keys": keys, "files": files, "activeTokens": tokens,
        "portalUrl": state.config.portal_url,
    })))
}

pub async fn list_apps(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let apps: Vec<AppRow> = sqlx::query_as(
        "SELECT a.id, a.name, a.description, a.portal_client_id, a.created_at, a.updated_at,
                COALESCE((SELECT group_concat(name, ',') FROM (SELECT name FROM vault_environments e WHERE e.app_id = a.id ORDER BY name = 'default' DESC, name)), ''),
                (SELECT COUNT(*) FROM vault_items i WHERE i.app_id = a.id AND kind = 'key'),
                (SELECT COUNT(*) FROM vault_items i WHERE i.app_id = a.id AND kind = 'file'),
                (SELECT COUNT(*) FROM vault_tokens t WHERE t.app_id = a.id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch()))
         FROM vault_apps a ORDER BY a.name COLLATE NOCASE",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        json!({"items": apps.into_iter().map(|(id, name, description, portal_client_id, created_at, updated_at, envs, keys, files, tokens)| json!({
        "id": id, "name": name, "description": description, "portalClientId": portal_client_id,
        "createdAt": created_at, "updatedAt": updated_at,
        "environments": envs.split(',').filter(|e| !e.is_empty()).collect::<Vec<_>>(),
        "keyCount": keys, "fileCount": files, "activeTokens": tokens,
    })).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewApp {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub portal_client_id: Option<String>,
    #[serde(default)]
    pub environments: Vec<String>,
}

fn check_app_fields(name: &str, description: &str, portal: Option<&str>) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 80 || description.len() > 500 {
        return Err(bad(
            "invalid_app",
            "Name is required (at most 80 characters); description at most 500",
        ));
    }
    if portal.is_some_and(|p| !p.is_empty() && !valid_app_id(p)) {
        return Err(bad("invalid_portal_client", "Portal client ids are slugs"));
    }
    Ok(())
}

pub async fn create_app(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Json(input): Json<NewApp>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let master = state.config.master_key.as_ref().ok_or_else(sealed)?;
    check_app(&input.id)?;
    let portal = input.portal_client_id.as_deref().filter(|p| !p.is_empty());
    check_app_fields(&input.name, &input.description, portal)?;
    let mut environments = vec![DEFAULT_ENV.to_owned()];
    for env in input.environments {
        check_environment(&env)?;
        if !environments.contains(&env) {
            environments.push(env);
        }
    }
    if environments.len() as i64 > MAX_ENVIRONMENTS {
        return Err(bad(
            "too_many_environments",
            "At most 50 environments per application",
        ));
    }
    let wrapped = master.new_data_key(&input.id).map_err(|_| internal())?;
    let who = actor.subject.clone();
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO vault_apps (id, name, description, portal_client_id, wrapped_key, created_by) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(&input.id)
    .bind(input.name.trim())
    .bind(input.description.trim())
    .bind(portal)
    .bind(wrapped)
    .bind(&who)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "app_exists",
            "An application with this id already exists",
        ));
    }
    for env in &environments {
        sqlx::query("INSERT INTO vault_environments (app_id, name) VALUES (?, ?)")
            .bind(&input.id)
            .bind(env)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit(&state.db, &actor, "vault.app.create", &input.id).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": input.id, "environments": environments})),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdate {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub portal_client_id: Option<String>,
}

pub async fn update_app(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(app): Path<String>,
    Json(input): Json<AppUpdate>,
) -> Result<Json<Value>, ApiError> {
    let portal = input.portal_client_id.as_deref().filter(|p| !p.is_empty());
    check_app_fields(&input.name, &input.description, portal)?;
    let updated = sqlx::query(
        "UPDATE vault_apps SET name = ?, description = ?, portal_client_id = ?, updated_at = unixepoch() WHERE id = ?",
    )
    .bind(input.name.trim())
    .bind(input.description.trim())
    .bind(portal)
    .bind(&app)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(missing("app_not_found", "Application not found"));
    }
    audit(&state.db, &actor, "vault.app.update", &app).await?;
    Ok(Json(json!({"id": app})))
}

#[derive(Deserialize)]
pub struct Confirm {
    pub confirm: Option<String>,
}

pub async fn delete_app(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(app): Path<String>,
    Query(confirm): Query<Confirm>,
) -> Result<StatusCode, ApiError> {
    if confirm.confirm.as_deref() != Some(app.as_str()) {
        return Err(bad(
            "confirmation_required",
            "Repeat the application id in ?confirm= to delete it and every secret it holds",
        ));
    }
    let mut tx = state.db.begin().await?;
    for table in [
        "vault_tokens",
        "vault_versions",
        "vault_items",
        "vault_environments",
    ] {
        let sql = if table == "vault_versions" {
            "DELETE FROM vault_versions WHERE item_id IN (SELECT id FROM vault_items WHERE app_id = ?)".to_owned()
        } else {
            format!("DELETE FROM {table} WHERE app_id = ?")
        };
        sqlx::query(&sql).bind(&app).execute(&mut *tx).await?;
    }
    let deleted = sqlx::query("DELETE FROM vault_apps WHERE id = ?")
        .bind(&app)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(missing("app_not_found", "Application not found"));
    }
    tx.commit().await?;
    audit(&state.db, &actor, "vault.app.delete", &app).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct NewEnvironment {
    pub name: String,
}

pub async fn create_environment(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(app): Path<String>,
    Json(input): Json<NewEnvironment>,
) -> Result<StatusCode, ApiError> {
    check_environment(&input.name)?;
    let (exists, count): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM vault_apps WHERE id = ?), (SELECT COUNT(*) FROM vault_environments WHERE app_id = ?)",
    )
    .bind(&app)
    .bind(&app)
    .fetch_one(&state.db)
    .await?;
    if exists == 0 {
        return Err(missing("app_not_found", "Application not found"));
    }
    if count >= MAX_ENVIRONMENTS {
        return Err(bad(
            "too_many_environments",
            "At most 50 environments per application",
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO vault_environments (app_id, name) VALUES (?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(&app)
    .bind(&input.name)
    .execute(&state.db)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "environment_exists",
            "This environment already exists",
        ));
    }
    audit(
        &state.db,
        &actor,
        "vault.environment.create",
        &format!("{app}/{}", input.name),
    )
    .await?;
    Ok(StatusCode::CREATED)
}

pub async fn delete_environment(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, environment)): Path<(String, String)>,
    Query(confirm): Query<Confirm>,
) -> Result<StatusCode, ApiError> {
    if environment == DEFAULT_ENV {
        return Err(bad(
            "default_environment",
            "The default environment cannot be deleted",
        ));
    }
    if confirm.confirm.as_deref() != Some(environment.as_str()) {
        return Err(bad(
            "confirmation_required",
            "Repeat the environment name in ?confirm= to delete it",
        ));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM vault_tokens WHERE app_id = ? AND environment = ?")
        .bind(&app)
        .bind(&environment)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM vault_versions WHERE item_id IN (SELECT id FROM vault_items WHERE app_id = ? AND environment = ?)")
        .bind(&app)
        .bind(&environment)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM vault_items WHERE app_id = ? AND environment = ?")
        .bind(&app)
        .bind(&environment)
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query("DELETE FROM vault_environments WHERE app_id = ? AND name = ?")
        .bind(&app)
        .bind(&environment)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(missing("environment_not_found", "Environment not found"));
    }
    tx.commit().await?;
    audit(
        &state.db,
        &actor,
        "vault.environment.delete",
        &format!("{app}/{environment}"),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Admin API: keys and files

pub async fn list_items(
    State(state): State<AppState>,
    Path((app, environment)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    ensure_environment(&state.db, &app, &environment).await?;
    let rows: Vec<(String, String, i64, String, i64, String, i64)> = sqlx::query_as(
        "SELECT i.kind, i.name, i.current_version, i.content_type, COALESCE(v.size, 0), i.updated_by, i.updated_at
         FROM vault_items i LEFT JOIN vault_versions v ON v.item_id = i.id AND v.version = i.current_version
         WHERE i.app_id = ? AND i.environment = ? ORDER BY i.kind, i.name",
    )
    .bind(&app)
    .bind(&environment)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        json!({"items": rows.into_iter().map(|(kind, name, version, content_type, size, updated_by, updated_at)| json!({
        "kind": kind, "name": name, "version": version, "contentType": content_type,
        "size": size, "updatedBy": updated_by, "updatedAt": updated_at,
    })).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize)]
pub struct KeyValue {
    pub value: String,
}

#[derive(Deserialize)]
pub struct VersionQuery {
    pub version: Option<i64>,
}

pub async fn put_item(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, environment, kind, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let kind = Kind::from_segment(&kind)?;
    kind.check_name(&name)?;
    let key = data_key(&state, &app).await?;
    ensure_environment(&state.db, &app, &environment).await?;
    let (bytes, content_type) = match kind {
        Kind::Key => {
            let input: KeyValue = serde_json::from_slice(&body)
                .map_err(|_| bad("invalid_body", "Send JSON: {\"value\": \"...\"}"))?;
            if input.value.len() > MAX_VALUE {
                return Err(bad("value_too_large", "Values are limited to 64 KiB"));
            }
            (input.value.into_bytes(), "text/plain".to_owned())
        }
        Kind::File => {
            if body.len() > MAX_FILE {
                return Err(bad("file_too_large", "Files are limited to 512 KiB"));
            }
            (body.to_vec(), content_type(&headers))
        }
    };
    let who = actor.subject.clone();
    let mut tx = state.db.begin().await?;
    let version = write_item(
        &mut tx,
        &key,
        &app,
        &environment,
        kind,
        &name,
        &bytes,
        &content_type,
        &who,
    )
    .await?;
    tx.commit().await?;
    audit(
        &state.db,
        &actor,
        &format!("vault.{}.write", kind.as_str()),
        &format!("{app}/{environment}/{name}@{version}"),
    )
    .await?;
    Ok(Json(json!({"name": name, "version": version})))
}

pub async fn get_item(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, environment, kind, name)): Path<(String, String, String, String)>,
    Query(query): Query<VersionQuery>,
) -> Result<Response, ApiError> {
    let kind = Kind::from_segment(&kind)?;
    kind.check_name(&name)?;
    let key = data_key(&state, &app).await?;
    let stored = read_item(
        &state.db,
        &key,
        &app,
        &environment,
        kind,
        &name,
        query.version,
    )
    .await?;
    audit(
        &state.db,
        &actor,
        &format!("vault.{}.reveal", kind.as_str()),
        &format!("{app}/{environment}/{name}@{}", stored.version),
    )
    .await?;
    Ok(match kind {
        Kind::Key => Json(json!({
            "name": name, "version": stored.version,
            "value": String::from_utf8_lossy(&stored.bytes),
        }))
        .into_response(),
        Kind::File => raw(stored, &name, kind),
    })
}

pub async fn delete_item(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, environment, kind, name)): Path<(String, String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let kind = Kind::from_segment(&kind)?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM vault_versions WHERE item_id IN (SELECT id FROM vault_items WHERE app_id = ? AND environment = ? AND kind = ? AND name = ?)")
        .bind(&app).bind(&environment).bind(kind.as_str()).bind(&name)
        .execute(&mut *tx).await?;
    let deleted = sqlx::query(
        "DELETE FROM vault_items WHERE app_id = ? AND environment = ? AND kind = ? AND name = ?",
    )
    .bind(&app)
    .bind(&environment)
    .bind(kind.as_str())
    .bind(&name)
    .execute(&mut *tx)
    .await?;
    if deleted.rows_affected() == 0 {
        return Err(missing("item_not_found", "No such key or file"));
    }
    tx.commit().await?;
    audit(
        &state.db,
        &actor,
        &format!("vault.{}.delete", kind.as_str()),
        &format!("{app}/{environment}/{name}"),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn versions(
    State(state): State<AppState>,
    Path((app, environment, kind, name)): Path<(String, String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let kind = Kind::from_segment(&kind)?;
    let rows: Vec<(i64, i64, String, i64, i64)> = sqlx::query_as(
        "SELECT v.version, v.size, v.created_by, v.created_at, i.current_version FROM vault_versions v
         JOIN vault_items i ON i.id = v.item_id
         WHERE i.app_id = ? AND i.environment = ? AND i.kind = ? AND i.name = ? ORDER BY v.version DESC",
    )
    .bind(&app)
    .bind(&environment)
    .bind(kind.as_str())
    .bind(&name)
    .fetch_all(&state.db)
    .await?;
    if rows.is_empty() {
        return Err(missing("item_not_found", "No such key or file"));
    }
    Ok(Json(
        json!({"items": rows.into_iter().map(|(version, size, by, at, current)| json!({
        "version": version, "size": size, "createdBy": by, "createdAt": at, "current": version == current,
    })).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize)]
pub struct Rollback {
    pub version: i64,
}

/// Restores an earlier version by writing it again as the newest one; history is never rewritten.
pub async fn rollback(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, environment, kind, name)): Path<(String, String, String, String)>,
    Json(input): Json<Rollback>,
) -> Result<Json<Value>, ApiError> {
    let kind = Kind::from_segment(&kind)?;
    let key = data_key(&state, &app).await?;
    let stored = read_item(
        &state.db,
        &key,
        &app,
        &environment,
        kind,
        &name,
        Some(input.version),
    )
    .await?;
    let who = actor.subject.clone();
    let mut tx = state.db.begin().await?;
    let version = write_item(
        &mut tx,
        &key,
        &app,
        &environment,
        kind,
        &name,
        &stored.bytes,
        &stored.content_type,
        &who,
    )
    .await?;
    tx.commit().await?;
    audit(
        &state.db,
        &actor,
        &format!("vault.{}.rollback", kind.as_str()),
        &format!("{app}/{environment}/{name}@{} -> @{version}", input.version),
    )
    .await?;
    Ok(Json(
        json!({"name": name, "version": version, "restoredFrom": input.version}),
    ))
}

#[derive(Deserialize)]
pub struct Import {
    pub format: String,
    pub content: String,
    /// Delete keys in the environment that the imported file does not contain.
    #[serde(default)]
    pub replace: bool,
}

/// Splits a `.properties` or dotenv file into individual keys. Unchanged values are skipped so
/// re-importing the same file creates no new versions.
pub async fn import(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, environment)): Path<(String, String)>,
    Json(input): Json<Import>,
) -> Result<Response, ApiError> {
    if input.content.len() > MAX_FILE {
        return Err(bad("file_too_large", "Imports are limited to 512 KiB"));
    }
    let map = match input.format.as_str() {
        "properties" => props::parse_properties(&input.content),
        "env" | "dotenv" => props::parse_dotenv(&input.content),
        _ => return Err(bad("invalid_format", "Import format is properties or env")),
    };
    if let Some(key) = map.keys().find(|k| !valid_key(k)) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"code": "invalid_key", "message": format!("Key '{}' uses unsupported characters. Allowed: letters, digits, '.', '_', '-', '[' and ']'", key.chars().take(80).collect::<String>())}})),
        )
            .into_response());
    }
    if let Some(key) = map
        .iter()
        .find(|(_, v)| v.len() > MAX_VALUE)
        .map(|(k, _)| k)
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"code": "value_too_large", "message": format!("The value of '{key}' exceeds 64 KiB")}})),
        )
            .into_response());
    }
    let key = data_key(&state, &app).await?;
    ensure_environment(&state.db, &app, &environment).await?;
    let existing: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM vault_items WHERE app_id = ? AND environment = ? AND kind = 'key'",
    )
    .bind(&app)
    .bind(&environment)
    .fetch_all(&state.db)
    .await?;
    let mut unchanged = 0;
    let mut changes = Vec::new();
    for (name, value) in &map {
        let same = if existing.iter().any(|(n,)| n == name) {
            read_item(&state.db, &key, &app, &environment, Kind::Key, name, None)
                .await
                .is_ok_and(|stored| stored.bytes == value.as_bytes())
        } else {
            false
        };
        if same {
            unchanged += 1;
        } else {
            changes.push((name, value));
        }
    }
    let who = actor.subject.clone();
    let mut tx = state.db.begin().await?;
    let mut removed = 0;
    if input.replace {
        for (name,) in existing.iter().filter(|(n,)| !map.contains_key(n)) {
            sqlx::query("DELETE FROM vault_versions WHERE item_id IN (SELECT id FROM vault_items WHERE app_id = ? AND environment = ? AND kind = 'key' AND name = ?)")
                .bind(&app).bind(&environment).bind(name).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM vault_items WHERE app_id = ? AND environment = ? AND kind = 'key' AND name = ?")
                .bind(&app).bind(&environment).bind(name).execute(&mut *tx).await?;
            removed += 1;
        }
    }
    for (name, value) in &changes {
        write_item(
            &mut tx,
            &key,
            &app,
            &environment,
            Kind::Key,
            name,
            value.as_bytes(),
            "text/plain",
            &who,
        )
        .await?;
    }
    tx.commit().await?;
    audit(
        &state.db,
        &actor,
        "vault.import",
        &format!(
            "{app}/{environment}: {} written, {unchanged} unchanged, {removed} removed",
            changes.len()
        ),
    )
    .await?;
    Ok(
        Json(json!({"written": changes.len(), "unchanged": unchanged, "removed": removed}))
            .into_response(),
    )
}

/// What an application token for this environment would receive (inheritance applied).
pub async fn preview_config(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, environment)): Path<(String, String)>,
    Query(query): Query<FormatQuery>,
) -> Result<Response, ApiError> {
    let key = data_key(&state, &app).await?;
    ensure_environment(&state.db, &app, &environment).await?;
    let layers = resolve(&state.db, &key, &app, &environment).await?;
    audit(
        &state.db,
        &actor,
        "vault.config.reveal",
        &format!("{app}/{environment}"),
    )
    .await?;
    render(
        &flatten(&layers),
        query.format.as_deref(),
        &format!("Keystone Vault: {app} ({environment})"),
    )
}

// ---------------------------------------------------------------------------------------------
// Admin API: application access tokens

pub async fn list_tokens(
    State(state): State<AppState>,
    Path(app): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let rows: Vec<TokenRow> = sqlx::query_as(
        "SELECT id, name, environment, created_by, created_at, expires_at, last_used_at, revoked_at
         FROM vault_tokens WHERE app_id = ? ORDER BY revoked_at IS NOT NULL, created_at DESC",
    )
    .bind(&app)
    .fetch_all(&state.db)
    .await?;
    let now = crate::now() as i64;
    Ok(Json(
        json!({"items": rows.into_iter().map(|(id, name, environment, by, at, expires, used, revoked)| json!({
        "id": id, "name": name, "environment": environment, "createdBy": by, "createdAt": at,
        "expiresAt": expires, "lastUsedAt": used, "revokedAt": revoked,
        "active": revoked.is_none() && expires.is_none_or(|e| e > now),
    })).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewToken {
    pub name: String,
    pub environment: String,
    /// 0 or absent: no expiry.
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

pub async fn create_token(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(app): Path<String>,
    Json(input): Json<NewToken>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if state.config.master_key.is_none() {
        return Err(sealed());
    }
    if input.name.trim().is_empty() || input.name.len() > 80 {
        return Err(bad("invalid_token_name", "Token names are 1–80 characters"));
    }
    if input.expires_in_days.is_some_and(|d| d > 3650) {
        return Err(bad(
            "invalid_expiry",
            "Tokens expire within 10 years at most",
        ));
    }
    ensure_environment(&state.db, &app, &input.environment).await?;
    let (active,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM vault_tokens WHERE app_id = ? AND revoked_at IS NULL")
            .bind(&app)
            .fetch_one(&state.db)
            .await?;
    if active >= MAX_TOKENS_PER_APP {
        return Err(bad(
            "too_many_tokens",
            "Revoke unused tokens first (at most 50)",
        ));
    }
    let token = crypto::new_token();
    let expires_at = input
        .expires_in_days
        .filter(|d| *d > 0)
        .map(|d| crate::now() as i64 + i64::from(d) * 86400);
    let who = actor.subject.clone();
    sqlx::query(
        "INSERT INTO vault_tokens (id, app_id, environment, name, secret_hash, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&token.id)
    .bind(&app)
    .bind(&input.environment)
    .bind(input.name.trim())
    .bind(&token.digest)
    .bind(&who)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    audit(
        &state.db,
        &actor,
        "vault.token.create",
        &format!("{app}/{} token {}", input.environment, token.id),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": token.id, "token": token.token, "app": app,
            "environment": input.environment, "expiresAt": expires_at,
        })),
    ))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path((app, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let revoked = sqlx::query(
        "UPDATE vault_tokens SET revoked_at = unixepoch() WHERE app_id = ? AND id = ? AND revoked_at IS NULL",
    )
    .bind(&app)
    .bind(&id)
    .execute(&state.db)
    .await?;
    if revoked.rows_affected() == 0 {
        return Err(missing("token_not_found", "No active token with this id"));
    }
    audit(
        &state.db,
        &actor,
        "vault.token.revoke",
        &format!("{app} token {id}"),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub app: Option<String>,
    /// `pulls` (app reads, admin reveals, refused tokens), `changes`, `denied` or `tokens`.
    pub kind: Option<String>,
    /// Free text matched against who, target, IP and User-Agent.
    pub q: Option<String>,
    /// Unix seconds, inclusive.
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// Keyset cursor: return events older than this id.
    pub before: Option<i64>,
    pub limit: Option<i64>,
    /// `csv` downloads the matching events (up to 10,000).
    pub format: Option<String>,
}

type AuditRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);

const PULL_EVENTS: &str =
    "(event LIKE '%.read' OR event LIKE '%.reveal' OR event = 'vault.token.denied')";
const CHANGE_EVENTS: &str = "(event LIKE '%.write' OR event LIKE '%.delete' OR event LIKE '%.create' OR event LIKE '%.update' OR event LIKE '%.rollback' OR event = 'vault.import' OR event = 'vault.token.revoke')";

/// One filter shared by the list, the CSV export and the summary. Binds: ?1 app, ?2 kind, ?3 q,
/// ?4 from, ?5 to.
fn audit_filter() -> String {
    format!(
        "event LIKE 'vault.%'
         AND (?1 IS NULL OR target = ?1 OR target LIKE ?1 || '/%' OR target LIKE ?1 || ' %')
         AND (?2 IS NULL
              OR (?2 = 'pulls' AND {PULL_EVENTS})
              OR (?2 = 'changes' AND {CHANGE_EVENTS})
              OR (?2 = 'denied' AND event = 'vault.token.denied')
              OR (?2 = 'tokens' AND event LIKE 'vault.token.%'))
         AND (?3 IS NULL OR instr(lower(subject || ' ' || COALESCE(target, '') || ' ' || COALESCE(ip, '') || ' ' || COALESCE(user_agent, '')), lower(?3)) > 0)
         AND (?4 IS NULL OR created_at >= ?4)
         AND (?5 IS NULL OR created_at <= ?5)"
    )
}

fn csv_field(value: &str) -> String {
    // Leading =, +, - or @ would run as a formula in a spreadsheet.
    let value = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", value.replace('"', "\"\""))
}

pub async fn audit_log(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<AuditQuery>,
) -> Result<Response, ApiError> {
    let app = query.app.filter(|a| !a.is_empty());
    if app.as_deref().is_some_and(|a| !valid_app_id(a)) {
        return Err(bad("invalid_app", "Unknown application filter"));
    }
    let kind = query.kind.filter(|k| !k.is_empty() && k != "all");
    if kind
        .as_deref()
        .is_some_and(|k| !matches!(k, "pulls" | "changes" | "denied" | "tokens"))
    {
        return Err(bad(
            "invalid_kind",
            "Use kind pulls, changes, denied or tokens",
        ));
    }
    let q = query
        .q
        .map(|q| q.trim().chars().take(100).collect::<String>())
        .filter(|q| !q.is_empty());
    let csv = query.format.as_deref() == Some("csv");
    let limit = if csv {
        10_000
    } else {
        query.limit.unwrap_or(100).clamp(1, 500)
    };
    let sql = format!(
        "SELECT id, subject, event, target, ip, user_agent, created_at FROM audit_events
         WHERE {} AND (?6 IS NULL OR id < ?6) ORDER BY id DESC LIMIT ?7",
        audit_filter()
    );
    let rows: Vec<AuditRow> = sqlx::query_as(&sql)
        .bind(&app)
        .bind(&kind)
        .bind(&q)
        .bind(query.from)
        .bind(query.to)
        .bind(query.before)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await?;
    if csv {
        audit(
            &state.db,
            &actor,
            "vault.audit.export",
            app.as_deref().unwrap_or("all applications"),
        )
        .await?;
        let mut out = String::from("time_utc,who,action,target,ip,user_agent\n");
        for (_, subject, event, target, ip, user_agent, at) in rows.iter().take(limit as usize) {
            let time = chrono_like(*at);
            out.push_str(
                &[
                    time,
                    subject.clone(),
                    event.clone(),
                    target.clone().unwrap_or_default(),
                    ip.clone().unwrap_or_default(),
                    user_agent.clone().unwrap_or_default(),
                ]
                .iter()
                .map(|v| csv_field(v))
                .collect::<Vec<_>>()
                .join(","),
            );
            out.push('\n');
        }
        return Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"keystone-vault-audit.csv\"",
                ),
            ],
            out,
        )
            .into_response());
    }
    let more = rows.len() as i64 > limit;
    let items: Vec<Value> = rows
        .iter()
        .take(limit as usize)
        .map(|(id, subject, event, target, ip, user_agent, at)| {
            json!({
                "id": id, "subject": subject, "event": event, "target": target,
                "ip": ip, "userAgent": user_agent, "createdAt": at,
            })
        })
        .collect();
    let next = if more {
        items.last().and_then(|e| e["id"].as_i64())
    } else {
        None
    };
    Ok(Json(json!({"items": items, "nextBefore": next})).into_response())
}

/// `2026-11-03T16:22:51Z` without a date-time dependency.
fn chrono_like(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Last-24-hour totals for the audit screen.
pub async fn audit_summary(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let app = query.app.filter(|a| !a.is_empty() && valid_app_id(a));
    let since = crate::now() as i64 - 86_400;
    let (pulls, denied, changes, ips, apps): (i64, i64, i64, i64, i64) = sqlx::query_as(&format!(
        "SELECT COALESCE(SUM({PULL_EVENTS} AND event != 'vault.token.denied'), 0),
                COALESCE(SUM(event = 'vault.token.denied'), 0),
                COALESCE(SUM({CHANGE_EVENTS}), 0),
                COUNT(DISTINCT ip),
                COUNT(DISTINCT CASE WHEN subject LIKE 'token:%' THEN subject END)
         FROM audit_events
         WHERE event LIKE 'vault.%' AND created_at >= ?2
           AND (?1 IS NULL OR target = ?1 OR target LIKE ?1 || '/%' OR target LIKE ?1 || ' %')"
    ))
    .bind(&app)
    .bind(since)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(json!({
        "since": since, "pulls": pulls, "denied": denied, "changes": changes,
        "distinctIps": ips, "activeTokens": apps,
    })))
}

#[cfg(test)]
mod tests {
    #[test]
    fn audit_time_format() {
        assert_eq!(super::chrono_like(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::chrono_like(1_793_725_371), "2026-11-03T17:02:51Z");
        assert_eq!(super::csv_field("=cmd()"), "\"'=cmd()\"");
        assert_eq!(super::csv_field("a\"b"), "\"a\"\"b\"");
    }
}
