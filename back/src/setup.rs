//! First-run setup, like Portal SSO's: license → setup key → sign-in (Portal SSO and/or a local
//! administrator) → database (built-in SQLite or MySQL) → finish.
//!
//! Until setup is finished the console shows the wizard and no one can sign in. Every step that
//! changes something needs the one-time setup key, printed at startup and saved to
//! `secrets/setup.key`, which proves the person at the browser also controls the server.
//! Unattended installs skip the wizard with `setup.accept-license=true` plus Portal settings or
//! `bootstrap.admin-*`. Installs that predate the wizard only need to accept the license.
use crate::{AppState, client::Actor, config, db, error::ApiError, vault};
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use subtle::ConstantTimeEq;

pub const LICENSE_ID: &str = "Apache-2.0";
pub const LICENSE_TEXT: &str = include_str!("../../LICENSE");
const COMPLETED: &str = "setup.completed";
const LICENSE: &str = "license.accepted";

pub fn required_error() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "setup_required",
        "Finish first-time setup in the Keystone console first",
    )
}
fn bad(code: &'static str, message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, code, message)
}
fn invalid(code: &str, message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": {"code": code, "message": message}})),
    )
        .into_response()
}

pub async fn get(db: &db::Db, name: &str) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM keystone_state WHERE name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|(v,)| v))
}

pub async fn set(db: &db::Db, name: &str, value: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM keystone_state WHERE name = ?")
        .bind(name)
        .execute(db)
        .await?;
    sqlx::query("INSERT INTO keystone_state (name, value, updated_at) VALUES (?, ?, ?)")
        .bind(name)
        .bind(value)
        .bind(crate::now() as i64)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn required(state: &AppState) -> Result<bool, ApiError> {
    Ok(get(&state.db, COMPLETED).await?.is_none())
}

async fn local_admins(db: &db::Db) -> Result<i64, ApiError> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT roles FROM local_users WHERE disabled = 0")
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .filter(|(r,)| r.split(',').any(|r| r == "ROLE_ADMIN"))
        .count() as i64)
}

fn key_file(state: &AppState) -> std::path::PathBuf {
    state.config.home.join("secrets").join("setup.key")
}

/// Startup: applies unattended settings, completes setup for installs that are already
/// configured, and otherwise prepares the one-time setup key.
pub async fn initialize(state: &AppState) -> anyhow::Result<()> {
    let c = &state.config;
    if c.accept_license && get(&state.db, LICENSE).await?.is_none() {
        let record = json!({"license": LICENSE_ID, "by": "configuration (setup.accept-license)", "at": crate::now()});
        set(&state.db, LICENSE, &record.to_string()).await?;
    }
    if let Some((email, password)) = &c.bootstrap_admin {
        let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM local_users")
            .fetch_one(&state.db)
            .await?;
        if users == 0 {
            crate::local_auth::create_user(
                state,
                email,
                "Administrator",
                password,
                &["ROLE_ADMIN".into()],
            )
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap.admin-*: {}", e.2))?;
            tracing::warn!(
                email,
                "Created the bootstrap administrator; remove bootstrap.admin-password from the configuration now"
            );
        }
    }
    let licensed = get(&state.db, LICENSE).await?.is_some();
    let can_sign_in = c.sso_configured() || (c.local_auth && local_admins(&state.db).await? > 0);
    if get(&state.db, COMPLETED).await?.is_none() && licensed && can_sign_in {
        set(&state.db, COMPLETED, &crate::now().to_string()).await?;
    }
    let file = key_file(state);
    if get(&state.db, COMPLETED).await?.is_some() {
        let _ = fs::remove_file(&file);
        return Ok(());
    }
    let key = match fs::read_to_string(&file)
        .ok()
        .map(|k| k.trim().to_owned())
        .filter(|k| k.len() >= 20)
    {
        Some(existing) => existing,
        None => {
            let mut raw = [0u8; 15];
            aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, &mut raw);
            let key: String = raw
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .chars()
                .collect::<Vec<_>>()
                .chunks(6)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("-");
            if let Some(parent) = file.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&file, format!("{key}\n"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
            }
            key
        }
    };
    *state.setup_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(key.clone());
    eprintln!(
        "\n  ================================================================\n   First-time setup: open the console and enter this setup key:\n\n       {key}\n\n   It is also saved in {}\n  ================================================================\n",
        file.display()
    );
    tracing::warn!(file = %file.display(), "Setup required: open the console to finish first-time setup");
    Ok(())
}

fn check_key(state: &AppState, headers: &HeaderMap, ip: &str) -> Result<(), ApiError> {
    let window = std::time::Duration::from_secs(state.config.lockout_minutes.max(1) * 60);
    let limit = state.config.failed_token_limit.max(1);
    let mut limiter = state
        .login_limiter
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if limiter.locked(ip, limit, window) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "Too many wrong setup keys from this address; try again later",
        ));
    }
    let expected = state
        .setup_key
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let given = headers
        .get("x-setup-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_owned();
    match expected {
        Some(expected) if bool::from(expected.as_bytes().ct_eq(given.as_bytes())) => Ok(()),
        Some(_) => {
            limiter.fail(ip, limit, window);
            Err(ApiError(
                StatusCode::FORBIDDEN,
                "invalid_setup_key",
                "That setup key is not correct. It is in the server log and in secrets/setup.key.",
            ))
        }
        None => Err(ApiError(
            StatusCode::CONFLICT,
            "setup_done",
            "Setup is already finished",
        )),
    }
}

/// Guards every setup mutation: setup unfinished, and the right setup key.
async fn guard(state: &AppState, request: Request) -> Result<(Actor, Request), ApiError> {
    let actor = Actor::new("setup".into(), &request, state.config.trust_proxy);
    let headers = request.headers().clone();
    if !required(state).await? {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "setup_done",
            "Setup is already finished",
        ));
    }
    check_key(state, &headers, actor.ip.as_deref().unwrap_or("unknown"))?;
    Ok((actor, request))
}

async fn json_body<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(|_| bad("invalid_body", "Request body too large"))?;
    serde_json::from_slice(&bytes).map_err(|_| bad("invalid_body", "Malformed JSON"))
}

pub async fn status(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    if !required(&state).await? {
        return Ok(Json(json!({"required": false})));
    }
    let c = &state.config;
    let fixed = |key: &str| c.fixed.iter().any(|f| f == key);
    let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM local_users")
        .fetch_one(&state.db)
        .await?;
    Ok(Json(json!({
        "required": true,
        "version": config::VERSION,
        "licenseId": LICENSE_ID,
        "licenseAccepted": get(&state.db, LICENSE).await?.is_some(),
        "keyFile": key_file(&state).display().to_string(),
        "configFile": c.writable_config_file().display().to_string(),
        "portal": {"configured": c.sso_configured(), "url": c.portal_url, "clientId": c.client_id, "fixed": fixed("portal.url")},
        "local": {"enabled": c.local_auth, "admins": local_admins(&state.db).await?, "users": users},
        "database": {"engine": state.dialect.name(), "url": db::redact(&c.database_url), "fixed": fixed("storage.database-url")},
    })))
}

pub async fn license() -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        LICENSE_TEXT,
    )
        .into_response()
}

pub async fn verify(
    State(state): State<AppState>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    guard(&state, request).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct Accept {
    accept: bool,
    #[serde(rename = "licenseId")]
    license_id: String,
}

pub async fn accept_license(
    State(state): State<AppState>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    let (actor, request) = guard(&state, request).await?;
    let input: Accept = json_body(request).await?;
    if !input.accept || input.license_id != LICENSE_ID {
        return Err(bad(
            "license_not_accepted",
            "Accept the license to continue",
        ));
    }
    let record =
        json!({"license": LICENSE_ID, "by": "setup wizard", "ip": actor.ip, "at": crate::now()});
    set(&state.db, LICENSE, &record.to_string()).await?;
    vault::audit(&state, &actor, "vault.setup.license", LICENSE_ID).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct UrlInput {
    url: String,
}

/// Checks that a Portal SSO issuer answers OIDC discovery with exactly this issuer.
async fn check_portal(state: &AppState, url: &str) -> Result<(), String> {
    let url = url.trim_end_matches('/');
    config::validate_url(url).map_err(|e| e.to_string())?;
    let discovery: Value = state
        .http
        .get(format!("{url}/.well-known/openid-configuration"))
        .send()
        .await
        .map_err(|_| format!("Could not reach {url}"))?
        .json()
        .await
        .map_err(|_| {
            "That address did not answer like a Portal SSO / OpenID Connect issuer".to_owned()
        })?;
    if discovery["issuer"] != url {
        return Err(format!(
            "The issuer reported by {url} is {}; use exactly that address",
            discovery["issuer"]
        ));
    }
    Ok(())
}

pub async fn test_portal(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let (_, request) = guard(&state, request).await?;
    let input: UrlInput = json_body(request).await?;
    Ok(match check_portal(&state, &input.url).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(message) => invalid("portal_unreachable", message),
    })
}

async fn check_database(url: &str) -> Result<(db::Db, String), String> {
    let dialect = db::Dialect::of_url(url).map_err(|e| e.to_string())?;
    let pool = db::open(url, false).await.map_err(|e| format!("{e:#}"))?;
    let version = if dialect == db::Dialect::MySql {
        sqlx::query_as::<_, (String,)>("SELECT VERSION()")
            .fetch_one(&pool)
            .await
            .map(|(v,)| format!("MySQL {v}"))
            .map_err(|e| e.to_string())?
    } else {
        "SQLite".into()
    };
    Ok((pool, version))
}

pub async fn test_database(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let (_, request) = guard(&state, request).await?;
    let input: UrlInput = json_body(request).await?;
    Ok(match check_database(input.url.trim()).await {
        Ok((pool, version)) => {
            pool.close().await;
            Json(json!({"ok": true, "server": version})).into_response()
        }
        Err(message) => invalid("database_unreachable", message),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortalChoice {
    url: String,
    client_id: String,
}
#[derive(Deserialize)]
struct AdminChoice {
    email: String,
    name: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Finish {
    portal: Option<PortalChoice>,
    admin: Option<AdminChoice>,
    /// A new database (MySQL); absent keeps the current one.
    database_url: Option<String>,
}

pub async fn finish(State(state): State<AppState>, request: Request) -> Result<Response, ApiError> {
    let (actor, request) = guard(&state, request).await?;
    let input: Finish = json_body(request).await?;
    let c = state.config.clone();
    if get(&state.db, LICENSE).await?.is_none() {
        return Err(bad("license_not_accepted", "Accept the license first"));
    }
    let mut changes: Vec<(&str, String)> = Vec::new();

    // Sign-in: Portal SSO, a local administrator, or both.
    if let Some(portal) = &input.portal {
        let url = portal.url.trim().trim_end_matches('/').to_owned();
        let client = portal.client_id.trim().to_owned();
        if client.is_empty() || !vault::valid_app_id(&client) {
            return Ok(invalid(
                "invalid_client",
                "Enter Keystone's public client id from Portal SSO (for example keystone)".into(),
            ));
        }
        if let Err(message) = check_portal(&state, &url).await {
            return Ok(invalid("portal_unreachable", message));
        }
        if url != c.portal_url {
            changes.push(("portal.url", url));
        }
        if client != c.client_id {
            changes.push(("portal.client-id", client));
        }
    }
    if let Some(admin) = &input.admin {
        crate::local_auth::create_user(
            &state,
            &admin.email,
            &admin.name,
            &admin.password,
            &["ROLE_ADMIN".into()],
        )
        .await?;
        vault::audit(
            &state,
            &actor,
            "vault.user.create",
            &admin.email.trim().to_lowercase(),
        )
        .await?;
    }
    let local_ready = local_admins(&state.db).await? > 0;
    if local_ready && !c.local_auth {
        changes.push(("auth.local", "true".into()));
    }
    if input.portal.is_none() && !c.sso_configured() && !local_ready {
        return Err(bad(
            "no_sign_in",
            "Choose Portal SSO, create a local administrator, or both",
        ));
    }
    for (key, _) in &changes {
        if c.fixed.iter().any(|f| f == key) {
            return Ok(invalid(
                "fixed_setting",
                format!("{key} is set by an environment variable or flag; change it there"),
            ));
        }
    }

    // Database: optionally move to MySQL, copying what exists so far.
    let target = input
        .database_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty() && *u != c.database_url);
    if target.is_some() && c.fixed.iter().any(|f| f == "storage.database-url") {
        return Ok(invalid(
            "fixed_setting",
            "storage.database-url is set by an environment variable or flag; change it there"
                .into(),
        ));
    }
    set(&state.db, COMPLETED, &crate::now().to_string()).await?;
    vault::audit(&state, &actor, "vault.setup.complete", "first-time setup").await?;
    if let Some(url) = target {
        let moved = async {
            let (pool, _) = check_database(url).await.map_err(anyhow::Error::msg)?;
            db::migrate(&pool, db::Dialect::of_url(url)?).await?;
            let (apps,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_apps")
                .fetch_one(&pool)
                .await?;
            anyhow::ensure!(
                apps == 0,
                "That database already holds Keystone applications; choose an empty one"
            );
            db::copy_all(&state.db, &pool).await?;
            if let Some(master) = &c.master_key {
                crate::verify_master_key(&pool, master).await?;
            }
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        if let Err(error) = moved {
            sqlx::query("DELETE FROM keystone_state WHERE name = ?")
                .bind(COMPLETED)
                .execute(&state.db)
                .await?;
            return Ok(invalid("database_failed", format!("{error:#}")));
        }
        changes.push(("storage.database-url", url.to_owned()));
    }

    // Persist the choices; Keystone restarts to apply them.
    let file = c.writable_config_file();
    let entries: Vec<(&str, &str)> = changes.iter().map(|(k, v)| (*k, v.as_str())).collect();
    if !entries.is_empty()
        && let Err(error) = config::set_in_file(&file, &entries)
    {
        sqlx::query("DELETE FROM keystone_state WHERE name = ?")
            .bind(COMPLETED)
            .execute(&state.db)
            .await?;
        let lines: Vec<String> = changes
            .iter()
            .map(|(k, v)| {
                format!(
                    "{k}={}",
                    if k.contains("database") {
                        db::redact(v)
                    } else {
                        v.clone()
                    }
                )
            })
            .collect();
        return Ok(invalid(
            "config_not_writable",
            format!(
                "Could not write {} ({error}). Add these lines yourself and restart: {}",
                file.display(),
                lines.join("; ")
            ),
        ));
    }
    let _ = fs::remove_file(key_file(&state));
    *state.setup_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let restart = !changes.is_empty();
    if restart {
        let state = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            state
                .restart
                .store(true, std::sync::atomic::Ordering::SeqCst);
            state.shutdown.notify_waiters();
        });
    }
    Ok(Json(json!({"restart": restart, "configFile": file.display().to_string()})).into_response())
}
