//! Local accounts: run Keystone without Portal SSO, or alongside it (a break-glass administrator
//! when Portal is down, or service owners who are not in Portal).
//!
//! Passwords are Argon2id hashes. A sign-in returns an opaque session token (`kss_…`, 256 random
//! bits) whose SHA-256 is stored with an expiry; the token itself is never stored. Roles use the
//! same names as Portal SSO (`ROLE_ADMIN`, `ROLE_VAULT_<APP>`), so access works identically.
use crate::{
    AppState,
    auth::{Access, Claims},
    client::Actor,
    error::ApiError,
    vault,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{
    Extension, Json,
    extract::{Path, Request, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const TOKEN_PREFIX: &str = "kss_";

/// id, email, name, roles, disabled, created_at, last_login_at
type UserRow = (i64, String, String, String, i64, i64, Option<i64>);
const MIN_PASSWORD: usize = 12;

fn bad(code: &'static str, message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, code, message)
}
fn failed() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "Email or password is incorrect",
    )
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("Could not hash the password: {e}"))
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// At least 12 characters, not the email address, not all one character class.
pub fn check_password(password: &str, email: &str) -> Result<(), ApiError> {
    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if password.chars().count() < MIN_PASSWORD || password.len() > 256 {
        return Err(bad("weak_password", "Use at least 12 characters"));
    }
    if classes < 3 {
        return Err(bad(
            "weak_password",
            "Mix at least three of: lower case, upper case, digits, symbols",
        ));
    }
    if password.eq_ignore_ascii_case(email) {
        return Err(bad(
            "weak_password",
            "The password cannot be the email address",
        ));
    }
    Ok(())
}

fn valid_email(email: &str) -> bool {
    email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        })
        && !email.contains(char::is_whitespace)
}

fn normalise_roles(roles: &[String]) -> Result<String, ApiError> {
    let mut out: Vec<String> = Vec::new();
    for role in roles {
        let role = role.trim().to_ascii_uppercase();
        let ok = role == "ROLE_ADMIN"
            || role
                .strip_prefix(crate::auth::VAULT_ROLE_PREFIX)
                .is_some_and(|r| {
                    !r.is_empty()
                        && r.bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                });
        if !ok {
            return Err(bad(
                "invalid_role",
                "Roles are ROLE_ADMIN or ROLE_VAULT_<APP>",
            ));
        }
        if !out.contains(&role) {
            out.push(role);
        }
    }
    Ok(out.join(","))
}

fn roles_of(stored: &str) -> Vec<String> {
    stored
        .split(',')
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Creates a local user. Used by setup (first administrator), bootstrap and Settings → Users.
pub async fn create_user(
    state: &AppState,
    email: &str,
    name: &str,
    password: &str,
    roles: &[String],
) -> Result<i64, ApiError> {
    let email = email.trim().to_lowercase();
    if !valid_email(&email) {
        return Err(bad("invalid_email", "Enter a valid email address"));
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(bad(
            "invalid_name",
            "A name is required (at most 120 characters)",
        ));
    }
    check_password(password, &email)?;
    let roles = normalise_roles(roles)?;
    let password = password.to_owned();
    let hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| internal())?
        .map_err(|_| internal())?;
    let now = crate::now() as i64;
    let inserted = sqlx::query(&format!(
        "{} local_users (email, name, password_hash, roles, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
        state.dialect.insert_ignore()
    ))
    .bind(&email)
    .bind(name)
    .bind(hash)
    .bind(roles)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "user_exists",
            "A user with this email already exists",
        ));
    }
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM local_users WHERE email = ?")
        .bind(&email)
        .fetch_one(&state.db)
        .await?;
    Ok(id)
}

fn internal() -> ApiError {
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Something went wrong",
    )
}

fn session_digest(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Resolves a `kss_` token into the same identity a Portal token would give.
pub async fn authenticate(state: &AppState, token: &str) -> Result<(Claims, Access), ApiError> {
    let unauthorized = || {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Your session has ended. Sign in again.",
        )
    };
    if !state.config.local_auth || token.len() > 100 {
        return Err(unauthorized());
    }
    let row: Option<(i64, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT u.id, u.email, u.name, u.roles, u.disabled, s.expires_at FROM local_sessions s
         JOIN local_users u ON u.id = s.user_id WHERE s.token_hash = ?",
    )
    .bind(session_digest(token))
    .fetch_optional(&state.db)
    .await?;
    let Some((id, email, name, roles, disabled, expires_at)) = row else {
        return Err(unauthorized());
    };
    if disabled != 0 || expires_at <= crate::now() as i64 {
        return Err(unauthorized());
    }
    let roles = roles_of(&roles);
    let access = Access::from_roles(&roles);
    if !access.any() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "admin_required",
            "Your account has no Keystone roles",
        ));
    }
    let claims = Claims {
        sub: format!("local:{id}"),
        exp: expires_at as u64,
        iss: "keystone-local".into(),
        aud: json!("keystone"),
        roles,
        email: Some(email),
        name: Some(name),
        scope: Some(json!("openid")),
    };
    Ok((claims, access))
}

#[derive(Deserialize)]
pub struct Login {
    pub email: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<Value>, ApiError> {
    if !state.config.local_auth {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "local_auth_disabled",
            "Local accounts are not enabled",
        ));
    }
    if crate::setup::required(&state).await? {
        return Err(crate::setup::required_error());
    }
    let actor_for = |email: &str, request: &Request| {
        Actor::new(format!("admin:{email}"), request, state.config.trust_proxy)
    };
    let ip = crate::client::client_ip(&request, state.config.trust_proxy)
        .unwrap_or_else(|| "unknown".into());
    let window = std::time::Duration::from_secs(state.config.lockout_minutes.max(1) * 60);
    let limit = state.config.failed_token_limit.max(1);
    if state
        .login_limiter
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .locked(&ip, limit, window)
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "Too many failed sign-ins from this address; try again later",
        ));
    }
    let headers_actor = actor_for("", &request);
    let bytes = axum::body::to_bytes(request.into_body(), 16 * 1024)
        .await
        .map_err(|_| bad("invalid_body", "Send JSON: {\"email\", \"password\"}"))?;
    let input: Login = serde_json::from_slice(&bytes)
        .map_err(|_| bad("invalid_body", "Send JSON: {\"email\", \"password\"}"))?;
    let email = input.email.trim().to_lowercase();
    let actor = Actor {
        subject: format!("admin:{email}"),
        ..headers_actor
    };
    let row: Option<(i64, String, i64)> =
        sqlx::query_as("SELECT id, password_hash, disabled FROM local_users WHERE email = ?")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
    // Verify against a real hash even for unknown accounts, so timing does not reveal which exist.
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let (hash, usable) = match &row {
        Some((_, hash, disabled)) => (hash.clone(), *disabled == 0),
        None => (
            DUMMY
                .get_or_init(|| hash_password("keystone-timing-equaliser").unwrap_or_default())
                .clone(),
            false,
        ),
    };
    let password = input.password.clone();
    let ok = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .unwrap_or(false)
        && usable;
    let Some((user_id, ..)) = row.filter(|_| ok) else {
        let lockout = state
            .login_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fail(&ip, limit, window);
        vault::audit(&state, &actor, "vault.auth.failed", "local sign-in").await?;
        if lockout {
            crate::alerts::on_event(&state, &actor, "vault.ratelimit.lockout", &ip);
        }
        return Err(failed());
    };
    let mut raw = [0u8; 32];
    aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, &mut raw);
    let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    let now = crate::now() as i64;
    let expires_at = now + state.config.session_hours * 3600;
    sqlx::query("DELETE FROM local_sessions WHERE expires_at < ?")
        .bind(now)
        .execute(&state.db)
        .await?;
    sqlx::query("INSERT INTO local_sessions (token_hash, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(session_digest(&token))
        .bind(user_id)
        .bind(now)
        .bind(expires_at)
        .bind(&actor.ip)
        .bind(&actor.user_agent)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE local_users SET last_login_at = ? WHERE id = ?")
        .bind(now)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    vault::audit(&state, &actor, "vault.auth.login", "local sign-in").await?;
    Ok(Json(json!({"token": token, "expiresAt": expires_at})))
}

fn bearer(request: &Request) -> Option<String> {
    request
        .headers()
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_owned())
}

pub async fn logout(
    State(state): State<AppState>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    if let Some(token) = bearer(&request).filter(|t| t.starts_with(TOKEN_PREFIX)) {
        sqlx::query("DELETE FROM local_sessions WHERE token_hash = ?")
            .bind(session_digest(&token))
            .execute(&state.db)
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PasswordChange {
    pub current: String,
    pub next: String,
}

/// A signed-in local user changes their own password; their other sessions end.
pub async fn change_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Extension(actor): Extension<Actor>,
    Json(input): Json<PasswordChange>,
) -> Result<StatusCode, ApiError> {
    let id: i64 = claims
        .sub
        .strip_prefix("local:")
        .and_then(|i| i.parse().ok())
        .ok_or(bad("not_local", "Change Portal SSO passwords in Portal"))?;
    let (email, hash): (String, String) =
        sqlx::query_as("SELECT email, password_hash FROM local_users WHERE id = ?")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    let current = input.current.clone();
    if !tokio::task::spawn_blocking(move || verify_password(&current, &hash))
        .await
        .unwrap_or(false)
    {
        return Err(bad("wrong_password", "The current password is incorrect"));
    }
    check_password(&input.next, &email)?;
    let next = input.next.clone();
    let hash = tokio::task::spawn_blocking(move || hash_password(&next))
        .await
        .map_err(|_| internal())?
        .map_err(|_| internal())?;
    sqlx::query("UPDATE local_users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(hash)
        .bind(crate::now() as i64)
        .bind(id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM local_sessions WHERE user_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    vault::audit(&state, &actor, "vault.auth.password", &email).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Settings → Users (administrators)

pub async fn list_users(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
) -> Result<Json<Value>, ApiError> {
    access.require_admin()?;
    let rows: Vec<UserRow> = sqlx::query_as(
        "SELECT id, email, name, roles, disabled, created_at, last_login_at FROM local_users ORDER BY email",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "enabled": state.config.local_auth,
        "items": rows.into_iter().map(|(id, email, name, roles, disabled, created, last)| json!({
            "id": id, "email": email, "name": name, "roles": roles_of(&roles),
            "disabled": disabled != 0, "createdAt": created, "lastLoginAt": last,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub struct NewUser {
    pub email: String,
    pub name: String,
    pub password: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

pub async fn add_user(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Json(input): Json<NewUser>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    access.require_admin()?;
    let id = create_user(
        &state,
        &input.email,
        &input.name,
        &input.password,
        &input.roles,
    )
    .await?;
    vault::audit(
        &state,
        &actor,
        "vault.user.create",
        &input.email.trim().to_lowercase(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({"id": id}))))
}

#[derive(Deserialize)]
pub struct UserUpdate {
    pub name: Option<String>,
    pub roles: Option<Vec<String>>,
    pub disabled: Option<bool>,
    pub password: Option<String>,
}

/// Enabled local administrators other than `except`.
async fn other_admins(state: &AppState, except: i64) -> Result<i64, ApiError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT roles FROM local_users WHERE id <> ? AND disabled = 0")
            .bind(except)
            .fetch_all(&state.db)
            .await?;
    Ok(rows
        .iter()
        .filter(|(r,)| roles_of(r).iter().any(|r| r == "ROLE_ADMIN"))
        .count() as i64)
}

/// Without Portal SSO, removing the last local administrator would lock everyone out.
async fn keep_an_admin(state: &AppState, id: i64) -> Result<(), ApiError> {
    if !state.config.sso_configured() && other_admins(state, id).await? == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "last_admin",
            "This is the last administrator; add another one first",
        ));
    }
    Ok(())
}

pub async fn update_user(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<i64>,
    Json(input): Json<UserUpdate>,
) -> Result<StatusCode, ApiError> {
    access.require_admin()?;
    let (email, roles): (String, String) =
        sqlx::query_as("SELECT email, roles FROM local_users WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await?
            .ok_or(ApiError(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "No such user",
            ))?;
    let was_admin = roles_of(&roles).iter().any(|r| r == "ROLE_ADMIN");
    let now = crate::now() as i64;
    if let Some(name) = &input.name {
        if name.trim().is_empty() || name.len() > 120 {
            return Err(bad(
                "invalid_name",
                "A name is required (at most 120 characters)",
            ));
        }
        sqlx::query("UPDATE local_users SET name = ?, updated_at = ? WHERE id = ?")
            .bind(name.trim())
            .bind(now)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(roles) = &input.roles {
        let next = normalise_roles(roles)?;
        if was_admin && !roles_of(&next).iter().any(|r| r == "ROLE_ADMIN") {
            keep_an_admin(&state, id).await?;
        }
        sqlx::query("UPDATE local_users SET roles = ?, updated_at = ? WHERE id = ?")
            .bind(next)
            .bind(now)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(disabled) = input.disabled {
        if disabled && was_admin {
            keep_an_admin(&state, id).await?;
        }
        sqlx::query("UPDATE local_users SET disabled = ?, updated_at = ? WHERE id = ?")
            .bind(i64::from(disabled))
            .bind(now)
            .bind(id)
            .execute(&state.db)
            .await?;
        if disabled {
            sqlx::query("DELETE FROM local_sessions WHERE user_id = ?")
                .bind(id)
                .execute(&state.db)
                .await?;
        }
    }
    if let Some(password) = &input.password {
        check_password(password, &email)?;
        let password = password.clone();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(|_| internal())?
            .map_err(|_| internal())?;
        sqlx::query("UPDATE local_users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(hash)
            .bind(now)
            .bind(id)
            .execute(&state.db)
            .await?;
        sqlx::query("DELETE FROM local_sessions WHERE user_id = ?")
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    vault::audit(&state, &actor, "vault.user.update", &email).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_user(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    access.require_admin()?;
    let (email, roles): (String, String) =
        sqlx::query_as("SELECT email, roles FROM local_users WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await?
            .ok_or(ApiError(
                StatusCode::NOT_FOUND,
                "user_not_found",
                "No such user",
            ))?;
    if roles_of(&roles).iter().any(|r| r == "ROLE_ADMIN") {
        keep_an_admin(&state, id).await?;
    }
    sqlx::query("DELETE FROM local_sessions WHERE user_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM local_users WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    vault::audit(&state, &actor, "vault.user.delete", &email).await?;
    Ok(StatusCode::NO_CONTENT)
}
