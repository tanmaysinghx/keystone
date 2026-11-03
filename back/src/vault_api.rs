//! What applications call at startup, authenticated by a Keystone application token
//! (`ksv_…`) scoped to one application environment. Tokens are read-only.
//!
//! Portal SSO does not yet issue `client_credentials` tokens, so machine identity is a Keystone
//! credential created by a Portal administrator in the Keystone console.
use crate::{
    AppState,
    client::Actor,
    crypto,
    error::ApiError,
    vault::{self, FormatQuery, Kind},
};
use axum::{
    Extension, Json,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

/// app, environment, name, secret hash, expires_at, revoked_at, allowed CIDRs
type TokenRow = (
    String,
    String,
    String,
    Vec<u8>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

/// Failed token attempts per client IP. After `security.failed-token-limit` failures within the
/// lockout window the address is refused (429) until the window passes.
#[derive(Default)]
pub struct Limiter {
    failures: std::collections::HashMap<String, (u32, std::time::Instant)>,
}

impl Limiter {
    pub fn locked(&mut self, ip: &str, limit: u32, window: std::time::Duration) -> bool {
        match self.failures.get(ip) {
            Some((count, since)) if since.elapsed() < window => *count >= limit,
            Some(_) => {
                self.failures.remove(ip);
                false
            }
            None => false,
        }
    }
    /// Returns true when this failure is the one that triggers the lockout.
    pub fn fail(&mut self, ip: &str, limit: u32, window: std::time::Duration) -> bool {
        if self.failures.len() > 50_000 {
            self.failures
                .retain(|_, (_, since)| since.elapsed() < window);
        }
        let entry = self
            .failures
            .entry(ip.to_owned())
            .or_insert((0, std::time::Instant::now()));
        if entry.1.elapsed() >= window {
            *entry = (0, std::time::Instant::now());
        }
        entry.0 += 1;
        entry.0 == limit
    }
}

/// Parses `10.0.0.0/8, 192.168.1.10, 2001:db8::/32`. A bare address means that one address.
pub fn parse_cidrs(raw: &str) -> Result<Vec<ipnet::IpNet>, String> {
    raw.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<ipnet::IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| format!("'{s}' is not an IP address or CIDR range"))
        })
        .collect()
}

fn ip_allowed(cidrs: &str, ip: Option<&str>) -> bool {
    let Some(ip) = ip.and_then(|ip| ip.parse::<std::net::IpAddr>().ok()) else {
        return false;
    };
    parse_cidrs(cidrs).is_ok_and(|nets| nets.iter().any(|net| net.contains(&ip)))
}

#[derive(Clone)]
pub struct TokenContext {
    pub id: String,
    pub app: String,
    pub environment: String,
    pub expires_at: Option<i64>,
}

fn invalid_token() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "invalid_vault_token",
        "A valid Keystone application token is required",
    )
}

/// Accepts `Authorization: Bearer ksv_…`, `X-Keystone-Token: ksv_…`, or HTTP Basic with the
/// token as the password (what Spring Cloud Config's `username`/`password` settings send).
fn presented(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = headers
        .get("x-keystone-token")
        .and_then(|v| v.to_str().ok())
    {
        return Some(token.trim().to_owned());
    }
    let auth = headers.get("authorization")?.to_str().ok()?;
    if let Some(token) = auth.strip_prefix("Bearer ") {
        return Some(token.trim().to_owned());
    }
    let decoded = STANDARD.decode(auth.strip_prefix("Basic ")?.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    Some(password.to_owned())
}

pub async fn require_token(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if state.config.master_key.is_none() {
        return Err(vault::sealed());
    }
    let client_ip = crate::client::client_ip(&request, state.config.trust_proxy)
        .unwrap_or_else(|| "unknown".into());
    let window = std::time::Duration::from_secs(state.config.lockout_minutes.max(1) * 60);
    let limit = state.config.failed_token_limit.max(1);
    if state
        .limiter
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .locked(&client_ip, limit, window)
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "Too many failed token attempts from this address; try again later",
        ));
    }
    let failed = |state: &AppState| {
        let lockout = state
            .limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fail(&client_ip, limit, window);
        if lockout {
            tracing::warn!(ip = %client_ip, "Locked out after repeated failed token attempts");
            let system = Actor {
                subject: "system:rate-limit".into(),
                ip: Some(client_ip.clone()),
                user_agent: None,
            };
            crate::alerts::on_event(state, &system, "vault.ratelimit.lockout", &client_ip);
        }
    };
    let Some(token) = presented(request.headers()) else {
        return Err(invalid_token());
    };
    let Some((id, secret)) = crypto::parse_token(&token) else {
        failed(&state);
        return Err(invalid_token());
    };
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT app_id, environment, name, secret_hash, expires_at, revoked_at, allowed_cidrs FROM vault_tokens WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some((app, environment, name, digest, expires_at, revoked_at, cidrs)) = row else {
        failed(&state);
        return Err(invalid_token());
    };
    let actor = Actor::new(
        format!("token:{id} ({name})"),
        &request,
        state.config.trust_proxy,
    );
    // A known token id presented with a wrong secret, after revocation or expiry, or from an
    // address outside its allow-list is worth an audit entry: a misconfigured deployment, or
    // someone holding a credential they should not have.
    let denied = if !crypto::token_matches(secret, &digest) {
        Some("wrong secret")
    } else if revoked_at.is_some() {
        Some("revoked")
    } else if expires_at.is_some_and(|at| at <= crate::now() as i64) {
        Some("expired")
    } else if cidrs
        .as_deref()
        .is_some_and(|c| !ip_allowed(c, actor.ip.as_deref()))
    {
        Some("address not allowed")
    } else {
        None
    };
    if let Some(reason) = denied {
        failed(&state);
        vault::audit(
            &state,
            &actor,
            "vault.token.denied",
            &format!("{app}/{environment} ({reason})"),
        )
        .await?;
        return Err(invalid_token());
    }
    sqlx::query(
        "UPDATE vault_tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)",
    )
    .bind(crate::now() as i64)
    .bind(id)
    .bind(crate::now() as i64 - 60)
    .execute(&state.db)
    .await?;
    request.extensions_mut().insert(actor);
    request.extensions_mut().insert(TokenContext {
        id: id.to_owned(),
        app,
        environment,
        expires_at,
    });
    Ok(next.run(request).await)
}

async fn record(
    state: &AppState,
    actor: &Actor,
    token: &TokenContext,
    event: &str,
    what: &str,
) -> Result<(), ApiError> {
    vault::audit(
        state,
        actor,
        event,
        &format!("{}/{}{what}", token.app, token.environment),
    )
    .await
}

pub async fn whoami(Extension(token): Extension<TokenContext>) -> Json<Value> {
    Json(json!({
        "app": token.app, "environment": token.environment,
        "tokenId": token.id, "expiresAt": token.expires_at,
    }))
}

/// A fingerprint of everything a token's environment resolves to. Changes whenever any value,
/// file or inheritance result changes; reveals nothing about the values.
pub fn version_of(layers: &[vault::Layer]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for layer in layers {
        hash.update(layer.name.as_bytes());
        for (k, v) in &layer.source {
            hash.update([0]);
            hash.update(k.as_bytes());
            hash.update([1]);
            hash.update(v.as_bytes());
        }
        hash.update([2]);
    }
    hash.finalize()[..10]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `GET /api/v1/vault/config?format=json|properties|env|shell`. Sends an `ETag`; a request with
/// `If-None-Match` set to the current one gets 304 (nothing is disclosed, so nothing is audited).
pub async fn config(
    State(state): State<AppState>,
    Extension(token): Extension<TokenContext>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<FormatQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let key = vault::data_key(&state, &token.app).await?;
    let layers = vault::resolve(&state.db, &key, &token.app, &token.environment).await?;
    let version = version_of(&layers);
    let etag = format!("\"{version}\"");
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        return Ok((StatusCode::NOT_MODIFIED, [(axum::http::header::ETAG, etag)]).into_response());
    }
    record(&state, &actor, &token, "vault.config.read", "").await?;
    let mut response = vault::render(
        &vault::flatten(&layers),
        query.format.as_deref(),
        &format!(
            "Keystone Vault: {} ({}) version {version}",
            token.app, token.environment
        ),
    )?;
    if let Ok(value) = axum::http::HeaderValue::from_str(&etag) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    Ok(response)
}

#[derive(serde::Deserialize)]
pub struct WatchQuery {
    pub version: Option<String>,
    pub timeout: Option<u64>,
}

/// `GET /api/v1/vault/watch?version=<current>&timeout=30`: long-polls until the configuration
/// changes (or the timeout passes) and answers with the latest version, so a running app knows
/// when to fetch again. Without `version` it answers immediately.
pub async fn watch(
    State(state): State<AppState>,
    Extension(token): Extension<TokenContext>,
    Query(query): Query<WatchQuery>,
) -> Result<Json<Value>, ApiError> {
    let key = vault::data_key(&state, &token.app).await?;
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(query.timeout.unwrap_or(30).clamp(1, 60));
    loop {
        let notified = state.changed.notified();
        let layers = vault::resolve(&state.db, &key, &token.app, &token.environment).await?;
        let version = version_of(&layers);
        let changed = query.version.as_deref().is_some_and(|v| v != version);
        if query.version.is_none() || changed || tokio::time::Instant::now() >= deadline {
            return Ok(Json(json!({"version": version, "changed": changed})));
        }
        // Wake on any vault write, and re-check at least every 15s.
        let _ = tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + std::time::Duration::from_secs(15)),
            notified,
        )
        .await;
    }
}

/// `GET /api/v1/vault/keys/{name}` and `/api/v1/vault/files/{name}`: one raw value.
/// A key missing from the token's environment falls back to `default`, like the merged config.
pub async fn item(
    State(state): State<AppState>,
    Extension(token): Extension<TokenContext>,
    Extension(actor): Extension<Actor>,
    Path((kind, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let kind = Kind::from_segment(&kind)?;
    kind.check_name(&name)?;
    let key = vault::data_key(&state, &token.app).await?;
    let mut stored = vault::read_item(
        &state.db,
        &key,
        &token.app,
        &token.environment,
        kind,
        &name,
        None,
    )
    .await;
    if stored.is_err() && token.environment != vault::DEFAULT_ENV {
        stored = vault::read_item(
            &state.db,
            &key,
            &token.app,
            vault::DEFAULT_ENV,
            kind,
            &name,
            None,
        )
        .await;
    }
    let stored = stored?;
    record(
        &state,
        &actor,
        &token,
        &format!("vault.{}.read", kind.as_str()),
        &format!("/{name}"),
    )
    .await?;
    Ok(vault::raw(stored, &name, kind))
}

/// Spring Cloud Config Server protocol: `GET /config/{application}/{profiles}[/{label}]`.
/// With `spring.config.import=configserver:` and `spring.cloud.config.uri=https://keystone/config`,
/// Spring Boot loads the vault before the application context starts. The token decides which
/// environment is served; the application name must match the token's application.
pub async fn spring(
    State(state): State<AppState>,
    Extension(token): Extension<TokenContext>,
    Extension(actor): Extension<Actor>,
    Path(params): Path<Vec<(String, String)>>,
) -> Result<Json<Value>, ApiError> {
    let application = params.first().map(|(_, v)| v.as_str()).unwrap_or("");
    if application != token.app {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "wrong_application",
            "This token belongs to a different application; set spring.application.name to its Keystone id",
        ));
    }
    let key = vault::data_key(&state, &token.app).await?;
    let layers = vault::resolve(&state.db, &key, &token.app, &token.environment).await?;
    record(&state, &actor, &token, "vault.config.read", " (spring)").await?;
    let label = params.get(2).map(|(_, v)| v.clone());
    let version = version_of(&layers);
    Ok(Json(json!({
        "name": token.app,
        "profiles": [token.environment],
        "label": label,
        "version": version,
        "state": null,
        "propertySources": layers.into_iter().map(|l| json!({"name": l.name, "source": l.source})).collect::<Vec<_>>(),
    })))
}
