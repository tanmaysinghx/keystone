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
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

/// app, environment, name, secret hash, expires_at, revoked_at
type TokenRow = (String, String, String, Vec<u8>, Option<i64>, Option<i64>);

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
    let token = presented(request.headers()).ok_or_else(invalid_token)?;
    let (id, secret) = crypto::parse_token(&token).ok_or_else(invalid_token)?;
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT app_id, environment, name, secret_hash, expires_at, revoked_at FROM vault_tokens WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some((app, environment, name, digest, expires_at, revoked_at)) = row else {
        return Err(invalid_token());
    };
    let actor = Actor::new(
        format!("token:{id} ({name})"),
        &request,
        state.config.trust_proxy,
    );
    // A known token id presented with a wrong secret, or after revocation or expiry, is worth
    // an audit entry: it is either a misconfigured deployment or someone holding a stale credential.
    let denied = if !crypto::token_matches(secret, &digest) {
        Some("wrong secret")
    } else if revoked_at.is_some() {
        Some("revoked")
    } else if expires_at.is_some_and(|at| at <= crate::now() as i64) {
        Some("expired")
    } else {
        None
    };
    if let Some(reason) = denied {
        vault::audit(
            &state.db,
            &actor,
            "vault.token.denied",
            &format!("{app}/{environment} ({reason})"),
        )
        .await?;
        return Err(invalid_token());
    }
    sqlx::query(
        "UPDATE vault_tokens SET last_used_at = unixepoch() WHERE id = ? AND (last_used_at IS NULL OR last_used_at < unixepoch() - 60)",
    )
    .bind(id)
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
        &state.db,
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

/// `GET /api/v1/vault/config?format=json|properties|env|shell`
pub async fn config(
    State(state): State<AppState>,
    Extension(token): Extension<TokenContext>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<FormatQuery>,
) -> Result<Response, ApiError> {
    let key = vault::data_key(&state, &token.app).await?;
    let layers = vault::resolve(&state.db, &key, &token.app, &token.environment).await?;
    record(&state, &actor, &token, "vault.config.read", "").await?;
    vault::render(
        &vault::flatten(&layers),
        query.format.as_deref(),
        &format!("Keystone Vault: {} ({})", token.app, token.environment),
    )
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
    Ok(Json(json!({
        "name": token.app,
        "profiles": [token.environment],
        "label": label,
        "version": null,
        "state": null,
        "propertySources": layers.into_iter().map(|l| json!({"name": l.name, "source": l.source})).collect::<Vec<_>>(),
    })))
}
