use crate::{
    AppState,
    error::{ApiError, unauthorized},
};
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub iss: String,
    pub aud: serde_json::Value,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    // Portal access tokens carry scope; ID tokens do not. Do not accept ID tokens as API credentials.
    #[serde(default)]
    pub scope: Option<serde_json::Value>,
}
#[derive(Default)]
pub struct KeyCache {
    pub keys: Option<JwkSet>,
    pub fetched: Option<Instant>,
    pub attempted: Option<Instant>,
}

pub async fn require_admin(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !state.config.sso_configured() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "sso_not_configured",
            "Portal SSO is not configured",
        ));
    }
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    if token.len() > 16384 {
        return Err(unauthorized());
    }
    let header = decode_header(token).map_err(|_| unauthorized())?;
    if header.alg != Algorithm::RS256 {
        return Err(unauthorized());
    }
    let kid = header.kid.ok_or_else(unauthorized)?;
    let mut cache = state.keys.lock().await;
    let expired = cache
        .fetched
        .is_none_or(|at| at.elapsed() > Duration::from_secs(300));
    let unknown = cache
        .keys
        .as_ref()
        .and_then(|keys| keys.find(&kid))
        .is_none();
    if (expired || unknown)
        && cache
            .attempted
            .is_none_or(|at| at.elapsed() > Duration::from_secs(10))
    {
        cache.attempted = Some(Instant::now());
        let response = state
            .http
            .get(format!("{}/oauth2/jwks", state.config.portal_url))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|_| {
                ApiError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "sso_unavailable",
                    "Portal key discovery is unavailable",
                )
            })?;
        let keys: JwkSet = response.json().await.map_err(|_| unauthorized())?;
        cache.keys = Some(keys);
        cache.fetched = Some(Instant::now());
    }
    // No indefinitely stale keys when the identity provider is unreachable.
    if cache
        .fetched
        .is_none_or(|at| at.elapsed() > Duration::from_secs(300))
    {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "sso_unavailable",
            "Portal key discovery is unavailable",
        ));
    }
    let jwk = cache
        .keys
        .as_ref()
        .and_then(|keys| keys.find(&kid))
        .ok_or_else(unauthorized)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| unauthorized())?;
    drop(cache);
    let claims = validate_token(
        token,
        &key,
        &state.config.portal_url,
        &state.config.client_id,
    )?;
    let actor = crate::client::Actor::new(
        crate::vault::admin_subject(&claims),
        &request,
        state.config.trust_proxy,
    );
    request.extensions_mut().insert(actor);
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

pub fn validate_token(
    token: &str,
    key: &DecodingKey,
    issuer: &str,
    audience: &str,
) -> Result<Claims, ApiError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.validate_nbf = true;
    validation.leeway = 15;
    let claims = decode::<Claims>(token, key, &validation)
        .map_err(|_| unauthorized())?
        .claims;
    let has_openid = match &claims.scope {
        Some(serde_json::Value::String(scope)) => scope.split_whitespace().any(|s| s == "openid"),
        Some(serde_json::Value::Array(scopes)) => {
            scopes.iter().any(|s| s.as_str() == Some("openid"))
        }
        _ => false,
    };
    if claims.sub.is_empty() || !has_openid {
        return Err(unauthorized());
    }
    if !claims.roles.iter().any(|role| role == "ROLE_ADMIN") {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "admin_required",
            "Portal administrator access is required",
        ));
    }
    Ok(claims)
}
