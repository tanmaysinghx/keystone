use crate::AppState;
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use std::collections::HashMap;

// Public PKCE client transport only: destination and client are deployment-owned.
pub async fn exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(input): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let fail = |status, error, description| {
        (
            status,
            Json(json!({"error":error,"error_description":description})),
        )
    };
    if headers
        .get("x-portal-token-relay")
        .and_then(|v| v.to_str().ok())
        != Some("1")
    {
        return fail(
            StatusCode::FORBIDDEN,
            "invalid_request",
            "Use the Keystone sign-in page.",
        );
    }
    if !state.config.sso_configured() {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Portal SSO is not configured.",
        );
    }
    let get = |key: &str| input.get(key).map(String::as_str).unwrap_or("");
    if get("client_id") != state.config.client_id {
        return fail(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Client does not match Keystone.",
        );
    }
    let mut form = HashMap::from([
        ("client_id", state.config.client_id.clone()),
        ("grant_type", get("grant_type").to_owned()),
    ]);
    match get("grant_type") {
        "authorization_code" => {
            let verifier = get("code_verifier");
            if get("code").is_empty()
                || get("code").len() > 4096
                || !(43..=128).contains(&verifier.len())
                || !verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                || get("redirect_uri")
                    != format!("{}/oauth2/popup-callback", state.config.portal_url)
            {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid authorization code, PKCE verifier, or redirect URI.",
                );
            }
            for key in ["code", "code_verifier", "redirect_uri"] {
                form.insert(key, get(key).to_owned());
            }
        }
        "refresh_token"
            if !get("refresh_token").is_empty() && get("refresh_token").len() <= 8192 =>
        {
            form.insert("refresh_token", get("refresh_token").to_owned());
        }
        _ => {
            return fail(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Use authorization code with PKCE or refresh token.",
            );
        }
    }
    let result = state
        .http
        .post(format!("{}/oauth2/token", state.config.portal_url))
        .form(&form)
        .send()
        .await;
    if let Ok(response) = result {
        let status = response.status();
        if (status.is_success() || status.is_client_error())
            && let Ok(payload) = response.json::<Value>().await
        {
            return (status, Json(payload));
        }
    }
    fail(
        StatusCode::BAD_GATEWAY,
        "temporarily_unavailable",
        "Portal token exchange is unavailable. Please retry sign-in.",
    )
}
