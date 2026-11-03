//! Console-managed settings (alert webhook), stored sealed by the master key, and the read-only
//! overview of how this server is configured.
use crate::{AppState, auth::Access, client::Actor, config, error::ApiError, vault};
use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

pub async fn get(state: &AppState, key: &str) -> Option<String> {
    let master = state.config.master_key.as_ref()?;
    let (sealed,): (Vec<u8>,) = sqlx::query_as("SELECT value FROM vault_settings WHERE `key` = ?")
        .bind(key)
        .fetch_optional(&state.db)
        .await
        .ok()??;
    let raw = master.open_setting(key, &sealed).ok()?;
    String::from_utf8(raw).ok()
}

async fn set(
    state: &AppState,
    key: &str,
    value: Option<&str>,
    actor: &Actor,
) -> Result<(), ApiError> {
    let master = state.config.master_key.as_ref().ok_or_else(vault::sealed)?;
    match value {
        Some(value) => {
            let sealed = master.seal_setting(key, value.as_bytes()).map_err(|_| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "vault_error",
                    "Could not seal the setting",
                )
            })?;
            sqlx::query(&format!(
                "INSERT INTO vault_settings (`key`, value, updated_by, updated_at) VALUES (?, ?, ?, ?) {}",
                state.dialect.upsert("`key`", &["value", "updated_by", "updated_at"], &[])
            ))
            .bind(key)
            .bind(sealed)
            .bind(&actor.subject)
            .bind(crate::now() as i64)
            .execute(&state.db)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM vault_settings WHERE `key` = ?")
                .bind(key)
                .execute(&state.db)
                .await?;
        }
    }
    Ok(())
}

fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

pub async fn overview(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
) -> Result<Json<Value>, ApiError> {
    access.require_admin()?;
    let c = &state.config;
    let webhook = crate::alerts::webhook_url(&state).await;
    let last_backup = crate::backup::latest(&c.backup_dir);
    Ok(Json(json!({
        "version": config::VERSION,
        "home": c.home.display().to_string(),
        "configFile": c.config_file.as_ref().map(|p| p.display().to_string()),
        "bind": c.bind,
        "trustProxy": c.trust_proxy,
        "portal": {"url": c.portal_url, "clientId": c.client_id},
        "masterKey": {"configured": c.master_key.is_some(), "source": c.master_key_source},
        "backups": {
            "dir": c.backup_dir.display().to_string(),
            "intervalHours": c.backup_interval_hours,
            "keep": c.backup_keep,
            "last": last_backup.map(|(name, at, size)| json!({"name": name, "createdAt": at, "size": size})),
        },
        "security": {
            "failedTokenLimit": c.failed_token_limit,
            "lockoutMinutes": c.lockout_minutes,
            "rotationDays": c.rotation_days,
            "tokenExpiryWarningDays": c.token_expiry_warning_days,
        },
        "alerts": {
            "configured": webhook.is_some(),
            "source": webhook.as_ref().map(|(_, s)| *s),
            "host": webhook.as_ref().map(|(u, _)| host_of(u)),
        },
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertSettings {
    /// Empty or null removes the webhook.
    pub webhook_url: Option<String>,
}

pub async fn put_alerts(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Json(input): Json<AlertSettings>,
) -> Result<StatusCode, ApiError> {
    access.require_admin()?;
    if state.config.alerts_webhook_url.is_some() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "set_in_config",
            "The webhook is set in keystone.properties (alerts.webhook-url); change it there",
        ));
    }
    let url = input
        .webhook_url
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty());
    if let Some(url) = &url
        && (url.len() > 500 || config::validate_url(url).is_err())
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_webhook",
            "Use an https:// webhook URL without credentials",
        ));
    }
    set(&state, crate::alerts::SETTING, url.as_deref(), &actor).await?;
    vault::audit(
        &state,
        &actor,
        "vault.settings.update",
        if url.is_some() {
            "alerts webhook set"
        } else {
            "alerts webhook removed"
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn test_alert(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Value>, ApiError> {
    access.require_admin()?;
    if crate::alerts::webhook_url(&state).await.is_none() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "no_webhook",
            "Set a webhook URL first",
        ));
    }
    let result = crate::alerts::deliver(
        &state,
        "vault.alerts.test",
        &format!("Test alert sent by {}. Alerts are working.", actor.subject),
        &actor,
    )
    .await;
    Ok(Json(
        json!({"delivered": result.is_ok(), "error": result.err().map(|e| e.to_string())}),
    ))
}
