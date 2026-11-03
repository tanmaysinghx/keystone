//! Health checks: what an operator should fix, ranked. Expiring and unused tokens, secrets not
//! rotated, production environments without protection, tokens without IP restrictions,
//! refused-token attempts, pending approvals, and backup / master-key hygiene.
use crate::{AppState, auth::Access, error::ApiError};
use axum::{Extension, Json, extract::State};
use serde_json::{Value, json};

fn finding(
    severity: &str,
    kind: &str,
    title: String,
    detail: String,
    app: Option<&str>,
    env: Option<&str>,
    action: &str,
) -> Value {
    json!({"severity": severity, "kind": kind, "title": title, "detail": detail, "app": app, "environment": env, "action": action})
}

fn is_production(env: &str) -> bool {
    matches!(env, "prod" | "production" | "prd" | "live")
        || env.starts_with("prod-")
        || env.starts_with("production-")
}

type TokenRow = (
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

pub async fn findings(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
) -> Result<Json<Value>, ApiError> {
    let c = &state.config;
    let now = crate::now() as i64;
    let day = 86_400;
    let mut out = Vec::new();

    if access.admin {
        if c.master_key.is_none() {
            out.push(finding("high", "sealed", "The vault is sealed".into(), "No master key is configured, so nothing can be stored or read. Set vault.master-key-file or let Keystone generate one.".into(), None, None, "settings"));
        }
        if c.backup_interval_hours == 0 {
            out.push(finding("high", "backups-off", "Automatic backups are off".into(), "Set backup.interval-hours (for example 24) so a lost disk does not lose every secret.".into(), None, None, "settings"));
        } else {
            let stale = crate::backup::latest(&c.backup_dir)
                .is_none_or(|(_, at, _)| now - at > 2 * c.backup_interval_hours as i64 * 3600);
            if stale {
                out.push(finding("high", "backup-stale", "No recent backup".into(), format!("The newest backup in {} is older than two backup intervals. Check that the folder is writable.", c.backup_dir.display()), None, None, "settings"));
            }
        }
        if c.master_key_source.starts_with("file ")
            && c.master_key_source.contains(&c.home.display().to_string())
        {
            out.push(finding("medium", "key-beside-data", "The master key sits next to the data".into(), "It was generated into the Keystone home. Keep a copy somewhere else (a password manager or secret store): a backup of the home folder alone exposes nothing, but losing both loses everything.".into(), None, None, "settings"));
        }
        if c.alerts_webhook_url.is_none()
            && crate::settings::get(&state, crate::alerts::SETTING)
                .await
                .is_none()
        {
            out.push(finding("low", "no-alerts", "Alerts are not set up".into(), "Add a Slack or Teams webhook under Settings to hear about refused tokens, deletions and pending approvals.".into(), None, None, "settings"));
        }
    }

    let tokens: Vec<TokenRow> = sqlx::query_as(
        "SELECT t.app_id, t.environment, t.id, t.name, t.created_at, t.expires_at, t.last_used_at, t.allowed_cidrs
         FROM vault_tokens t WHERE t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?)",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    let protected: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT app_id, name, protected FROM vault_environments")
            .fetch_all(&state.db)
            .await?;
    let is_protected = |app: &str, env: &str| {
        protected
            .iter()
            .any(|(a, e, p)| a == app && e == env && *p != 0)
    };
    for (app, env, id, name, created, expires, used, cidrs) in
        tokens.iter().filter(|t| access.can(&t.0))
    {
        if let Some(at) = expires
            && *at - now < c.token_expiry_warning_days * day
        {
            out.push(finding("medium", "token-expiring", format!("Token “{name}” expires soon"), format!("ksv_{id}… for {app}/{env} expires in {} days. Issue a replacement and roll it out before then.", ((at - now) / day).max(0)), Some(app), Some(env), "tokens"));
        }
        let idle = used.map_or(now - created, |u| now - u);
        if idle > 30 * day {
            out.push(finding(
                "low",
                "token-unused",
                format!("Token “{name}” looks unused"),
                format!(
                    "ksv_{id}… for {app}/{env} has {} for {} days. Revoke it if nothing needs it.",
                    if used.is_some() {
                        "not been used"
                    } else {
                        "never been used"
                    },
                    idle / day
                ),
                Some(app),
                Some(env),
                "tokens",
            ));
        }
        if cidrs.is_none() && (is_protected(app, env) || is_production(env)) {
            out.push(finding("medium", "token-unrestricted", format!("Token “{name}” works from any IP"), format!("{app}/{env} is a production environment. Restrict ksv_{id}… to your servers' addresses so a leaked token is useless elsewhere."), Some(app), Some(env), "tokens"));
        }
    }

    let stale: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT app_id, environment, COUNT(*), MIN(updated_at) FROM vault_items
         WHERE kind = 'key' AND updated_at < ? GROUP BY app_id, environment",
    )
    .bind(now - c.rotation_days * day)
    .fetch_all(&state.db)
    .await?;
    for (app, env, count, oldest) in stale.iter().filter(|s| access.can(&s.0)) {
        out.push(finding("low", "keys-stale", format!("{count} keys not rotated in {} days", c.rotation_days), format!("{app}/{env}: the oldest was last changed {} days ago. Rotate credentials there on a schedule.", (now - oldest) / day), Some(app), Some(env), "keys"));
    }

    for (app, env, p) in protected.iter().filter(|e| access.can(&e.0)) {
        if *p == 0 && is_production(env) {
            out.push(finding("medium", "prod-unprotected", format!("{app}/{env} is not protected"), "Production changes apply immediately. Protect the environment so every change needs a second administrator's approval.".into(), Some(app), Some(env), "protect"));
        }
    }

    let denied: Vec<(String, i64)> = sqlx::query_as(
        "SELECT target, COUNT(*) FROM audit_events WHERE event = 'vault.token.denied' AND created_at >= ? GROUP BY target",
    )
    .bind(now - day)
    .fetch_all(&state.db)
    .await?;
    for (target, count) in denied {
        let app = target.split(['/', ' ']).next().unwrap_or("").to_owned();
        if access.can(&app) {
            out.push(finding("high", "token-denied", format!("{count} refused token attempts in 24 hours"), format!("{target}. A deployment is using a stale token, or someone is trying one they should not have."), Some(&app), None, "audit"));
        }
    }

    let pending: Vec<(String, i64)> = sqlx::query_as(
        "SELECT app_id, COUNT(*) FROM vault_change_requests WHERE status = 'pending' GROUP BY app_id",
    )
    .fetch_all(&state.db)
    .await?;
    for (app, count) in pending.iter().filter(|p| access.can(&p.0)) {
        out.push(finding("medium", "approvals-pending", format!("{count} changes waiting for approval"), format!("{app} has protected-environment changes that apply only after another administrator approves them."), Some(app), None, "approvals"));
    }

    let rank = |s: &Value| match s["severity"].as_str() {
        Some("high") => 0,
        Some("medium") => 1,
        _ => 2,
    };
    out.sort_by_key(rank);
    let counts = json!({
        "high": out.iter().filter(|f| f["severity"] == "high").count(),
        "medium": out.iter().filter(|f| f["severity"] == "medium").count(),
        "low": out.iter().filter(|f| f["severity"] == "low").count(),
        "pendingApprovals": pending.iter().filter(|p| access.can(&p.0)).map(|p| p.1).sum::<i64>(),
    });
    Ok(Json(json!({"items": out, "counts": counts})))
}
