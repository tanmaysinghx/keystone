//! Security alerts to a webhook (Slack, Microsoft Teams, or any endpoint accepting JSON).
//!
//! Sent for events an operator should hear about immediately: refused tokens, reveals in protected
//! environments, deletions, protection turned off, change requests waiting for approval, audit
//! exports and failed backups. Delivery is fire-and-forget with a short timeout, so a slow webhook
//! never delays a request; repeated alerts for the same thing are throttled.
use crate::{AppState, client::Actor};
use serde_json::json;
use std::time::{Duration, Instant};

pub const SETTING: &str = "alerts.webhook-url";
const THROTTLE: Duration = Duration::from_secs(600);

/// Which audited events alert, and how they read.
fn describe(event: &str, actor: &Actor, target: &str) -> Option<String> {
    let who = &actor.subject;
    let from = actor
        .ip
        .as_deref()
        .map(|ip| format!(" from {ip}"))
        .unwrap_or_default();
    Some(match event {
        "vault.token.denied" => format!("Refused application token {who}{from}: {target}"),
        "vault.app.delete" => format!("{who} deleted application {target}"),
        "vault.environment.delete" => format!("{who} deleted environment {target}"),
        "vault.environment.unprotect" => format!("{who} turned off protection for {target}"),
        "vault.key.delete" | "vault.file.delete" => format!("{who} deleted {target}"),
        "vault.change.request" => format!("Approval needed: {who} proposed {target}"),
        "vault.audit.export" => format!("{who} exported the audit log ({target}){from}"),
        "vault.backup.failed" => format!("Backup failed: {target}"),
        "vault.ratelimit.lockout" => {
            format!("Locked out {target} after repeated failed token attempts")
        }
        _ => return None,
    })
}

pub fn on_event(state: &AppState, actor: &Actor, event: &str, target: &str) {
    if let Some(text) = describe(event, actor, target) {
        // One alert per event and target (and IP) per throttle window.
        let throttle_key = format!("{event}|{target}|{}", actor.ip.as_deref().unwrap_or(""));
        send_throttled(state, event, text, actor, throttle_key);
    }
}

pub fn send(state: &AppState, event: &str, text: String, actor: &Actor) {
    let key = format!("{event}|{text}");
    send_throttled(state, event, text, actor, key);
}

fn send_throttled(
    state: &AppState,
    event: &str,
    text: String,
    actor: &Actor,
    throttle_key: String,
) {
    {
        let mut seen = state.alerts_sent.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        seen.retain(|_, at| now.duration_since(*at) < THROTTLE);
        if seen.contains_key(&throttle_key) {
            return;
        }
        seen.insert(throttle_key, now);
    }
    let state = state.clone();
    let event = event.to_owned();
    let actor = actor.clone();
    tokio::spawn(async move {
        if let Err(error) = deliver(&state, &event, &text, &actor).await {
            tracing::warn!(%error, event, "Alert webhook delivery failed");
        }
    });
}

pub async fn webhook_url(state: &AppState) -> Option<(String, &'static str)> {
    if let Some(url) = &state.config.alerts_webhook_url {
        return Some((url.clone(), "config"));
    }
    crate::settings::get(state, SETTING)
        .await
        .map(|url| (url, "console"))
}

pub async fn deliver(
    state: &AppState,
    event: &str,
    text: &str,
    actor: &Actor,
) -> anyhow::Result<()> {
    let Some((url, _)) = webhook_url(state).await else {
        return Ok(());
    };
    let body = json!({
        // Slack and Teams render `text`; other receivers can use the structured fields.
        "text": format!(":lock: Keystone Vault: {text}"),
        "event": event,
        "subject": actor.subject,
        "ip": actor.ip,
        "time": crate::now(),
        "source": "keystone-vault",
    });
    let response = state
        .http
        .post(url)
        .timeout(Duration::from_secs(5))
        .json(&body)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "webhook answered {}",
        response.status()
    );
    Ok(())
}
