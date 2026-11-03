//! `keystone connect-portal https://sso.example.com`: registers Keystone with Portal SSO through
//! its App Connect flow (a Portal administrator approves it in the browser) and saves the
//! issuer and public client id into keystone.properties. No secret is copied anywhere.
use crate::config;
use anyhow::{Context, bail, ensure};
use axum::{Router, extract::Query, response::Html, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, oneshot};

pub async fn run(cfg: &config::Config, args: &config::Args) -> anyhow::Result<()> {
    let issuer = args
        .positional
        .first()
        .context("Usage: keystone connect-portal https://sso.example.com [--app-url=https://keystone.example.com]")?
        .trim_end_matches('/')
        .to_owned();
    config::validate_url(&issuer)?;
    let port = cfg.bind.rsplit(':').next().unwrap_or("8090");
    let app_url = args
        .flags
        .get("app-url")
        .cloned()
        .unwrap_or_else(|| format!("http://localhost:{port}"))
        .trim_end_matches('/')
        .to_owned();
    config::validate_url(&app_url)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let discovery: Value = http
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .send()
        .await?
        .json()
        .await
        .context("Not a Portal SSO / OIDC issuer")?;
    ensure!(
        discovery["issuer"] == issuer.as_str(),
        "The issuer in discovery does not match {issuer}"
    );

    let mut raw = [0u8; 48];
    aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, &mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let callback = format!("{app_url}/api/setup/portal-callback");
    let manifest = json!({
        "product": "keystone", "name": "Keystone Vault",
        "description": "Encrypted secrets and configuration for Portal applications.",
        "appUrl": app_url, "clientId": "keystone", "redirectUris": [app_url],
        "scopes": ["openid", "profile", "email"], "confidential": false,
        "externalAuth": false, "externalRegistration": false,
    });
    let response = http
        .post(format!("{issuer}/api/external/connect/requests"))
        .json(&json!({"manifest": manifest, "callbackUri": callback, "codeChallenge": challenge, "codeChallengeMethod": "S256"}))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "Portal refused the connection request: HTTP {}",
        response.status()
    );
    let created: Value = response.json().await?;
    let request_id = created["requestId"]
        .as_str()
        .context("Unexpected response from Portal")?
        .to_owned();
    let approval = created["approvalUrl"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    ensure!(approval.starts_with(&issuer), "Unexpected approval URL");

    let file = cfg
        .config_file
        .clone()
        .unwrap_or_else(|| cfg.home.join("keystone.properties"));
    let (done_tx, done_rx) = oneshot::channel::<anyhow::Result<String>>();
    let done = Arc::new(Mutex::new(Some(done_tx)));
    let handler = {
        let (issuer, request_id, verifier, file, http, done) = (
            issuer.clone(),
            request_id.clone(),
            verifier,
            file.clone(),
            http.clone(),
            done.clone(),
        );
        move |Query(query): Query<HashMap<String, String>>| {
            let (issuer, request_id, verifier, file, http, done) = (
                issuer.clone(),
                request_id.clone(),
                verifier.clone(),
                file.clone(),
                http.clone(),
                done.clone(),
            );
            async move {
                if query.get("request_id") != Some(&request_id) {
                    return Html("Unknown request.".to_owned());
                }
                let Some(code) = query.get("code") else {
                    return Html("Portal did not approve the connection.".to_owned());
                };
                let result = async {
                    let redeemed: Value = http
                        .post(format!(
                            "{issuer}/api/external/connect/requests/{request_id}/redeem"
                        ))
                        .json(&json!({"code": code, "codeVerifier": verifier}))
                        .send()
                        .await?
                        .error_for_status()?
                        .json()
                        .await?;
                    let creds = &redeemed["credentials"];
                    let client = creds["oidc"]["clientId"]
                        .as_str()
                        .context("No client id in the registration")?;
                    if creds["issuerUrl"] != issuer.as_str()
                        || creds["oidc"]["confidential"] == true
                    {
                        bail!("Unexpected registration details");
                    }
                    config::set_in_file(
                        &file,
                        &[("portal.url", &issuer), ("portal.client-id", client)],
                    )?;
                    Ok(client.to_owned())
                }
                .await;
                let page = match &result {
                    Ok(_) => "<!doctype html><title>Keystone connected</title><h1>Keystone Vault is connected to Portal SSO.</h1><p>Close this tab and start Keystone.</p>".to_owned(),
                    Err(e) => format!("<!doctype html><h1>Connection failed</h1><p>{e}. Reopen the Portal approval page and use Continue.</p>"),
                };
                if result.is_ok()
                    && let Some(tx) = done.lock().await.take()
                {
                    let _ = tx.send(result);
                }
                Html(page)
            }
        }
    };
    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| {
            format!(
                "Port {} is busy. Stop Keystone while connecting, then start it again.",
                cfg.bind
            )
        })?;
    println!(
        "Approve Keystone in Portal SSO (sign in as a Portal administrator):\n\n  {approval}\n"
    );
    println!("Waiting for the approval (30 minutes)…");
    let app = Router::new().route("/api/setup/portal-callback", get(handler));
    let server = axum::serve(listener, app);
    tokio::select! {
        result = done_rx => {
            let client = result??;
            println!("Connected. Saved portal.url and portal.client-id={client} to {}", file.display());
            println!("Start Keystone and sign in at {app_url}");
            Ok(())
        }
        _ = server => bail!("The callback listener stopped"),
        _ = tokio::time::sleep(Duration::from_secs(1800)) => bail!("Timed out waiting for approval"),
    }
}
