//! Operational features: per-app roles, token IP allow-lists, lockout, protected environments with
//! two-person approval, promote, reload (ETag / watch), backups, master-key verification, health
//! checks and alert webhooks.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
use keystone::{
    AppState,
    auth::KeyCache,
    config::{Config, master_key},
    router, state,
};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use serde_json::{Value, json};
use std::{sync::LazyLock, time::Instant};
use tower::ServiceExt;

static SIGNER: LazyLock<(String, JwkSet)> = LazyLock::new(|| {
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let jwks: JwkSet = serde_json::from_value(json!({"keys":[{"kty":"RSA","kid":"k","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}]})).unwrap();
    (key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(), jwks)
});

fn config() -> Config {
    Config {
        portal_url: "https://portal.test".into(),
        client_id: "keystone-test".into(),
        master_key: master_key(&STANDARD.encode([5u8; 32])).unwrap(),
        trust_proxy: true,
        failed_token_limit: 3,
        backup_dir: std::env::temp_dir().join(format!("keystone-backups-{}", uuid::Uuid::new_v4())),
        ..Default::default()
    }
}

fn person(email: &str, roles: &[&str]) -> String {
    let claims = json!({"sub": email, "email": email, "iss":"https://portal.test","aud":["keystone-test"],"exp":keystone::now()+300,"roles":roles,"scope":"openid"});
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("k".into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(SIGNER.0.as_bytes()).unwrap(),
    )
    .unwrap()
}

async fn setup(config: Config) -> (Router, AppState) {
    let s = state(on_test_db(config).await).await.unwrap();
    *s.keys.lock().await = KeyCache {
        keys: Some(SIGNER.1.clone()),
        fetched: Some(Instant::now()),
        attempted: Some(Instant::now()),
    };
    (router(s.clone()), s)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    auth: &str,
    body: Option<Value>,
    ip: &str,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", auth)
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        headers,
    )
}

const BASE: &str = "/api/v1/admin/vault";
const IP: &str = "198.51.100.1";

/// billing (default, prod) and payroll; one prod token for billing.
async fn seed(app: &Router, admin: &str) -> String {
    for (id, envs) in [("billing", json!(["prod", "qa"])), ("payroll", json!([]))] {
        let (s, ..) = call(
            app,
            "POST",
            &format!("{BASE}/apps"),
            admin,
            Some(json!({"id": id, "name": id, "environments": envs})),
            IP,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
    }
    call(
        app,
        "PUT",
        &format!("{BASE}/apps/billing/environments/qa/keys/db.url"),
        admin,
        Some(json!({"value":"jdbc:qa"})),
        IP,
    )
    .await;
    call(
        app,
        "PUT",
        &format!("{BASE}/apps/billing/environments/qa/keys/feature"),
        admin,
        Some(json!({"value":"on"})),
        IP,
    )
    .await;
    let (_, token, _) = call(
        app,
        "POST",
        &format!("{BASE}/apps/billing/tokens"),
        admin,
        Some(
            json!({"name":"prod","environment":"prod","allowedCidrs":"203.0.113.0/24, 192.0.2.7"}),
        ),
        IP,
    )
    .await;
    token["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn portal_roles_scope_people_to_their_applications() {
    let (app, _) = setup(config()).await;
    let admin = format!("Bearer {}", person("admin@x", &["ROLE_ADMIN"]));
    seed(&app, &admin).await;
    let owner = format!(
        "Bearer {}",
        person("owner@x", &["ROLE_USER", "ROLE_VAULT_BILLING"])
    );
    let (_, list, _) = call(&app, "GET", &format!("{BASE}/apps"), &owner, None, IP).await;
    let ids: Vec<_> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, ["billing"]);
    assert_eq!(list["items"][0]["role"], "ROLE_VAULT_BILLING");
    let (s, ..) = call(
        &app,
        "GET",
        &format!("{BASE}/apps/billing/environments/qa/keys/db.url"),
        &owner,
        None,
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, body, _) = call(
        &app,
        "GET",
        &format!("{BASE}/apps/payroll/environments/default/items"),
        &owner,
        None,
        IP,
    )
    .await;
    assert_eq!(
        (s, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("app_forbidden"))
    );
    let (s, ..) = call(
        &app,
        "POST",
        &format!("{BASE}/apps"),
        &owner,
        Some(json!({"id":"x","name":"x"})),
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, ..) = call(&app, "GET", &format!("{BASE}/audit"), &owner, None, IP).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, ..) = call(
        &app,
        "GET",
        &format!("{BASE}/audit?app=billing"),
        &owner,
        None,
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let nobody = format!("Bearer {}", person("u@x", &["ROLE_USER"]));
    let (s, ..) = call(&app, "GET", &format!("{BASE}/apps"), &nobody, None, IP).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tokens_honour_ip_allow_lists_and_addresses_get_locked_out() {
    let (app, _) = setup(config()).await;
    let admin = format!("Bearer {}", person("admin@x", &["ROLE_ADMIN"]));
    let token = seed(&app, &admin).await;
    let bearer = format!("Bearer {token}");
    let (s, ..) = call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &bearer,
        None,
        "203.0.113.20",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, ..) = call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &bearer,
        None,
        "192.0.2.7",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, ..) = call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &bearer,
        None,
        "198.18.0.1",
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, log, _) = call(
        &app,
        "GET",
        &format!("{BASE}/audit?kind=denied"),
        &admin,
        None,
        IP,
    )
    .await;
    assert_eq!(
        log["items"][0]["target"],
        "billing/prod (address not allowed)"
    );

    // Three failures from one address lock it out, even for a valid token; others are unaffected.
    let wrong = format!(
        "Bearer {}{}",
        &token[..token.len() - 1],
        if token.ends_with('A') { 'B' } else { 'A' }
    );
    for _ in 0..2 {
        call(
            &app,
            "GET",
            "/api/v1/vault/whoami",
            &wrong,
            None,
            "203.0.113.99",
        )
        .await;
    }
    let (s, ..) = call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &bearer,
        None,
        "203.0.113.99",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &wrong,
        None,
        "203.0.113.99",
    )
    .await;
    let (s, body, _) = call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &bearer,
        None,
        "203.0.113.99",
    )
    .await;
    assert_eq!(
        (s, body["error"]["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("too_many_attempts"))
    );
    let (s, ..) = call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &bearer,
        None,
        "203.0.113.20",
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // The allow-list can be changed later.
    let (_, tokens, _) = call(
        &app,
        "GET",
        &format!("{BASE}/apps/billing/tokens"),
        &admin,
        None,
        IP,
    )
    .await;
    let id = tokens["items"][0]["id"].as_str().unwrap();
    let (s, body, _) = call(
        &app,
        "PATCH",
        &format!("{BASE}/apps/billing/tokens/{id}"),
        &admin,
        Some(json!({"allowedCidrs": "nonsense"})),
        IP,
    )
    .await;
    assert_eq!(
        (s, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_cidr"))
    );
    call(
        &app,
        "PATCH",
        &format!("{BASE}/apps/billing/tokens/{id}"),
        &admin,
        Some(json!({"allowedCidrs": ""})),
        IP,
    )
    .await;
    let (s, ..) = call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &bearer,
        None,
        "198.18.0.1",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn protected_environments_need_a_second_administrator() {
    let (app, _) = setup(config()).await;
    let alice = format!("Bearer {}", person("alice@x", &["ROLE_ADMIN"]));
    let bob = format!("Bearer {}", person("bob@x", &["ROLE_ADMIN"]));
    let token = seed(&app, &alice).await;
    let owner = format!("Bearer {}", person("owner@x", &["ROLE_VAULT_BILLING"]));
    let (s, ..) = call(
        &app,
        "PUT",
        &format!("{BASE}/apps/billing/environments/prod/protection"),
        &owner,
        Some(json!({"protected": true})),
        IP,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "only administrators change protection"
    );
    let (s, ..) = call(
        &app,
        "PUT",
        &format!("{BASE}/apps/billing/environments/prod/protection"),
        &alice,
        Some(json!({"protected": true})),
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (s, body, _) = call(
        &app,
        "PUT",
        &format!("{BASE}/apps/billing/environments/prod/keys/db.password"),
        &alice,
        Some(json!({"value":"s3cret"})),
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let id = body["pendingApproval"].as_i64().unwrap();
    // Not applied yet.
    let (_, items, _) = call(
        &app,
        "GET",
        &format!("{BASE}/apps/billing/environments/prod/items"),
        &alice,
        None,
        IP,
    )
    .await;
    assert_eq!(items["items"], json!([]));
    let (s, body, _) = call(
        &app,
        "POST",
        &format!("{BASE}/changes/{id}/approve"),
        &alice,
        None,
        IP,
    )
    .await;
    assert_eq!(
        (s, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("self_approval"))
    );
    let (_, review, _) = call(
        &app,
        "GET",
        &format!("{BASE}/changes/{id}/reveal"),
        &bob,
        None,
        IP,
    )
    .await;
    assert_eq!(
        (review["proposed"].as_str(), review["current"].as_null()),
        (Some("s3cret"), Some(()))
    );
    let (s, ..) = call(
        &app,
        "POST",
        &format!("{BASE}/changes/{id}/approve"),
        &bob,
        None,
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, ..) = call(
        &app,
        "POST",
        &format!("{BASE}/changes/{id}/approve"),
        &bob,
        None,
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "applied once");
    let (_, value, _) = call(
        &app,
        "GET",
        "/api/v1/vault/config",
        &format!("Bearer {token}"),
        None,
        "203.0.113.1",
    )
    .await;
    assert_eq!(value["db.password"], "s3cret");
    let (_, items, _) = call(
        &app,
        "GET",
        &format!("{BASE}/apps/billing/environments/prod/items"),
        &alice,
        None,
        IP,
    )
    .await;
    assert_eq!(
        items["items"][0]["updatedBy"],
        "admin:alice@x (approved by admin:bob@x)"
    );

    // Deletes and imports are proposals too; a requester can withdraw their own.
    let (s, body, _) = call(
        &app,
        "DELETE",
        &format!("{BASE}/apps/billing/environments/prod/keys/db.password"),
        &bob,
        None,
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (_, body, _) = call(
        &app,
        "POST",
        &format!("{BASE}/changes/{}/reject", body["pendingApproval"]),
        &bob,
        None,
        IP,
    )
    .await;
    assert_eq!(body["status"], "cancelled");
    let (s, body, _) = call(
        &app,
        "POST",
        &format!("{BASE}/apps/billing/environments/prod/import"),
        &bob,
        Some(json!({"format":"properties","content":"a=1\nb=2\n"})),
        IP,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (_, pending, _) = call(&app, "GET", &format!("{BASE}/changes"), &alice, None, IP).await;
    assert_eq!(pending["items"].as_array().unwrap().len(), 1);
    call(
        &app,
        "POST",
        &format!("{BASE}/changes/{}/approve", body["pendingApproval"]),
        &alice,
        None,
        IP,
    )
    .await;
    let (_, value, _) = call(
        &app,
        "GET",
        "/api/v1/vault/config",
        &format!("Bearer {token}"),
        None,
        "203.0.113.1",
    )
    .await;
    assert_eq!(
        (value["a"].as_str(), value["b"].as_str()),
        (Some("1"), Some("2"))
    );
}

#[tokio::test]
async fn promote_compares_without_revealing_and_copies() {
    let (app, _) = setup(config()).await;
    let admin = format!("Bearer {}", person("admin@x", &["ROLE_ADMIN"]));
    seed(&app, &admin).await;
    call(
        &app,
        "PUT",
        &format!("{BASE}/apps/billing/environments/prod/keys/feature"),
        &admin,
        Some(json!({"value":"off"})),
        IP,
    )
    .await;
    let path = format!("{BASE}/apps/billing/environments/prod/promote");
    let (_, plan, _) = call(
        &app,
        "POST",
        &path,
        &admin,
        Some(json!({"from":"qa","dryRun":true})),
        IP,
    )
    .await;
    assert_eq!(
        plan["diff"],
        json!([{"item":"key:db.url","status":"added"},{"item":"key:feature","status":"changed"}])
    );
    assert!(!plan.to_string().contains("jdbc:qa"));
    let (_, done, _) = call(
        &app,
        "POST",
        &path,
        &admin,
        Some(json!({"from":"qa","items":["key:db.url"]})),
        IP,
    )
    .await;
    assert_eq!(done["copied"], 1);
    let (_, plan, _) = call(
        &app,
        "POST",
        &path,
        &admin,
        Some(json!({"from":"qa","dryRun":true})),
        IP,
    )
    .await;
    assert_eq!(plan["diff"][0]["status"], "same");
}

#[tokio::test]
async fn apps_can_reload_without_restarting() {
    let (app, _) = setup(config()).await;
    let admin = format!("Bearer {}", person("admin@x", &["ROLE_ADMIN"]));
    let token = format!("Bearer {}", seed(&app, &admin).await);
    let ip = "203.0.113.5";
    let (s, _, headers) = call(&app, "GET", "/api/v1/vault/config", &token, None, ip).await;
    assert_eq!(s, StatusCode::OK);
    let etag = headers["etag"].to_str().unwrap().to_owned();
    let request = |etag: &str| {
        Request::get("/api/v1/vault/config")
            .header("authorization", &token)
            .header("if-none-match", etag)
            .header("x-forwarded-for", ip)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request(&etag)).await.unwrap().status(),
        StatusCode::NOT_MODIFIED
    );
    let version = etag.trim_matches('"').to_owned();
    let watcher = {
        let app = app.clone();
        let (token, version) = (token.clone(), version.clone());
        tokio::spawn(async move {
            call(
                &app,
                "GET",
                &format!("/api/v1/vault/watch?version={version}&timeout=10"),
                &token,
                None,
                "203.0.113.5",
            )
            .await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    call(
        &app,
        "PUT",
        &format!("{BASE}/apps/billing/environments/default/keys/new.key"),
        &admin,
        Some(json!({"value":"x"})),
        IP,
    )
    .await;
    let (_, changed, _) = watcher.await.unwrap();
    assert_eq!(changed["changed"], true);
    assert_ne!(changed["version"], version.as_str());
    assert_eq!(
        app.clone().oneshot(request(&etag)).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn backups_and_master_key_verification() {
    let file = std::env::temp_dir().join(format!("keystone-ops-{}.db", uuid::Uuid::new_v4()));
    let mut cfg = config();
    cfg.database_url = format!("sqlite://{}", file.display());
    let (app, _) = setup(cfg.clone()).await;
    let admin = format!("Bearer {}", person("admin@x", &["ROLE_ADMIN"]));
    seed(&app, &admin).await;
    let (s, created, _) = call(&app, "POST", &format!("{BASE}/backups"), &admin, None, IP).await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, list, _) = call(&app, "GET", &format!("{BASE}/backups"), &admin, None, IP).await;
    assert_eq!(list["items"][0]["name"], created["name"]);
    let request = Request::get(format!(
        "{BASE}/backups/{}",
        created["name"].as_str().unwrap()
    ))
    .header("authorization", &admin)
    .body(Body::empty())
    .unwrap();
    let bytes = app
        .clone()
        .oneshot(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(bytes.starts_with(b"SQLite format 3"));
    let (s, ..) = call(
        &app,
        "GET",
        &format!("{BASE}/backups/..%2Fkeystone.db"),
        &admin,
        None,
        IP,
    )
    .await;
    assert_ne!(s, StatusCode::OK);

    // Restarting with another master key is refused instead of failing on every request.
    let mut wrong = cfg.clone();
    wrong.master_key = master_key(&STANDARD.encode([6u8; 32])).unwrap();
    let error = state(wrong)
        .await
        .err()
        .expect("wrong key must be refused")
        .to_string();
    assert!(
        error.contains("not the one this vault was created with"),
        "{error}"
    );
    assert!(state(cfg.clone()).await.is_ok());
    let _ = std::fs::remove_dir_all(&cfg.backup_dir);
    let _ = std::fs::remove_file(file);
}

#[tokio::test]
async fn health_checks_and_alert_webhooks() {
    // A local webhook receiver.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let hook = Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let tx = tx.clone();
            async move {
                tx.send(body).ok();
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, hook).await.unwrap() });

    let mut cfg = config();
    cfg.alerts_webhook_url = Some(format!("http://127.0.0.1:{port}/hook"));
    let (app, _) = setup(cfg).await;
    let admin = format!("Bearer {}", person("admin@x", &["ROLE_ADMIN"]));
    let token = seed(&app, &admin).await;
    let (_, findings, _) = call(&app, "GET", &format!("{BASE}/insights"), &admin, None, IP).await;
    let kinds: Vec<&str> = findings["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"prod-unprotected"), "{kinds:?}");
    assert!(kinds.contains(&"backups-off"), "{kinds:?}");

    let (_, settings, _) = call(&app, "GET", &format!("{BASE}/settings"), &admin, None, IP).await;
    assert_eq!(settings["alerts"]["source"], "config");
    let (_, test, _) = call(
        &app,
        "POST",
        &format!("{BASE}/settings/alerts/test"),
        &admin,
        None,
        IP,
    )
    .await;
    assert_eq!(test["delivered"], true);
    assert!(
        rx.recv().await.unwrap()["text"]
            .as_str()
            .unwrap()
            .contains("Test alert")
    );

    call(
        &app,
        "GET",
        "/api/v1/vault/whoami",
        &format!("Bearer {token}"),
        None,
        "198.18.0.9",
    )
    .await;
    let alert = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alert["event"], "vault.token.denied");
    assert!(
        alert["text"]
            .as_str()
            .unwrap()
            .contains("address not allowed")
    );
}

#[tokio::test]
async fn master_key_rotation_keeps_every_secret_readable() {
    let home = std::env::temp_dir().join(format!("keystone-rotate-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(home.join("secrets")).unwrap();
    let key_file = home.join("secrets/master.key");
    std::fs::write(&key_file, STANDARD.encode([7u8; 32])).unwrap();
    let mut cfg = config();
    cfg.home = home.clone();
    cfg.bind = "127.0.0.1:1".into();
    cfg.backup_dir = home.join("backups");
    cfg.database_url = format!("sqlite://{}", home.join("keystone.db").display());
    cfg.master_key = master_key(&STANDARD.encode([7u8; 32])).unwrap();
    cfg.master_key_source = format!("file {}", key_file.display());
    let token = {
        let (app, s) = setup(cfg.clone()).await;
        let admin = format!("Bearer {}", person("admin@x", &["ROLE_ADMIN"]));
        let token = seed(&app, &admin).await;
        call(
            &app,
            "PUT",
            &format!("{BASE}/apps/billing/environments/prod/keys/secret"),
            &admin,
            Some(json!({"value":"before-rotation"})),
            IP,
        )
        .await;
        s.db.close().await;
        token
    };
    let args = keystone::config::parse_args(Vec::<String>::new()).unwrap();
    keystone::cli::rotate_master_key(&cfg, &args).await.unwrap();
    let rotated = std::fs::read_to_string(&key_file).unwrap();
    assert_ne!(rotated.trim(), STANDARD.encode([7u8; 32]));
    // The old key no longer opens the vault; the new one does, with every value intact.
    assert!(state(cfg.clone()).await.is_err());
    cfg.master_key = master_key(rotated.trim()).unwrap();
    let (app, _) = setup(cfg).await;
    let (_, value, _) = call(
        &app,
        "GET",
        "/api/v1/vault/config",
        &format!("Bearer {token}"),
        None,
        "203.0.113.1",
    )
    .await;
    assert_eq!(value["secret"], "before-rotation");
    let _ = std::fs::remove_dir_all(home);
}

/// In-memory SQLite, or a fresh MySQL database when KEYSTONE_TEST_MYSQL_URL is set (CI).
async fn on_test_db(mut config: Config) -> Config {
    if config.database_url == "sqlite::memory:" {
        config.database_url = keystone::db::test_url().await;
    }
    config
}
