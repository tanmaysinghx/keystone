//! First-time setup (license, setup key, sign-in method, database), local accounts, and moving
//! a vault between databases.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use keystone::{
    AppState,
    config::{Config, master_key},
    router, state,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASSWORD: &str = "Correct-Horse-42";

fn config() -> Config {
    Config {
        master_key: master_key(&STANDARD.encode([3u8; 32])).unwrap(),
        accept_license: false,
        trust_proxy: true,
        failed_token_limit: 3,
        ..Default::default()
    }
}

async fn start(mut config: Config) -> (Router, AppState) {
    if config.database_url == "sqlite::memory:" {
        config.database_url = keystone::db::test_url().await;
    }
    let s = state(config).await.unwrap();
    (router(s.clone()), s)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-forwarded-for", "198.51.100.4");
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into())),
    )
}

#[tokio::test]
async fn wizard_needs_the_license_and_the_setup_key_then_configures_local_sign_in() {
    let (app, s) = start(config()).await;
    let (_, status) = call(&app, "GET", "/api/v1/setup/status", &[], None).await;
    assert_eq!(
        (
            status["required"].as_bool(),
            status["licenseAccepted"].as_bool()
        ),
        (Some(true), Some(false))
    );
    // Nothing else works until setup is done.
    let (code, body) = call(
        &app,
        "GET",
        "/api/v1/auth/me",
        &[("authorization", "Bearer x")],
        None,
    )
    .await;
    assert_eq!(
        (code, body["error"]["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("setup_required"))
    );
    let (_, license) = call(&app, "GET", "/api/v1/setup/license", &[], None).await;
    assert!(license.as_str().unwrap().contains("Apache License"));

    let key = s.setup_key.lock().unwrap().clone().unwrap();
    assert_eq!(
        std::fs::read_to_string(s.config.home.join("secrets/setup.key"))
            .unwrap()
            .trim(),
        key
    );
    let (code, _) = call(
        &app,
        "POST",
        "/api/v1/setup/verify",
        &[("x-setup-key", "wrong")],
        None,
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let k = [("x-setup-key", key.as_str())];
    assert_eq!(
        call(&app, "POST", "/api/v1/setup/verify", &k, None).await.0,
        StatusCode::NO_CONTENT
    );

    let (code, body) = call(&app, "POST", "/api/v1/setup/finish", &k, Some(json!({}))).await;
    assert_eq!(
        (code, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("license_not_accepted"))
    );
    let (code, _) = call(
        &app,
        "POST",
        "/api/v1/setup/license",
        &k,
        Some(json!({"accept": false, "licenseId": "Apache-2.0"})),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/v1/setup/license",
            &k,
            Some(json!({"accept": true, "licenseId": "Apache-2.0"}))
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (code, body) = call(&app, "POST", "/api/v1/setup/finish", &k, Some(json!({}))).await;
    assert_eq!(
        (code, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("no_sign_in"))
    );
    let (code, body) = call(
        &app,
        "POST",
        "/api/v1/setup/finish",
        &k,
        Some(json!({"admin": {"email": "ops@example.com", "name": "Ops", "password": "short"}})),
    )
    .await;
    assert_eq!(
        (code, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("weak_password"))
    );

    let (code, done) = call(
        &app,
        "POST",
        "/api/v1/setup/finish",
        &k,
        Some(json!({"admin": {"email": "Ops@Example.com", "name": "Ops", "password": PASSWORD}})),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{done}");
    assert_eq!(done["restart"], true);
    let written = std::fs::read_to_string(s.config.home.join("keystone.properties")).unwrap();
    assert!(written.contains("auth.local=true"), "{written}");
    assert!(!s.config.home.join("secrets/setup.key").exists());
    assert_eq!(
        call(&app, "GET", "/api/v1/setup/status", &[], None).await.1,
        json!({"required": false})
    );
    let (code, _) = call(&app, "POST", "/api/v1/setup/verify", &k, None).await;
    assert_eq!(code, StatusCode::CONFLICT, "the key is single-use");
}

#[tokio::test]
async fn existing_portal_installs_only_accept_the_license_without_a_restart() {
    let mut cfg = config();
    cfg.portal_url = "https://portal.test".into();
    cfg.client_id = "keystone".into();
    let (app, s) = start(cfg).await;
    let key = s.setup_key.lock().unwrap().clone().unwrap();
    let k = [("x-setup-key", key.as_str())];
    call(
        &app,
        "POST",
        "/api/v1/setup/license",
        &k,
        Some(json!({"accept": true, "licenseId": "Apache-2.0"})),
    )
    .await;
    let (code, done) = call(&app, "POST", "/api/v1/setup/finish", &k, Some(json!({}))).await;
    assert_eq!(
        (code, done["restart"].as_bool()),
        (StatusCode::OK, Some(false))
    );
}

#[tokio::test]
async fn local_accounts_sign_in_manage_users_and_resist_guessing() {
    let mut cfg = config();
    cfg.accept_license = true;
    cfg.local_auth = true;
    cfg.bootstrap_admin = Some(("admin@example.com".into(), PASSWORD.into()));
    let (app, _) = start(cfg).await;
    // Unattended setup: license from configuration plus a bootstrap administrator.
    assert_eq!(
        call(&app, "GET", "/api/v1/setup/status", &[], None).await.1,
        json!({"required": false})
    );
    let (_, auth) = call(&app, "GET", "/api/v1/auth/config", &[], None).await;
    assert_eq!(
        (auth["local"].as_bool(), auth["configured"].as_bool()),
        (Some(true), Some(false))
    );

    let login = |email: &str, password: &str| json!({"email": email, "password": password});
    let (code, body) = call(
        &app,
        "POST",
        "/api/v1/auth/local/login",
        &[],
        Some(login("admin@example.com", "Wrong-password-1")),
    )
    .await;
    assert_eq!(
        (code, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_credentials"))
    );
    let (code, session) = call(
        &app,
        "POST",
        "/api/v1/auth/local/login",
        &[],
        Some(login("ADMIN@example.com", PASSWORD)),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let admin = format!("Bearer {}", session["token"].as_str().unwrap());
    let a = [("authorization", admin.as_str())];
    let (_, me) = call(&app, "GET", "/api/v1/auth/me", &a, None).await;
    assert_eq!(
        (me["email"].as_str(), me["admin"].as_bool()),
        (Some("admin@example.com"), Some(true))
    );

    // A full vault workflow with a local administrator.
    call(
        &app,
        "POST",
        "/api/v1/admin/vault/apps",
        &a,
        Some(json!({"id": "billing", "name": "Billing", "environments": ["prod"]})),
    )
    .await;
    let (code, _) = call(
        &app,
        "PUT",
        "/api/v1/admin/vault/apps/billing/environments/prod/keys/db.password",
        &a,
        Some(json!({"value": "s3cret"})),
    )
    .await;
    assert_eq!(code, StatusCode::OK);

    // An application owner sees only their application.
    let (code, _) = call(&app, "POST", "/api/v1/admin/users", &a, Some(json!({"email": "owner@example.com", "name": "Owner", "password": PASSWORD, "roles": ["ROLE_VAULT_BILLING"]}))).await;
    assert_eq!(code, StatusCode::CREATED);
    let (_, owner) = call(
        &app,
        "POST",
        "/api/v1/auth/local/login",
        &[],
        Some(login("owner@example.com", PASSWORD)),
    )
    .await;
    let o = format!("Bearer {}", owner["token"].as_str().unwrap());
    let (_, list) = call(
        &app,
        "GET",
        "/api/v1/admin/vault/apps",
        &[("authorization", &o)],
        None,
    )
    .await;
    assert_eq!(list["items"][0]["id"], "billing");
    let (code, _) = call(
        &app,
        "GET",
        "/api/v1/admin/users",
        &[("authorization", &o)],
        None,
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);

    // Without Portal SSO the last administrator cannot be removed or demoted.
    let (_, users) = call(&app, "GET", "/api/v1/admin/users", &a, None).await;
    let admin_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "admin@example.com")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (code, body) = call(
        &app,
        "DELETE",
        &format!("/api/v1/admin/users/{admin_id}"),
        &a,
        None,
    )
    .await;
    assert_eq!(
        (code, body["error"]["code"].as_str()),
        (StatusCode::CONFLICT, Some("last_admin"))
    );
    let (code, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/admin/users/{admin_id}"),
        &a,
        Some(json!({"roles": []})),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT);

    // Changing a password ends that user's sessions.
    let (code, _) = call(
        &app,
        "POST",
        "/api/v1/auth/local/password",
        &[("authorization", &o)],
        Some(json!({"current": PASSWORD, "next": "Another-Strong-77"})),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    let (code, _) = call(
        &app,
        "GET",
        "/api/v1/auth/me",
        &[("authorization", &o)],
        None,
    )
    .await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    // Sign-out ends the session.
    call(&app, "POST", "/api/v1/auth/local/logout", &a, None).await;
    assert_eq!(
        call(&app, "GET", "/api/v1/auth/me", &a, None).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Guessing locks the address out; every attempt is audited.
    for _ in 0..3 {
        call(
            &app,
            "POST",
            "/api/v1/auth/local/login",
            &[],
            Some(login("admin@example.com", "nope-nope-nope")),
        )
        .await;
    }
    let (code, _) = call(
        &app,
        "POST",
        "/api/v1/auth/local/login",
        &[],
        Some(login("admin@example.com", PASSWORD)),
    )
    .await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_vault_moves_between_databases_with_everything_intact() {
    let dir = std::env::temp_dir().join(format!("keystone-move-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = config();
    cfg.accept_license = true;
    cfg.local_auth = true;
    cfg.bootstrap_admin = Some(("admin@example.com".into(), PASSWORD.into()));
    cfg.database_url = format!("sqlite://{}/source.db", dir.display());
    let (app, source) = start(cfg.clone()).await;
    let (_, session) = call(
        &app,
        "POST",
        "/api/v1/auth/local/login",
        &[],
        Some(json!({"email": "admin@example.com", "password": PASSWORD})),
    )
    .await;
    let admin = format!("Bearer {}", session["token"].as_str().unwrap());
    let a = [("authorization", admin.as_str())];
    call(
        &app,
        "POST",
        "/api/v1/admin/vault/apps",
        &a,
        Some(json!({"id": "orders", "name": "Orders", "environments": ["qa"]})),
    )
    .await;
    call(
        &app,
        "PUT",
        "/api/v1/admin/vault/apps/orders/environments/qa/keys/db.url",
        &a,
        Some(json!({"value": "jdbc:qa"})),
    )
    .await;
    let (_, token) = call(
        &app,
        "POST",
        "/api/v1/admin/vault/apps/orders/tokens",
        &a,
        Some(json!({"name": "qa", "environment": "qa"})),
    )
    .await;

    // Into a fresh database (MySQL in CI when KEYSTONE_TEST_MYSQL_URL is set, else SQLite).
    let target_url = match std::env::var("KEYSTONE_TEST_MYSQL_URL") {
        Ok(u) if !u.is_empty() => keystone::db::test_url().await,
        _ => format!("sqlite://{}/target.db", dir.display()),
    };
    let target = keystone::db::connect(&target_url).await.unwrap();
    let rows = keystone::db::copy_all(&source.db, &target).await.unwrap();
    assert!(rows > 5);
    target.close().await;
    cfg.database_url = target_url;
    cfg.bootstrap_admin = None;
    let (moved, _) = start(cfg).await;
    let (_, value) = call(
        &moved,
        "GET",
        "/api/v1/vault/config",
        &[(
            "authorization",
            &format!("Bearer {}", token["token"].as_str().unwrap()),
        )],
        None,
    )
    .await;
    assert_eq!(value["db.url"], "jdbc:qa");
    // Accounts and the audit trail moved too.
    let (code, _) = call(
        &moved,
        "POST",
        "/api/v1/auth/local/login",
        &[],
        Some(json!({"email": "admin@example.com", "password": PASSWORD})),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let _ = std::fs::remove_dir_all(dir);
}
