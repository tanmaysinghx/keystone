use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode, jwk::JwkSet};
use keystone::{
    AppState,
    auth::{KeyCache, validate_token},
    config::Config,
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

const SERVICE_KEY: &str = "integration-test-service-key-not-for-production";
static SIGNER: LazyLock<(String, JwkSet)> = LazyLock::new(|| {
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let jwks: JwkSet=serde_json::from_value(json!({"keys":[{"kty":"RSA","kid":"test-key","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}]})).unwrap();
    (key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(), jwks)
});
fn config() -> Config {
    Config {
        bind: "127.0.0.1:0".into(),
        database_url: "sqlite::memory:".into(),
        ui_dir: "missing-test-ui".into(),
        service_key: SERVICE_KEY.into(),
        portal_url: "https://portal.test".into(),
        client_id: "keystone-test".into(),
        master_key: None,
        trust_proxy: true,
    }
}
fn claims() -> Value {
    json!({"sub":"test-admin","iss":"https://portal.test","aud":["keystone-test"],"exp":keystone::now()+300,"roles":["ROLE_ADMIN"],"scope":"openid profile email"})
}
fn token(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".into());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(SIGNER.0.as_bytes()).unwrap(),
    )
    .unwrap()
}
async fn test_state() -> AppState {
    let s = state(config()).await.unwrap();
    *s.keys.lock().await = KeyCache {
        keys: Some(SIGNER.1.clone()),
        fetched: Some(Instant::now()),
        attempted: Some(Instant::now()),
    };
    s
}
async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
fn reaction(visitor: &str, action: &str) -> Request<Body> {
    Request::post("/api/v1/blog/stats")
        .header("content-type", "application/json")
        .header("x-keystone-key", SERVICE_KEY)
        .body(Body::from(
            json!({"slug":"test-post","action":action,"visitor":visitor}).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn concurrent_retries_count_once_and_different_visitors_count_separately() {
    let s = test_state().await;
    let app = router(s.clone());
    let visitor = uuid::Uuid::new_v4().to_string();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let app = app.clone();
        let visitor = visitor.clone();
        tasks.spawn(async move {
            app.oneshot(reaction(&visitor, "like"))
                .await
                .unwrap()
                .status()
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), StatusCode::OK);
    }
    assert_eq!(
        keystone::blog::counts(&s.db, "test-post")
            .await
            .unwrap()
            .likes,
        1
    );
    app.clone()
        .oneshot(reaction(&uuid::Uuid::new_v4().to_string(), "like"))
        .await
        .unwrap();
    app.clone()
        .oneshot(reaction(&visitor, "view"))
        .await
        .unwrap();
    app.oneshot(reaction(&visitor, "view")).await.unwrap();
    let counts = keystone::blog::counts(&s.db, "test-post").await.unwrap();
    assert_eq!(counts.likes, 2);
    assert_eq!(counts.views, 1);
}
#[tokio::test]
async fn endpoints_enforce_service_and_admin_boundaries() {
    let app = router(test_state().await);
    for path in [
        "/api/v1/auth/me",
        "/api/v1/admin/vault/apps",
        "/api/v1/blog/stats?slug=test-post",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let mut ordinary = claims();
    ordinary["roles"] = json!(["ROLE_USER"]);
    assert_eq!(
        app.clone()
            .oneshot(
                Request::get("/api/v1/auth/me")
                    .header("authorization", format!("Bearer {}", token(&ordinary)))
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = app
        .oneshot(
            Request::get("/api/v1/auth/me")
                .header("authorization", format!("Bearer {}", token(&claims())))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["subject"], "test-admin");
}
#[test]
fn jwt_rejects_wrong_issuer_audience_expiry_signature_and_id_token() {
    let key = DecodingKey::from_jwk(&SIGNER.1.keys[0]).unwrap();
    let mut array_scopes = claims();
    array_scopes["scope"] = json!(["openid", "profile", "email"]);
    assert!(
        validate_token(
            &token(&array_scopes),
            &key,
            "https://portal.test",
            "keystone-test"
        )
        .is_ok()
    );
    assert!(
        validate_token(
            &token(&claims()),
            &key,
            "https://portal.test",
            "keystone-test"
        )
        .is_ok()
    );
    for (field, value) in [
        ("iss", json!("https://evil.test")),
        ("aud", json!(["another-app"])),
        ("exp", json!(keystone::now() - 60)),
        ("scope", json!(null)),
        ("nbf", json!(keystone::now() + 300)),
    ] {
        let mut c = claims();
        c[field] = value;
        assert!(
            validate_token(&token(&c), &key, "https://portal.test", "keystone-test").is_err(),
            "Accepted invalid {field}"
        );
    }
    let signed = token(&claims());
    let mut pieces: Vec<&str> = signed.split('.').collect();
    let payload = URL_SAFE_NO_PAD.encode(json!({"sub":"attacker"}).to_string());
    pieces[1] = &payload;
    assert!(
        validate_token(
            &pieces.join("."),
            &key,
            "https://portal.test",
            "keystone-test"
        )
        .is_err()
    );
}
#[tokio::test]
async fn invalid_input_and_unconfigured_services_fail_closed() {
    let app = router(test_state().await);
    let response = app
        .clone()
        .oneshot(reaction("not-a-uuid", "like"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = app
        .oneshot(
            Request::get("/api/v1/blog/stats?slug=bad_slug")
                .header("x-keystone-key", SERVICE_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let mut cfg = config();
    cfg.client_id.clear();
    cfg.service_key.clear();
    let app = router(state(cfg).await.unwrap());
    for path in ["/api/v1/auth/me", "/api/v1/blog/stats?slug=test"] {
        assert_eq!(
            app.clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(
        app.oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
#[tokio::test]
async fn reactions_survive_restart_and_readiness_detects_storage_failure() {
    let file = std::env::temp_dir().join(format!("keystone-test-{}.db", uuid::Uuid::new_v4()));
    let mut cfg = config();
    cfg.database_url = format!("sqlite://{}", file.to_string_lossy().replace('\\', "/"));
    let s = state(cfg.clone()).await.unwrap();
    router(s.clone())
        .oneshot(reaction(&uuid::Uuid::new_v4().to_string(), "like"))
        .await
        .unwrap();
    s.db.close().await;
    drop(s);
    let s = state(cfg).await.unwrap();
    assert_eq!(
        keystone::blog::counts(&s.db, "test-post")
            .await
            .unwrap()
            .likes,
        1
    );
    s.db.close().await;
    let response = router(s)
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(response);
    // SQLite closes its worker thread asynchronously; Windows retains the file handle briefly.
    for attempt in 0..20 {
        match std::fs::remove_file(&file) {
            Ok(()) => break,
            Err(error) if attempt == 19 => panic!("Could not remove test database: {error}"),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    }
}

#[tokio::test]
async fn token_relay_validates_and_forwards_public_pkce() {
    use axum::{Form, Json, Router, routing::post};
    use std::collections::HashMap;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/oauth2/token",
                post(|Form(form): Form<HashMap<String, String>>| async move {
                    assert_eq!(form["client_id"], "keystone-test");
                    assert!(!form.contains_key("client_secret"));
                    assert!(!form.contains_key("extra"));
                    if form["grant_type"] == "authorization_code" {
                        assert_eq!(form["code_verifier"].len(), 64);
                    }
                    Json(json!({"access_token":"test-only-token","token_type":"Bearer"}))
                }),
            ),
        )
        .await
        .unwrap();
    });
    let mut cfg = config();
    cfg.portal_url = origin.clone();
    let app = router(state(cfg).await.unwrap());
    for (form, header, expected) in [
        (
            format!(
                "grant_type=authorization_code&client_id=keystone-test&code=test&code_verifier={}&redirect_uri={}/oauth2/popup-callback&extra=discard",
                "a".repeat(64),
                origin
            ),
            true,
            StatusCode::OK,
        ),
        (
            "grant_type=refresh_token&client_id=keystone-test&refresh_token=test".into(),
            true,
            StatusCode::OK,
        ),
        (
            "grant_type=client_credentials&client_id=keystone-test".into(),
            true,
            StatusCode::BAD_REQUEST,
        ),
        (
            "grant_type=authorization_code&client_id=keystone-test&code=test".into(),
            true,
            StatusCode::BAD_REQUEST,
        ),
        (
            "grant_type=refresh_token&client_id=wrong&refresh_token=test".into(),
            true,
            StatusCode::BAD_REQUEST,
        ),
        (
            "grant_type=refresh_token&client_id=keystone-test&refresh_token=test".into(),
            false,
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::post("/api/v1/auth/token")
            .header("content-type", "application/x-www-form-urlencoded");
        if header {
            request = request.header("x-portal-token-relay", "1");
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(form)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
        if expected == StatusCode::OK {
            assert_eq!(body(response).await["access_token"], "test-only-token");
        }
    }
    upstream.abort();
}
