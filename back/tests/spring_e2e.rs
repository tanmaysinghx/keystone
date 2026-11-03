//! Serves a seeded Keystone on a real port so a real Spring Boot client can be pointed at it.
//! Opt-in: `cargo test -p keystone --test spring_e2e -- --ignored --nocapture`
//! Prints the qa token to the file named by KEYSTONE_E2E_TOKEN_FILE, then serves for 180 seconds.
use axum::{body::Body, http::Request};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
use keystone::{auth::KeyCache, config::Config, router, state};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "serves for a real Spring Boot client; run explicitly"]
async fn serve_seeded_vault_for_spring_boot() {
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let jwks: JwkSet = serde_json::from_value(json!({"keys":[{"kty":"RSA","kid":"k","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}]})).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let config = Config {
        bind: "127.0.0.1:18093".into(),
        database_url: "sqlite::memory:".into(),
        ui_dir: "missing".into(),
        service_key: String::new(),
        portal_url: "https://portal.test".into(),
        client_id: "keystone-test".into(),
        master_key: keystone::config::master_key(&STANDARD.encode([9u8; 32])).unwrap(),
        trust_proxy: false,
    };
    let s = state(config).await.unwrap();
    *s.keys.lock().await = KeyCache {
        keys: Some(jwks),
        fetched: Some(Instant::now() + Duration::from_secs(3600)),
        attempted: Some(Instant::now()),
    };
    let app = router(s.clone());
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("k".into());
    let admin = encode(&header, &json!({"sub":"admin","email":"admin@example.com","iss":"https://portal.test","aud":["keystone-test"],"exp":keystone::now()+3600,"roles":["ROLE_ADMIN"],"scope":"openid"}), &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap();
    let call = |method: &str, path: &str, body: Body, content_type: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {admin}"))
            .header("content-type", content_type)
            .body(body)
            .unwrap()
    };
    let json_body = |v: Value| Body::from(v.to_string());
    let base = "/api/v1/admin/vault/apps";
    for (method, path, body, ct) in [
        (
            "POST",
            base.to_owned(),
            json_body(
                json!({"id":"orders-service","name":"Orders Service","portalClientId":"orders-service","environments":["qa","uat","prod"]}),
            ),
            "application/json",
        ),
        // Shared by every environment.
        (
            "PUT",
            format!("{base}/orders-service/environments/default/keys/orders.retry-limit"),
            json_body(json!({"value":"3"})),
            "application/json",
        ),
        (
            "PUT",
            format!("{base}/orders-service/environments/default/keys/orders.payment-gateway"),
            json_body(json!({"value":"https://sandbox.pay.example"})),
            "application/json",
        ),
        // The qa application.properties, stored whole.
        (
            "PUT",
            format!("{base}/orders-service/environments/qa/files/application.properties"),
            Body::from(
                "spring.datasource.url=jdbc:postgresql://qa-db.internal:5432/orders\nspring.datasource.username=orders_qa\norders.retry-limit=5\n",
            ),
            "text/x-java-properties",
        ),
        // A secret kept as its own key so it can be rotated and audited separately.
        (
            "PUT",
            format!("{base}/orders-service/environments/qa/keys/spring.datasource.password"),
            json_body(json!({"value":"qa-S3cret!"})),
            "application/json",
        ),
    ] {
        let status = app
            .clone()
            .oneshot(call(method, &path, body, ct))
            .await
            .unwrap()
            .status();
        assert!(status.is_success(), "{method} {path} -> {status}");
    }
    let response = app
        .clone()
        .oneshot(call(
            "POST",
            &format!("{base}/orders-service/tokens"),
            json_body(json!({"name":"orders qa (e2e)","environment":"qa"})),
            "application/json",
        ))
        .await
        .unwrap();
    let issued: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    std::fs::write(
        std::env::var("KEYSTONE_E2E_TOKEN_FILE").unwrap(),
        issued["token"].as_str().unwrap(),
    )
    .unwrap();
    let audit_app = app.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18093")
        .await
        .unwrap();
    println!("E2E-READY");
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );
    let _ = tokio::time::timeout(Duration::from_secs(180), server).await;
    let response = audit_app
        .oneshot(call(
            "GET",
            "/api/v1/admin/vault/audit?app=orders-service&kind=pulls",
            Body::empty(),
            "application/json",
        ))
        .await
        .unwrap();
    println!(
        "E2E-AUDIT {}",
        String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
    );
}
