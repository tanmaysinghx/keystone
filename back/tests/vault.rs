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
    let jwks: JwkSet = serde_json::from_value(json!({"keys":[{"kty":"RSA","kid":"test-key","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}]})).unwrap();
    (key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(), jwks)
});

fn config(sealed: bool) -> Config {
    Config {
        bind: "127.0.0.1:0".into(),
        database_url: "sqlite::memory:".into(),
        ui_dir: "missing-test-ui".into(),
        service_key: String::new(),
        portal_url: "https://portal.test".into(),
        client_id: "keystone-test".into(),
        master_key: if sealed {
            None
        } else {
            master_key(&STANDARD.encode([42u8; 32])).unwrap()
        },
        trust_proxy: true,
    }
}

fn admin_token() -> String {
    let claims = json!({"sub":"admin-1","email":"admin@test","iss":"https://portal.test","aud":["keystone-test"],"exp":keystone::now()+300,"roles":["ROLE_ADMIN"],"scope":"openid profile email"});
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(SIGNER.0.as_bytes()).unwrap(),
    )
    .unwrap()
}

async fn app(sealed: bool) -> (Router, AppState) {
    let s = state(config(sealed)).await.unwrap();
    *s.keys.lock().await = KeyCache {
        keys: Some(SIGNER.1.clone()),
        fetched: Some(Instant::now()),
        attempted: Some(Instant::now()),
    };
    (router(s.clone()), s)
}

struct Call<'a> {
    app: &'a Router,
}
impl Call<'_> {
    async fn send(&self, request: Request<Body>) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, bytes, headers)
    }
    async fn admin(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", admin_token()))
            .header("content-type", "application/json");
        let request = builder
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let (status, bytes, _) = self.send(request).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn machine(&self, path: &str, auth: &str) -> (StatusCode, String) {
        let request = Request::get(path)
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap();
        let (status, bytes, _) = self.send(request).await;
        (status, String::from_utf8(bytes).unwrap())
    }
}

const BASE: &str = "/api/v1/admin/vault/apps";

async fn seed(call: &Call<'_>) -> String {
    let (status, _) = call
        .admin(
            "POST",
            BASE,
            Some(json!({"id":"billing","name":"Billing","portalClientId":"billing","environments":["prod","dev"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    for (env, key, value) in [
        (
            "default",
            "spring.datasource.url",
            "jdbc:postgresql://db/billing",
        ),
        ("default", "feature.flag", "off"),
        ("prod", "feature.flag", "on"),
        ("prod", "spring.datasource.password", "s3cr3t'pw"),
        ("dev", "spring.datasource.password", "dev-only"),
    ] {
        let (status, _) = call
            .admin(
                "PUT",
                &format!("{BASE}/billing/environments/{env}/keys/{key}"),
                Some(json!({"value": value})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, token) = call
        .admin(
            "POST",
            &format!("{BASE}/billing/tokens"),
            Some(json!({"name":"billing prod","environment":"prod"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    token["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn applications_read_merged_config_with_environment_overrides() {
    let (router, _) = app(false).await;
    let call = Call { app: &router };
    let token = seed(&call).await;
    let bearer = format!("Bearer {token}");

    let (status, body) = call.machine("/api/v1/vault/config", &bearer).await;
    assert_eq!(status, StatusCode::OK);
    let config: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(config["feature.flag"], "on");
    assert_eq!(
        config["spring.datasource.url"],
        "jdbc:postgresql://db/billing"
    );
    assert_eq!(config["spring.datasource.password"], "s3cr3t'pw");

    let (_, properties) = call
        .machine("/api/v1/vault/config?format=properties", &bearer)
        .await;
    assert!(
        properties.contains("spring.datasource.url=jdbc\\:postgresql")
            || properties.contains("spring.datasource.url=jdbc:postgresql")
    );
    let (_, shell) = call
        .machine("/api/v1/vault/config?format=shell", &bearer)
        .await;
    assert!(shell.contains("export SPRING_DATASOURCE_PASSWORD='s3cr3t'\\''pw'"));

    // Single key, falling back to default.
    let (status, value) = call
        .machine("/api/v1/vault/keys/spring.datasource.url", &bearer)
        .await;
    assert_eq!(
        (status, value.as_str()),
        (StatusCode::OK, "jdbc:postgresql://db/billing")
    );

    // HTTP Basic with the token as password, as Spring Cloud Config sends it.
    let basic = format!("Basic {}", STANDARD.encode(format!("keystone:{token}")));
    let (status, body) = call.machine("/config/billing/prod", &basic).await;
    assert_eq!(status, StatusCode::OK);
    let spring: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        spring["propertySources"][0]["name"],
        "keystone:billing/prod"
    );
    assert_eq!(spring["propertySources"][0]["source"]["feature.flag"], "on");
    assert_eq!(
        spring["propertySources"][1]["source"]["feature.flag"],
        "off"
    );
    let (status, _) = call.machine("/config/other-app/prod", &basic).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn whole_properties_files_are_stored_served_and_merged() {
    let (router, _) = app(false).await;
    let call = Call { app: &router };
    let token = seed(&call).await;
    let file = "# Billing\nserver.port=8081\nfeature.flag=from-file\nmessage=caf\\u00e9\n";
    let request = Request::put(format!(
        "{BASE}/billing/environments/prod/files/application.properties"
    ))
    .header("authorization", format!("Bearer {}", admin_token()))
    .header("content-type", "text/x-java-properties")
    .body(Body::from(file))
    .unwrap();
    assert_eq!(call.send(request).await.0, StatusCode::OK);

    let bearer = format!("Bearer {token}");
    let (status, raw) = call
        .machine("/api/v1/vault/files/application.properties", &bearer)
        .await;
    assert_eq!((status, raw.as_str()), (StatusCode::OK, file));
    let (_, body) = call.machine("/api/v1/vault/config", &bearer).await;
    let config: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(config["server.port"], "8081");
    assert_eq!(config["message"], "café");
    // Individual keys override keys from files in the same environment.
    assert_eq!(config["feature.flag"], "on");

    // Raw files are never rendered as active content on Keystone's origin.
    let request = Request::get("/api/v1/vault/files/application.properties")
        .header("authorization", &bearer)
        .body(Body::empty())
        .unwrap();
    let (_, _, headers) = call.send(request).await;
    assert_eq!(
        headers["content-security-policy"],
        "default-src 'none'; sandbox"
    );
    assert!(
        headers["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );
}

#[tokio::test]
async fn import_versions_rollback_and_audit() {
    let (router, s) = app(false).await;
    let call = Call { app: &router };
    seed(&call).await;
    let path = format!("{BASE}/billing/environments/dev/import");
    let (status, result) = call
        .admin(
            "POST",
            &path,
            Some(json!({"format":"properties","content":"a.b=1\nspring.datasource.password=dev-only\n"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result, json!({"written":1,"unchanged":1,"removed":0}));
    let (_, result) = call
        .admin(
            "POST",
            &path,
            Some(json!({"format":"env","content":"A_B=2\n","replace":true})),
        )
        .await;
    assert_eq!(result, json!({"written":1,"unchanged":0,"removed":2}));
    let (status, bad) = call
        .admin(
            "POST",
            &path,
            Some(json!({"format":"properties","content":"bad\\ key=1"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        bad["error"]["message"]
            .as_str()
            .unwrap()
            .contains("bad key")
    );

    let key = format!("{BASE}/billing/environments/prod/keys/feature.flag");
    call.admin("PUT", &key, Some(json!({"value":"v2"}))).await;
    let (_, history) = call.admin("GET", &format!("{key}/versions"), None).await;
    assert_eq!(history["items"][0]["version"], 2);
    let (_, restored) = call
        .admin(
            "POST",
            &format!("{key}/rollback"),
            Some(json!({"version":1})),
        )
        .await;
    assert_eq!(restored["version"], 3);
    let (_, current) = call.admin("GET", &key, None).await;
    assert_eq!(
        (current["value"].as_str(), current["version"].as_i64()),
        (Some("on"), Some(3))
    );
    let (_, old) = call.admin("GET", &format!("{key}?version=2"), None).await;
    assert_eq!(old["value"], "v2");

    // Plaintext never reaches the database.
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT ciphertext FROM vault_versions")
        .fetch_all(&s.db)
        .await
        .unwrap();
    assert!(
        rows.iter()
            .all(|(c,)| !c.windows(9).any(|w| w == b"s3cr3t'pw"))
    );

    let (_, log) = call
        .admin("GET", "/api/v1/admin/vault/audit?app=billing", None)
        .await;
    let events: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert!(events.contains(&"vault.key.reveal"));
    assert!(events.contains(&"vault.key.rollback"));
    assert!(events.contains(&"vault.token.create"));
}

#[tokio::test]
async fn tokens_are_scoped_revocable_and_cannot_use_admin_routes() {
    let (router, _) = app(false).await;
    let call = Call { app: &router };
    let token = seed(&call).await;
    let bearer = format!("Bearer {token}");
    let (_, who) = call.machine("/api/v1/vault/whoami", &bearer).await;
    let who: Value = serde_json::from_str(&who).unwrap();
    assert_eq!(
        (who["app"].as_str(), who["environment"].as_str()),
        (Some("billing"), Some("prod"))
    );

    // Application tokens are not admin credentials, and admin tokens are not app tokens.
    let (status, _) = call
        .machine(&format!("{BASE}/billing/environments/prod/items"), &bearer)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call
        .machine("/api/v1/vault/config", &format!("Bearer {}", admin_token()))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let last = if token.ends_with('A') { 'B' } else { 'A' };
    let tampered = format!("{}{last}", &token[..token.len() - 1]);
    let (status, _) = call
        .machine("/api/v1/vault/config", &format!("Bearer {tampered}"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // dev's password is never visible to the prod token.
    let (_, body) = call.machine("/api/v1/vault/config", &bearer).await;
    assert!(!body.contains("dev-only"));

    let id = who["tokenId"].as_str().unwrap();
    let (status, _) = call
        .admin("DELETE", &format!("{BASE}/billing/tokens/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call.machine("/api/v1/vault/config", &bearer).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sealed_vault_and_destructive_operations_fail_safe() {
    let (router, _) = app(true).await;
    let call = Call { app: &router };
    let (status, body) = call
        .admin("POST", BASE, Some(json!({"id":"x","name":"X"})))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "vault_sealed");

    let (router, _) = app(false).await;
    let call = Call { app: &router };
    seed(&call).await;
    let (status, _) = call.admin("DELETE", &format!("{BASE}/billing"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call
        .admin(
            "DELETE",
            &format!("{BASE}/billing/environments/default?confirm=default"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call
        .admin("DELETE", &format!("{BASE}/billing?confirm=billing"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = call.admin("GET", BASE, None).await;
    assert_eq!(list["items"], json!([]));
}

#[tokio::test]
async fn file_uploads_use_the_vault_body_limit_not_the_global_one() {
    let (router, _) = app(false).await;
    let call = Call { app: &router };
    seed(&call).await;
    let upload = |size: usize| {
        Request::put(format!("{BASE}/billing/environments/prod/files/big.bin"))
            .header("authorization", format!("Bearer {}", admin_token()))
            .header("content-type", "application/octet-stream")
            .body(Body::from(vec![7u8; size]))
            .unwrap()
    };
    assert_eq!(call.send(upload(300 * 1024)).await.0, StatusCode::OK);
    assert_eq!(
        call.send(upload(600 * 1024)).await.0,
        StatusCode::BAD_REQUEST
    );
    // Other routes keep the 16 KiB limit.
    let request = Request::post("/api/v1/auth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(vec![b'a'; 64 * 1024]))
        .unwrap();
    assert_eq!(call.send(request).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn audit_records_who_pulled_what_from_where() {
    let (router, _) = app(false).await;
    let call = Call { app: &router };
    let token = seed(&call).await;
    let request = Request::get("/api/v1/vault/config")
        .header("authorization", format!("Bearer {token}"))
        .header("x-forwarded-for", "198.51.100.7, 203.0.113.9")
        .header("user-agent", "billing-service/1.0")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call.send(request).await.0, StatusCode::OK);
    let last = if token.ends_with('A') { 'B' } else { 'A' };
    let wrong = format!("{}{last}", &token[..token.len() - 1]);
    let request = Request::get("/api/v1/vault/config")
        .header("authorization", format!("Bearer {wrong}"))
        .header("x-forwarded-for", "192.0.2.66")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call.send(request).await.0, StatusCode::UNAUTHORIZED);

    let (_, log) = call
        .admin(
            "GET",
            "/api/v1/admin/vault/audit?app=billing&kind=pulls",
            None,
        )
        .await;
    let items = log["items"].as_array().unwrap();
    let denied = &items[0];
    assert_eq!(denied["event"], "vault.token.denied");
    assert_eq!(denied["ip"], "192.0.2.66");
    assert_eq!(denied["target"], "billing/prod (wrong secret)");
    let read = &items[1];
    assert_eq!(read["event"], "vault.config.read");
    assert_eq!(read["ip"], "203.0.113.9");
    assert_eq!(read["userAgent"], "billing-service/1.0");
    assert!(
        read["subject"]
            .as_str()
            .unwrap()
            .ends_with("(billing prod)")
    );
    // Pulls only: writes and token issuance are filtered out.
    assert!(items.iter().all(|e| e["event"] != "vault.key.write"));
}

#[tokio::test]
async fn audit_screen_filters_pages_summarises_and_exports() {
    let (router, _) = app(false).await;
    let call = Call { app: &router };
    let token = seed(&call).await;
    for _ in 0..3 {
        let request = Request::get("/api/v1/vault/config")
            .header("authorization", format!("Bearer {token}"))
            .header("x-forwarded-for", "203.0.113.50")
            .body(Body::empty())
            .unwrap();
        call.send(request).await;
    }
    let audit = "/api/v1/admin/vault/audit";
    let (_, changes) = call
        .admin("GET", &format!("{audit}?kind=changes"), None)
        .await;
    assert!(
        changes["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["event"] != "vault.config.read")
    );
    let (_, by_ip) = call
        .admin("GET", &format!("{audit}?q=203.0.113.50"), None)
        .await;
    assert_eq!(by_ip["items"].as_array().unwrap().len(), 3);
    // Keyset paging: two pages of 2 cover the same rows as one page of 4, in order.
    let (_, page1) = call.admin("GET", &format!("{audit}?limit=2"), None).await;
    let next = page1["nextBefore"].as_i64().unwrap();
    let (_, page2) = call
        .admin("GET", &format!("{audit}?limit=2&before={next}"), None)
        .await;
    let (_, all) = call.admin("GET", &format!("{audit}?limit=4"), None).await;
    let ids = |v: &Value| {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_i64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!([ids(&page1), ids(&page2)].concat(), ids(&all));
    let (_, summary) = call
        .admin("GET", &format!("{audit}/summary?app=billing"), None)
        .await;
    assert_eq!(summary["pulls"], 3);
    assert_eq!(summary["activeTokens"], 1);
    let (status, _) = call
        .admin("GET", &format!("{audit}?kind=nonsense"), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let request = Request::get(format!("{audit}?app=billing&format=csv"))
        .header("authorization", format!("Bearer {}", admin_token()))
        .body(Body::empty())
        .unwrap();
    let (status, bytes, headers) = call.send(request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers["content-disposition"]
            .to_str()
            .unwrap()
            .contains("keystone-vault-audit.csv")
    );
    let csv = String::from_utf8(bytes).unwrap();
    assert!(csv.starts_with("time_utc,who,action,target,ip,user_agent\n"));
    assert!(csv.contains("\"vault.config.read\""));
    // The export is itself audited.
    let (_, log) = call.admin("GET", &format!("{audit}?limit=1"), None).await;
    assert_eq!(log["items"][0]["event"], "vault.audit.export");
}
