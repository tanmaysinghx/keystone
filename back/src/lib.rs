pub mod admin;
pub mod alerts;
pub mod approvals;
pub mod auth;
pub mod backup;
pub mod blog;
pub mod cli;
pub mod client;
pub mod config;
pub mod connect;
pub mod crypto;
pub mod db;
pub mod error;
pub mod insights;
pub mod local_auth;
pub mod props;
pub mod settings;
pub mod setup;
pub mod token;
pub mod ui;
pub mod vault;
pub mod vault_api;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, StatusCode},
    middleware,
    routing::{get, post},
};
use db::Db;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub db: Db,
    pub dialect: db::Dialect,
    pub http: reqwest::Client,
    pub keys: Arc<Mutex<auth::KeyCache>>,
    pub started: Instant,
    /// Woken on every vault write, for /api/v1/vault/watch.
    pub changed: Arc<tokio::sync::Notify>,
    pub limiter: Arc<std::sync::Mutex<vault_api::Limiter>>,
    pub alerts_sent: Arc<std::sync::Mutex<std::collections::HashMap<String, Instant>>>,
    /// Failed local sign-ins and setup-key attempts per client IP.
    pub login_limiter: Arc<std::sync::Mutex<vault_api::Limiter>>,
    /// The one-time setup key while first-time setup is unfinished.
    pub setup_key: Arc<std::sync::Mutex<Option<String>>>,
    /// Setup asks the server to stop (`shutdown`) and start again with the new configuration.
    pub shutdown: Arc<tokio::sync::Notify>,
    pub restart: Arc<std::sync::atomic::AtomicBool>,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub async fn state(config: config::Config) -> anyhow::Result<AppState> {
    let dialect = db::Dialect::of_url(&config.database_url)?;
    let db = db::connect(&config.database_url).await?;
    if let Some(master) = &config.master_key {
        verify_master_key(&db, master).await?;
    }
    let state = AppState {
        config: Arc::new(config),
        db,
        dialect,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        keys: Arc::new(Mutex::new(auth::KeyCache::default())),
        started: Instant::now(),
        changed: Arc::new(tokio::sync::Notify::new()),
        limiter: Arc::default(),
        alerts_sent: Arc::default(),
        login_limiter: Arc::default(),
        setup_key: Arc::default(),
        shutdown: Arc::new(tokio::sync::Notify::new()),
        restart: Arc::default(),
    };
    setup::initialize(&state).await?;
    Ok(state)
}

/// Checks a snapshot against the key without writing to it (restore).
pub async fn verify_master_key_readonly(db: &Db, master: &crypto::MasterKey) -> anyhow::Result<()> {
    let check: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT value FROM vault_meta WHERE `key` = 'kek_check'")
            .fetch_optional(db)
            .await
            .unwrap_or(None);
    if let Some((check,)) = check {
        anyhow::ensure!(
            master.verify(&check),
            "This backup was written with a different master key"
        );
        return Ok(());
    }
    let sample: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT id, wrapped_key FROM vault_apps LIMIT 1")
            .fetch_optional(db)
            .await?;
    if let Some((app, wrapped)) = sample {
        anyhow::ensure!(
            master.unwrap_data_key(&app, &wrapped).is_ok(),
            "This backup was written with a different master key"
        );
    }
    Ok(())
}

/// Refuses to start with a master key that cannot open this database, instead of failing on
/// every request. Databases created before the check value existed are verified against an
/// application key once, then get a check value.
pub async fn verify_master_key(db: &Db, master: &crypto::MasterKey) -> anyhow::Result<()> {
    let check: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT value FROM vault_meta WHERE `key` = 'kek_check'")
            .fetch_optional(db)
            .await?;
    if let Some((check,)) = check {
        anyhow::ensure!(
            master.verify(&check),
            "The configured master key is not the one this vault was created with. Restore the original key (see vault.master-key-file), or rotate deliberately with `keystone rotate-master-key`."
        );
        return Ok(());
    }
    let sample: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT id, wrapped_key FROM vault_apps LIMIT 1")
            .fetch_optional(db)
            .await?;
    if let Some((app, wrapped)) = sample {
        anyhow::ensure!(
            master.unwrap_data_key(&app, &wrapped).is_ok(),
            "The configured master key cannot open this vault's data. Restore the original key."
        );
    }
    sqlx::query("INSERT INTO vault_meta (`key`, value) VALUES ('kek_check', ?)")
        .bind(master.check_value()?)
        .execute(db)
        .await?;
    Ok(())
}
pub fn router(state: AppState) -> Router {
    let admin = Router::new()
        .route("/api/v1/auth/me", get(admin::me))
        .route(
            "/api/v1/auth/local/password",
            post(local_auth::change_password),
        )
        .route(
            "/api/v1/admin/users",
            get(local_auth::list_users).post(local_auth::add_user),
        )
        .route(
            "/api/v1/admin/users/{id}",
            axum::routing::patch(local_auth::update_user).delete(local_auth::delete_user),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));
    let vault_admin = Router::new()
        .route("/api/v1/admin/vault/status", get(vault::status))
        .route("/api/v1/admin/vault/audit", get(vault::audit_log))
        .route(
            "/api/v1/admin/vault/audit/summary",
            get(vault::audit_summary),
        )
        .route(
            "/api/v1/admin/vault/apps",
            get(vault::list_apps).post(vault::create_app),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}",
            axum::routing::patch(vault::update_app).delete(vault::delete_app),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments",
            post(vault::create_environment),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}",
            axum::routing::delete(vault::delete_environment),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/items",
            get(vault::list_items),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/import",
            post(vault::import),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/config",
            get(vault::preview_config),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/{kind}/{name}",
            get(vault::get_item)
                .put(vault::put_item)
                .delete(vault::delete_item),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/{kind}/{name}/versions",
            get(vault::versions),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/{kind}/{name}/rollback",
            post(vault::rollback),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/tokens",
            get(vault::list_tokens).post(vault::create_token),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/tokens/{id}",
            axum::routing::delete(vault::revoke_token).patch(vault::update_token),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/protection",
            axum::routing::put(approvals::set_protection),
        )
        .route(
            "/api/v1/admin/vault/apps/{app}/environments/{env}/promote",
            post(approvals::promote),
        )
        .route("/api/v1/admin/vault/changes", get(approvals::list))
        .route(
            "/api/v1/admin/vault/changes/{id}/reveal",
            get(approvals::reveal),
        )
        .route(
            "/api/v1/admin/vault/changes/{id}/approve",
            post(approvals::approve),
        )
        .route(
            "/api/v1/admin/vault/changes/{id}/reject",
            post(approvals::reject),
        )
        .route("/api/v1/admin/vault/insights", get(insights::findings))
        .route("/api/v1/admin/vault/settings", get(settings::overview))
        .route(
            "/api/v1/admin/vault/settings/alerts",
            axum::routing::put(settings::put_alerts),
        )
        .route(
            "/api/v1/admin/vault/settings/alerts/test",
            post(settings::test_alert),
        )
        .route(
            "/api/v1/admin/vault/backups",
            get(backup::list_backups).post(backup::create_backup),
        )
        .route(
            "/api/v1/admin/vault/backups/{name}",
            get(backup::download_backup),
        )
        .layer(DefaultBodyLimit::max(vault::MAX_FILE * 2))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));
    let vault_machine = Router::new()
        .route("/api/v1/vault/whoami", get(vault_api::whoami))
        .route("/api/v1/vault/config", get(vault_api::config))
        .route("/api/v1/vault/watch", get(vault_api::watch))
        .route("/api/v1/vault/{kind}/{name}", get(vault_api::item))
        .route("/config/{application}/{profiles}", get(vault_api::spring))
        .route(
            "/config/{application}/{profiles}/{label}",
            get(vault_api::spring),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            vault_api::require_token,
        ));
    let blog = Router::new()
        .route("/api/v1/blog/stats", get(blog::get_stats).post(blog::react))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            blog::require_service,
        ));
    let console: Router<AppState> = match &state.config.ui_dir {
        Some(dir) => Router::new().fallback_service(
            ServeDir::new(dir).not_found_service(ServeFile::new(format!("{dir}/index.html"))),
        ),
        None => Router::new().fallback(ui::serve),
    };
    Router::new()
        .merge(admin)
        .merge(vault_admin)
        .merge(vault_machine)
        .merge(blog)
        .route(
            "/health/live",
            get(|| async { Json(json!({"status":"up"})) }),
        )
        .route("/health/ready", get(ready))
        .route(
            "/api/v1/info",
            get(|| async {
                Json(json!({"name":"Keystone Vault","version":config::VERSION,"apiVersion":"v1"}))
            }),
        )
        .route("/api/v1/auth/config", get(auth_config))
        .route("/api/v1/auth/token", axum::routing::post(token::exchange))
        .route("/api/v1/auth/local/login", post(local_auth::login))
        .route("/api/v1/auth/local/logout", post(local_auth::logout))
        .route("/api/v1/setup/status", get(setup::status))
        .route("/api/v1/setup/license", get(setup::license))
        .route("/api/v1/setup/verify", post(setup::verify))
        .route("/api/v1/setup/license", post(setup::accept_license))
        .route("/api/v1/setup/portal/test", post(setup::test_portal))
        .route("/api/v1/setup/database/test", post(setup::test_database))
        .route("/api/v1/setup/finish", post(setup::finish))
        .route(
            "/api/{*path}",
            get(not_found)
                .post(not_found)
                .put(not_found)
                .delete(not_found),
        )
        .merge(console)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(
            |request: axum::extract::Request, next: middleware::Next| async move {
                let mut response = next.run(request).await;
                let h = response.headers_mut();
                h.insert("x-content-type-options", "nosniff".parse().unwrap());
                h.insert("x-frame-options", "DENY".parse().unwrap());
                h.insert(
                    "referrer-policy",
                    "strict-origin-when-cross-origin".parse().unwrap(),
                );
                h.insert("cache-control", "no-store".parse().unwrap());
                response
            },
        ))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(HeaderName::from_static(
            "x-request-id",
        )))
        .layer(SetRequestIdLayer::new(
            HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .with_state(state)
}
async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let ok = sqlx::query("SELECT COUNT(*) FROM vault_meta")
        .execute(&state.db)
        .await
        .is_ok();
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"status":if ok {"ready"}else{"unavailable"}})),
    )
}
async fn auth_config(State(state): State<AppState>) -> Json<Value> {
    let setup = setup::required(&state).await.unwrap_or(true);
    Json(json!({
        "configured": state.config.sso_configured(),
        "portalUrl": state.config.portal_url,
        "clientId": state.config.client_id,
        "scope": "openid profile email",
        "requiredRole": "ROLE_ADMIN",
        "local": state.config.local_auth,
        "setupRequired": setup,
    }))
}
async fn not_found() -> error::ApiError {
    error::ApiError(StatusCode::NOT_FOUND, "not_found", "Endpoint not found")
}
