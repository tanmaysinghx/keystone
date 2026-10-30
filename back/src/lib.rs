pub mod admin;
pub mod auth;
pub mod blog;
pub mod config;
pub mod error;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, StatusCode},
    middleware,
    routing::get,
};
use serde_json::{Value, json};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{
    str::FromStr,
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
    pub db: SqlitePool,
    pub http: reqwest::Client,
    pub keys: Arc<Mutex<auth::KeyCache>>,
    pub started: Instant,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub async fn state(config: config::Config) -> anyhow::Result<AppState> {
    let options = SqliteConnectOptions::from_str(&config.database_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(3));
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(options)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    Ok(AppState {
        config: Arc::new(config),
        db,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        keys: Arc::new(Mutex::new(auth::KeyCache::default())),
        started: Instant::now(),
    })
}
pub fn router(state: AppState) -> Router {
    let admin = Router::new()
        .route("/api/v1/auth/me", get(admin::me))
        .route("/api/v1/admin/services", get(admin::services))
        .route("/api/v1/admin/overview", get(admin::overview))
        .route("/api/v1/admin/posts", get(admin::posts))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));
    let blog = Router::new()
        .route("/api/v1/blog/stats", get(blog::get_stats).post(blog::react))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            blog::require_service,
        ));
    let static_files = ServeDir::new(&state.config.ui_dir).not_found_service(ServeFile::new(
        format!("{}/index.html", state.config.ui_dir),
    ));
    Router::new().merge(admin).merge(blog)
        .route("/health/live", get(|| async { Json(json!({"status":"up"})) }))
        .route("/health/ready", get(ready))
        .route("/api/v1/info", get(|| async {Json(json!({"name":"Keystone","version":env!("CARGO_PKG_VERSION"),"apiVersion":"v1"}))}))
        .route("/api/v1/auth/config", get(auth_config))
        .route("/api/{*path}", get(not_found).post(not_found).put(not_found).delete(not_found))
        .fallback_service(static_files)
        .layer(DefaultBodyLimit::max(16*1024))
        .layer(middleware::from_fn(|request: axum::extract::Request, next: middleware::Next| async move {
            let mut response = next.run(request).await;
            let h=response.headers_mut();
            h.insert("x-content-type-options", "nosniff".parse().unwrap());
            h.insert("x-frame-options", "DENY".parse().unwrap());
            h.insert("referrer-policy", "strict-origin-when-cross-origin".parse().unwrap());
            h.insert("cache-control", "no-store".parse().unwrap());
            response
        }))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(HeaderName::from_static("x-request-id")))
        .layer(SetRequestIdLayer::new(HeaderName::from_static("x-request-id"),MakeRequestUuid))
        .with_state(state)
}
async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
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
    Json(
        json!({"configured":state.config.sso_configured(),"portalUrl":state.config.portal_url,"clientId":state.config.client_id,"scope":"openid profile email","requiredRole":"ROLE_ADMIN"}),
    )
}
async fn not_found() -> error::ApiError {
    error::ApiError(StatusCode::NOT_FOUND, "not_found", "Endpoint not found")
}
