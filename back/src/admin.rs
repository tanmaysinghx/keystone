use crate::{AppState, auth::Claims, error::ApiError};
use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Instant;

pub async fn me(Extension(claims): Extension<Claims>) -> Json<Value> {
    Json(
        json!({"subject": claims.sub, "name": claims.name, "email": claims.email, "roles": claims.roles, "expiresAt": claims.exp}),
    )
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub name: String,
    pub status: String,
    pub detail: String,
    pub latency_ms: u128,
}
fn status(name: &str, state: &str, detail: &str, latency_ms: u128) -> ServiceStatus {
    ServiceStatus {
        name: name.into(),
        status: state.into(),
        detail: detail.into(),
        latency_ms,
    }
}
pub async fn services(State(state): State<AppState>) -> Json<Value> {
    let start = Instant::now();
    let database_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let mut services = vec![
        status("Keystone API", "up", "Serving requests", 0),
        status(
            "SQLite storage",
            if database_ok { "up" } else { "down" },
            if database_ok {
                "Database query succeeded"
            } else {
                "Database query failed"
            },
            start.elapsed().as_millis(),
        ),
        status(
            "Blog reactions",
            if state.config.service_key.is_empty() {
                "unconfigured"
            } else if database_ok {
                "up"
            } else {
                "down"
            },
            "Likes and daily unique views",
            0,
        ),
    ];
    let mut checks = tokio::task::JoinSet::new();
    for monitor in state.config.monitors.clone() {
        let client = state.http.clone();
        checks.spawn(async move {
            let start = Instant::now();
            let ok = client
                .get(&monitor.url)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
            status(
                &monitor.name,
                if ok { "up" } else { "down" },
                if ok {
                    "Health endpoint responded successfully"
                } else {
                    "Health endpoint failed or timed out"
                },
                start.elapsed().as_millis(),
            )
        });
    }
    if state.config.sso_configured() {
        let client = state.http.clone();
        let issuer = state.config.portal_url.clone();
        checks.spawn(async move {
            let start = Instant::now();
            let ok = match client
                .get(format!("{issuer}/.well-known/openid-configuration"))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => response
                    .json::<Value>()
                    .await
                    .is_ok_and(|v| v["issuer"] == issuer),
                _ => false,
            };
            status(
                "Portal SSO",
                if ok { "up" } else { "down" },
                "OIDC discovery and issuer verification",
                start.elapsed().as_millis(),
            )
        });
    } else {
        services.push(status(
            "Portal SSO",
            "unconfigured",
            "Issuer and public client ID are required",
            0,
        ));
    }
    while let Some(Ok(result)) = checks.join_next().await {
        services.push(result);
    }
    Json(json!({"checkedAt": crate::now(), "services": services}))
}
pub async fn overview(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (likes, views, posts): (i64,i64,i64) = sqlx::query_as("SELECT COALESCE(SUM(action='like'),0),COALESCE(SUM(action='view'),0),COUNT(DISTINCT slug) FROM reactions").fetch_one(&state.db).await?;
    Ok(Json(
        json!({"likes":likes,"views":views,"posts":posts,"uptimeSeconds":state.started.elapsed().as_secs(),"version":env!("CARGO_PKG_VERSION")}),
    ))
}
#[derive(Deserialize)]
pub struct Page {
    pub page: Option<u32>,
}
pub async fn posts(
    State(state): State<AppState>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page.unwrap_or(0);
    if page > 10000 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_page",
            "Page is out of range",
        ));
    }
    let rows: Vec<(String,i64,i64)> = sqlx::query_as("SELECT slug, SUM(action='like'), SUM(action='view') FROM reactions GROUP BY slug ORDER BY slug LIMIT 50 OFFSET ?")
        .bind(i64::from(page)*50).fetch_all(&state.db).await?;
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(DISTINCT slug) FROM reactions")
        .fetch_one(&state.db)
        .await?;
    Ok(Json(
        json!({"page":page,"pageSize":50,"total":total,"items":rows.into_iter().map(|(slug,likes,views)|json!({"slug":slug,"likes":likes,"views":views})).collect::<Vec<_>>()}),
    ))
}
