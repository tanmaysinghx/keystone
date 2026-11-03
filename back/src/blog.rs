use crate::{AppState, error::ApiError};
use axum::{
    Json,
    extract::{Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Deserialize)]
pub struct StatsQuery {
    pub slug: String,
}
#[derive(Deserialize)]
pub struct Reaction {
    pub slug: String,
    pub action: String,
    pub visitor: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Stats {
    pub views: i64,
    pub likes: i64,
    pub configured: bool,
}

pub async fn require_service(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if state.config.service_key.is_empty() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "likes_not_configured",
            "Blog reactions are not configured",
        ));
    }
    let actual = request
        .headers()
        .get("x-keystone-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected_hash = Sha256::digest(state.config.service_key.as_bytes());
    let actual_hash = Sha256::digest(actual.as_bytes());
    if !bool::from(expected_hash.ct_eq(&actual_hash)) {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid_service_key",
            "A service credential is required",
        ));
    }
    Ok(next.run(request).await)
}
pub fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 100
        && slug.as_bytes()[0].is_ascii_alphanumeric()
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn check_slug(slug: &str) -> Result<(), ApiError> {
    if valid_slug(slug) {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_slug",
            "Invalid post slug",
        ))
    }
}
pub async fn counts(pool: &crate::db::Db, slug: &str) -> Result<Stats, ApiError> {
    let (views, likes): (i64, i64) = sqlx::query_as("SELECT CAST(COALESCE(SUM(CASE WHEN action = 'view' THEN 1 ELSE 0 END), 0) AS SIGNED), CAST(COALESCE(SUM(CASE WHEN action = 'like' THEN 1 ELSE 0 END), 0) AS SIGNED) FROM reactions WHERE slug = ?")
        .bind(slug).fetch_one(pool).await?;
    Ok(Stats {
        views,
        likes,
        configured: true,
    })
}
pub async fn get_stats(
    State(state): State<AppState>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Stats>, ApiError> {
    check_slug(&query.slug)?;
    Ok(Json(counts(&state.db, &query.slug).await?))
}
pub async fn react(
    State(state): State<AppState>,
    Json(body): Json<Reaction>,
) -> Result<Json<Stats>, ApiError> {
    check_slug(&body.slug)?;
    if !matches!(body.action.as_str(), "view" | "like")
        || uuid::Uuid::parse_str(&body.visitor).is_err()
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_reaction",
            "Expected action view or like and a UUID visitor",
        ));
    }
    // Only the portfolio server supplies this opaque identity; never IP addresses or browser tokens.
    let visitor = format!("{:x}", Sha256::digest(body.visitor.as_bytes()));
    let bucket = if body.action == "view" {
        (crate::now() / 86400).to_string()
    } else {
        "forever".into()
    };
    // One atomic insert and a unique key make parallel requests/retries idempotent.
    sqlx::query(&format!(
        "{} reactions (slug, visitor, action, bucket, created_at) VALUES (?, ?, ?, ?, ?)",
        state.dialect.insert_ignore()
    ))
    .bind(&body.slug)
    .bind(&visitor)
    .bind(&body.action)
    .bind(bucket)
    .bind(crate::now() as i64)
    .execute(&state.db)
    .await?;
    Ok(Json(counts(&state.db, &body.slug).await?))
}
