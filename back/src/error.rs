use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str, pub &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(json!({"error": {"code": self.1, "message": self.2}})),
        )
            .into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "Database operation failed");
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "Storage is temporarily unavailable",
        )
    }
}
pub fn unauthorized() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "A valid Portal SSO access token is required",
    )
}
