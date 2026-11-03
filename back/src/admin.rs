use crate::auth::{Access, Claims};
use axum::{Extension, Json};
use serde_json::{Value, json};

pub async fn me(
    Extension(claims): Extension<Claims>,
    Extension(access): Extension<Access>,
) -> Json<Value> {
    Json(json!({
        "subject": claims.sub, "name": claims.name, "email": claims.email, "roles": claims.roles,
        "expiresAt": claims.exp, "admin": access.admin, "apps": access.apps,
    }))
}
