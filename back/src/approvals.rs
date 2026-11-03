//! Protected environments and two-person change approval, plus compare & promote between
//! environments.
//!
//! Every write to a protected environment (set, delete, rollback, import, promote) is stored as a
//! change request, its proposed content sealed with the application's data key. A *different*
//! administrator approves it, and only then is it applied.
use crate::db::Db;
use crate::{
    AppState,
    auth::Access,
    client::Actor,
    crypto::{self, DataKey},
    error::ApiError,
    vault::{self, Kind},
};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

fn bad(code: &'static str, message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, code, message)
}

pub async fn is_protected(db: &Db, app: &str, environment: &str) -> Result<bool, ApiError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT protected FROM vault_environments WHERE app_id = ? AND name = ?")
            .bind(app)
            .bind(environment)
            .fetch_optional(db)
            .await?;
    Ok(row.is_some_and(|(p,)| p != 0))
}

pub struct Proposal<'a> {
    pub app: &'a str,
    pub environment: &'a str,
    pub operation: &'a str,
    pub kind: Kind,
    pub name: &'a str,
    pub payload: Option<&'a [u8]>,
    pub content_type: &'a str,
    pub summary: String,
}

fn location(reference: &str) -> String {
    format!("keystone:change-request:{reference}")
}

/// Stores the proposal and answers 202 with its id.
pub async fn submit(
    state: &AppState,
    actor: &Actor,
    key: &DataKey,
    proposal: Proposal<'_>,
) -> Result<Response, ApiError> {
    let id = create(state, actor, key, &proposal).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "pendingApproval": id,
            "message": format!("{} is protected: the change waits for another administrator's approval.", proposal.environment),
        })),
    )
        .into_response())
}

async fn create(
    state: &AppState,
    actor: &Actor,
    key: &DataKey,
    proposal: &Proposal<'_>,
) -> Result<i64, ApiError> {
    let (pending,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM vault_change_requests WHERE app_id = ? AND status = 'pending'",
    )
    .bind(proposal.app)
    .fetch_one(&state.db)
    .await?;
    if pending >= 100 {
        return Err(bad(
            "too_many_pending",
            "This application has 100 pending change requests; decide some first",
        ));
    }
    let reference = uuid::Uuid::new_v4().to_string();
    let sealed = match proposal.payload {
        Some(bytes) => Some(key.seal(bytes, &location(&reference)).map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "vault_error",
                "Could not seal the proposal",
            )
        })?),
        None => None,
    };
    sqlx::query(
        "INSERT INTO vault_change_requests (ref, app_id, environment, operation, kind, name, payload, content_type, summary, requested_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&reference)
    .bind(proposal.app)
    .bind(proposal.environment)
    .bind(proposal.operation)
    .bind(proposal.kind.as_str())
    .bind(proposal.name)
    .bind(sealed)
    .bind(proposal.content_type)
    .bind(&proposal.summary)
    .bind(&actor.subject)
    .bind(crate::now() as i64)
    .execute(&state.db)
    .await?;
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM vault_change_requests WHERE ref = ?")
        .bind(&reference)
        .fetch_one(&state.db)
        .await?;
    vault::audit(
        state,
        actor,
        "vault.change.request",
        &format!(
            "{}/{} #{id}: {}",
            proposal.app, proposal.environment, proposal.summary
        ),
    )
    .await?;
    Ok(id)
}

type RequestRow = (
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
    Option<i64>,
    Option<String>,
);

fn row_json(r: RequestRow) -> Value {
    let (id, app, env, op, kind, name, summary, by, at, status, decided_by, decided_at, note) = r;
    json!({
        "id": id, "app": app, "environment": env, "operation": op, "kind": kind, "name": name,
        "summary": summary, "requestedBy": by, "createdAt": at, "status": status,
        "decidedBy": decided_by, "decidedAt": decided_at, "note": note,
    })
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    pub app: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let status = query.status.unwrap_or_else(|| "pending".into());
    let rows: Vec<RequestRow> = sqlx::query_as(
        "SELECT id, app_id, environment, operation, kind, name, summary, requested_by, created_at, status, decided_by, decided_at, note
         FROM vault_change_requests WHERE (? = 'all' OR status = ?) AND (? IS NULL OR app_id = ?)
         ORDER BY id DESC LIMIT 200",
    )
    .bind(&status)
    .bind(&status)
    .bind(query.app.clone().filter(|a| !a.is_empty()))
    .bind(query.app.filter(|a| !a.is_empty()))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "items": rows.into_iter().filter(|r| access.can(&r.1)).map(row_json).collect::<Vec<_>>(),
    })))
}

async fn load(
    state: &AppState,
    id: i64,
) -> Result<(RequestRow, String, Option<Vec<u8>>, String), ApiError> {
    let row: Option<(String, Option<Vec<u8>>, String)> =
        sqlx::query_as("SELECT ref, payload, content_type FROM vault_change_requests WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (reference, payload, content_type) = row.ok_or(ApiError(
        StatusCode::NOT_FOUND,
        "change_not_found",
        "No such change request",
    ))?;
    let r: RequestRow = sqlx::query_as(
        "SELECT id, app_id, environment, operation, kind, name, summary, requested_by, created_at, status, decided_by, decided_at, note
         FROM vault_change_requests WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?;
    Ok((r, reference, payload, content_type))
}

/// The proposed value, for a reviewer. Audited like any reveal.
pub async fn reveal(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let (row, reference, payload, content_type) = load(&state, id).await?;
    access.require(&row.1)?;
    let key = vault::data_key(&state, &row.1).await?;
    let proposed = match payload {
        Some(sealed) => Some(key.open(&sealed, &location(&reference)).map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "vault_error",
                "Could not open the proposal",
            )
        })?),
        None => None,
    };
    let current = if row.3 == "import" {
        None
    } else {
        vault::read_item(
            &state.db,
            &key,
            &row.1,
            &row.2,
            Kind::from_segment(&format!("{}s", row.4))?,
            &row.5,
            None,
        )
        .await
        .ok()
        .map(|s| s.bytes)
    };
    vault::audit(
        &state,
        &actor,
        "vault.change.reveal",
        &format!("{}/{} #{id}", row.1, row.2),
    )
    .await?;
    let text = |b: &Option<Vec<u8>>| {
        b.as_ref().map(|b| {
            if content_type.starts_with("text/")
                || content_type == "application/json"
                || std::str::from_utf8(b).is_ok()
            {
                String::from_utf8_lossy(b).into_owned()
            } else {
                format!("<{} bytes of binary content>", b.len())
            }
        })
    };
    Ok(Json(
        json!({"proposed": text(&proposed), "current": text(&current)}),
    ))
}

#[derive(Deserialize, Default)]
pub struct Decision {
    #[serde(default)]
    pub note: Option<String>,
}

/// The optional `{"note": "..."}`; an empty body is fine.
fn note(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Decision>(body)
        .ok()
        .and_then(|d| d.note)
        .map(|n| n.chars().take(500).collect())
}

pub async fn approve(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<i64>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let (row, reference, payload, content_type) = load(&state, id).await?;
    let (_, app, env, op, kind, name, summary, requested_by, ..) = row.clone();
    access.require(&app)?;
    if row.9 != "pending" {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "already_decided",
            "This change request was already decided",
        ));
    }
    if requested_by == actor.subject {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "self_approval",
            "Another administrator must approve your own change",
        ));
    }
    // Claim the request first, so two approvers clicking at once apply it once.
    let claimed = sqlx::query(
        "UPDATE vault_change_requests SET status = 'applied', decided_by = ?, decided_at = ?, note = ?
         WHERE id = ? AND status = 'pending'",
    )
    .bind(&actor.subject)
    .bind(crate::now() as i64)
    .bind(note(&body))
    .bind(id)
    .execute(&state.db)
    .await?;
    if claimed.rows_affected() == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "already_decided",
            "This change request was already decided",
        ));
    }
    let key = vault::data_key(&state, &app).await?;
    let content = match payload {
        Some(sealed) => Some(key.open(&sealed, &location(&reference)).map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "vault_error",
                "Could not open the proposal",
            )
        })?),
        None => None,
    };
    let kind = Kind::from_segment(&format!("{kind}s"))?;
    let who = format!("{} (approved by {})", requested_by, actor.subject);
    let result = async {
        match op.as_str() {
            "put" => {
                let mut tx = state.db.begin().await?;
                let bytes = content.unwrap_or_default();
                vault::write_item(
                    &mut tx,
                    &key,
                    &app,
                    &env,
                    kind,
                    &name,
                    &bytes,
                    &content_type,
                    &who,
                )
                .await?;
                tx.commit().await?;
            }
            "delete" => {
                let mut tx = state.db.begin().await?;
                vault::delete_item_rows(&mut tx, &app, &env, kind, &name).await?;
                tx.commit().await?;
            }
            "import" => {
                let spec: Value = serde_json::from_slice(&content.unwrap_or_default())
                    .map_err(|_| bad("invalid_change", "Unreadable import proposal"))?;
                let map = vault::parse_import(
                    spec["format"].as_str().unwrap_or(""),
                    spec["content"].as_str().unwrap_or(""),
                )
                .map_err(|_| bad("invalid_change", "The proposed import is no longer valid"))?;
                vault::apply_import(
                    &state,
                    &key,
                    &app,
                    &env,
                    &map,
                    spec["replace"].as_bool().unwrap_or(false),
                    &who,
                )
                .await?;
            }
            _ => return Err(bad("invalid_change", "Unknown operation")),
        }
        Ok::<(), ApiError>(())
    }
    .await;
    if let Err(error) = result {
        // Put it back so it can be retried or rejected.
        sqlx::query("UPDATE vault_change_requests SET status = 'pending', decided_by = NULL, decided_at = NULL WHERE id = ?")
            .bind(id)
            .execute(&state.db)
            .await?;
        return Err(error);
    }
    vault::audit(
        &state,
        &actor,
        "vault.change.approve",
        &format!("{app}/{env} #{id}: {summary}"),
    )
    .await?;
    Ok(Json(json!({"id": id, "status": "applied"})))
}

pub async fn reject(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<i64>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let (row, ..) = load(&state, id).await?;
    access.require(&row.1)?;
    // The requester withdrawing their own change is a cancellation, not a rejection.
    let status = if row.7 == actor.subject {
        "cancelled"
    } else {
        "rejected"
    };
    let updated = sqlx::query(
        "UPDATE vault_change_requests SET status = ?, decided_by = ?, decided_at = ?, note = ?, payload = NULL
         WHERE id = ? AND status = 'pending'",
    )
    .bind(status)
    .bind(&actor.subject)
    .bind(crate::now() as i64)
    .bind(note(&body))
    .bind(id)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "already_decided",
            "This change request was already decided",
        ));
    }
    vault::audit(
        &state,
        &actor,
        &format!(
            "vault.change.{}",
            if status == "cancelled" {
                "cancel"
            } else {
                "reject"
            }
        ),
        &format!("{}/{} #{id}: {}", row.1, row.2, row.6),
    )
    .await?;
    Ok(Json(json!({"id": id, "status": status})))
}

#[derive(Deserialize)]
pub struct Protection {
    pub protected: bool,
}

/// Turning protection on or off is an administrator decision, and always audited (and alerted).
pub async fn set_protection(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path((app, environment)): Path<(String, String)>,
    Json(input): Json<Protection>,
) -> Result<StatusCode, ApiError> {
    access.require_admin()?;
    let updated =
        sqlx::query("UPDATE vault_environments SET protected = ? WHERE app_id = ? AND name = ?")
            .bind(input.protected)
            .bind(&app)
            .bind(&environment)
            .execute(&state.db)
            .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "environment_not_found",
            "Environment not found",
        ));
    }
    let event = if input.protected {
        "vault.environment.protect"
    } else {
        "vault.environment.unprotect"
    };
    vault::audit(&state, &actor, event, &format!("{app}/{environment}")).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Promote {
    pub from: String,
    /// Items to copy, as "key:name" / "file:name". Absent: every added or changed item.
    #[serde(default)]
    pub items: Option<Vec<String>>,
    #[serde(default)]
    pub dry_run: bool,
}

/// Compares two environments of one application without revealing values, and copies the chosen
/// items from `from` into the target. A protected target gets one change request per item.
pub async fn promote(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path((app, target)): Path<(String, String)>,
    Json(input): Json<Promote>,
) -> Result<Json<Value>, ApiError> {
    access.require(&app)?;
    if input.from == target {
        return Err(bad(
            "same_environment",
            "Choose a different source environment",
        ));
    }
    vault::ensure_environment(&state.db, &app, &input.from).await?;
    vault::ensure_environment(&state.db, &app, &target).await?;
    let key = vault::data_key(&state, &app).await?;
    let rows: Vec<(String, String, String, i64, Vec<u8>, String)> = sqlx::query_as(
        "SELECT i.environment, i.kind, i.name, i.current_version, v.ciphertext, i.content_type FROM vault_items i
         JOIN vault_versions v ON v.item_id = i.id AND v.version = i.current_version
         WHERE i.app_id = ? AND i.environment IN (?, ?)",
    )
    .bind(&app)
    .bind(&input.from)
    .bind(&target)
    .fetch_all(&state.db)
    .await?;
    let open = |env: &str, kind: &str, name: &str, version: i64, ct: &[u8]| {
        key.open(ct, &crypto::location(&app, env, kind, name, version))
            .map_err(|_| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "vault_error",
                    "Stored value failed authentication",
                )
            })
    };
    let mut source = std::collections::BTreeMap::new();
    let mut existing = std::collections::BTreeMap::new();
    for (env, kind, name, version, ct, content_type) in &rows {
        let bytes = open(env, kind, name, *version, ct)?;
        let entry = (format!("{kind}:{name}"), (bytes, content_type.clone()));
        if *env == input.from {
            source.insert(entry.0, entry.1);
        } else {
            existing.insert(entry.0, entry.1);
        }
    }
    let mut diff = Vec::new();
    for (id, (bytes, _)) in &source {
        let status = match existing.get(id) {
            None => "added",
            Some((other, _)) if other == bytes => "same",
            Some(_) => "changed",
        };
        diff.push(json!({"item": id, "status": status}));
    }
    for id in existing.keys().filter(|id| !source.contains_key(*id)) {
        diff.push(json!({"item": id, "status": "only-in-target"}));
    }
    if input.dry_run {
        return Ok(Json(json!({"diff": diff})));
    }
    let chosen: Vec<String> = match &input.items {
        Some(items) => items.clone(),
        None => diff
            .iter()
            .filter(|d| d["status"] == "added" || d["status"] == "changed")
            .filter_map(|d| d["item"].as_str().map(str::to_owned))
            .collect(),
    };
    let protected = is_protected(&state.db, &app, &target).await?;
    let mut copied = 0;
    let mut pending = Vec::new();
    for id in &chosen {
        let Some((bytes, content_type)) = source.get(id) else {
            continue;
        };
        let (kind, name) = id
            .split_once(':')
            .ok_or(bad("invalid_item", "Items look like key:name or file:name"))?;
        let kind = Kind::from_segment(&format!("{kind}s"))?;
        if protected {
            let proposal = Proposal {
                app: &app,
                environment: &target,
                operation: "put",
                kind,
                name,
                payload: Some(bytes),
                content_type,
                summary: format!("Promote {} {name} from {}", kind.as_str(), input.from),
            };
            pending.push(create(&state, &actor, &key, &proposal).await?);
        } else {
            let mut tx = state.db.begin().await?;
            vault::write_item(
                &mut tx,
                &key,
                &app,
                &target,
                kind,
                name,
                bytes,
                content_type,
                &actor.subject,
            )
            .await?;
            tx.commit().await?;
            copied += 1;
        }
    }
    if copied > 0 {
        vault::audit(
            &state,
            &actor,
            "vault.promote",
            &format!("{app}/{target}: {copied} items from {}", input.from),
        )
        .await?;
    }
    Ok(Json(
        json!({"diff": diff, "copied": copied, "pendingApproval": pending}),
    ))
}
