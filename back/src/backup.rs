//! Backups, taken on a schedule and on demand: on SQLite a consistent copy of the database file
//! (`VACUUM INTO`, `.db`); on MySQL a portable export of every table (`.json`), restorable into
//! either engine. Secrets inside a snapshot stay encrypted; the master key is never written into it,
//! so a snapshot is only useful together with the separately kept key.
use crate::{AppState, auth::Access, client::Actor, error::ApiError, vault};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

fn valid_name(name: &str) -> bool {
    name.starts_with("keystone-")
        && (name.ends_with(".db") || name.ends_with(".json"))
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Writes `keystone-<label>-<UTC timestamp>.db` into `dir` and returns its path.
pub async fn snapshot(db: &crate::db::Db, dir: &FsPath, label: &str) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let mut conn = db.acquire().await?;
    let dialect = crate::db::Dialect::of(&conn);
    let ext = if dialect == crate::db::Dialect::Sqlite {
        "db"
    } else {
        "json"
    };
    let stamp = vault::chrono_like(crate::now() as i64).replace([':', '-'], "");
    let mut path = dir.join(format!("keystone-{label}-{stamp}.{ext}"));
    let mut n = 1;
    while path.exists() {
        path = dir.join(format!("keystone-{label}-{stamp}-{n}.{ext}"));
        n += 1;
    }
    if dialect == crate::db::Dialect::Sqlite {
        sqlx::query("VACUUM INTO ?")
            .bind(path.to_string_lossy().to_string())
            .execute(&mut *conn)
            .await?;
    } else {
        drop(conn);
        let data = crate::db::export(db).await?;
        fs::write(&path, serde_json::to_vec(&data)?)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

/// (name, created unix seconds, size), newest first.
pub fn list(dir: &FsPath) -> Vec<(String, i64, u64)> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            let meta = entry.metadata().ok()?;
            let at = meta
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs() as i64;
            valid_name(&name).then_some((name, at, meta.len()))
        })
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
    out
}

pub fn latest(dir: &FsPath) -> Option<(String, i64, u64)> {
    list(dir).into_iter().next()
}

/// Keeps the newest `keep` automatic backups; manual ones are never pruned.
pub fn prune(dir: &FsPath, keep: usize) {
    for (name, ..) in list(dir)
        .into_iter()
        .filter(|(n, ..)| n.starts_with("keystone-auto-"))
        .skip(keep)
    {
        let _ = fs::remove_file(dir.join(name));
    }
}

/// Runs for the life of the server when `backup.interval-hours` > 0.
pub fn schedule(state: AppState) {
    let hours = state.config.backup_interval_hours;
    if hours == 0 {
        return;
    }
    tokio::spawn(async move {
        let period = Duration::from_secs(hours * 3600);
        loop {
            // First run soon after start if the last backup is older than one period.
            let due = latest(&state.config.backup_dir)
                .map(|(_, at, _)| (crate::now() as i64 - at).max(0) as u64 >= period.as_secs())
                .unwrap_or(true);
            if due {
                let system = Actor {
                    subject: "system:backup".into(),
                    ip: None,
                    user_agent: None,
                };
                match snapshot(&state.db, &state.config.backup_dir, "auto").await {
                    Ok(path) => {
                        prune(&state.config.backup_dir, state.config.backup_keep);
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let _ = vault::audit(&state, &system, "vault.backup.create", &name).await;
                        tracing::info!(path = %path.display(), "Automatic backup written");
                    }
                    Err(error) => {
                        tracing::error!(%error, "Automatic backup failed");
                        let _ = vault::audit(
                            &state,
                            &system,
                            "vault.backup.failed",
                            &error.to_string(),
                        )
                        .await;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3600).min(period)).await;
        }
    });
}

pub async fn list_backups(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
) -> Result<Json<Value>, ApiError> {
    access.require_admin()?;
    Ok(Json(json!({
        "dir": state.config.backup_dir.display().to_string(),
        "intervalHours": state.config.backup_interval_hours,
        "keep": state.config.backup_keep,
        "items": list(&state.config.backup_dir).into_iter().map(|(name, at, size)| json!({
            "name": name, "createdAt": at, "size": size, "automatic": name.starts_with("keystone-auto-"),
        })).collect::<Vec<_>>(),
    })))
}

pub async fn create_backup(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    access.require_admin()?;
    let path = snapshot(&state.db, &state.config.backup_dir, "manual")
        .await
        .map_err(|error| {
            tracing::error!(%error, "Manual backup failed");
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backup_failed",
                "The backup could not be written; check backup.dir",
            )
        })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    vault::audit(&state, &actor, "vault.backup.create", &name).await?;
    Ok((StatusCode::CREATED, Json(json!({"name": name}))))
}

pub async fn download_backup(
    State(state): State<AppState>,
    Extension(access): Extension<Access>,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    access.require_admin()?;
    if !valid_name(&name) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_backup",
            "Unknown backup",
        ));
    }
    let bytes = fs::read(state.config.backup_dir.join(&name))
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "backup_not_found", "No such backup"))?;
    vault::audit(&state, &actor, "vault.backup.download", &name).await?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                if name.ends_with(".json") {
                    "application/json"
                } else {
                    "application/vnd.sqlite3"
                }
                .to_owned(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}
