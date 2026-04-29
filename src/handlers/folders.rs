use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::auth::Claims;
use crate::db::{self, touch_user_updated_at};
use crate::error::AppError;
use crate::models::folder::{CreateFolderRequest, Folder, FolderResponse};
use crate::notifications::{self, UpdateType};

#[worker::send]
pub async fn list_folders(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .all()
        .await?
        .results()
        .map_err(|_| AppError::Database)?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    Ok(Json(json!({
        "data": folders,
        "object": "list",
        "continuationToken": null,
    })))
}

#[worker::send]
pub async fn get_folder(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = db::get_db(&env)?;

    let folder: Folder = query!(
        &db,
        "SELECT * FROM folders WHERE id = ?1 AND user_id = ?2",
        &id,
        &claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or_else(|| {
        AppError::BadRequest(
            "Invalid folder: Folder does not exist or belongs to another user".to_string(),
        )
    })?;

    Ok(Json(folder.into()))
}

#[worker::send]
pub async fn create_folder(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    let folder = Folder {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        name: payload.name,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    query!(
        &db,
        "INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        folder.id,
        folder.user_id,
        folder.name,
        folder.created_at,
        folder.updated_at
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    touch_user_updated_at(&db, &claims.sub, &folder.updated_at).await?;

    notifications::publish_folder_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncFolderCreate,
        &folder.id,
        &folder.updated_at,
        Some(&claims.device),
    )
    .await;

    let response = FolderResponse {
        id: folder.id,
        name: folder.name,
        revision_date: folder.updated_at,
        object: "folder".to_string(),
    };

    Ok(Json(response))
}

#[worker::send]
pub async fn delete_folder(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    query!(
        &db,
        "DELETE FROM folders WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_folder_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncFolderDelete,
        &id,
        &now,
        Some(&claims.device),
    )
    .await;

    Ok(Json(()))
}
#[worker::send]
pub async fn update_folder(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    let existing_folder: Folder = query!(
        &db,
        "SELECT * FROM folders WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Folder not found".to_string()))?;

    let folder = Folder {
        id: id.clone(),
        user_id: existing_folder.user_id,
        name: payload.name,
        created_at: existing_folder.created_at,
        updated_at: now.clone(),
    };

    query!(
        &db,
        "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
        folder.name,
        folder.updated_at,
        folder.id,
        folder.user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    touch_user_updated_at(&db, &claims.sub, &folder.updated_at).await?;

    notifications::publish_folder_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncFolderUpdate,
        &folder.id,
        &folder.updated_at,
        Some(&claims.device),
    )
    .await;

    let response = FolderResponse {
        id: folder.id,
        name: folder.name,
        revision_date: folder.updated_at,
        object: "folder".to_string(),
    };

    Ok(Json(response))
}
