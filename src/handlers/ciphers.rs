use axum::extract::Path;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use log; // Used for warning logs on parse failures
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, wasm_bindgen::JsValue, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::handlers::attachments;
use crate::models::cipher::{
    Cipher, CipherDBModel, CipherData, CipherRequestData, CreateCipherRequest, PartialCipherData,
};
use crate::models::user::{PasswordOrOtpData, User};
use crate::BaseUrl;

/// A wrapper for raw JSON strings that implements IntoResponse.
/// Use this to return pre-built JSON without re-parsing/re-serializing.
pub struct RawJson(pub String);

impl IntoResponse for RawJson {
    fn into_response(self) -> Response {
        ([(header::CONTENT_TYPE, "application/json")], self.0).into_response()
    }
}

/// Helper to fetch a cipher by id for a user or return NotFound.
async fn fetch_cipher_for_user(
    db: &worker::D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDBModel, AppError> {
    db.prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
        .bind(&[cipher_id.to_string().into(), user_id.to_string().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let cipher_data_req = payload.cipher;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        type_fields: cipher_data_req.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite.unwrap_or(false),
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if payload.collection_ids.is_empty() {
            None
        } else {
            Some(payload.collection_ids)
        },
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,

         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(_base_url)): Extension<BaseUrl>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_cipher: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])?
            .first(None)
            .await?;

        if folder_exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid folder: Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    // Reject updates based on stale client data when the last known revision is provided
    if let Some(dt) = payload.last_known_revision_date.as_deref() {
        match DateTime::parse_from_rfc3339(dt) {
            Ok(client_dt) => match DateTime::parse_from_rfc3339(&existing_cipher.updated_at) {
                Ok(server_dt) => {
                    if server_dt.signed_duration_since(client_dt).num_seconds() > 1 {
                        return Err(AppError::BadRequest(
                            "The client copy of this cipher is out of date. Resync the client and try again.".to_string(),
                        ));
                    }
                }
                Err(err) => log::warn!(
                    "Error parsing server revisionDate '{}' for cipher {}: {}",
                    existing_cipher.updated_at,
                    existing_cipher.id,
                    err
                ),
            },
            Err(err) => log::warn!("Error parsing lastKnownRevisionDate '{}': {}", dt, err),
        }
    }

    let cipher_data_req = payload;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        type_fields: cipher_data_req.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: id.clone(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite.unwrap_or(false),
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND user_id = ?8",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers - list all non-trashed ciphers for current user
#[worker::send]
pub async fn list_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let include_attachments = attachments::attachments_enabled(env.as_ref());
    let force_row_query = super::ciphers_default_row_query(env.as_ref());
    // Response schema: {"data":[...],"object":"list","continuationToken":null}
    let mut response = String::new();
    response.push_str("{\"data\":");
    append_cipher_json_array_raw(
        &mut response,
        &db,
        include_attachments,
        "WHERE c.user_id = ?1 AND c.deleted_at IS NULL",
        &[claims.sub.clone().into()],
        "ORDER BY c.updated_at DESC",
        force_row_query,
    )
    .await?;
    response.push_str(",\"object\":\"list\",\"continuationToken\":null}");

    Ok(RawJson(response))
}

/// GET /api/ciphers/{id}
#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let cipher = fetch_cipher_for_user(&db, &id, &claims.sub).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers/{id}/details
#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    state: State<Arc<Env>>,
    id: Path<String>,
) -> Result<Json<Cipher>, AppError> {
    get_cipher(claims, state, id).await
}

/// PUT/POST /api/ciphers/{id}/partial
#[worker::send]
pub async fn update_cipher_partial(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), user_id.clone().into()])?
            .first(None)
            .await?;

        if folder_exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid folder: Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    // Ensure cipher exists and belongs to user
    fetch_cipher_for_user(&db, &id, user_id).await?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    query!(
        &db,
        "UPDATE ciphers SET folder_id = ?1, favorite = ?2, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
        payload.folder_id,
        payload.favorite,
        now,
        id,
        user_id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    db::touch_user_updated_at(&db, user_id).await?;

    let cipher = fetch_cipher_for_user(&db, &id, user_id).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    Ok(Json(cipher))
}

/// Soft delete a single cipher (PUT /api/ciphers/{id}/delete)
/// Sets deleted_at to current timestamp
#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Soft delete multiple ciphers (PUT /api/ciphers/delete)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE user_id = ?2 AND id IN (SELECT value FROM json_each(?3, '$.ids'))",
        now,
        claims.sub,
        body
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Hard delete a single cipher (DELETE /api/ciphers/{id} or POST /api/ciphers/{id}/delete)
/// Permanently removes the cipher from database
#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;

    if attachments::attachments_enabled(env.as_ref()) {
        let id_json = serde_json::to_string(&[&id]).map_err(|_| AppError::Internal)?;
        let keys = attachments::list_attachment_keys_for_cipher_ids_json(
            &db,
            &id_json,
            "$",
            Some(&claims.sub),
        )
        .await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Hard delete multiple ciphers (DELETE /api/ciphers or POST /api/ciphers/delete)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;

    if attachments::attachments_enabled(env.as_ref()) {
        let keys = attachments::list_attachment_keys_for_cipher_ids_json(
            &db,
            &body,
            "$.ids",
            Some(&claims.sub),
        )
        .await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    query!(
        &db,
        "DELETE FROM ciphers WHERE user_id = ?1 AND id IN (SELECT value FROM json_each(?2, '$.ids'))",
        claims.sub,
        body
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Restore a single cipher (PUT /api/ciphers/{id}/restore)
/// Clears the deleted_at timestamp
#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Update the cipher to clear deleted_at
    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    // Fetch and return the restored cipher
    let cipher_db: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    let mut cipher: Cipher = cipher_db.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// Restore multiple ciphers (PUT /api/ciphers/restore)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn restore_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Single bulk UPDATE using json_each() with path
    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE user_id = ?2 AND id IN (SELECT value FROM json_each(?3, '$.ids'))",
        now,
        claims.sub,
        body
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    let include_attachments = attachments::attachments_enabled(env.as_ref());
    let force_row_query = super::ciphers_default_row_query(env.as_ref());

    db::touch_user_updated_at(&db, &claims.sub).await?;

    // Build response JSON via string concatenation (no parsing!)
    // Response schema: {"data":[...],"object":"list","continuationToken":null}
    let mut response = String::new();
    response.push_str("{\"data\":");
    append_cipher_json_array_raw(
        &mut response,
        &db,
        include_attachments,
        "WHERE c.user_id = ?1 AND c.id IN (SELECT value FROM json_each(?2, '$.ids'))",
        &[claims.sub.clone().into(), body.clone().into()],
        "",
        force_row_query,
    )
    .await?;
    response.push_str(",\"object\":\"list\",\"continuationToken\":null}");

    Ok(RawJson(response))
}

/// Handler for POST /api/ciphers
/// Accepts flat JSON structure (camelCase) as sent by Bitwarden clients
/// when creating a cipher without collection assignments.
#[worker::send]
pub async fn create_cipher_simple(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let cipher_data = CipherData {
        name: payload.name,
        notes: payload.notes,
        type_fields: payload.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: payload.organization_id.clone(),
        r#type: payload.r#type,
        data: data_value,
        favorite: payload.favorite.unwrap_or(false),
        folder_id: payload.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_| AppError::Database)?
    .run()
    .await?;

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// Move selected ciphers to a folder (POST/PUT /api/ciphers/move)
/// Accepts raw JSON body and uses json_extract/json_each to extract values directly.
/// Expected JSON: {"folderId": "optional-folder-id-or-null", "ids": ["cipher_id1", ...]}
/// The folderId is optional and treated as null if not provided in vaultwarden.
/// D1/SQLite's json_extract returns SQL NULL for non-existent paths, which is identical to the behavior in vaultwarden.
#[worker::send]
pub async fn move_cipher_selected(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Validate folder exists and belongs to user (if folder_id is provided)
    // Uses json_extract to get folderId from request body
    let folder_invalid: Option<Value> = db
        .prepare(
            "SELECT 1 WHERE json_extract(?1, '$.folderId') IS NOT NULL 
             AND NOT EXISTS (
                 SELECT 1 FROM folders WHERE id = json_extract(?1, '$.folderId') AND user_id = ?2
             )",
        )
        .bind(&[body.clone().into(), user_id.clone().into()])?
        .first(None)
        .await
        .map_err(db::map_d1_json_error)?;

    if folder_invalid.is_some() {
        return Err(AppError::BadRequest(
            "Invalid folder: Folder does not exist or belongs to another user".to_string(),
        ));
    }

    // Update folder_id for all ciphers that belong to the user and are in the ids list
    // Uses json_extract for folderId and json_each for ids array
    db.prepare(
        "UPDATE ciphers SET folder_id = json_extract(?1, '$.folderId'), updated_at = ?2 
         WHERE user_id = ?3 AND id IN (SELECT value FROM json_each(?1, '$.ids'))",
    )
    .bind(&[body.into(), now.into(), user_id.clone().into()])?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    // Update user's revision date
    db::touch_user_updated_at(&db, user_id).await?;

    Ok(Json(()))
}

/// Purge the user's vault - delete all ciphers and folders
/// POST /api/ciphers/purge
///
/// This is a destructive operation that requires password verification.
/// In vaultwarden, this endpoint also supports purging organization vaults,
/// but this simplified version only supports personal vault purge.
#[worker::send]
pub async fn purge_vault(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    // Get the user from the database
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    // Validate password (OTP not supported in this simplified version)
    let provided_hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::BadRequest("Missing master password hash".to_string()))?;

    let verification = user.verify_master_password(&provided_hash).await?;

    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    if attachments::attachments_enabled(env.as_ref()) {
        let keys = attachments::list_attachment_keys_for_user(&db, user_id).await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    // Delete all user's ciphers (both active and soft-deleted)
    query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Delete all user's folders
    query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Update user's revision date to trigger client sync
    db::touch_user_updated_at(&db, user_id).await?;

    Ok(Json(()))
}

#[derive(Deserialize)]
struct CipherJsonArrayRow {
    ciphers_json: String,
}

/// Build the SQL expression for a single cipher as JSON.
fn cipher_json_expr(attachments_enabled: bool) -> String {
    let attachments_expr = if attachments_enabled {
        "
            (
                SELECT CASE WHEN COUNT(1)=0 THEN NULL ELSE json_group_array(
                    json_object(
                        'id', a.id,
                        'url', NULL,
                        'fileName', a.file_name,
                        'size', CAST(a.file_size AS TEXT),
                        'sizeName',
                            CASE
                                WHEN a.file_size < 1024 THEN printf('%d B', a.file_size)
                                WHEN a.file_size < 1048576 THEN printf('%.1f KB', a.file_size / 1024.0)
                                WHEN a.file_size < 1073741824 THEN printf('%.1f MB', a.file_size / 1048576.0)
                                WHEN a.file_size < 1099511627776 THEN printf('%.1f GB', a.file_size / 1073741824.0)
                                ELSE printf('%.1f TB', a.file_size / 1099511627776.0)
                            END,
                        'key', a.akey,
                        'object', 'attachment'
                    )
                ) END
                FROM attachments a
                WHERE a.cipher_id = c.id
            )
        "
    } else {
        "NULL"
    };

    format!(
        "json_object(
            'object', 'cipherDetails',
            'id', c.id,
            'userId', c.user_id,
            'organizationId', c.organization_id,
            'folderId', c.folder_id,
            'type', c.type,
            'favorite', CASE WHEN c.favorite THEN json('true') ELSE json('false') END,
            'edit', json('true'),
            'viewPassword', json('true'),
            'permissions', json_object('delete', json('true'), 'restore', json('true')),
            'organizationUseTotp', json('false'),
            'collectionIds', NULL,
            'revisionDate', c.updated_at,
            'creationDate', c.created_at,
            'deletedDate', c.deleted_at,
            'attachments', {attachments_expr},
            'name', json_extract(c.data, '$.name'),
            'notes', json_extract(c.data, '$.notes'),
            'fields', json_extract(c.data, '$.fields'),
            'passwordHistory', json_extract(c.data, '$.passwordHistory'),
            'reprompt', COALESCE(json_extract(c.data, '$.reprompt'), 0),
            'login', CASE WHEN c.type = 1 THEN json_extract(c.data, '$.login') ELSE NULL END,
            'secureNote', CASE WHEN c.type = 2 THEN json_extract(c.data, '$.secureNote') ELSE NULL END,
            'card', CASE WHEN c.type = 3 THEN json_extract(c.data, '$.card') ELSE NULL END,
            'identity', CASE WHEN c.type = 4 THEN json_extract(c.data, '$.identity') ELSE NULL END,
            'sshKey', CASE WHEN c.type = 5 THEN json_extract(c.data, '$.sshKey') ELSE NULL END
        )",
        attachments_expr = attachments_expr,
    )
}

/// Build SQL that returns ciphers as a JSON array string (using json_group_array).
fn cipher_json_array_sql(
    attachments_enabled: bool,
    where_clause: &str,
    order_clause: &str,
) -> String {
    let cipher_expr = cipher_json_expr(attachments_enabled);
    // Use a subquery to ensure ORDER BY is applied before json_group_array
    format!(
        "SELECT COALESCE(json_group_array(json(sub.cipher_json)), '[]') AS ciphers_json
        FROM (
            SELECT {cipher_expr} AS cipher_json
            FROM ciphers c
            {where_clause}
            {order_clause}
        ) sub",
        cipher_expr = cipher_expr,
        where_clause = where_clause,
        order_clause = order_clause,
    )
}

fn cipher_json_rows_sql(
    attachments_enabled: bool,
    where_clause: &str,
    order_clause: &str,
) -> String {
    let cipher_expr = cipher_json_expr(attachments_enabled);
    format!(
        "SELECT {cipher_expr} AS cipher_json
        FROM ciphers c
        {where_clause}
        {order_clause}",
        cipher_expr = cipher_expr,
        where_clause = where_clause,
        order_clause = order_clause,
    )
}

fn is_sqlite_toobig(err: &worker::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("sqlite_toobig") || msg.contains("string or blob too big")
}

/// Append ciphers JSON array to an existing buffer.
/// This avoids JSON parsing in Rust, significantly reducing CPU time.
pub(crate) async fn append_cipher_json_array_raw(
    out: &mut String,
    db: &worker::D1Database,
    attachments_enabled: bool,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
    force_row_query: bool,
) -> Result<(), AppError> {
    if force_row_query {
        return append_from_rows(
            out,
            db,
            attachments_enabled,
            where_clause,
            params,
            order_clause,
        )
        .await;
    }

    let sql = cipher_json_array_sql(attachments_enabled, where_clause, order_clause);

    let row: Result<Option<CipherJsonArrayRow>, worker::Error> =
        db.prepare(&sql).bind(params)?.first(None).await;

    match row {
        Ok(row) => {
            if let Some(r) = row {
                out.reserve(r.ciphers_json.len());
                out.push_str(&r.ciphers_json);
            } else {
                out.push_str("[]");
            }
            Ok(())
        }
        Err(err) if is_sqlite_toobig(&err) => {
            append_from_rows(
                out,
                db,
                attachments_enabled,
                where_clause,
                params,
                order_clause,
            )
            .await
        }
        Err(err) => Err(db::map_d1_json_error(err)),
    }
}

/// Append ciphers JSON array to an existing buffer row by row.
/// This avoids JSON array exceeding the maximum size that can be returned in a single string.
///
/// Uses `raw_js_value()` to bypass Serde deserialization entirely, which should reduce
/// CPU time for large payloads. Each row from `raw_js_value()` is a JS array `[cipher_json]`
/// where the first element is the JSON string we need.
pub(crate) async fn append_from_rows(
    out: &mut String,
    db: &worker::D1Database,
    attachments_enabled: bool,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
) -> Result<(), AppError> {
    use js_sys::Array;
    use wasm_bindgen::JsCast;

    let sql = cipher_json_rows_sql(attachments_enabled, where_clause, order_clause);

    // Use raw_js_value() to get Vec<JsValue> without Serde deserialization.
    // Each JsValue is a JS array: [cipher_json_string]
    let raw_rows: Vec<JsValue> = db
        .prepare(&sql)
        .bind(params)?
        .raw_js_value()
        .await
        .map_err(db::map_d1_json_error)?;

    if raw_rows.is_empty() {
        out.push_str("[]");
        return Ok(());
    }

    out.push('[');
    for (idx, row_js) in raw_rows.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        // Each row is a JS array [column0, column1, ...]. We only select one column (cipher_json).
        let row_array = row_js
            .dyn_ref::<Array>()
            .ok_or_else(|| AppError::Internal)?;
        let cipher_json_js = row_array.get(0);
        let cipher_json = cipher_json_js
            .as_string()
            .ok_or_else(|| AppError::Internal)?;
        out.push_str(&cipher_json);
    }
    out.push(']');
    Ok(())
}
