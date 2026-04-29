use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Multipart, Path, State},
    Extension, Json,
};
use chrono::{TimeZone, Utc};
use jwt_compact::AlgorithmExt;
use jwt_compact::{alg::Hs256Key, Claims as JwtClaims, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::{D1Database, Env};

use crate::{
    auth::{Claims, JWT_VALIDATION_LEEWAY_SECS},
    db,
    error::AppError,
    handlers::attachments::{
        attachments_enabled, delete_storage_objects, is_kv_backend, upload_to_storage,
    },
    handlers::get_env_usize,
    models::attachment::display_size,
    models::send::{validate_send_dates, SendDB, SendRequestData, SendType, SEND_INACCESSIBLE_MSG},
    notifications::{self, UpdateType},
    BaseUrl,
};

const DEFAULT_SEND_TTL_SECS: i64 = 300;
const DEFAULT_SEND_MAX_BYTES: i64 = 100 * 1024 * 1024; // 100 MiB
const DEFAULT_SEND_TEXT_MAX_BYTES: usize = 1_887_436; // ~1.8 MiB
const KV_MAX_VALUE_BYTES: i64 = 25 * 1024 * 1024;

// ── Token claims ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SendUploadClaims {
    pub sub: String,
    pub device: String,
    pub send_id: String,
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SendDownloadClaims {
    pub send_id: String,
    pub file_id: String,
}

// ── Upload response ─────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileUploadResponse {
    object: String,
    url: String,
    file_upload_type: i32,
    send_response: Value,
}

// ── Config helpers ──────────────────────────────────────────────────

fn send_ttl_secs(env: &Env) -> i64 {
    env.var("SEND_TTL_SECS")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_SEND_TTL_SECS)
}

fn send_max_bytes(env: &Env) -> i64 {
    env.var("SEND_MAX_BYTES")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_SEND_MAX_BYTES)
}

fn send_text_max_bytes(env: &Env) -> usize {
    get_env_usize(env, "SEND_TEXT_MAX_BYTES", DEFAULT_SEND_TEXT_MAX_BYTES)
}

fn user_send_limit_bytes(env: &Env) -> Option<i64> {
    env.var("USER_SEND_LIMIT_KB")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .map(|kb| kb * 1024)
}

// ── JWT helpers ─────────────────────────────────────────────────────

fn build_upload_token(
    env: &Env,
    user_id: &str,
    device: &str,
    send_id: &str,
    file_id: &str,
) -> Result<String, AppError> {
    let ttl = send_ttl_secs(env);
    let now = Utc::now().timestamp();
    let exp = now
        .checked_add(ttl)
        .and_then(|e| e.checked_sub(JWT_VALIDATION_LEEWAY_SECS as i64))
        .ok_or(AppError::Internal)?;

    let expiration = Utc
        .timestamp_opt(exp, 0)
        .single()
        .ok_or(AppError::Internal)?;
    let mut claims = JwtClaims::new(SendUploadClaims {
        sub: user_id.to_string(),
        device: device.to_string(),
        send_id: send_id.to_string(),
        file_id: file_id.to_string(),
    });
    claims.expiration = Some(expiration);

    let secret = super::attachments::jwt_secret(env)?;
    let key = Hs256Key::new(secret.as_bytes());
    jwt_compact::alg::Hs256
        .token(&Header::empty(), &claims, &key)
        .map_err(|_| AppError::Crypto("Failed to create send upload token".into()))
}

pub fn build_download_token(env: &Env, send_id: &str, file_id: &str) -> Result<String, AppError> {
    let ttl = send_ttl_secs(env);
    let now = Utc::now().timestamp();
    let exp = now
        .checked_add(ttl)
        .and_then(|e| e.checked_sub(JWT_VALIDATION_LEEWAY_SECS as i64))
        .ok_or(AppError::Internal)?;

    let expiration = Utc
        .timestamp_opt(exp, 0)
        .single()
        .ok_or(AppError::Internal)?;
    let mut claims = JwtClaims::new(SendDownloadClaims {
        send_id: send_id.to_string(),
        file_id: file_id.to_string(),
    });
    claims.expiration = Some(expiration);

    let secret = super::attachments::jwt_secret(env)?;
    let key = Hs256Key::new(secret.as_bytes());
    jwt_compact::alg::Hs256
        .token(&Header::empty(), &claims, &key)
        .map_err(|_| AppError::Crypto("Failed to create send download token".into()))
}

// ── Helpers ─────────────────────────────────────────────────────────

fn prepare_send_data(payload: &SendRequestData) -> Result<String, AppError> {
    let data_val = if payload.send_type == SendType::Text as i32 {
        payload.text.clone()
    } else if payload.send_type == SendType::File as i32 {
        payload.file.clone()
    } else {
        return Err(AppError::BadRequest("Unsupported send type".into()));
    };

    let mut d = data_val.ok_or_else(|| AppError::BadRequest("Send data not provided".into()))?;
    d.as_object_mut().and_then(|o| o.remove("response"));
    serde_json::to_string(&d).map_err(|_| AppError::Internal)
}

/// Build a `SendDB` from request payload, setting all common fields.
fn build_send(
    user_id: String,
    payload: &SendRequestData,
    data: String,
    deletion_date: String,
    expiration_date: Option<String>,
) -> Result<SendDB, AppError> {
    let mut send = SendDB::new(
        user_id,
        payload.send_type,
        payload.name.clone(),
        data,
        payload.key.clone(),
        deletion_date,
    );
    send.notes = payload.notes.clone();
    send.max_access_count = match &payload.max_access_count {
        Some(m) => Some(m.into_i32()?),
        None => None,
    };
    send.expiration_date = expiration_date;
    send.disabled = payload.disabled.unwrap_or(false) as i32;
    send.hide_email = payload.hide_email.unwrap_or(false) as i32;
    Ok(send)
}

/// Apply mutable fields from request to an existing send (for update).
fn apply_update(
    send: &mut SendDB,
    payload: &SendRequestData,
    deletion_date: String,
    expiration_date: Option<String>,
) -> Result<(), AppError> {
    send.name = payload.name.clone();
    send.akey = payload.key.clone();
    send.notes = payload.notes.clone();
    send.max_access_count = match &payload.max_access_count {
        Some(m) => Some(m.into_i32()?),
        None => None,
    };
    send.expiration_date = expiration_date;
    send.deletion_date = deletion_date;
    send.disabled = payload.disabled.unwrap_or(false) as i32;
    send.hide_email = payload.hide_email.unwrap_or(false) as i32;
    Ok(())
}

async fn resolve_creator_identifier(db: &D1Database, send: &SendDB) -> Option<String> {
    if send.hide_email != 0 {
        return None;
    }
    #[derive(Deserialize)]
    struct EmailRow {
        email: String,
    }
    db.prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[send.user_id.clone().into()])
        .ok()?
        .first::<EmailRow>(None)
        .await
        .ok()
        .flatten()
        .map(|r| r.email)
}

// ── GET /api/sends ──────────────────────────────────────────────────

#[worker::send]
pub async fn list_sends(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let sends = SendDB::find_by_user(&db, &claims.sub).await?;
    let list: Vec<Value> = sends.iter().map(SendDB::to_json).collect();
    Ok(Json(serde_json::json!({
        "data": list,
        "object": "list",
        "continuationToken": null,
    })))
}

// ── GET /api/sends/{send_id} ────────────────────────────────────────

#[worker::send]
pub async fn get_send(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(send_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let send = SendDB::find_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Send not found".into()))?;
    Ok(Json(send.to_json()))
}

// ── POST /api/sends (text send) ─────────────────────────────────────

#[worker::send]
pub async fn create_text_send(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SendRequestData>,
) -> Result<Json<Value>, AppError> {
    if payload.send_type != SendType::Text as i32 {
        return Err(AppError::BadRequest(
            "Use /api/sends/file/v2 for file sends".into(),
        ));
    }

    let (del, exp) =
        validate_send_dates(&payload.deletion_date, payload.expiration_date.as_deref())?;

    let data = prepare_send_data(&payload)?;
    let text_limit = send_text_max_bytes(&env);
    if data.len() > text_limit {
        return Err(AppError::BadRequest(format!(
            "Text send data exceeds limit ({text_limit} bytes). Use file send for larger content."
        )));
    }

    let mut send = build_send(claims.sub.clone(), &payload, data, del, exp)?;
    send.set_password(payload.password.as_deref()).await?;

    let db = db::get_db(&env)?;
    send.insert(&db).await?;
    db::touch_user_updated_at(&db, &claims.sub, &send.updated_at).await?;

    notifications::publish_send_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncSendCreate,
        &send.id,
        &send.updated_at,
        Some(&claims.device),
    )
    .await;

    Ok(Json(send.to_json()))
}

// ── POST /api/sends/file/v2 (preferred file send creation) ──────────

#[worker::send]
pub async fn create_file_send_v2(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    Json(payload): Json<SendRequestData>,
) -> Result<Json<SendFileUploadResponse>, AppError> {
    if payload.send_type != SendType::File as i32 {
        return Err(AppError::BadRequest("Send content is not a file".into()));
    }

    if !attachments_enabled(&env) {
        return Err(AppError::BadRequest("File storage is not enabled".into()));
    }

    let (del, exp) =
        validate_send_dates(&payload.deletion_date, payload.expiration_date.as_deref())?;

    let declared_size: i64 = payload
        .file_length
        .clone()
        .ok_or_else(|| AppError::BadRequest("Invalid send length".into()))?
        .into_i64()?;

    if declared_size < 0 {
        return Err(AppError::BadRequest("Send size can't be negative".into()));
    }

    let max = send_max_bytes(&env);
    if declared_size > max {
        return Err(AppError::BadRequest("File size exceeds send limit".into()));
    }

    if is_kv_backend(&env) && declared_size > KV_MAX_VALUE_BYTES {
        return Err(AppError::BadRequest(format!(
            "File size exceeds KV limit (max {}MB)",
            KV_MAX_VALUE_BYTES / 1024 / 1024
        )));
    }

    let db = db::get_db(&env)?;

    if let Some(limit) = user_send_limit_bytes(&env) {
        let used = SendDB::file_usage_by_user(&db, &claims.sub).await?;
        if used + declared_size > limit {
            return Err(AppError::BadRequest("Send storage limit reached".into()));
        }
    }

    let file_id = uuid::Uuid::new_v4().to_string();

    let data = prepare_send_data(&payload)?;
    let mut file_data: Value = serde_json::from_str(&data).map_err(|_| AppError::Internal)?;
    if let Some(o) = file_data.as_object_mut() {
        o.insert("id".into(), Value::String(file_id.clone()));
        o.insert("size".into(), serde_json::json!(declared_size));
        o.insert(
            "sizeName".into(),
            Value::String(display_size(declared_size)),
        );
    }
    let data = serde_json::to_string(&file_data).map_err(|_| AppError::Internal)?;

    let mut send = build_send(claims.sub.clone(), &payload, data, del, exp)?;
    send.set_password(payload.password.as_deref()).await?;
    send.insert_pending(&db).await?;

    let token = build_upload_token(&env, &claims.sub, &claims.device, &send.id, &file_id)?;
    let url = format!(
        "{base_url}/api/sends/{}/file/{file_id}/azure-upload?token={token}",
        send.id
    );

    let send_response = send.to_json();

    Ok(Json(SendFileUploadResponse {
        object: "send-fileUpload".into(),
        url,
        file_upload_type: 1,
        send_response,
    }))
}

// ── POST /api/sends/file (legacy multipart) ─────────────────────────

#[worker::send]
pub async fn create_file_send_legacy(
    claims: Claims,
    State(env): State<Arc<Env>>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    if !attachments_enabled(&env) {
        return Err(AppError::BadRequest("File storage is not enabled".into()));
    }

    let mut model_json: Option<String> = None;
    let mut file_bytes: Option<Bytes> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest("Invalid multipart data".into()))?
    {
        match field.name() {
            Some("model") => {
                model_json = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| AppError::BadRequest("Invalid model field".into()))?,
                );
            }
            Some("data") | Some("file") => {
                content_type = field.content_type().map(|s| s.to_string());
                file_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|_| AppError::BadRequest("Failed to read file".into()))?,
                );
            }
            _ => {}
        }
    }

    let model_str = model_json.ok_or_else(|| AppError::BadRequest("Missing model data".into()))?;
    let payload: SendRequestData = serde_json::from_str(&model_str)
        .map_err(|_| AppError::BadRequest("Invalid send data".into()))?;

    if payload.send_type != SendType::File as i32 {
        return Err(AppError::BadRequest("Send content is not a file".into()));
    }

    let (del, exp) =
        validate_send_dates(&payload.deletion_date, payload.expiration_date.as_deref())?;

    let file_bytes = file_bytes.ok_or_else(|| AppError::BadRequest("Missing file data".into()))?;
    let actual_size = file_bytes.len() as i64;

    let max = send_max_bytes(&env);
    if actual_size > max {
        return Err(AppError::BadRequest("File size exceeds send limit".into()));
    }

    let db = db::get_db(&env)?;

    if let Some(limit) = user_send_limit_bytes(&env) {
        let used = SendDB::file_usage_by_user(&db, &claims.sub).await?;
        if used + actual_size > limit {
            return Err(AppError::BadRequest("Send storage limit reached".into()));
        }
    }

    let file_id = uuid::Uuid::new_v4().to_string();

    let data = prepare_send_data(&payload)?;
    let mut file_data: Value = serde_json::from_str(&data).map_err(|_| AppError::Internal)?;
    if let Some(o) = file_data.as_object_mut() {
        o.insert("id".into(), Value::String(file_id.clone()));
        o.insert("size".into(), serde_json::json!(actual_size));
        o.insert("sizeName".into(), Value::String(display_size(actual_size)));
    }
    let data = serde_json::to_string(&file_data).map_err(|_| AppError::Internal)?;

    let mut send = build_send(claims.sub.clone(), &payload, data, del, exp)?;
    send.set_password(payload.password.as_deref()).await?;

    let storage_key = format!("sends/{}/{file_id}", send.id);
    upload_to_storage(&env, &storage_key, content_type, file_bytes.to_vec()).await?;

    send.insert(&db).await?;
    db::touch_user_updated_at(&db, &claims.sub, &send.updated_at).await?;

    notifications::publish_send_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncSendCreate,
        &send.id,
        &send.updated_at,
        Some(&claims.device),
    )
    .await;

    Ok(Json(send.to_json()))
}

// ── POST /api/sends/{send_id}/file/{file_id} (Direct upload compat) ─

#[worker::send]
pub async fn upload_file_send_direct(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((send_id, file_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<(), AppError> {
    if !attachments_enabled(&env) {
        return Err(AppError::BadRequest("File storage is not enabled".into()));
    }

    let db = db::get_db(&env)?;

    let mut pending = SendDB::find_pending_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Send not found. Unable to save the file.".into()))?;

    let expected_file_id = pending.file_id().ok_or_else(|| AppError::Internal)?;
    if expected_file_id != file_id {
        return Err(AppError::BadRequest(
            "Send file does not match send data.".into(),
        ));
    }

    let mut file_bytes: Option<Bytes> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest("Invalid multipart data".into()))?
    {
        if field.name() == Some("data") || field.name() == Some("file") {
            content_type = field.content_type().map(|s| s.to_string());
            file_bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|_| AppError::BadRequest("Failed to read file".into()))?,
            );
        }
    }

    let file_bytes = file_bytes.ok_or_else(|| AppError::BadRequest("Missing file data".into()))?;
    let actual_size = file_bytes.len() as i64;

    let declared_size: i64 = serde_json::from_str::<Value>(&pending.data)
        .ok()
        .and_then(|v| v.get("size").and_then(|s| s.as_i64()))
        .ok_or_else(|| AppError::Internal)?;

    if actual_size != declared_size {
        return Err(AppError::BadRequest(
            "Send file size does not match.".into(),
        ));
    }

    let storage_key = pending.storage_key().ok_or_else(|| AppError::Internal)?;
    upload_to_storage(&env, &storage_key, content_type, file_bytes.to_vec()).await?;

    pending.finalize(&db).await?;
    db::touch_user_updated_at(&db, &claims.sub, &pending.updated_at).await?;

    notifications::publish_send_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncSendCreate,
        &pending.id,
        &pending.updated_at,
        Some(&claims.device),
    )
    .await;

    Ok(())
}

// ── PUT /api/sends/{send_id} ────────────────────────────────────────

#[worker::send]
pub async fn update_send(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(send_id): Path<String>,
    Json(payload): Json<SendRequestData>,
) -> Result<Json<Value>, AppError> {
    let (del, exp) =
        validate_send_dates(&payload.deletion_date, payload.expiration_date.as_deref())?;

    let db = db::get_db(&env)?;
    let mut send = SendDB::find_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Send not found".into()))?;

    if send.send_type != payload.send_type {
        return Err(AppError::BadRequest("Sends can't change type".into()));
    }

    if payload.send_type == SendType::Text as i32 {
        let data = prepare_send_data(&payload)?;
        let text_limit = send_text_max_bytes(&env);
        if data.len() > text_limit {
            return Err(AppError::BadRequest(format!(
                "Text send data exceeds limit ({text_limit} bytes)"
            )));
        }
        send.data = data;
    }

    apply_update(&mut send, &payload, del, exp)?;

    if let Some(ref pw) = payload.password {
        send.set_password(Some(pw)).await?;
    }

    send.update(&db).await?;
    db::touch_user_updated_at(&db, &claims.sub, &send.updated_at).await?;

    notifications::publish_send_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncSendUpdate,
        &send.id,
        &send.updated_at,
        Some(&claims.device),
    )
    .await;

    Ok(Json(send.to_json()))
}

// ── DELETE /api/sends/{send_id} ─────────────────────────────────────

#[worker::send]
pub async fn delete_send(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(send_id): Path<String>,
) -> Result<(), AppError> {
    let db = db::get_db(&env)?;
    let send = SendDB::find_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Send not found".into()))?;

    if let Some(key) = send.storage_key() {
        delete_storage_objects(env.as_ref(), &[key]).await?;
    }

    send.delete(&db).await?;

    let now = db::now_string();
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;
    notifications::publish_send_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncSendDelete,
        &send_id,
        &now,
        Some(&claims.device),
    )
    .await;

    Ok(())
}

// ── PUT /api/sends/{send_id}/remove-password ────────────────────────

#[worker::send]
pub async fn remove_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(send_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut send = SendDB::find_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Send not found".into()))?;

    send.set_password(None).await?;
    send.update(&db).await?;
    db::touch_user_updated_at(&db, &claims.sub, &send.updated_at).await?;

    notifications::publish_send_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncSendUpdate,
        &send.id,
        &send.updated_at,
        Some(&claims.device),
    )
    .await;

    Ok(Json(send.to_json()))
}

// ── POST /api/sends/access/{access_id} (anonymous access) ──────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SendAccessRequest {
    #[serde(default)]
    pub password: Option<String>,
}

#[worker::send]
pub async fn access_send(
    State(env): State<Arc<Env>>,
    Path(access_id): Path<String>,
    Json(payload): Json<SendAccessRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut send = SendDB::find_by_access_id(&db, &access_id)
        .await?
        .ok_or_else(|| AppError::NotFound(SEND_INACCESSIBLE_MSG.into()))?;

    send.validate_access()?;

    if send.has_password() {
        let pw = payload
            .password
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("Password not provided".into()))?;
        if !send.check_password(pw).await? {
            return Err(AppError::BadRequest("Invalid password".into()));
        }
    }

    // Text sends increment access count here; file sends increment on download.
    // Both types get a revision bump and sync notification (aligns with Vaultwarden).
    if send.send_type != SendType::File as i32 {
        send.increment_access_count(&db).await?;
    } else {
        send.update(&db).await?;
    }

    db::touch_user_updated_at(&db, &send.user_id, &send.updated_at).await?;

    notifications::publish_send_update(
        env.as_ref(),
        &send.user_id,
        UpdateType::SyncSendUpdate,
        &send.id,
        &send.updated_at,
        None,
    )
    .await;

    let creator_id = resolve_creator_identifier(&db, &send).await;
    Ok(Json(send.to_access_json(creator_id.as_deref())))
}

// ── POST /api/sends/{send_id}/access/file/{file_id} (anonymous file) ─

#[worker::send]
pub async fn access_file_send(
    State(env): State<Arc<Env>>,
    Path((send_id, file_id)): Path<(String, String)>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    Json(payload): Json<SendAccessRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut send = SendDB::find_by_id(&db, &send_id)
        .await?
        .ok_or_else(|| AppError::NotFound(SEND_INACCESSIBLE_MSG.into()))?;

    send.validate_access()?;

    if send.send_type != SendType::File as i32 {
        return Err(AppError::NotFound(SEND_INACCESSIBLE_MSG.into()));
    }

    if send.has_password() {
        let pw = payload
            .password
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("Password not provided".into()))?;
        if !send.check_password(pw).await? {
            return Err(AppError::BadRequest("Invalid password".into()));
        }
    }

    send.increment_access_count(&db).await?;
    db::touch_user_updated_at(&db, &send.user_id, &send.updated_at).await?;

    notifications::publish_send_update(
        env.as_ref(),
        &send.user_id,
        UpdateType::SyncSendUpdate,
        &send.id,
        &send.updated_at,
        None,
    )
    .await;

    let token = build_download_token(&env, &send_id, &file_id)?;
    let url = format!("{base_url}/api/sends/{send_id}/{file_id}?t={token}");

    Ok(Json(serde_json::json!({
        "id": file_id,
        "url": url,
        "object": "send-fileDownload",
    })))
}

// ── Key rotation support ────────────────────────────────────────────

pub async fn rotate_user_sends(
    db: &D1Database,
    _env: &Env,
    user_id: &str,
    sends: &[SendRequestData],
    now: &str,
    batch_size: usize,
) -> Result<(), AppError> {
    let db_sends = SendDB::find_by_user(db, user_id).await?;

    let db_ids: std::collections::HashSet<&str> = db_sends.iter().map(|s| s.id.as_str()).collect();
    let req_ids: std::collections::HashSet<&str> = sends
        .iter()
        .map(|s| {
            s.id.as_ref()
                .ok_or_else(|| AppError::BadRequest("Each send must have an id".into()))
                .map(|id| id.as_str())
        })
        .collect::<Result<_, _>>()?;

    if db_ids.len() != req_ids.len() || db_ids != req_ids {
        return Err(AppError::BadRequest(
            "All existing sends must be included in the rotation".into(),
        ));
    }

    let mut statements = Vec::with_capacity(sends.len());
    for send_data in sends {
        let data = if send_data.send_type == SendType::Text as i32 {
            serde_json::to_string(&send_data.text).map_err(|_| AppError::Internal)?
        } else if send_data.send_type == SendType::File as i32 {
            serde_json::to_string(&send_data.file).map_err(|_| AppError::Internal)?
        } else {
            continue;
        };

        let stmt = worker::query!(
            db,
            "UPDATE sends SET name = ?1, notes = ?2, data = ?3, akey = ?4, updated_at = ?5 WHERE id = ?6 AND user_id = ?7",
            send_data.name,
            send_data.notes,
            data,
            send_data.key,
            now,
            send_data.id,
            user_id
        )
        .map_err(|_| AppError::Database)?;
        statements.push(stmt);
    }

    db::execute_in_batches(db, statements, batch_size).await?;
    Ok(())
}

// ── Cleanup helpers ─────────────────────────────────────────────────

pub async fn delete_user_sends(db: &D1Database, env: &Env, user_id: &str) -> Result<(), AppError> {
    if attachments_enabled(env) {
        let keys = SendDB::storage_keys_by_user(db, user_id).await?;
        if !keys.is_empty() {
            delete_storage_objects(env, &keys).await?;
        }
    }

    SendDB::delete_all_by_user(db, user_id).await?;
    Ok(())
}

// ── Sync helper ─────────────────────────────────────────────────────

pub async fn append_sends_json_array(
    out: &mut String,
    db: &D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    let sends = SendDB::find_by_user(db, user_id).await?;
    let list: Vec<Value> = sends.iter().map(SendDB::to_json).collect();
    let json = serde_json::to_string(&list).map_err(|_| AppError::Internal)?;
    out.push_str(&json);
    Ok(())
}
