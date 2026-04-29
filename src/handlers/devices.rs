use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{auth::Claims, db, error::AppError, models::device::Device, push};

fn required_header(headers: &HeaderMap, name: &str) -> Result<String, AppError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AppError::BadRequest(format!("Missing {name} header")))
}

fn decode_base64url_email(encoded: &str) -> Result<String, AppError> {
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| general_purpose::URL_SAFE.decode(encoded))
        .map_err(|_| AppError::BadRequest("Invalid X-Request-Email header".to_string()))?;
    String::from_utf8(decoded)
        .map_err(|_| AppError::BadRequest("Invalid X-Request-Email header".to_string()))
}

async fn current_device(
    db: &worker::D1Database,
    claims: &Claims,
    path_device_id: &str,
) -> Result<Device, AppError> {
    if path_device_id != claims.device.as_str() {
        return Err(AppError::Unauthorized(
            "Can only manage the current authenticated device".to_string(),
        ));
    }

    Device::find_by_identifier_and_user(db, &claims.device, &claims.sub)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid token".to_string()))
}

/// GET /devices
#[worker::send]
pub async fn get_devices(
    State(env): State<Arc<Env>>,
    claims: Claims,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let devices = Device::list_by_user(&db, &claims.sub).await?;

    Ok(Json(json!({
        "data": devices.into_iter().map(|device| device.to_json()).collect::<Vec<Value>>(),
        "continuationToken": null,
        "object": "list"
    })))
}

/// GET /devices/knowndevice
#[worker::send]
pub async fn get_known_device(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
) -> Result<Json<bool>, AppError> {
    let encoded_email = required_header(&headers, "X-Request-Email")?;
    let identifier = required_header(&headers, "X-Device-Identifier")?;
    let email = decode_base64url_email(&encoded_email)?.to_lowercase();
    let db = db::get_db(&env)?;

    let user_id: Option<String> = db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first(Some("id"))
        .await
        .map_err(|_| AppError::Database)?;

    let is_known = if let Some(user_id) = user_id {
        Device::find_by_identifier_and_user(&db, &identifier, &user_id)
            .await?
            .is_some()
    } else {
        false
    };

    Ok(Json(is_known))
}

/// GET /devices/identifier/{device_id}
#[worker::send]
pub async fn get_device(
    State(env): State<Arc<Env>>,
    claims: Claims,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let device = Device::find_by_identifier_and_user(&db, &device_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    Ok(Json(device.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushToken {
    push_token: String,
}

async fn upsert_device_token(
    env: Arc<Env>,
    claims: Claims,
    device_id: String,
    push_token: String,
) -> Result<Json<Value>, AppError> {
    let push_token = push_token.trim().to_string();
    if push_token.is_empty() {
        return Err(AppError::BadRequest("Missing pushToken".to_string()));
    }

    let db = db::get_db(&env)?;
    let mut device = current_device(&db, &claims, &device_id).await?;
    // Also check that push_uuid is present before skipping registration.
    // Unlike vaultwarden, which pre-allocates push_uuid at Device::new() time,
    // we only generate it during relay registration. If a previous registration
    // call saved the token but failed at the relay step, push_uuid will be
    // missing; in that case we must NOT early-return so the retry can complete
    // the relay registration.
    if device.push_token.as_deref() == Some(push_token.as_str()) && device.push_uuid.is_some() {
        log::debug!(
            "Device {} for user {} is already registered and token is identical",
            device_id,
            claims.sub
        );
        return Ok(Json(json!({})));
    }

    device.set_push_token(&db, Some(&push_token)).await?;

    if let Some(cfg) = push::push_config(&env)? {
        let push_uuid_created = push::register_push_device(&cfg, &mut device).await?;
        if push_uuid_created {
            device.persist_push_uuid(&db).await?;
        }
    }

    Ok(Json(json!({})))
}

/// POST /devices/identifier/{device_id}/token
#[worker::send]
pub async fn post_device_token(
    State(env): State<Arc<Env>>,
    claims: Claims,
    Path(device_id): Path<String>,
    Json(data): Json<PushToken>,
) -> Result<Json<Value>, AppError> {
    upsert_device_token(env, claims, device_id, data.push_token).await
}

/// PUT /devices/identifier/{device_id}/token
#[worker::send]
pub async fn put_device_token(
    State(env): State<Arc<Env>>,
    claims: Claims,
    Path(device_id): Path<String>,
    Json(data): Json<PushToken>,
) -> Result<Json<Value>, AppError> {
    upsert_device_token(env, claims, device_id, data.push_token).await
}

async fn clear_device_token(
    env: Arc<Env>,
    claims: Claims,
    device_id: String,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut device = current_device(&db, &claims, &device_id).await?;

    device.set_push_token(&db, None).await?;

    if let Some(cfg) = push::push_config(&env)? {
        push::unregister_push_device(&cfg, device.push_uuid.as_deref()).await?;
    }

    Ok(Json(json!({})))
}

/// PUT /devices/identifier/{device_id}/clear-token
#[worker::send]
pub async fn put_clear_device_token(
    State(env): State<Arc<Env>>,
    claims: Claims,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    clear_device_token(env, claims, device_id).await
}

/// POST /devices/identifier/{device_id}/clear-token
#[worker::send]
pub async fn post_clear_device_token(
    State(env): State<Arc<Env>>,
    claims: Claims,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    clear_device_token(env, claims, device_id).await
}
