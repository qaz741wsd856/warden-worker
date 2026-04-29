#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use web_sys::UrlSearchParams;
use worker::{
    wasm_bindgen::JsValue, Cache, Env, Fetch, Headers, Method, Request, RequestInit, Response,
};

use crate::db;
use crate::{error::AppError, models::device::Device};

const PUSH_TOKEN_CACHE_BASE: &str = "https://push-token.internal/relay-token";
const DEFAULT_PUSH_RELAY_URI: &str = "https://push.bitwarden.com";
const DEFAULT_PUSH_IDENTITY_URI: &str = "https://identity.bitwarden.com";

// ── PushConfig ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PushConfig {
    pub relay_uri: String,
    pub identity_uri: String,
    pub installation_id: String,
    pub installation_key: String,
}

/// Try to build a `PushConfig` from environment variables.
///
/// Returns `None` when `PUSH_ENABLED` is not `"true"`.
/// Returns `Err` when push is enabled but required secrets are missing.
pub fn push_config(env: &Env) -> Result<Option<PushConfig>, AppError> {
    let enabled = env
        .var("PUSH_ENABLED")
        .ok()
        .is_some_and(|v| v.to_string() == "true");
    if !enabled {
        return Ok(None);
    }

    let relay_uri = env
        .var("PUSH_RELAY_URI")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| DEFAULT_PUSH_RELAY_URI.to_string());

    let identity_uri = env
        .var("PUSH_IDENTITY_URI")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| DEFAULT_PUSH_IDENTITY_URI.to_string());

    let installation_id = env
        .secret("PUSH_INSTALLATION_ID")
        .map(|v| v.to_string())
        .map_err(|_| {
            log::error!("PUSH_ENABLED is true but PUSH_INSTALLATION_ID secret is missing");
            AppError::Internal
        })?;

    let installation_key = env
        .secret("PUSH_INSTALLATION_KEY")
        .map(|v| v.to_string())
        .map_err(|_| {
            log::error!("PUSH_ENABLED is true but PUSH_INSTALLATION_KEY secret is missing");
            AppError::Internal
        })?;

    Ok(Some(PushConfig {
        relay_uri,
        identity_uri,
        installation_id,
        installation_key,
    }))
}

// ── OAuth2 token management ─────────────────────────────────────────

#[derive(Deserialize)]
struct AuthPushToken {
    access_token: String,
    expires_in: i32,
}

async fn fetch_relay_token(cfg: &PushConfig) -> Result<(String, i32), AppError> {
    let client_id = format!("installation.{}", cfg.installation_id);

    let params = UrlSearchParams::new().map_err(|_| AppError::Internal)?;
    params.append("grant_type", "client_credentials");
    params.append("scope", "api.push");
    params.append("client_id", &client_id);
    params.append("client_secret", &cfg.installation_key);
    let body = params.to_string();

    let url = format!("{}/connect/token", cfg.identity_uri);

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Accept", "application/json")
        .map_err(AppError::Worker)?;

    let mut response = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&response.status_code()) {
        let body = response.text().await.unwrap_or_default();
        log::error!(
            "Push token request failed ({}): {body}",
            response.status_code()
        );
        return Err(AppError::Internal);
    }

    let token: AuthPushToken = response.json().await.map_err(AppError::Worker)?;
    Ok((token.access_token, token.expires_in))
}

fn push_cache_url(cfg: &PushConfig) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h = DefaultHasher::new();
    cfg.identity_uri.hash(&mut h);
    cfg.installation_id.hash(&mut h);
    cfg.installation_key.hash(&mut h);
    format!("{}?h={:x}", PUSH_TOKEN_CACHE_BASE, h.finish())
}

async fn get_relay_token(cfg: &PushConfig) -> Result<String, AppError> {
    let cache_url = push_cache_url(cfg);
    let cache = Cache::default();
    if let Some(mut cached) = cache
        .get(&cache_url, false)
        .await
        .map_err(AppError::Worker)?
    {
        if let Ok(token) = cached.text().await {
            if !token.is_empty() {
                return Ok(token);
            }
        }
    }

    let (access_token, expires_in) = fetch_relay_token(cfg).await?;
    let max_age = (expires_in / 2).max(60);

    let headers = Headers::new();
    headers
        .set("Cache-Control", &format!("max-age={max_age}"))
        .map_err(AppError::Worker)?;
    headers
        .set("Content-Type", "text/plain")
        .map_err(AppError::Worker)?;

    let response = Response::ok(&access_token)
        .map_err(AppError::Worker)?
        .with_headers(headers);
    let _ = cache.put(&cache_url, response).await;

    Ok(access_token)
}

// ── Device registration / unregistration ────────────────────────────

fn ensure_push_uuid(device: &mut Device) -> bool {
    if device.push_uuid.is_none() {
        device.push_uuid = Some(uuid::Uuid::new_v4().to_string());
        return true;
    }
    false
}

pub async fn register_push_device(cfg: &PushConfig, device: &mut Device) -> Result<bool, AppError> {
    if !device.is_push_device() {
        return Ok(false);
    }

    let Some(push_token) = device.push_token.clone() else {
        log::warn!(
            "Skipping push registration for device {} — no push_token",
            device.identifier
        );
        return Ok(false);
    };

    let push_uuid_created = ensure_push_uuid(device);
    let push_uuid = device.push_uuid.as_deref().unwrap();

    let data = json!({
        "deviceId": push_uuid,
        "pushToken": push_token,
        "userId": device.user_id,
        "type": device.r#type,
        "identifier": device.identifier,
        "installationId": cfg.installation_id,
    });

    let token = get_relay_token(cfg).await?;
    let url = format!("{}/push/register", cfg.relay_uri);
    post_to_relay(&url, &token, &data, true).await?;
    Ok(push_uuid_created)
}

pub async fn unregister_push_device(
    cfg: &PushConfig,
    push_uuid: Option<&str>,
) -> Result<(), AppError> {
    let Some(push_uuid) = push_uuid else {
        return Ok(());
    };

    let token = get_relay_token(cfg).await?;
    let url = format!("{}/push/delete/{push_uuid}", cfg.relay_uri);

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Authorization", &format!("Bearer {token}"))
        .map_err(AppError::Worker)?;

    let response = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&response.status_code()) {
        log::warn!(
            "Push device unregistration returned non-success status: {}",
            response.status_code()
        );
    }
    Ok(())
}

// ── Push notification sending ───────────────────────────────────────

pub async fn send_to_push_relay(cfg: &PushConfig, payload: &Value) -> Result<(), AppError> {
    let token = get_relay_token(cfg).await?;
    let url = format!("{}/push/send", cfg.relay_uri);
    post_to_relay(&url, &token, payload, false).await
}

// In this project, org feature is not supported, so we set organizationId and collectionIds to null

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePushInfo {
    pub push_uuid: Option<String>,
    pub identifier: String,
}

// ── Internal helpers ────────────────────────────────────────────────

async fn post_to_relay(
    url: &str,
    token: &str,
    data: &Value,
    fail_on_http_error: bool,
) -> Result<(), AppError> {
    let body = serde_json::to_string(data).map_err(|_| AppError::Internal)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));

    let mut req = Request::new_with_init(url, &init).map_err(AppError::Worker)?;
    let headers = req.headers_mut().map_err(AppError::Worker)?;
    headers
        .set("Content-Type", "application/json")
        .map_err(AppError::Worker)?;
    headers
        .set("Accept", "application/json")
        .map_err(AppError::Worker)?;
    headers
        .set("Authorization", &format!("Bearer {token}"))
        .map_err(AppError::Worker)?;

    let mut response = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&response.status_code()) {
        let body = response.text().await.unwrap_or_default();
        log::error!(
            "Push relay POST to {url} failed ({}): {body}",
            response.status_code()
        );
        if fail_on_http_error {
            return Err(AppError::Internal);
        }
    }
    Ok(())
}

// ── D1 queries (push device checks) ────────────────────────────

pub async fn user_has_push_device(env: &Env, user_id: &str) -> Result<bool, AppError> {
    let db = db::get_db(env)?;
    let count: Option<f64> = db
        .prepare(
            "SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?1 AND push_token IS NOT NULL AND push_uuid IS NOT NULL",
        )
        .bind(&[user_id.into()])
        .map_err(AppError::Worker)?
        .first(Some("cnt"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(count.unwrap_or(0.0) > 0.0)
}

pub async fn lookup_device_push_info(
    env: &Env,
    user_id: &str,
    device_identifier: &str,
) -> Result<Option<DevicePushInfo>, AppError> {
    let db = db::get_db(env)?;
    let row: Option<Value> = db
        .prepare("SELECT push_uuid, identifier FROM devices WHERE identifier = ?1 AND user_id = ?2")
        .bind(&[device_identifier.into(), user_id.into()])
        .map_err(AppError::Worker)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(row.and_then(|r| serde_json::from_value(r).ok()))
}

/// Unregister all push devices for a user from the relay.
/// Should be called before deleting device rows (e.g. account deletion, session revocation).
/// Failures are logged but do not prevent the caller from proceeding.
pub async fn unregister_push_devices_by_user(env: &Env, user_id: &str) {
    let Some(cfg) = try_get_push_config(env) else {
        return;
    };
    let db = match db::get_db(env) {
        Ok(db) => db,
        Err(_) => return,
    };

    let stmt = match db
        .prepare("SELECT push_uuid FROM devices WHERE user_id = ?1 AND push_uuid IS NOT NULL")
        .bind(&[user_id.into()])
    {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Failed to query push devices for user {user_id}: {e}");
            return;
        }
    };

    let push_uuids: Vec<String> = match stmt.all().await {
        Ok(res) => res
            .results::<serde_json::Value>()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|row| {
                row.get("push_uuid")
                    .and_then(|v| v.as_str().map(String::from))
            })
            .collect(),
        Err(e) => {
            log::warn!("Failed to query push devices for user {user_id}: {e}");
            return;
        }
    };

    for push_uuid in &push_uuids {
        if let Err(e) = unregister_push_device(&cfg, Some(push_uuid.as_str())).await {
            log::warn!("Failed to unregister push device {push_uuid}: {e}");
        }
    }
}

// ── Push notification helpers ───────────────────────────────────

fn try_get_push_config(env: &Env) -> Option<PushConfig> {
    match push_config(env) {
        Ok(Some(cfg)) => Some(cfg),
        Ok(None) => None,
        Err(e) => {
            log::error!("Push config error: {e}");
            None
        }
    }
}

async fn resolve_device_info(
    env: &Env,
    user_id: &str,
    context_id: Option<&str>,
) -> Option<DevicePushInfo> {
    let ctx = context_id?;
    lookup_device_push_info(env, user_id, ctx)
        .await
        .ok()
        .flatten()
}

// ── High-level push functions (called from notification entry points) ──

pub async fn push_user_update(
    env: &Env,
    user_id: &str,
    update_type: i32,
    date: &str,
    context_id: Option<&str>,
) {
    let Some(cfg) = try_get_push_config(env) else {
        return;
    };
    if !user_has_push_device(env, user_id).await.unwrap_or(false) {
        return;
    }
    let device = resolve_device_info(env, user_id, context_id).await;
    let payload = json!({
        "userId": user_id,
        "organizationId": null,
        "deviceId": device.as_ref().and_then(|d| d.push_uuid.as_deref()),
        "identifier": device.as_ref().map(|d| d.identifier.as_str()),
        "type": update_type,
        "payload": {
            "userId": user_id,
            "date": date,
        },
        "clientType": null,
        "installationId": null,
    });
    if let Err(e) = send_to_push_relay(&cfg, &payload).await {
        log::warn!("Push relay failed for user_update: {e}");
    }
}

pub async fn push_folder_update(
    env: &Env,
    user_id: &str,
    update_type: i32,
    folder_id: &str,
    revision_date: &str,
    context_id: Option<&str>,
) {
    let Some(cfg) = try_get_push_config(env) else {
        return;
    };
    if !user_has_push_device(env, user_id).await.unwrap_or(false) {
        return;
    }
    let device = resolve_device_info(env, user_id, context_id).await;
    let payload = json!({
        "userId": user_id,
        "organizationId": null,
        "deviceId": device.as_ref().and_then(|d| d.push_uuid.as_deref()),
        "identifier": device.as_ref().map(|d| d.identifier.as_str()),
        "type": update_type,
        "payload": {
            "id": folder_id,
            "userId": user_id,
            "revisionDate": revision_date,
        },
        "clientType": null,
        "installationId": null,
    });
    if let Err(e) = send_to_push_relay(&cfg, &payload).await {
        log::warn!("Push relay failed for folder_update: {e}");
    }
}

pub async fn push_cipher_update(
    env: &Env,
    user_id: &str,
    update_type: i32,
    cipher_id: &str,
    revision_date: &str,
    context_id: Option<&str>,
) {
    let Some(cfg) = try_get_push_config(env) else {
        return;
    };
    if !user_has_push_device(env, user_id).await.unwrap_or(false) {
        return;
    }
    let device = resolve_device_info(env, user_id, context_id).await;
    let payload = json!({
        "userId": user_id,
        "organizationId": null,
        "deviceId": device.as_ref().and_then(|d| d.push_uuid.as_deref()),
        "identifier": device.as_ref().map(|d| d.identifier.as_str()),
        "type": update_type,
        "payload": {
            "id": cipher_id,
            "userId": user_id,
            "organizationId": null,
            "collectionIds": null,
            "revisionDate": revision_date,
        },
        "clientType": null,
        "installationId": null,
    });
    if let Err(e) = send_to_push_relay(&cfg, &payload).await {
        log::warn!("Push relay failed for cipher_update: {e}");
    }
}

pub async fn push_send_update(
    env: &Env,
    user_id: &str,
    update_type: i32,
    send_id: &str,
    revision_date: &str,
    context_id: Option<&str>,
) {
    let Some(cfg) = try_get_push_config(env) else {
        return;
    };
    if !user_has_push_device(env, user_id).await.unwrap_or(false) {
        return;
    }
    let device = resolve_device_info(env, user_id, context_id).await;
    let payload = json!({
        "userId": user_id,
        "organizationId": null,
        "deviceId": device.as_ref().and_then(|d| d.push_uuid.as_deref()),
        "identifier": device.as_ref().map(|d| d.identifier.as_str()),
        "type": update_type,
        "payload": {
            "id": send_id,
            "userId": user_id,
            "revisionDate": revision_date,
        },
        "clientType": null,
        "installationId": null,
    });
    if let Err(e) = send_to_push_relay(&cfg, &payload).await {
        log::warn!("Push relay failed for send_update: {e}");
    }
}

pub async fn push_auth_request(
    env: &Env,
    user_id: &str,
    auth_request_id: &str,
    context_id: Option<&str>,
) {
    let Some(cfg) = try_get_push_config(env) else {
        return;
    };
    if !user_has_push_device(env, user_id).await.unwrap_or(false) {
        return;
    }
    let device = resolve_device_info(env, user_id, context_id).await;
    let payload = json!({
        "userId": user_id,
        "organizationId": null,
        "deviceId": device.as_ref().and_then(|d| d.push_uuid.as_deref()),
        "identifier": device.as_ref().map(|d| d.identifier.as_str()),
        "type": 15,
        "payload": {
            "userId": user_id,
            "id": auth_request_id,
        },
        "clientType": null,
        "installationId": null,
    });
    if let Err(e) = send_to_push_relay(&cfg, &payload).await {
        log::warn!("Push relay failed for auth_request: {e}");
    }
}

pub async fn push_auth_response(
    env: &Env,
    user_id: &str,
    auth_request_id: &str,
    context_id: Option<&str>,
) {
    let Some(cfg) = try_get_push_config(env) else {
        return;
    };
    if !user_has_push_device(env, user_id).await.unwrap_or(false) {
        return;
    }
    let device = resolve_device_info(env, user_id, context_id).await;
    let payload = json!({
        "userId": user_id,
        "organizationId": null,
        "deviceId": device.as_ref().and_then(|d| d.push_uuid.as_deref()),
        "identifier": device.as_ref().map(|d| d.identifier.as_str()),
        "type": 16,
        "payload": {
            "userId": user_id,
            "id": auth_request_id,
        },
        "clientType": null,
        "installationId": null,
    });
    if let Err(e) = send_to_push_relay(&cfg, &payload).await {
        log::warn!("Push relay failed for auth_response: {e}");
    }
}
