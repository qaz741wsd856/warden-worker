use jwt_compact::{alg::Hs256Key, AlgorithmExt, UntrustedToken};
use serde::{Deserialize, Serialize};
use web_sys::ReadableStream;
use worker::{Env, Headers, HttpMetadata, Method, Request, Response, Url};

use crate::{
    auth::jwt_time_options,
    db::{self, touch_user_updated_at},
    error::AppError,
    handlers::attachments::{
        self, get_storage_backend, jwt_secret, AttachmentClaims, StorageBackend,
    },
    handlers::sends::{SendDownloadClaims, SendUploadClaims},
    models::send::SendDB,
    notifications::{self, UpdateType},
};

const ATTACHMENTS_BUCKET: &str = "ATTACHMENTS_BUCKET";
const ATTACHMENTS_KV: &str = "ATTACHMENTS_KV";

// ── KV metadata ─────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct KvFileMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    file_size: i64,
}

// ── Routing ─────────────────────────────────────────────────────────

pub fn is_streaming_route(method: &Method, path: &str) -> bool {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    match *method {
        Method::Put => {
            matches!(
                segs.as_slice(),
                ["api", "ciphers", _, "attachment", _, "azure-upload"]
                    | ["api", "sends", _, "file", _, "azure-upload"]
            )
        }
        Method::Get => {
            matches!(
                segs.as_slice(),
                ["api", "ciphers", _, "attachment", _, "download"]
            ) || matches!(
                segs.as_slice(),
                ["api", "sends", send_id, _file_id] if *send_id != "access" && *send_id != "file"
            )
        }
        _ => false,
    }
}

pub async fn handle(req: Request, env: &Env, method: &Method, path: &str, url: &Url) -> Response {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();

    let result = match (method, segs.as_slice()) {
        (&Method::Put, ["api", "ciphers", cid, "attachment", aid, "azure-upload"]) => {
            match query_param(url, "token") {
                Some(token) => handle_attachment_upload(req, env, cid, aid, &token).await,
                None => Err(bad("Missing query parameter: token")),
            }
        }
        (&Method::Get, ["api", "ciphers", cid, "attachment", aid, "download"]) => {
            match query_param(url, "token") {
                Some(token) => handle_attachment_download(env, cid, aid, &token).await,
                None => Err(bad("Missing query parameter: token")),
            }
        }
        (&Method::Put, ["api", "sends", sid, "file", fid, "azure-upload"]) => {
            match query_param(url, "token") {
                Some(token) => handle_send_upload(req, env, sid, fid, &token).await,
                None => Err(bad("Missing query parameter: token")),
            }
        }
        (&Method::Get, ["api", "sends", sid, fid]) if *sid != "access" && *sid != "file" => {
            let token = query_param(url, "t").unwrap_or_default();
            handle_send_download(env, sid, fid, &token).await
        }
        _ => Err(AppError::NotFound("Not found".into())),
    };

    match result {
        Ok(resp) => resp,
        Err(e) => app_error_to_response(&e),
    }
}

fn query_param(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

// ── Attachment upload ───────────────────────────────────────────────

async fn handle_attachment_upload(
    req: Request,
    env: &Env,
    cipher_id: &str,
    attachment_id: &str,
    token: &str,
) -> Result<Response, AppError> {
    let backend = get_storage_backend(env).ok_or_else(|| bad("Attachments are not enabled"))?;
    let db = db::get_db(env)?;

    let claims = verify_token::<AttachmentClaims>(env, token)?;
    if claims.cipher_id != cipher_id || claims.attachment_id != attachment_id {
        log::warn!("Attachment upload token claims mismatch: expected cipher={cipher_id} att={attachment_id}");
        return Err(AppError::Unauthorized("Invalid token".into()));
    }

    let user_id = &claims.sub;
    let context_id = if claims.device.is_empty() {
        None
    } else {
        Some(claims.device.as_str())
    };

    attachments::ensure_cipher_for_user(&db, cipher_id, user_id).await?;
    let pending = attachments::fetch_pending_attachment(&db, attachment_id).await?;
    if pending.cipher_id != cipher_id {
        return Err(bad("Attachment does not belong to cipher"));
    }

    let declared_size = pending.file_size;
    if declared_size <= 0 {
        return Err(bad("Invalid pending attachment size"));
    }

    let content_length = parse_content_length(req.headers())?;
    if content_length != declared_size {
        return Err(bad(&format!(
            "Uploaded size ({content_length}) does not match declared size ({declared_size})"
        )));
    }

    let body_stream = request_body(&req)?;
    let content_type = req.headers().get("content-type").ok().flatten();

    let storage_key = format!("{cipher_id}/{attachment_id}");
    put_stream_to_storage(
        env,
        backend,
        &storage_key,
        body_stream,
        content_type.as_deref(),
        declared_size,
    )
    .await?;

    let mut pending = pending;
    let now = pending.finalize_pending(&db).await?;
    touch_user_updated_at(&db, user_id, &now).await?;

    notifications::publish_cipher_update(
        env,
        user_id,
        UpdateType::SyncCipherUpdate,
        cipher_id,
        &now,
        context_id,
    )
    .await;

    ok_empty(201)
}

// ── Attachment download ─────────────────────────────────────────────

async fn handle_attachment_download(
    env: &Env,
    cipher_id: &str,
    attachment_id: &str,
    token: &str,
) -> Result<Response, AppError> {
    let backend = get_storage_backend(env).ok_or_else(|| bad("Attachments are not enabled"))?;
    let db = db::get_db(env)?;

    let claims = verify_token::<AttachmentClaims>(env, token)?;
    if claims.cipher_id != cipher_id || claims.attachment_id != attachment_id {
        log::warn!("Attachment download token claims mismatch: expected cipher={cipher_id} att={attachment_id}");
        return Err(AppError::Unauthorized("Invalid token".into()));
    }

    let _cipher = attachments::ensure_cipher_for_user(&db, cipher_id, &claims.sub).await?;
    let attachment = attachments::fetch_attachment(&db, attachment_id).await?;
    if attachment.cipher_id != cipher_id {
        return Err(bad("Attachment does not belong to cipher"));
    }

    let storage_key = format!("{cipher_id}/{attachment_id}");
    stream_download_from_storage(env, backend, &storage_key, Some(attachment.file_size)).await
}

// ── Send upload ─────────────────────────────────────────────────────

async fn handle_send_upload(
    req: Request,
    env: &Env,
    send_id: &str,
    file_id: &str,
    token: &str,
) -> Result<Response, AppError> {
    let backend = get_storage_backend(env).ok_or_else(|| bad("File storage is not enabled"))?;
    let db = db::get_db(env)?;

    let claims = verify_token::<SendUploadClaims>(env, token)?;
    if claims.send_id != send_id || claims.file_id != file_id {
        log::warn!("Send upload token claims mismatch: expected send={send_id} file={file_id}");
        return Err(AppError::Unauthorized("Invalid token".into()));
    }
    let user_id = &claims.sub;

    let pending = SendDB::find_pending_by_id_and_user(&db, send_id, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Pending send not found or already uploaded".into()))?;

    let pending_data: serde_json::Value =
        serde_json::from_str(&pending.data).map_err(|_| bad("Invalid pending send data"))?;
    let pending_file_id = pending_data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad("Missing file ID in pending send data"))?;
    if pending_file_id != file_id {
        return Err(bad("File ID mismatch"));
    }

    let declared_size = pending_data
        .get("size")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| bad("Invalid declared file size in pending send"))?;
    if declared_size < 0 {
        return Err(bad("Invalid declared file size in pending send"));
    }

    let content_length = parse_content_length(req.headers())?;
    if content_length != declared_size {
        return Err(bad(&format!(
            "Uploaded size ({content_length}) does not match declared size ({declared_size})"
        )));
    }

    let body_stream = request_body(&req)?;
    let content_type = req.headers().get("content-type").ok().flatten();

    let storage_key = format!("sends/{send_id}/{file_id}");
    put_stream_to_storage(
        env,
        backend,
        &storage_key,
        body_stream,
        content_type.as_deref(),
        declared_size,
    )
    .await?;

    let mut pending = pending;
    pending.data = serde_json::to_string(&pending_data).map_err(|_| AppError::Internal)?;
    pending.finalize(&db).await?;
    let now = &pending.updated_at;

    db::touch_user_updated_at(&db, user_id, now).await?;

    notifications::publish_send_update(
        env,
        user_id,
        UpdateType::SyncSendCreate,
        send_id,
        now,
        Some(&claims.device),
    )
    .await;

    ok_empty(201)
}

// ── Send download ───────────────────────────────────────────────────

async fn handle_send_download(
    env: &Env,
    send_id: &str,
    file_id: &str,
    token: &str,
) -> Result<Response, AppError> {
    let backend = get_storage_backend(env).ok_or_else(|| bad("File storage is not enabled"))?;
    let db = db::get_db(env)?;

    let claims = verify_token::<SendDownloadClaims>(env, token).map_err(|e| {
        log::warn!("Send download token verification failed: {e}");
        AppError::NotFound("Not found".into())
    })?;
    if claims.send_id != send_id || claims.file_id != file_id {
        log::warn!("Send download token claims mismatch: expected send={send_id} file={file_id}");
        return Err(AppError::NotFound("Not found".into()));
    }

    let send = SendDB::find_by_id(&db, send_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Not found".into()))?;

    let storage_key = format!("sends/{send_id}/{file_id}");
    let fallback_size: Option<i64> = serde_json::from_str::<serde_json::Value>(&send.data)
        .ok()
        .and_then(|v| v.get("size").and_then(|s| s.as_i64()));

    stream_download_from_storage(env, backend, &storage_key, fallback_size).await
}

// ── Storage helpers ─────────────────────────────────────────────────

async fn put_stream_to_storage(
    env: &Env,
    backend: StorageBackend,
    key: &str,
    body: ReadableStream,
    content_type: Option<&str>,
    declared_size: i64,
) -> Result<(), AppError> {
    match backend {
        StorageBackend::R2 => {
            let bucket = env
                .bucket(ATTACHMENTS_BUCKET)
                .map_err(|_| AppError::Internal)?;
            let mut builder = bucket.put(key, body);
            if let Some(ct) = content_type {
                builder = builder.http_metadata(HttpMetadata {
                    content_type: Some(ct.to_string()),
                    ..Default::default()
                });
            }
            let r2_obj = builder.execute().await.map_err(|e| {
                log::error!("R2 upload failed for key '{key}': {e}");
                AppError::Internal
            })?;
            if let Some(ref obj) = r2_obj {
                if obj.size() != declared_size as u64 {
                    if let Err(del_err) = bucket.delete(key).await {
                        log::error!("R2 cleanup failed for key '{key}': {del_err}");
                    }
                    return Err(bad(&format!(
                        "Uploaded size ({}) does not match declared size ({declared_size})",
                        obj.size()
                    )));
                }
            }
            Ok(())
        }
        StorageBackend::KV => {
            let kv = env.kv(ATTACHMENTS_KV).map_err(|_| AppError::Internal)?;
            let meta = KvFileMetadata {
                content_type: content_type.map(|s| s.to_string()),
                file_size: declared_size,
            };
            kv.put_stream(key, body)
                .map_err(|e| {
                    log::error!("KV put_stream init failed for key '{key}': {e}");
                    AppError::Internal
                })?
                .metadata(meta)
                .map_err(|e| {
                    log::error!("KV metadata failed for key '{key}': {e}");
                    AppError::Internal
                })?
                .execute()
                .await
                .map_err(|e| {
                    log::error!("KV upload failed for key '{key}': {e}");
                    AppError::Internal
                })?;
            Ok(())
        }
    }
}

async fn stream_download_from_storage(
    env: &Env,
    backend: StorageBackend,
    key: &str,
    fallback_size: Option<i64>,
) -> Result<Response, AppError> {
    match backend {
        StorageBackend::R2 => {
            let bucket = env
                .bucket(ATTACHMENTS_BUCKET)
                .map_err(|_| AppError::Internal)?;
            let obj = bucket
                .get(key)
                .execute()
                .await
                .map_err(AppError::Worker)?
                .ok_or_else(|| AppError::NotFound("Not found in storage".into()))?;

            let ct = obj
                .http_metadata()
                .content_type
                .unwrap_or_else(|| "application/octet-stream".into());
            let size = obj.size();
            let body = obj
                .body()
                .ok_or(AppError::Internal)?
                .response_body()
                .map_err(AppError::Worker)?;

            let resp = Response::builder()
                .with_status(200)
                .with_header("content-type", &ct)?
                .with_header("content-length", &size.to_string())?
                .body(body);
            Ok(resp)
        }
        StorageBackend::KV => {
            let kv = env.kv(ATTACHMENTS_KV).map_err(|_| AppError::Internal)?;
            let (stream, metadata) = kv
                .get(key)
                .stream_with_metadata::<KvFileMetadata>()
                .await
                .map_err(|e| {
                    log::error!("KV get failed for key '{key}': {e}");
                    AppError::Internal
                })?;

            let stream = stream.ok_or_else(|| AppError::NotFound("Not found in storage".into()))?;

            let ct = metadata
                .as_ref()
                .and_then(|m| m.content_type.clone())
                .unwrap_or_else(|| "application/octet-stream".into());
            let size = metadata.as_ref().map(|m| m.file_size).or(fallback_size);

            let mut builder = Response::builder()
                .with_status(200)
                .with_header("content-type", &ct)?;
            if let Some(s) = size {
                if s >= 0 {
                    builder = builder.with_header("content-length", &s.to_string())?;
                }
            }
            let resp = builder.stream(stream);
            Ok(resp)
        }
    }
}

// ── JWT verification ────────────────────────────────────────────────

fn verify_token<T: Clone + for<'de> Deserialize<'de>>(
    env: &Env,
    token: &str,
) -> Result<T, AppError> {
    let secret = jwt_secret(env)?;
    let key = Hs256Key::new(secret.as_bytes());
    let time_opts = jwt_time_options();

    let untrusted = UntrustedToken::new(token).map_err(|e| {
        log::warn!("Malformed token: {e}");
        AppError::Unauthorized("Invalid token".into())
    })?;
    let verified = jwt_compact::alg::Hs256
        .validator::<T>(&key)
        .validate(&untrusted)
        .map_err(|e| {
            log::warn!("Token validation failed: {e}");
            AppError::Unauthorized("Invalid token".into())
        })?;

    verified
        .claims()
        .validate_expiration(&time_opts)
        .map_err(|e| {
            log::warn!("Token expired: {e}");
            AppError::Unauthorized("Invalid token".into())
        })?;

    Ok(verified.claims().custom.clone())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn request_body(req: &Request) -> Result<ReadableStream, AppError> {
    req.inner().body().ok_or_else(|| bad("Request has no body"))
}

fn parse_content_length(headers: &Headers) -> Result<i64, AppError> {
    let val = headers
        .get("content-length")
        .ok()
        .flatten()
        .ok_or_else(|| bad("Missing Content-Length header"))?;
    val.parse::<i64>()
        .map_err(|_| bad("Invalid Content-Length header"))
}

fn bad(msg: &str) -> AppError {
    AppError::BadRequest(msg.to_string())
}

fn app_error_to_response(err: &AppError) -> Response {
    let (status, msg) = match err {
        AppError::NotFound(msg) => (404u16, msg.as_str()),
        AppError::BadRequest(msg) => (400, msg.as_str()),
        AppError::Unauthorized(msg) => (401, msg.as_str()),
        AppError::TooManyRequests(msg) => (429, msg.as_str()),
        _ => (500, "Internal server error"),
    };
    Response::from_json(&serde_json::json!({ "error": msg }))
        .unwrap_or_else(|_| Response::error(msg, status).unwrap())
        .with_status(status)
}

fn ok_empty(status: u16) -> Result<Response, AppError> {
    Response::empty()
        .map(|r| r.with_status(status))
        .map_err(AppError::Worker)
}
