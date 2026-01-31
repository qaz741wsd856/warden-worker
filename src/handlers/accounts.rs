use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use glob_match::glob_match;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, D1PreparedStatement, Env};

use super::{get_batch_size, server_password_iterations, two_factor_enabled};
use crate::{
    auth::Claims,
    crypto::{generate_salt, hash_password_for_storage},
    db,
    error::AppError,
    handlers::attachments,
    models::{
        cipher::CipherData,
        sync::Profile,
        user::{
            AvatarData, ChangeKdfRequest, ChangePasswordRequest, MasterPasswordUnlockData,
            PasswordHintRequest, PasswordOrOtpData, PreloginResponse, ProfileData, RegisterRequest,
            RotateKeyRequest, User,
        },
    },
};

const KDF_TYPE_PBKDF2: i32 = 0;
const KDF_TYPE_ARGON2ID: i32 = 1;
const MIN_PBKDF2_ITERATIONS: i32 = 100_000;
const DEFAULT_PBKDF2_ITERATIONS: i32 = 600_000;

fn ensure_supported_kdf(
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> Result<(), AppError> {
    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            if iterations < MIN_PBKDF2_ITERATIONS {
                return Err(AppError::BadRequest(format!(
                    "PBKDF2 iterations must be at least {}",
                    MIN_PBKDF2_ITERATIONS
                )));
            }
        }
        KDF_TYPE_ARGON2ID => {
            if iterations < 1 {
                return Err(AppError::BadRequest(
                    "Argon2 KDF iterations must be at least 1".to_string(),
                ));
            }
            match memory {
                Some(m) if (15..=1024).contains(&m) => {}
                Some(_) => {
                    return Err(AppError::BadRequest(
                        "Argon2 memory must be between 15 MB and 1024 MB".to_string(),
                    ));
                }
                None => {
                    return Err(AppError::BadRequest(
                        "Argon2 memory parameter is required".to_string(),
                    ));
                }
            }
            match parallelism {
                Some(p) if (1..=16).contains(&p) => {}
                Some(_) => {
                    return Err(AppError::BadRequest(
                        "Argon2 parallelism must be between 1 and 16".to_string(),
                    ));
                }
                None => {
                    return Err(AppError::BadRequest(
                        "Argon2 parallelism parameter is required".to_string(),
                    ));
                }
            }
        }
        _ => {
            return Err(AppError::BadRequest(
                "Unsupported KDF type. Only PBKDF2 (0) and Argon2id (1) are supported".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_rotation_metadata(
    user: &User,
    unlock_data: &MasterPasswordUnlockData,
    account_public_key: &str,
) -> Result<(), AppError> {
    let kdf_matches = user.kdf_type == unlock_data.kdf_type
        && user.kdf_iterations == unlock_data.kdf_iterations
        && user.kdf_memory == unlock_data.kdf_memory
        && user.kdf_parallelism == unlock_data.kdf_parallelism;

    if user.email != unlock_data.email || !kdf_matches {
        log::error!(
            "KDF/email mismatch in rotation request: email_equal={}, kdf_equal={}",
            user.email == unlock_data.email,
            kdf_matches
        );
        return Err(AppError::BadRequest(
            "Changing the kdf variant or email is not supported during key rotation".to_string(),
        ));
    }

    if user.public_key != account_public_key {
        log::error!("Public key mismatch in rotation request: stored != provided");
        return Err(AppError::BadRequest(
            "Changing the asymmetric keypair is not supported during key rotation".to_string(),
        ));
    }

    Ok(())
}

#[worker::send]
pub async fn prelogin(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;

    // Check rate limit using IP address as key to prevent email enumeration attacks
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        let ip = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        let rate_limit_key = format!("prelogin:{}", ip);
        if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests(
                    "Too many requests. Please try again later.".to_string(),
                ));
            }
        }
    }

    let db = db::get_db(&env)?;

    let stmt = db.prepare(
        "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE email = ?1",
    );
    let query = stmt.bind(&[email.into()])?;
    let row: Option<Value> = query.first(None).await.map_err(|_| AppError::Database)?;

    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) = if let Some(row) = row {
        let kdf_type = row
            .get("kdf_type")
            .and_then(|value| value.as_i64())
            .map(|value| value as i32);
        let kdf_iterations = row
            .get("kdf_iterations")
            .and_then(|value| value.as_i64())
            .map(|value| value as i32);
        let kdf_memory = row
            .get("kdf_memory")
            .and_then(|value| value.as_i64())
            .map(|value| value as i32);
        let kdf_parallelism = row
            .get("kdf_parallelism")
            .and_then(|value| value.as_i64())
            .map(|value| value as i32);
        (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
    } else {
        (None, None, None, None)
    };

    Ok(Json(PreloginResponse {
        kdf: kdf_type.unwrap_or(KDF_TYPE_PBKDF2),
        kdf_iterations: kdf_iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS),
        kdf_memory,
        kdf_parallelism,
    }))
}

#[worker::send]
pub async fn register(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    // Check rate limit using IP address as key to prevent mass registration and email enumeration
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        let ip = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        let rate_limit_key = format!("register:{}", ip);
        if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests(
                    "Too many requests. Please try again later.".to_string(),
                ));
            }
        }
    }

    let allowed_emails = env
        .secret("ALLOWED_EMAILS")
        .map_err(|_| AppError::Internal)?;
    let allowed_emails = allowed_emails
        .as_ref()
        .as_string()
        .ok_or_else(|| AppError::Internal)?;
    if !allowed_emails
        .split(',')
        .any(|pattern| glob_match(pattern.trim(), &payload.email))
    {
        return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
    }

    ensure_supported_kdf(
        payload.kdf,
        payload.kdf_iterations,
        payload.kdf_memory,
        payload.kdf_parallelism,
    )?;

    // Generate salt and hash the password with server-side PBKDF2
    let password_salt = generate_salt()?;
    let password_iterations = server_password_iterations(&env) as i32;
    let hashed_password = hash_password_for_storage(
        &payload.master_password_hash,
        &password_salt,
        password_iterations as u32,
    )
    .await?;

    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    // Only store kdf_memory and kdf_parallelism for Argon2id, clear for PBKDF2
    let (kdf_memory, kdf_parallelism) = if payload.kdf == KDF_TYPE_ARGON2ID {
        (payload.kdf_memory, payload.kdf_parallelism)
    } else {
        (None, None)
    };

    let user = User {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        avatar_color: None,
        email: payload.email.to_lowercase(),
        email_verified: false,
        master_password_hash: hashed_password,
        master_password_hint: payload.master_password_hint,
        password_salt: Some(password_salt),
        password_iterations,
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        security_stamp: Uuid::new_v4().to_string(),
        equivalent_domains: "[]".to_string(),
        excluded_globals: "[]".to_string(),
        totp_recover: None,
        created_at: now.clone(),
        updated_at: now,
    };

    query!(
        &db,
        "INSERT INTO users (id, name, email, master_password_hash, master_password_hint, password_salt, password_iterations, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, equivalent_domains, excluded_globals, totp_recover, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
         user.id,
         user.name,
         user.email,
         user.master_password_hash,
         user.master_password_hint,
         user.password_salt,
         user.password_iterations,
         user.key,
         user.private_key,
         user.public_key,
         user.kdf_type,
         user.kdf_iterations,
         user.kdf_memory,
         user.kdf_parallelism,
         user.security_stamp,
         user.equivalent_domains,
         user.excluded_globals,
         user.totp_recover,
         user.created_at,
         user.updated_at
    ).map_err(|_|{
        AppError::Database
    })?
    .run()
    .await
    .map_err(|_|{
        AppError::Database
    })?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn send_verification_email() -> Result<Json<String>, AppError> {
    Ok(Json("fixed-token-to-mock".to_string()))
}

/// POST /api/accounts/password-hint
///
/// Bitwarden normally sends the master password hint via email. This project does not implement
/// email delivery, so we return the hint directly.
#[worker::send]
pub async fn password_hint(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<PasswordHintRequest>,
) -> Result<Json<Value>, AppError> {
    // Basic rate limit by IP to slow down bulk email enumeration attempts.
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        let ip = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        let rate_limit_key = format!("password-hint:{}", ip);
        if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests(
                    "Too many requests. Please try again later.".to_string(),
                ));
            }
        }
    }

    const NO_HINT: &str = "Sorry, you have no password hint...";

    let db = db::get_db(&env)?;
    let email = payload.email.to_lowercase();

    let hint: Option<String> = db
        .prepare("SELECT master_password_hint FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first(Some("master_password_hint"))
        .await
        .map_err(|_| AppError::Database)?;

    let hint = hint.and_then(|h| {
        let trimmed = h.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });

    if let Some(hint) = hint {
        return Err(AppError::BadRequest(format!(
            "Your password hint is: {hint}"
        )));
    }

    Err(AppError::BadRequest(NO_HINT.to_string()))
}

#[worker::send]
pub async fn revision_date(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<i64>, AppError> {
    let db = db::get_db(&env)?;

    // get the user's updated_at timestamp
    let updated_at: Option<String> = db
        .prepare("SELECT updated_at FROM users WHERE id = ?1")
        .bind(&[claims.sub.into()])?
        .first(Some("updated_at"))
        .await
        .map_err(|_| AppError::Database)?;

    // convert the timestamp to a millisecond-level Unix timestamp
    let revision_date = updated_at
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts).ok())
        .map(|dt| dt.timestamp_millis())
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    Ok(Json(revision_date))
}

/// GET /api/accounts/tasks
///
/// Vaultwarden returns an empty list here; some official clients call this endpoint.
/// We don't implement task workflows, so always return an empty list.
#[worker::send]
pub async fn get_tasks() -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "data": [],
        "object": "list"
    })))
}

/// GET /api/auth-requests
///
/// Bitwarden clients may call this to fetch pending "login with device" auth requests.
/// This minimal implementation doesn't support device auth requests, so we always return an empty list.
///
/// Vaultwarden currently aliases this endpoint to `/api/auth-requests/pending`.
#[worker::send]
pub async fn get_auth_requests(claims: Claims) -> Result<Json<Value>, AppError> {
    get_auth_requests_pending(claims).await
}

/// GET /api/auth-requests/pending
///
/// Stub: always returns an empty list.
#[worker::send]
pub async fn get_auth_requests_pending(_claims: Claims) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "data": [],
        "continuationToken": null,
        "object": "list"
    })))
}

#[worker::send]
pub async fn get_profile(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Profile>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = claims.sub;

    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let two_factor_enabled = two_factor_enabled(&db, &user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled)?;

    Ok(Json(profile))
}

#[worker::send]
pub async fn post_profile(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ProfileData>,
) -> Result<Json<Profile>, AppError> {
    if payload.name.len() > 50 {
        return Err(AppError::BadRequest(
            "The field Name must be a string with a maximum length of 50.".to_string(),
        ));
    }

    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let mut user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;
    let now = Utc::now().to_rfc3339();

    user.name = Some(payload.name);
    user.updated_at = now.clone();

    query!(
        &db,
        "UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3",
        user.name,
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let two_factor_enabled = two_factor_enabled(&db, user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled)?;

    Ok(Json(profile))
}

#[worker::send]
pub async fn put_profile(
    claims: Claims,
    state: State<Arc<Env>>,
    json: Json<ProfileData>,
) -> Result<Json<Profile>, AppError> {
    post_profile(claims, state, json).await
}

#[worker::send]
pub async fn put_avatar(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<AvatarData>,
) -> Result<Json<Profile>, AppError> {
    if let Some(color) = &payload.avatar_color {
        if color.len() != 7 {
            return Err(AppError::BadRequest(
                "The field AvatarColor must be a HTML/Hex color code with a length of 7 characters"
                    .to_string(),
            ));
        }
    }

    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let mut user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;
    let now = Utc::now().to_rfc3339();

    user.avatar_color = payload.avatar_color;
    user.updated_at = now.clone();

    query!(
        &db,
        "UPDATE users SET avatar_color = ?1, updated_at = ?2 WHERE id = ?3",
        user.avatar_color,
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let two_factor_enabled = two_factor_enabled(&db, user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled)?;

    Ok(Json(profile))
}

#[worker::send]
pub async fn delete_account(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
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

    // Verify the master password hash
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

    // Delete all user's ciphers
    query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Delete all user's folders
    query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Delete the user
    query!(&db, "DELETE FROM users WHERE id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    Ok(Json(json!({})))
}

/// POST /accounts/password - Change master password
#[worker::send]
pub async fn post_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, AppError> {
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

    // Verify the current master password
    let verification = user
        .verify_master_password(&payload.master_password_hash)
        .await?;

    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    // Generate new salt and hash the new password
    let new_salt = generate_salt()?;
    let password_iterations = server_password_iterations(&env) as i32;
    let new_hashed_password = hash_password_for_storage(
        &payload.new_master_password_hash,
        &new_salt,
        password_iterations as u32,
    )
    .await?;

    // Generate new security stamp and update timestamp
    let new_security_stamp = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Update user record
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3, key = ?4, master_password_hint = ?5, security_stamp = ?6, updated_at = ?7 WHERE id = ?8",
        new_hashed_password,
        new_salt,
        password_iterations,
        payload.key,
        payload.master_password_hint,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}

/// POST /accounts/key-management/rotate-user-account-keys - Rotate user encryption keys
#[worker::send]
pub async fn post_rotatekey(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<RotateKeyRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;
    let batch_size = get_batch_size(&env);

    // Get the user from the database
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    // Verify the current master password
    let verification = user
        .verify_master_password(&payload.old_master_key_authentication_hash)
        .await?;

    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    let unlock_data = &payload.account_unlock_data.master_password_unlock_data;

    validate_rotation_metadata(&user, unlock_data, &payload.account_keys.account_public_key)?;

    // Validate KDF parameters
    ensure_supported_kdf(
        unlock_data.kdf_type,
        unlock_data.kdf_iterations,
        unlock_data.kdf_memory,
        unlock_data.kdf_parallelism,
    )?;

    // Validate data integrity using D1 batch operations
    // Step 1: Ensure all personal ciphers have id (required for key rotation)
    // Step 2: Count check - ensure request has exactly the same number of items as DB
    // Step 3: EXCEPT check - ensure request has exactly the same IDs as DB
    let personal_ciphers: Vec<_> = payload
        .account_data
        .ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .collect();

    let request_cipher_ids: Vec<String> = personal_ciphers
        .iter()
        .filter_map(|c| c.id.clone())
        .collect();

    // All personal ciphers must have an id for key rotation
    if personal_ciphers.len() != request_cipher_ids.len() {
        log::error!(
            "All ciphers must have an id for key rotation: {:?} != {:?}",
            personal_ciphers.len(),
            request_cipher_ids.len()
        );
        return Err(AppError::BadRequest(
            "All ciphers must have an id for key rotation".to_string(),
        ));
    }

    // Filter out null folder IDs (Bitwarden client bug: https://github.com/bitwarden/clients/issues/8453)
    let request_folder_ids: Vec<String> = payload
        .account_data
        .folders
        .iter()
        .filter_map(|f| f.id.clone())
        .collect();

    let cipher_ids_json =
        serde_json::to_string(&request_cipher_ids).map_err(|_| AppError::Internal)?;
    let folder_ids_json =
        serde_json::to_string(&request_folder_ids).map_err(|_| AppError::Internal)?;

    // Batch: 2 COUNT queries + 2 EXCEPT queries
    let validation_results = db
        .batch(vec![
            // Count ciphers in DB
            db.prepare(
                "SELECT COUNT(*) AS cnt FROM ciphers WHERE user_id = ?1 AND organization_id IS NULL",
            )
            .bind(&[user_id.clone().into()])?,
            // Count folders in DB
            db.prepare("SELECT COUNT(*) AS cnt FROM folders WHERE user_id = ?1")
                .bind(&[user_id.clone().into()])?,
            // DB cipher IDs EXCEPT request cipher IDs (finds missing)
            db.prepare(
                "SELECT id FROM ciphers WHERE user_id = ?1 AND organization_id IS NULL
                 EXCEPT
                 SELECT value FROM json_each(?2) LIMIT 1",
            )
            .bind(&[user_id.clone().into(), cipher_ids_json.into()])?,
            // DB folder IDs EXCEPT request folder IDs (finds missing)
            db.prepare(
                "SELECT id FROM folders WHERE user_id = ?1
                 EXCEPT
                 SELECT value FROM json_each(?2) LIMIT 1",
            )
            .bind(&[user_id.clone().into(), folder_ids_json.into()])?,
        ])
        .await?;

    // Check counts match
    let db_cipher_count = validation_results[0]
        .results::<Value>()?
        .first()
        .and_then(|v| v.get("cnt")?.as_i64())
        .unwrap_or(0) as usize;
    let db_folder_count = validation_results[1]
        .results::<Value>()?
        .first()
        .and_then(|v| v.get("cnt")?.as_i64())
        .unwrap_or(0) as usize;

    if db_cipher_count != request_cipher_ids.len() || db_folder_count != request_folder_ids.len() {
        log::error!(
            "Cipher or folder count mismatch in rotation request: {:?} != {:?} or {:?} != {:?}",
            db_cipher_count,
            request_cipher_ids.len(),
            db_folder_count,
            request_folder_ids.len()
        );
        return Err(AppError::BadRequest(
            "All existing ciphers and folders must be included in the rotation".to_string(),
        ));
    }

    // Check EXCEPT results (if count matches but IDs differ)
    let has_missing_ciphers = !validation_results[2].results::<Value>()?.is_empty();
    let has_missing_folders = !validation_results[3].results::<Value>()?.is_empty();

    if has_missing_ciphers || has_missing_folders {
        log::error!(
            "Missing ciphers or folders in rotation request: {:?} or {:?}",
            has_missing_ciphers,
            has_missing_folders
        );
        return Err(AppError::BadRequest(
            "All existing ciphers and folders must be included in the rotation".to_string(),
        ));
    }

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Update all folders with new encrypted names (batch operation)
    // Skip null folder IDs (Bitwarden client bug: https://github.com/bitwarden/clients/issues/8453)
    let mut folder_statements: Vec<D1PreparedStatement> =
        Vec::with_capacity(payload.account_data.folders.len());
    for folder in &payload.account_data.folders {
        // Skip null folder id entries
        let Some(folder_id) = &folder.id else {
            continue;
        };
        let stmt = query!(
            &db,
            "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
            folder.name,
            now,
            folder_id,
            user_id
        )
        .map_err(|_| AppError::Database)?;
        folder_statements.push(stmt);
    }
    db::execute_in_batches(&db, folder_statements, batch_size).await?;

    // Update all ciphers with new encrypted data (batch operation)
    // Only update personal ciphers (organization_id is None)
    let mut cipher_statements: Vec<D1PreparedStatement> =
        Vec::with_capacity(personal_ciphers.len());
    let mut attachment_statements: Vec<D1PreparedStatement> = Vec::new();
    for cipher in personal_ciphers {
        // id is guaranteed to exist (validated above)
        let cipher_id = cipher.id.as_ref().unwrap();

        let cipher_data = CipherData {
            name: cipher.name.clone(),
            notes: cipher.notes.clone(),
            type_fields: cipher.type_fields.clone(),
        };

        let data = serde_json::to_string(&cipher_data).map_err(|_| AppError::Internal)?;

        let stmt = query!(
            &db,
            "UPDATE ciphers SET data = ?1, folder_id = ?2, favorite = ?3, updated_at = ?4 WHERE id = ?5 AND user_id = ?6",
            data,
            cipher.folder_id,
            cipher.favorite.unwrap_or(false),
            now,
            cipher_id,
            user_id
        )
        .map_err(|_| AppError::Database)?;
        cipher_statements.push(stmt);

        // Update attachments key and encrypted filename when rotating.
        // The Bitwarden clients send `attachments2` only during key rotation.
        if let Some(attachments2) = &cipher.attachments2 {
            for (attachment_id, attachment) in attachments2 {
                let stmt = query!(
                    &db,
                    "UPDATE attachments SET file_name = ?1, akey = ?2, updated_at = ?3 WHERE id = ?4 AND cipher_id = ?5",
                    attachment.file_name,
                    attachment.key,
                    now,
                    attachment_id,
                    cipher_id
                )
                .map_err(|_| AppError::Database)?;
                attachment_statements.push(stmt);
            }
        }
    }
    db::execute_in_batches(&db, cipher_statements, batch_size).await?;
    db::execute_in_batches(&db, attachment_statements, batch_size).await?;

    // Generate new salt and hash the new password
    let new_salt = generate_salt()?;
    let password_iterations = server_password_iterations(&env) as i32;
    let new_hashed_password = hash_password_for_storage(
        &unlock_data.master_key_authentication_hash,
        &new_salt,
        password_iterations as u32,
    )
    .await?;

    // Generate new security stamp
    let new_security_stamp = Uuid::new_v4().to_string();

    // Only store kdf_memory and kdf_parallelism for Argon2id, clear for PBKDF2
    let (kdf_memory, kdf_parallelism) = if unlock_data.kdf_type == KDF_TYPE_ARGON2ID {
        (unlock_data.kdf_memory, unlock_data.kdf_parallelism)
    } else {
        (None, None)
    };

    // Update user record with new keys and password
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3, key = ?4, private_key = ?5, kdf_type = ?6, kdf_iterations = ?7, kdf_memory = ?8, kdf_parallelism = ?9, security_stamp = ?10, updated_at = ?11 WHERE id = ?12",
        new_hashed_password,
        new_salt,
        password_iterations,
        unlock_data.master_key_encrypted_user_key,
        payload.account_keys.user_key_encrypted_account_private_key,
        unlock_data.kdf_type,
        unlock_data.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}

/// POST /accounts/kdf - Change KDF settings (PBKDF2 <-> Argon2id)
///
/// API Format History:
/// - Bitwarden switched to complex format in v2025.10.0
/// - Vaultwarden followed in PR #6458, WITHOUT backward compatibility
/// - We implement backward compatibility to support both formats
///
/// Supports two request formats:
///
/// 1. Simple/Legacy format (Bitwarden < v2025.10.0, e.g. web vault 2025.07):
/// { "kdf": 0, "kdfIterations": 650000, "key": "...", "masterPasswordHash": "...", "newMasterPasswordHash": "..." }
///
/// 2. Complex format (Bitwarden >= v2025.10.0, e.g. official client 2025.11.x):
/// { "authenticationData": {...}, "unlockData": {...}, "key": "...", "masterPasswordHash": "...", "newMasterPasswordHash": "..." }
#[worker::send]
pub async fn post_kdf(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeKdfRequest>,
) -> Result<Json<Value>, AppError> {
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

    // Verify the current master password
    let verification = user
        .verify_master_password(&payload.master_password_hash)
        .await?;

    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    // Additional validation for complex format
    if let (Some(ref auth_data), Some(ref unlock_data)) =
        (&payload.authentication_data, &payload.unlock_data)
    {
        // KDF settings must match between authentication and unlock
        if auth_data.kdf != unlock_data.kdf {
            return Err(AppError::BadRequest(
                "KDF settings must be equal for authentication and unlock".to_string(),
            ));
        }
        // Salt (email) must match
        if user.email != auth_data.salt || user.email != unlock_data.salt {
            return Err(AppError::BadRequest(
                "Invalid master password salt".to_string(),
            ));
        }
    }

    // Extract KDF parameters from either format
    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) = payload
        .get_kdf_params()
        .ok_or_else(|| AppError::BadRequest("Missing KDF parameters".to_string()))?;

    // Validate new KDF parameters
    ensure_supported_kdf(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)?;

    // Generate new salt and hash the new password
    let new_salt = generate_salt()?;
    let password_iterations = server_password_iterations(&env) as i32;
    let new_hashed_password = hash_password_for_storage(
        payload.get_new_password_hash(),
        &new_salt,
        password_iterations as u32,
    )
    .await?;

    // Generate new security stamp
    let new_security_stamp = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Determine kdf_memory and kdf_parallelism based on KDF type
    let (final_kdf_memory, final_kdf_parallelism) = if kdf_type == KDF_TYPE_ARGON2ID {
        (kdf_memory, kdf_parallelism)
    } else {
        // For PBKDF2, clear these fields
        (None, None)
    };

    // Get the new encrypted user key
    let new_key = payload.get_new_key();

    // Update user record with new KDF settings and password
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3, key = ?4, kdf_type = ?5, kdf_iterations = ?6, kdf_memory = ?7, kdf_parallelism = ?8, security_stamp = ?9, updated_at = ?10 WHERE id = ?11",
        new_hashed_password,
        new_salt,
        password_iterations,
        new_key,
        kdf_type,
        kdf_iterations,
        final_kdf_memory,
        final_kdf_parallelism,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}
