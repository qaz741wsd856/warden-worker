use axum::{extract::State, Json};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, D1PreparedStatement, Env};

use super::get_batch_size;
use crate::{
    auth::Claims,
    crypto::{generate_salt, hash_password_for_storage},
    db,
    error::AppError,
    models::{
        cipher::CipherData,
        user::{
            ChangePasswordRequest, DeleteAccountRequest, PreloginResponse, RegisterRequest,
            RotateKeyRequest, User,
        },
    },
};

#[worker::send]
pub async fn prelogin(
    State(env): State<Arc<Env>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;
    let db = db::get_db(&env)?;

    let stmt = db.prepare("SELECT kdf_iterations FROM users WHERE email = ?1");
    let query = stmt.bind(&[email.into()])?;
    let kdf_iterations: Option<i32> = query
        .first(Some("kdf_iterations"))
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(PreloginResponse {
        kdf: 0, // PBKDF2
        kdf_iterations: kdf_iterations.unwrap_or(600_000),
    }))
}

#[worker::send]
pub async fn register(
    State(env): State<Arc<Env>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    let allowed_emails = env
        .secret("ALLOWED_EMAILS")
        .map_err(|_| AppError::Internal)?;
    let allowed_emails = allowed_emails
        .as_ref()
        .as_string()
        .ok_or_else(|| AppError::Internal)?;
    if allowed_emails
        .split(",")
        .all(|email| email.trim() != payload.email)
    {
        return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
    }

    // Generate salt and hash the password with server-side PBKDF2
    let password_salt = generate_salt()?;
    let hashed_password =
        hash_password_for_storage(&payload.master_password_hash, &password_salt).await?;

    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        email: payload.email.to_lowercase(),
        email_verified: false,
        master_password_hash: hashed_password,
        master_password_hint: payload.master_password_hint,
        password_salt: Some(password_salt),
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        security_stamp: Uuid::new_v4().to_string(),
        totp_recover: None,
        created_at: now.clone(),
        updated_at: now,
    };

    query!(
        &db,
        "INSERT INTO users (id, name, email, master_password_hash, master_password_hint, password_salt, key, private_key, public_key, kdf_iterations, security_stamp, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
         user.id,
         user.name,
         user.email,
         user.master_password_hash,
         user.master_password_hint,
         user.password_salt,
         user.key,
         user.private_key,
         user.public_key,
         user.kdf_iterations,
         user.security_stamp,
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

#[worker::send]
pub async fn delete_account(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DeleteAccountRequest>,
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
    let new_hashed_password =
        hash_password_for_storage(&payload.new_master_password_hash, &new_salt).await?;

    // Generate new security stamp and update timestamp
    let new_security_stamp = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Update user record
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, key = ?3, master_password_hint = ?4, security_stamp = ?5, updated_at = ?6 WHERE id = ?7",
        new_hashed_password,
        new_salt,
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

    // Validate that email and kdf settings match
    let unlock_data = &payload.account_unlock_data.master_password_unlock_data;
    if user.email != unlock_data.email {
        log::error!("Email mismatch in rotation request: {:?} != {:?}", user.email, unlock_data.email);
        return Err(AppError::BadRequest(
            "Email mismatch in rotation request".to_string(),
        ));
    }

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
        log::error!("All ciphers must have an id for key rotation: {:?} != {:?}", personal_ciphers.len(), request_cipher_ids.len());
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
        log::error!("Cipher or folder count mismatch in rotation request: {:?} != {:?} or {:?} != {:?}", db_cipher_count, request_cipher_ids.len(), db_folder_count, request_folder_ids.len());
        return Err(AppError::BadRequest(
            "All existing ciphers and folders must be included in the rotation".to_string(),
        ));
    }

    // Check EXCEPT results (if count matches but IDs differ)
    let has_missing_ciphers = !validation_results[2].results::<Value>()?.is_empty();
    let has_missing_folders = !validation_results[3].results::<Value>()?.is_empty();

    if has_missing_ciphers || has_missing_folders {
        log::error!("Missing ciphers or folders in rotation request: {:?} or {:?}", has_missing_ciphers, has_missing_folders);
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
    }
    db::execute_in_batches(&db, cipher_statements, batch_size).await?;

    // Generate new salt and hash the new password
    let new_salt = generate_salt()?;
    let new_hashed_password =
        hash_password_for_storage(&unlock_data.master_key_authentication_hash, &new_salt).await?;

    // Generate new security stamp
    let new_security_stamp = Uuid::new_v4().to_string();

    // Update user record with new keys and password
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, key = ?3, private_key = ?4, security_stamp = ?5, updated_at = ?6 WHERE id = ?7",
        new_hashed_password,
        new_salt,
        unlock_data.master_key_encrypted_user_key,
        payload.account_keys.user_key_encrypted_account_private_key,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(json!({})))
}
