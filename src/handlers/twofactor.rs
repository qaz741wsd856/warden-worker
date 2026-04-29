use axum::{extract::State, Json};
use serde_json::Value;
use std::sync::Arc;
use worker::{query, Env};

use crate::{
    auth::AuthUser,
    crypto::{base32_decode, ct_eq, generate_recovery_code, generate_totp_secret, validate_totp},
    db,
    error::AppError,
    handlers::allow_totp_drift,
    models::twofactor::{
        DisableAuthenticatorData, DisableTwoFactorData, EnableAuthenticatorData, RecoverTwoFactor,
        TwoFactor, TwoFactorType,
    },
    models::user::{PasswordOrOtpData, User},
};

/// List all 2FA records for a user (excludes atype >= 1000).
pub(crate) async fn list_user_twofactors(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<Vec<TwoFactor>, AppError> {
    db.prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
        .bind(&[user_id.to_string().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<TwoFactor>()
        .map_err(|_| AppError::Database)
}

/// Whether the user has 2FA enabled.
///
/// For now, we intentionally only treat Authenticator (TOTP) as a real 2FA provider.
/// Remember-device tokens are never considered a 2FA method by themselves.
pub(crate) fn is_twofactor_enabled(twofactors: &[TwoFactor]) -> bool {
    twofactors
        .iter()
        .any(|tf| tf.enabled && tf.atype == TwoFactorType::Authenticator as i32)
}

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub async fn get_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let twofactors = list_user_twofactors(&db, &user_id).await?;
    let twofactors: Vec<Value> = twofactors.iter().map(|tf| tf.to_json_provider()).collect();

    Ok(Json(serde_json::json!({
        "data": twofactors,
        "object": "list",
        "continuationToken": null,
    })))
}

/// POST /api/two-factor/get-authenticator - Get or generate TOTP secret
#[worker::send]
pub async fn get_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&user, &data).await?;

    // Check if TOTP is already configured
    let existing: Option<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let (enabled, key) = match existing {
        Some(tf_value) => {
            let tf: TwoFactor = serde_json::from_value(tf_value).map_err(|_| AppError::Internal)?;
            (true, tf.data)
        }
        None => (false, generate_totp_secret()?),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub async fn activate_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let key = data.key.to_uppercase();

    // Validate key format (Base32, 20 bytes = 32 characters without padding)
    let decoded_key = base32_decode(&key)?;
    if decoded_key.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    // Check if TOTP is already configured - reuse existing record for replay protection
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    // Get last_used from existing record to prevent replay during reconfiguration
    let previous_last_used = existing.as_ref().map(|tf| tf.last_used).unwrap_or(0);

    // Validate TOTP code and capture time step for replay protection
    let allow_drift = allow_totp_drift(&env);
    let last_used_step = validate_totp(&data.token, &key, previous_last_used, allow_drift).await?;

    // Delete existing TOTP and any remember-device tokens bound to it to avoid stale bypass
    query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype IN (?2, ?3)",
        &user_id,
        TwoFactorType::Authenticator as i32,
        TwoFactorType::Remember as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Create new TOTP entry
    let mut twofactor = TwoFactor::new(user_id.clone(), TwoFactorType::Authenticator, key.clone());
    twofactor.last_used = last_used_step;

    query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Generate recovery code if not exists
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// PUT /api/two-factor/authenticator - Same as POST
#[worker::send]
pub async fn activate_authenticator_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    activate_authenticator(state, auth_user, json).await
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub async fn disable_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let type_ = data.r#type;

    // Delete the specified 2FA type
    query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        type_
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    log::info!("User {} disabled 2FA type {}", user_id, type_);

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[worker::send]
pub async fn disable_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    if data.r#type != TwoFactorType::Authenticator as i32 {
        return Err(AppError::BadRequest("Invalid two factor type".to_string()));
    }

    // Verify master password (OTP not supported in this minimal implementation)
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    // Fetch existing TOTP and verify key matches before deleting
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.clone().into(), data.r#type.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    let Some(tf) = existing else {
        return Err(AppError::BadRequest("TOTP not configured".to_string()));
    };

    // Compare keys case-insensitively (key is stored uppercased during activation)
    if !ct_eq(&tf.data, &data.key.to_uppercase()) {
        return Err(AppError::BadRequest(
            "TOTP key does not match recorded value".to_string(),
        ));
    }

    query!(&db, "DELETE FROM twofactor WHERE uuid = ?1", &tf.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    log::info!(
        "User {} disabled authenticator (2FA type {})",
        user_id,
        data.r#type
    );

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": data.r#type,
        "object": "twoFactorProvider"
    })))
}

/// PUT /api/two-factor/disable - Same as POST
#[worker::send]
pub async fn disable_twofactor_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(state, auth_user, json).await
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub async fn get_recover(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&user, &data).await?;

    Ok(Json(serde_json::json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover"
    })))
}

/// POST /api/two-factor/recover - Use recovery code to disable all 2FA
#[worker::send]
pub async fn recover(
    State(env): State<Arc<Env>>,
    Json(data): Json<RecoverTwoFactor>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Get user by email
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE email = ?1")
        .bind(&[data.email.to_lowercase().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("Username or password is incorrect".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    // Verify master password
    let verification = user
        .verify_master_password(&data.master_password_hash)
        .await?;
    if !verification.is_valid() {
        return Err(AppError::Unauthorized(
            "Username or password is incorrect".to_string(),
        ));
    }

    // Check recovery code (case-insensitive)
    let is_valid = user.totp_recover.as_ref().is_some_and(|stored_code| {
        ct_eq(
            &stored_code.to_uppercase(),
            &data.recovery_code.to_uppercase(),
        )
    });

    if !is_valid {
        return Err(AppError::BadRequest(
            "Recovery code is incorrect. Try again.".to_string(),
        ));
    }

    // Delete all 2FA methods
    query!(&db, "DELETE FROM twofactor WHERE user_uuid = ?1", &user.id)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    // Clear recovery code
    query!(
        &db,
        "UPDATE users SET totp_recover = NULL WHERE id = ?1",
        &user.id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    log::info!("User {} recovered 2FA using recovery code", user.id);

    Ok(Json(serde_json::json!({})))
}

// Helper functions

async fn validate_password_or_otp(user: &User, data: &PasswordOrOtpData) -> Result<(), AppError> {
    if let Some(ref password_hash) = data.master_password_hash {
        let verification = user.verify_master_password(password_hash).await?;
        if verification.is_valid() {
            return Ok(());
        }
    }

    // OTP validation would be handled here if we had protected actions support
    // For now, master password is required

    Err(AppError::Unauthorized("Invalid password".to_string()))
}

async fn generate_recovery_code_for_user(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    // Check if recovery code already exists
    let user_value: Value = db
        .prepare("SELECT totp_recover FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let totp_recover: Option<String> = user_value
        .get("totp_recover")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if totp_recover.is_none() {
        let recovery_code = generate_recovery_code()?;
        query!(
            db,
            "UPDATE users SET totp_recover = ?1 WHERE id = ?2",
            &recovery_code,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

/// Clear recovery code when no real 2FA providers remain.
async fn clear_recovery_if_no_twofactor(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    let remaining: Vec<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000 AND atype != ?2")
        .bind(&[
            user_id.to_string().into(),
            (TwoFactorType::Remember as i32).into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    if remaining.is_empty() {
        query!(
            db,
            "UPDATE users SET totp_recover = NULL WHERE id = ?1",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}
