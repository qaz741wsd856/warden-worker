use axum::{extract::State, Json};
use serde_json::Value;
use std::sync::Arc;
use worker::{query, Env};

use crate::{
    auth::AuthUser,
    crypto::{base32_decode, ct_eq, generate_recovery_code, generate_totp_secret, validate_totp},
    db,
    error::AppError,
    models::twofactor::{
        DisableTwoFactorData, EnableAuthenticatorData, PasswordOrOtpData, RecoverTwoFactor,
        TwoFactor, TwoFactorType,
    },
    models::user::User,
};

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub async fn get_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let twofactors: Vec<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
        .bind(&[user_id.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<TwoFactor>()
        .map_err(|_| AppError::Database)?
        .iter()
        .map(|tf| tf.to_json_provider())
        .collect();

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
        .bind(&[user_id.clone().into(), (TwoFactorType::Authenticator as i32).into()])?
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

    // Validate TOTP code and capture time step for replay protection
    let last_used_step = validate_totp(&data.token, &key, 0, true).await?;

    // Delete existing TOTP if any
    query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        TwoFactorType::Authenticator as i32
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

    // Check if any 2FA methods remain
    let remaining: Vec<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
        .bind(&[user_id.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    // If no 2FA methods remain, clear recovery code
    if remaining.is_empty() {
        query!(&db, "UPDATE users SET totp_recover = NULL WHERE id = ?1", &user_id)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    }

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": type_,
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
    let verification = user.verify_master_password(&data.master_password_hash).await?;
    if !verification.is_valid() {
        return Err(AppError::Unauthorized(
            "Username or password is incorrect".to_string(),
        ));
    }

    // Check recovery code
    if let Some(ref stored_code) = user.totp_recover {
        if !ct_eq(stored_code, &data.recovery_code) {
            return Err(AppError::BadRequest(
                "Recovery code is incorrect".to_string(),
            ));
        }
    } else {
        return Err(AppError::BadRequest(
            "Recovery code is incorrect".to_string(),
        ));
    }

    // Delete all 2FA methods
    query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1",
        &user.id
    )
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

