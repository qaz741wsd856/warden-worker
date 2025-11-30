use axum::{extract::State, Form, Json};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use worker::{query, Env};

use crate::{
    auth::Claims,
    crypto::{ct_eq, generate_salt, hash_password_for_storage, validate_totp},
    db,
    error::AppError,
    models::twofactor::{TwoFactor, TwoFactorType},
    models::user::User,
};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
    // 2FA fields
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<i32>,
    #[serde(rename = "twoFactorRemember")]
    two_factor_remember: Option<i32>,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "expires_in")]
    expires_in: i64,
    #[serde(rename = "token_type")]
    token_type: String,
    #[serde(rename = "refresh_token")]
    refresh_token: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "Kdf")]
    kdf: i32,
    #[serde(rename = "ResetMasterPassword")]
    reset_master_password: bool,
    #[serde(rename = "ForcePasswordReset")]
    force_password_reset: bool,
    #[serde(rename = "UserDecryptionOptions")]
    user_decryption_options: UserDecryptionOptions,
    #[serde(rename = "TwoFactorToken", skip_serializing_if = "Option::is_none")]
    two_factor_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserDecryptionOptions {
    pub has_master_password: bool,
    pub object: String,
}

fn generate_tokens_and_response(
    user: User,
    env: &Arc<Env>,
    two_factor_token: Option<String>,
) -> Result<Json<TokenResponse>, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let exp = (now + expires_in).timestamp() as usize;

    let access_claims = Claims {
        sub: user.id.clone(),
        exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.clone().unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
    };

    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )?;

    let refresh_expires_in = Duration::days(30);
    let refresh_exp = (now + refresh_expires_in).timestamp() as usize;
    let refresh_claims = Claims {
        sub: user.id.clone(),
        exp: refresh_exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
    };
    let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(jwt_refresh_secret.as_ref()),
    )?;

    Ok(Json(TokenResponse {
        access_token,
        expires_in: expires_in.num_seconds(),
        token_type: "Bearer".to_string(),
        refresh_token,
        key: user.key,
        private_key: user.private_key,
        kdf: user.kdf_type,
        force_password_reset: false,
        reset_master_password: false,
        user_decryption_options: UserDecryptionOptions {
            has_master_password: true,
            object: "userDecryptionOptions".to_string(),
        },
        two_factor_token,
    }))
}

#[worker::send]
pub async fn token(
    State(env): State<Arc<Env>>,
    Form(payload): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let db = db::get_db(&env)?;
    match payload.grant_type.as_str() {
        "password" => {
            let username = payload
                .username
                .ok_or_else(|| AppError::BadRequest("Missing username".to_string()))?;
            let password_hash = payload
                .password
                .ok_or_else(|| AppError::BadRequest("Missing password".to_string()))?;

            let user_value: Value = db
                .prepare("SELECT * FROM users WHERE email = ?1")
                .bind(&[username.to_lowercase().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
            let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

            let verification = user.verify_master_password(&password_hash).await?;

            if !verification.is_valid() {
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            // Check for 2FA
            let twofactors: Vec<TwoFactor> = db
                .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
                .bind(&[user.id.clone().into()])?
                .all()
                .await
                .map_err(|_| AppError::Database)?
                .results()
                .unwrap_or_default();

            let mut two_factor_remember_token: Option<String> = None;

            if !twofactors.is_empty() {
                // 2FA is enabled, need to verify
                let twofactor_ids: Vec<i32> = twofactors.iter().map(|tf| tf.atype).collect();
                let selected_id = payload.two_factor_provider.unwrap_or(twofactor_ids[0]);

                let twofactor_code = match &payload.two_factor_token {
                    Some(code) => code,
                    None => {
                        // Return 2FA required error
                        return Err(AppError::TwoFactorRequired(json_err_twofactor(&twofactor_ids)));
                    }
                };

                // Find the selected twofactor
                let selected_twofactor = twofactors
                    .iter()
                    .find(|tf| tf.atype == selected_id && tf.enabled);

                match TwoFactorType::from_i32(selected_id) {
                    Some(TwoFactorType::Authenticator) => {
                        let tf = selected_twofactor.ok_or_else(|| {
                            AppError::BadRequest("TOTP not configured".to_string())
                        })?;
                        
                        // Validate TOTP code
                        let new_last_used = validate_totp(twofactor_code, &tf.data, tf.last_used, true).await?;
                        
                        // Update last_used
                        query!(
                            &db,
                            "UPDATE twofactor SET last_used = ?1 WHERE uuid = ?2",
                            new_last_used,
                            &tf.uuid
                        )
                        .map_err(|_| AppError::Database)?
                        .run()
                        .await
                        .map_err(|_| AppError::Database)?;
                    }
                    Some(TwoFactorType::Remember) => {
                        // Check remember token against device
                        if let Some(ref device_id) = payload.device_identifier {
                            let stored_token: Option<Value> = db
                                .prepare("SELECT data FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
                                .bind(&[user.id.clone().into(), (TwoFactorType::Remember as i32).into()])?
                                .first(None)
                                .await
                                .map_err(|_| AppError::Database)?;
                            
                            if let Some(token_value) = stored_token {
                                let stored_data = token_value.get("data")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                
                                // Parse stored remember tokens (format: device_id:token,device_id:token,...)
                                let expected_token = format!("{}:{}", device_id, twofactor_code);
                                if !stored_data.contains(&expected_token) {
                                    return Err(AppError::TwoFactorRequired(json_err_twofactor(&twofactor_ids)));
                                }
                            } else {
                                return Err(AppError::TwoFactorRequired(json_err_twofactor(&twofactor_ids)));
                            }
                        } else {
                            return Err(AppError::TwoFactorRequired(json_err_twofactor(&twofactor_ids)));
                        }
                    }
                    Some(TwoFactorType::RecoveryCode) => {
                        // Check recovery code
                        if let Some(ref stored_code) = user.totp_recover {
                            if !ct_eq(stored_code, twofactor_code) {
                                return Err(AppError::BadRequest("Recovery code is incorrect".to_string()));
                            }
                            
                            // Delete all 2FA and clear recovery code
                            query!(
                                &db,
                                "DELETE FROM twofactor WHERE user_uuid = ?1",
                                &user.id
                            )
                            .map_err(|_| AppError::Database)?
                            .run()
                            .await
                            .map_err(|_| AppError::Database)?;
                            
                            query!(
                                &db,
                                "UPDATE users SET totp_recover = NULL WHERE id = ?1",
                                &user.id
                            )
                            .map_err(|_| AppError::Database)?
                            .run()
                            .await
                            .map_err(|_| AppError::Database)?;
                        } else {
                            return Err(AppError::BadRequest("Recovery code is incorrect".to_string()));
                        }
                    }
                    _ => {
                        return Err(AppError::BadRequest("Invalid two factor provider".to_string()));
                    }
                }

                // Generate remember token if requested
                if payload.two_factor_remember == Some(1) {
                    if let Some(ref device_id) = payload.device_identifier {
                        let remember_token = uuid::Uuid::new_v4().to_string();
                        let token_data = format!("{}:{}", device_id, remember_token);
                        
                        // Store or update remember token
                        query!(
                            &db,
                            "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) 
                             VALUES (?1, ?2, ?3, 1, ?4, 0)
                             ON CONFLICT(user_uuid, atype) DO UPDATE SET data = ?4",
                            uuid::Uuid::new_v4().to_string(),
                            &user.id,
                            TwoFactorType::Remember as i32,
                            &token_data
                        )
                        .map_err(|_| AppError::Database)?
                        .run()
                        .await
                        .map_err(|_| AppError::Database)?;
                        
                        two_factor_remember_token = Some(remember_token);
                    }
                }
            }

            // Migrate legacy user to PBKDF2 if password matches and no salt exists
            let user = if verification.needs_migration() {
                // Generate new salt and hash the password
                let new_salt = generate_salt()?;
                let new_hash = hash_password_for_storage(&password_hash, &new_salt).await?;
                let now = Utc::now().to_rfc3339();

                // Update user in database
                query!(
                    &db,
                    "UPDATE users SET master_password_hash = ?1, password_salt = ?2, updated_at = ?3 WHERE id = ?4",
                    &new_hash,
                    &new_salt,
                    &now,
                    &user.id
                )
                .map_err(|_| AppError::Database)?
                .run()
                .await
                .map_err(|_| AppError::Database)?;

                // Return updated user
                User {
                    master_password_hash: new_hash,
                    password_salt: Some(new_salt),
                    updated_at: now,
                    ..user
                }
            } else {
                user
            };

            generate_tokens_and_response(user, &env, two_factor_remember_token)
        }
        "refresh_token" => {
            let refresh_token = payload
                .refresh_token
                .ok_or_else(|| AppError::BadRequest("Missing refresh_token".to_string()))?;

            let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
            let token_data = decode::<Claims>(
                &refresh_token,
                &DecodingKey::from_secret(jwt_refresh_secret.as_ref()),
                &Validation::default(),
            )
            .map_err(|_| AppError::Unauthorized("Invalid refresh token".to_string()))?;

            let user_id = token_data.claims.sub;
            let user: Value = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid user".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid user".to_string()))?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

            generate_tokens_and_response(user, &env, None)
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}

/// Generates the JSON error response for 2FA required
fn json_err_twofactor(providers: &[i32]) -> Value {
    let mut result = serde_json::json!({
        "error": "invalid_grant",
        "error_description": "Two factor required.",
        "TwoFactorProviders": providers.iter().map(|p| p.to_string()).collect::<Vec<String>>(),
        "TwoFactorProviders2": {},
        "MasterPasswordPolicy": {
            "Object": "masterPasswordPolicy"
        }
    });

    // Add provider-specific info
    for provider in providers {
        result["TwoFactorProviders2"][provider.to_string()] = Value::Null;
        
        // TOTP doesn't need any additional info
        // Other providers like Email, WebAuthn etc. would add their info here
    }

    result
}
