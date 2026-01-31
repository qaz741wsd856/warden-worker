use axum::{extract::State, Form, Json};
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::sync::Arc;
use worker::{query, Env};

use crate::{
    auth::{jwt_validation, Claims},
    crypto::{ct_eq, generate_salt, hash_password_for_storage, validate_totp},
    db,
    error::AppError,
    handlers::{
        allow_totp_drift, server_password_iterations,
        twofactor::{is_twofactor_enabled, list_user_twofactors},
    },
    models::twofactor::{RememberTokenData, TwoFactor, TwoFactorType},
    models::user::User,
};

/// Deserialize an Option<i32> that may have trailing/leading whitespace.
/// This handles Android clients that send "0 " instead of "0".
fn deserialize_trimmed_i32<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                trimmed
                    .parse::<i32>()
                    .map(Some)
                    .map_err(|_| D::Error::custom(format!("invalid integer: {}", s)))
            }
        }
        None => Ok(None),
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
    // 2FA fields
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(
        rename = "twoFactorProvider",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
    two_factor_provider: Option<i32>,
    #[serde(
        rename = "twoFactorRemember",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
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
    #[serde(rename = "KdfIterations")]
    kdf_iterations: i32,
    #[serde(rename = "KdfMemory")]
    kdf_memory: Option<i32>,
    #[serde(rename = "KdfParallelism")]
    kdf_parallelism: Option<i32>,
    #[serde(rename = "ResetMasterPassword")]
    reset_master_password: bool,
    #[serde(rename = "ForcePasswordReset")]
    force_password_reset: bool,
    #[serde(rename = "UserDecryptionOptions")]
    user_decryption_options: UserDecryptionOptions,
    #[serde(rename = "AccountKeys")]
    account_keys: serde_json::Value,
    #[serde(rename = "TwoFactorToken", skip_serializing_if = "Option::is_none")]
    two_factor_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserDecryptionOptions {
    pub has_master_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_unlock: Option<serde_json::Value>,
    pub object: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshClaims {
    pub sub: String, // User ID
    pub exp: usize,  // Expiration time
    pub nbf: usize,  // Not before time

    // NOTE: We intentionally do NOT implement refresh token rotation / replay detection here.
    // Vaultwarden's default auth flow also doesn't do rotation/reuse detection; in this project we
    // currently avoid device/session management. If we later add minimal device state, we can add
    // refresh token rotation (jti/family) + reuse detection on top.
    pub sstamp: String,
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
        sstamp: user.security_stamp.clone(),
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
    let refresh_claims = RefreshClaims {
        sub: user.id,
        exp: refresh_exp,
        nbf: now.timestamp() as usize,
        sstamp: user.security_stamp,
    };
    let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(jwt_refresh_secret.as_ref()),
    )?;

    let has_master_password = !user.master_password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        Some(serde_json::json!({
            "Kdf": {
                "KdfType": user.kdf_type,
                "Iterations": user.kdf_iterations,
                "Memory": user.kdf_memory,
                "Parallelism": user.kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "MasterKeyEncryptedUserKey": user.key,
            "MasterKeyWrappedUserKey": user.key,
            "Salt": user.email
        }))
    } else {
        None
    };

    let account_keys = serde_json::json!({
        "publicKeyEncryptionKeyPair": {
            "wrappedPrivateKey": user.private_key,
            "publicKey": user.public_key,
            "Object": "publicKeyEncryptionKeyPair"
        },
        "Object": "privateKeys"
    });

    Ok(Json(TokenResponse {
        access_token,
        expires_in: expires_in.num_seconds(),
        token_type: "Bearer".to_string(),
        refresh_token,
        key: user.key,
        private_key: user.private_key,
        kdf: user.kdf_type,
        kdf_iterations: user.kdf_iterations,
        kdf_memory: user.kdf_memory,
        kdf_parallelism: user.kdf_parallelism,
        force_password_reset: false,
        reset_master_password: false,
        user_decryption_options: UserDecryptionOptions {
            has_master_password,
            master_password_unlock,
            object: "userDecryptionOptions".to_string(),
        },
        account_keys,
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

            // Check rate limit using email as key to prevent brute force attacks
            // This limits login attempts per email address, not per IP
            if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
                let rate_limit_key = format!("login:{}", username.to_lowercase());
                if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
                    if !outcome.success {
                        return Err(AppError::TooManyRequests(
                            "Too many login attempts. Please try again later.".to_string(),
                        ));
                    }
                }
            }

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

            // Check for 2FA (TOTP) for this user.
            let twofactors: Vec<TwoFactor> = list_user_twofactors(&db, &user.id).await?;

            let mut two_factor_remember_token: Option<String> = None;

            if is_twofactor_enabled(&twofactors) {
                // Only advertise Authenticator (TOTP) as the real provider for now.
                let twofactor_ids: Vec<i32> = vec![TwoFactorType::Authenticator as i32];
                let selected_id = payload.two_factor_provider.unwrap_or(twofactor_ids[0]);

                let twofactor_code = match &payload.two_factor_token {
                    Some(code) => code,
                    None => {
                        // Return 2FA required error
                        return Err(AppError::TwoFactorRequired(json_err_twofactor(
                            &twofactor_ids,
                        )));
                    }
                };

                match TwoFactorType::from_i32(selected_id) {
                    Some(TwoFactorType::Authenticator) => {
                        let tf = twofactors
                            .iter()
                            .find(|tf| {
                                tf.enabled && tf.atype == TwoFactorType::Authenticator as i32
                            })
                            .ok_or_else(|| {
                                AppError::BadRequest("TOTP not configured".to_string())
                            })?;

                        // Validate TOTP code
                        let allow_drift = allow_totp_drift(&env);
                        let new_last_used =
                            validate_totp(twofactor_code, &tf.data, tf.last_used, allow_drift)
                                .await?;

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
                        // Remember is handled separately - client sends remember token from previous login
                        // Check remember token against stored value for this device
                        if let Some(ref device_id) = payload.device_identifier {
                            let remember_tf = twofactors.iter().find(|tf| {
                                tf.enabled && tf.atype == TwoFactorType::Remember as i32
                            });

                            if let Some(tf) = remember_tf {
                                // Parse stored remember tokens as JSON
                                let mut token_data = RememberTokenData::from_json(&tf.data);

                                // Remove expired tokens first
                                token_data.remove_expired();

                                // Validate the provided token
                                if !token_data.validate(device_id, twofactor_code) {
                                    return Err(AppError::TwoFactorRequired(json_err_twofactor(
                                        &twofactor_ids,
                                    )));
                                }

                                // Update database with cleaned tokens (remove expired)
                                let updated_data = token_data.to_json();
                                query!(
                                    &db,
                                    "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
                                    &updated_data,
                                    &tf.uuid
                                )
                                .map_err(|_| AppError::Database)?
                                .run()
                                .await
                                .map_err(|_| AppError::Database)?;

                                // Remember token valid, proceed with login
                            } else {
                                return Err(AppError::TwoFactorRequired(json_err_twofactor(
                                    &twofactor_ids,
                                )));
                            }
                        } else {
                            return Err(AppError::TwoFactorRequired(json_err_twofactor(
                                &twofactor_ids,
                            )));
                        }
                    }
                    Some(TwoFactorType::RecoveryCode) => {
                        // Check recovery code
                        if let Some(ref stored_code) = user.totp_recover {
                            if !ct_eq(&stored_code.to_uppercase(), &twofactor_code.to_uppercase()) {
                                return Err(AppError::BadRequest(
                                    "Recovery code is incorrect".to_string(),
                                ));
                            }

                            // Delete all 2FA and clear recovery code
                            query!(&db, "DELETE FROM twofactor WHERE user_uuid = ?1", &user.id)
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
                            return Err(AppError::BadRequest(
                                "Recovery code is incorrect".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(AppError::BadRequest(
                            "Invalid two factor provider".to_string(),
                        ));
                    }
                }

                // Generate remember token if requested
                if payload.two_factor_remember == Some(1) {
                    if let Some(ref device_id) = payload.device_identifier {
                        let remember_token = uuid::Uuid::new_v4().to_string();

                        // Load existing remember tokens or create new
                        let remember_tf = twofactors
                            .iter()
                            .find(|tf| tf.atype == TwoFactorType::Remember as i32);

                        let mut token_data = remember_tf
                            .map(|tf| RememberTokenData::from_json(&tf.data))
                            .unwrap_or_default();

                        // Remove expired tokens first
                        token_data.remove_expired();

                        // Add/update token for this device
                        token_data.upsert(device_id.clone(), remember_token.clone());

                        let json_data = token_data.to_json();

                        // Store or update remember token
                        query!(
                            &db,
                            "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) 
                             VALUES (?1, ?2, ?3, 1, ?4, 0)
                             ON CONFLICT(user_uuid, atype) DO UPDATE SET data = ?4",
                            uuid::Uuid::new_v4().to_string(),
                            &user.id,
                            TwoFactorType::Remember as i32,
                            &json_data
                        )
                        .map_err(|_| AppError::Database)?
                        .run()
                        .await
                        .map_err(|_| AppError::Database)?;

                        two_factor_remember_token = Some(remember_token);
                    }
                }
            }

            // Migrate/upgrade server-side password hashing parameters on successful verification.
            //
            // - Legacy users (no salt) are upgraded to server-side PBKDF2.
            // - Existing users are upgraded if their per-user iteration count is below the configured minimum.
            let desired_iterations = server_password_iterations(&env) as i32;
            let needs_upgrade =
                verification.needs_migration() || user.password_iterations < desired_iterations;

            let user = if needs_upgrade {
                // Generate new salt and hash the password using the desired iterations.
                let new_salt = generate_salt()?;
                let new_hash =
                    hash_password_for_storage(&password_hash, &new_salt, desired_iterations as u32)
                        .await?;
                let now = Utc::now().to_rfc3339();

                // Update user in database
                query!(
                    &db,
                    "UPDATE users SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3, updated_at = ?4 WHERE id = ?5",
                    &new_hash,
                    &new_salt,
                    desired_iterations,
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
                    password_iterations: desired_iterations,
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
            let token_data = decode::<RefreshClaims>(
                &refresh_token,
                &DecodingKey::from_secret(jwt_refresh_secret.as_ref()),
                &jwt_validation(),
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

            if !constant_time_eq(
                token_data.claims.sstamp.as_bytes(),
                user.security_stamp.as_bytes(),
            ) {
                return Err(AppError::Unauthorized("Invalid refresh token".to_string()));
            }

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
