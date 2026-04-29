use axum::{extract::State, Form, Json};
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use jwt_compact::AlgorithmExt;
use jwt_compact::{alg::Hs256Key, Claims as JwtClaims, Header, UntrustedToken};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::sync::Arc;
use worker::{query, Env};

use crate::{
    auth::{jwt_time_options, Claims},
    crypto::{ct_eq, generate_salt, hash_password_for_storage, validate_totp},
    db,
    error::AppError,
    handlers::{
        allow_totp_drift, server_password_iterations,
        twofactor::{is_twofactor_enabled, list_user_twofactors},
    },
    models::{
        device::{Device, DeviceType},
        twofactor::{TwoFactor, TwoFactorType},
        user::User,
    },
    push,
};

const PASSWORD_SCOPE: &str = "api offline_access";
const REMEMBER_TOKEN_ISSUER: &str = "warden-worker-device-remember";

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
                    .map_err(|_| D::Error::custom(format!("invalid integer: {s}")))
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
    #[serde(rename = "client_id", alias = "clientId")]
    client_id: Option<String>,
    scope: Option<String>,
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
    #[serde(rename = "device_identifier", alias = "deviceIdentifier")]
    device_identifier: Option<String>,
    #[serde(rename = "device_name", alias = "deviceName")]
    device_name: Option<String>,
    #[serde(rename = "device_type", alias = "deviceType", alias = "devicetype")]
    device_type: Option<String>,
}

#[derive(Debug)]
struct DeviceAuthRequest {
    client_id: String,
    identifier: String,
    name: String,
    r#type: i32,
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
    #[serde(rename = "scope")]
    scope: String,
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum RefreshAuthMethod {
    Password,
}

impl RefreshAuthMethod {
    fn scope(self) -> &'static str {
        PASSWORD_SCOPE
    }

    fn scope_vec(self) -> Vec<String> {
        self.scope()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshClaims {
    pub sub: RefreshAuthMethod,
    pub device_token: String,
    pub sstamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RememberJwtClaims {
    pub sub: String,
    pub user_uuid: String,
    pub iss: String,
}

fn required_field(value: Option<&str>, name: &str) -> Result<String, AppError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AppError::BadRequest(format!("Missing {name}")))
}

fn optional_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn validate_password_scope(value: Option<&str>, required: bool) -> Result<(), AppError> {
    let scope = optional_field(value);
    match scope {
        Some(scope) if scope == PASSWORD_SCOPE => Ok(()),
        Some(scope) => Err(AppError::BadRequest(format!("Unsupported scope: {scope}"))),
        None if required => Err(AppError::BadRequest("Missing scope".to_string())),
        None => Ok(()),
    }
}

fn parse_password_device_request(payload: &TokenRequest) -> Result<DeviceAuthRequest, AppError> {
    validate_password_scope(payload.scope.as_deref(), true)?;

    Ok(DeviceAuthRequest {
        client_id: required_field(payload.client_id.as_deref(), "client_id")?,
        identifier: required_field(payload.device_identifier.as_deref(), "device_identifier")?,
        name: required_field(payload.device_name.as_deref(), "device_name")?,
        r#type: DeviceType::from_str(&required_field(
            payload.device_type.as_deref(),
            "device_type",
        )?)
        .as_i32(),
    })
}

async fn load_user_by_email(db: &worker::D1Database, email: &str) -> Result<User, AppError> {
    let user_value: Option<Value> = db
        .prepare("SELECT * FROM users WHERE email = ?1")
        .bind(&[email.to_lowercase().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let user_value =
        user_value.ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
    serde_json::from_value(user_value).map_err(|_| AppError::Internal)
}

async fn load_user_by_id(db: &worker::D1Database, user_id: &str) -> Result<User, AppError> {
    let user_value: Option<Value> = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let user_value = user_value.ok_or_else(|| AppError::BadRequest("invalid_grant".to_string()))?;
    serde_json::from_value(user_value).map_err(|_| AppError::Internal)
}

async fn maybe_upgrade_password_hash(
    db: &worker::D1Database,
    env: &Env,
    user: User,
    password_hash: &str,
    needs_migration: bool,
) -> Result<User, AppError> {
    let desired_iterations = server_password_iterations(env) as i32;
    let needs_upgrade = needs_migration || user.password_iterations < desired_iterations;

    if !needs_upgrade {
        return Ok(user);
    }

    let new_salt = generate_salt()?;
    let new_hash =
        hash_password_for_storage(password_hash, &new_salt, desired_iterations as u32).await?;
    let now = db::now_string();

    query!(
        db,
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

    Ok(User {
        master_password_hash: new_hash,
        password_salt: Some(new_salt),
        password_iterations: desired_iterations,
        updated_at: now,
        ..user
    })
}

fn generate_remember_token(env: &Env, user: &User, device: &Device) -> Result<String, AppError> {
    let now = Utc::now();
    let time_options = jwt_time_options();
    let claims = JwtClaims::new(RememberJwtClaims {
        sub: device.identifier.clone(),
        user_uuid: user.id.clone(),
        iss: REMEMBER_TOKEN_ISSUER.to_string(),
    })
    .set_duration_and_issuance(&time_options, Duration::days(30))
    .set_not_before(now);

    let secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let key = Hs256Key::new(secret.as_bytes());
    jwt_compact::alg::Hs256
        .token(&Header::empty(), &claims, &key)
        .map_err(|_| AppError::Crypto("Failed to create remember token".to_string()))
}

fn validate_remember_token(
    env: &Env,
    user: &User,
    device: &Device,
    raw_token: &str,
    twofactor_ids: &[i32],
) -> Result<(), AppError> {
    let secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let key = Hs256Key::new(secret.as_bytes());
    let token = UntrustedToken::new(raw_token)
        .map_err(|_| AppError::TwoFactorRequired(json_err_twofactor(twofactor_ids)))?;
    let token = jwt_compact::alg::Hs256
        .validator::<RememberJwtClaims>(&key)
        .validate(&token)
        .map_err(|_| AppError::TwoFactorRequired(json_err_twofactor(twofactor_ids)))?;
    let time_options = jwt_time_options();
    token
        .claims()
        .validate_expiration(&time_options)
        .map_err(|_| AppError::TwoFactorRequired(json_err_twofactor(twofactor_ids)))?;
    token
        .claims()
        .validate_maturity(&time_options)
        .map_err(|_| AppError::TwoFactorRequired(json_err_twofactor(twofactor_ids)))?;

    let remember_claims = token.into_parts().1.custom;
    if remember_claims.iss != REMEMBER_TOKEN_ISSUER
        || remember_claims.sub.as_str() != device.identifier.as_str()
        || remember_claims.user_uuid.as_str() != user.id.as_str()
    {
        return Err(AppError::TwoFactorRequired(json_err_twofactor(
            twofactor_ids,
        )));
    }

    let stored_token = device
        .twofactor_remember
        .as_deref()
        .ok_or_else(|| AppError::TwoFactorRequired(json_err_twofactor(twofactor_ids)))?;
    if !constant_time_eq(stored_token.as_bytes(), raw_token.as_bytes()) {
        return Err(AppError::TwoFactorRequired(json_err_twofactor(
            twofactor_ids,
        )));
    }

    Ok(())
}

fn generate_tokens_and_response(
    user: User,
    device: &Device,
    client_id: &str,
    env: &Arc<Env>,
    two_factor_token: Option<String>,
) -> Result<Json<TokenResponse>, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let time_options = jwt_time_options();
    let auth_method = RefreshAuthMethod::Password;

    let access_claims = JwtClaims::new(Claims {
        sub: user.id.clone(),
        sstamp: user.security_stamp.clone(),
        premium: true,
        name: user.name.clone().unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: user.email_verified,
        device: device.identifier.clone(),
        devicetype: DeviceType::from_i32(device.r#type)
            .display_name()
            .to_string(),
        client_id: client_id.to_string(),
        scope: auth_method.scope_vec(),
        amr: vec!["Application".into()],
    })
    .set_duration_and_issuance(&time_options, expires_in)
    .set_not_before(now);

    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let access_key = Hs256Key::new(jwt_secret.as_bytes());
    let access_token = jwt_compact::alg::Hs256
        .token(&Header::empty(), &access_claims, &access_key)
        .map_err(|_| AppError::Crypto("Failed to create access token".to_string()))?;

    let refresh_claims = JwtClaims::new(RefreshClaims {
        sub: auth_method,
        device_token: device.refresh_token.clone(),
        sstamp: user.security_stamp.clone(),
    })
    .set_duration_and_issuance(&time_options, Duration::days(30))
    .set_not_before(now);
    let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let refresh_key = Hs256Key::new(jwt_refresh_secret.as_bytes());
    let refresh_token = jwt_compact::alg::Hs256
        .token(&Header::empty(), &refresh_claims, &refresh_key)
        .map_err(|_| AppError::Crypto("Failed to create refresh token".to_string()))?;

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
        scope: auth_method.scope().to_string(),
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
            let username = required_field(payload.username.as_deref(), "username")?;
            let password_hash = required_field(payload.password.as_deref(), "password")?;
            let device_request = parse_password_device_request(&payload)?;

            // Check rate limit using email as key to prevent brute force attacks.
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

            let user = load_user_by_email(&db, &username).await?;
            let verification = user.verify_master_password(&password_hash).await?;
            if !verification.is_valid() {
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            let mut device = Device::get_or_create(
                &db,
                device_request.identifier,
                user.id.clone(),
                device_request.name,
                device_request.r#type,
            )
            .await?;

            let twofactors: Vec<TwoFactor> = list_user_twofactors(&db, &user.id).await?;
            let twofactor_ids = vec![TwoFactorType::Authenticator as i32];
            let mut should_issue_remember = false;

            if is_twofactor_enabled(&twofactors) {
                let selected_id = payload.two_factor_provider.unwrap_or(twofactor_ids[0]);
                let twofactor_code = payload.two_factor_token.as_deref().ok_or_else(|| {
                    AppError::TwoFactorRequired(json_err_twofactor(&twofactor_ids))
                })?;

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

                        let allow_drift = allow_totp_drift(&env);
                        let new_last_used =
                            validate_totp(twofactor_code, &tf.data, tf.last_used, allow_drift)
                                .await?;

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

                        should_issue_remember = payload.two_factor_remember == Some(1);
                    }
                    Some(TwoFactorType::Remember) => {
                        validate_remember_token(
                            env.as_ref(),
                            &user,
                            &device,
                            twofactor_code,
                            &twofactor_ids,
                        )?;
                        should_issue_remember = payload.two_factor_remember == Some(1);
                    }
                    Some(TwoFactorType::RecoveryCode) => {
                        if let Some(ref stored_code) = user.totp_recover {
                            if !ct_eq(&stored_code.to_uppercase(), &twofactor_code.to_uppercase()) {
                                return Err(AppError::BadRequest(
                                    "Recovery code is incorrect".to_string(),
                                ));
                            }

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
                            query!(
                                &db,
                                "UPDATE devices SET twofactor_remember = NULL WHERE user_id = ?1",
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
            }

            let user = maybe_upgrade_password_hash(
                &db,
                env.as_ref(),
                user,
                &password_hash,
                verification.needs_migration(),
            )
            .await?;
            let mut two_factor_remember_token = None;
            if should_issue_remember {
                let remember_token = generate_remember_token(env.as_ref(), &user, &device)?;
                device
                    .set_twofactor_remember(&db, Some(&remember_token))
                    .await?;
                two_factor_remember_token = Some(remember_token);
            } else {
                device.touch(&db).await?;
            }

            if device.push_token.is_some() && device.is_push_device() {
                if let Ok(Some(cfg)) = push::push_config(&env) {
                    match push::register_push_device(&cfg, &mut device).await {
                        Ok(push_uuid_created) => {
                            if push_uuid_created {
                                if let Err(e) = device.persist_push_uuid(&db).await {
                                    log::warn!("Push uuid persistence on login failed: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("Push re-registration on login failed: {e}");
                        }
                    }
                }
            }

            generate_tokens_and_response(
                user,
                &device,
                &device_request.client_id,
                &env,
                two_factor_remember_token,
            )
        }
        "refresh_token" => {
            // When a refresh token is invalid or missing we need to respond with an HTTP BadRequest (400)
            // It also needs to return a json which holds at least a key `error` with the value `invalid_grant`
            // See the link below for details
            // https://github.com/bitwarden/clients/blob/2ee158e720a5e7dbe3641caf80b569e97a1dd91b/libs/common/src/services/api.service.ts#L1786-L1797
            let refresh_token = required_field(payload.refresh_token.as_deref(), "refresh_token")
                .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;
            validate_password_scope(payload.scope.as_deref(), false)
                .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;

            let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
            let refresh_key = Hs256Key::new(jwt_refresh_secret.as_bytes());
            let token = UntrustedToken::new(&refresh_token)
                .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;
            let token = jwt_compact::alg::Hs256
                .validator::<RefreshClaims>(&refresh_key)
                .validate(&token)
                .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;
            let time_options = jwt_time_options();
            token
                .claims()
                .validate_expiration(&time_options)
                .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;
            token
                .claims()
                .validate_maturity(&time_options)
                .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;

            let refresh_claims = token.into_parts().1.custom;
            let mut device = Device::find_by_refresh_token(&db, &refresh_claims.device_token)
                .await?
                .ok_or_else(|| AppError::BadRequest("invalid_grant".to_string()))?;
            let user = load_user_by_id(&db, &device.user_id).await?;

            if !constant_time_eq(
                refresh_claims.sstamp.as_bytes(),
                user.security_stamp.as_bytes(),
            ) {
                return Err(AppError::BadRequest("invalid_grant".to_string()));
            }

            device.touch(&db).await?;

            let client_id = optional_field(payload.client_id.as_deref())
                .unwrap_or_else(|| "undefined".to_string());
            generate_tokens_and_response(user, &device, &client_id, &env, None)
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

    for provider in providers {
        result["TwoFactorProviders2"][provider.to_string()] = Value::Null;
    }

    result
}
