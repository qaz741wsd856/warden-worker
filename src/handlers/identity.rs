use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Form, Json,
};
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use jwt_compact::AlgorithmExt;
use jwt_compact::{alg::Hs256Key, Claims as JwtClaims, Header, UntrustedToken};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use worker::{Delay, Env};

use crate::d1_query;
use crate::{
    auth::{
        jwt_time_options,
        send::{create_send_access_token, SEND_ACCESS_TOKEN_TTL_SECS},
        Claims,
    },
    client_context::{parse_required_device_type, request_ip_from_headers},
    crypto::{ct_eq, generate_salt, hash_password_for_storage, validate_totp},
    db,
    error::AppError,
    handlers::{
        allow_totp_drift, api_key_enabled, enforce_ip_rate_limit, enforce_rate_limit,
        server_password_iterations,
        twofactor::{is_twofactor_enabled, list_user_twofactors},
    },
    models::{
        auth_request::AuthRequest,
        device::{Device, DeviceType},
        send::{SendAccessTokenResponse, SendDB},
        twofactor::{TwoFactor, TwoFactorType},
        user::User,
    },
    push,
};

const PASSWORD_SCOPE: &str = "api offline_access";
/// Scope used by the `client_credentials` (personal API key) grant.
const API_KEY_SCOPE: &str = "api";
const REMEMBER_TOKEN_ISSUER: &str = "warden-worker-device-remember";

fn login_missing_user_delay_ms(env: &Env) -> u64 {
    const JITTER_MS: i32 = 30;
    const DEFAULT_LOGIN_MISSING_USER_DELAY_MS: i32 = 550;
    let base_ms = env
        .var("LOGIN_MISSING_USER_DELAY_MS")
        .ok()
        .and_then(|value| value.to_string().parse::<i32>().ok())
        .unwrap_or(DEFAULT_LOGIN_MISSING_USER_DELAY_MS);

    let mut random_byte = [0u8; 1];
    let jitter_ms = if getrandom::fill(&mut random_byte).is_ok() {
        (i32::from(random_byte[0]) * (JITTER_MS * 2 + 1) / 256) - JITTER_MS
    } else {
        0
    };
    (base_ms + jitter_ms).max(0) as u64
}

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
    password: Option<String>, // masterPasswordHash or auth request access code
    refresh_token: Option<String>,
    #[serde(rename = "client_id", alias = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "client_secret", alias = "clientSecret")]
    client_secret: Option<String>,
    send_id: Option<String>,
    password_hash_b64: Option<String>,
    scope: Option<String>,
    #[serde(rename = "authrequest", alias = "authRequest")]
    auth_request: Option<String>,
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

#[derive(Debug)]
struct PasswordGrantAuthContext {
    user: User,
    device_request: DeviceAuthRequest,
    password_hash: Option<String>,
    needs_migration: bool,
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
    // API key logins do not get a refresh token: clients repeat the `client_credentials` flow.
    #[serde(rename = "refresh_token", skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
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

/// `sub` of the signed refresh JWT. Only grants that issue refresh tokens appear here.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum RefreshAuthMethod {
    Password,
}

/// How the caller authenticated on this token request. Drives the granted scope and
/// whether a refresh token is issued; it is not part of any signed token payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginAuthMethod {
    Password,
    UserApiKey,
}

impl LoginAuthMethod {
    fn scope(self) -> &'static str {
        match self {
            Self::Password => PASSWORD_SCOPE,
            Self::UserApiKey => API_KEY_SCOPE,
        }
    }

    fn scope_vec(self) -> Vec<String> {
        self.scope()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// API key logins are one-shot; upstream expects the client to redo the flow instead.
    fn issues_refresh_token(self) -> bool {
        matches!(self, Self::Password)
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
        r#type: parse_required_device_type(payload.device_type.as_deref(), "device_type")?,
    })
}

/// The personal API key grant only supports the user scope; `api.organization` (upstream's
/// org API keys) is deliberately not implemented in this fork.
fn validate_api_key_scope(value: Option<&str>) -> Result<(), AppError> {
    match optional_field(value) {
        Some(scope) if scope == API_KEY_SCOPE => Ok(()),
        _ => Err(AppError::BadRequest("Scope not supported".to_string())),
    }
}

fn parse_api_key_device_request(payload: &TokenRequest) -> Result<DeviceAuthRequest, AppError> {
    validate_api_key_scope(payload.scope.as_deref())?;

    Ok(DeviceAuthRequest {
        client_id: required_field(payload.client_id.as_deref(), "client_id")?,
        identifier: required_field(payload.device_identifier.as_deref(), "device_identifier")?,
        name: required_field(payload.device_name.as_deref(), "device_name")?,
        r#type: parse_required_device_type(payload.device_type.as_deref(), "device_type")?,
    })
}

async fn generate_send_access_token_response(
    env: &Env,
    db: &crate::db::Db,
    headers: &HeaderMap,
    payload: &TokenRequest,
) -> Result<Json<SendAccessTokenResponse>, AppError> {
    let _client_id = required_field(payload.client_id.as_deref(), "client_id")?;
    let access_id = required_field(payload.send_id.as_deref(), "send_id")?;
    let mut send = SendDB::find_by_access_id(db, &access_id)
        .await?
        .ok_or_else(AppError::send_access_invalid)?;

    if send.validate_access().is_err() {
        return Err(AppError::send_access_invalid());
    }

    if send.has_password() {
        enforce_ip_rate_limit(
            env,
            headers,
            "SEND_ACCESS_RATE_LIMITER",
            "send-access",
            "Too many send password attempts. Please try again later.",
        )
        .await?;

        let password_hash_b64 =
            required_field(payload.password_hash_b64.as_deref(), "password_hash_b64")
                .map_err(|_| AppError::send_access_password_required())?;
        if !send.check_password(&password_hash_b64).await? {
            return Err(AppError::send_access_password_invalid());
        }
    }

    send.increment_access_count(db).await?;
    let access_token = create_send_access_token(env, &send.id)?;

    Ok(Json(SendAccessTokenResponse {
        access_token,
        expires_in: SEND_ACCESS_TOKEN_TTL_SECS,
        token_type: "Bearer".to_string(),
        scope: "api.send.access".to_string(),
    }))
}

async fn authenticate_password_grant(
    env: &Env,
    db: &crate::db::Db,
    headers: &HeaderMap,
    payload: &TokenRequest,
    username: &str,
) -> Result<PasswordGrantAuthContext, AppError> {
    let password_hash = required_field(payload.password.as_deref(), "password")?;
    let device_request = parse_password_device_request(payload)?;
    let user = match User::find_by_email(db, &username.to_lowercase()).await? {
        Some(user) => user,
        None => {
            Delay::from(StdDuration::from_millis(login_missing_user_delay_ms(env))).await;
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }
    };

    // Bitwarden "login with device" flow:
    // When `authrequest` is present, clients send the auth-request access code in the `password`
    // field. In that case we do NOT verify the user's master password (or run KDF migration);
    // we only validate the auth request (approval, expiry, IP/device match, access code).
    if let Some(auth_request_id) = optional_field(payload.auth_request.as_deref()) {
        let auth_request = AuthRequest::find_by_id_and_user(db, &auth_request_id, &user.id)
            .await?
            .ok_or_else(|| {
                AppError::BadRequest("Auth request not found. Try again.".to_string())
            })?;

        if !auth_request.is_approved()
            || auth_request.is_expired()
            || auth_request.request_ip != request_ip_from_headers(headers)
            || auth_request.request_device_identifier != device_request.identifier
            || auth_request.device_type != device_request.r#type
            || !auth_request.check_access_code(&password_hash)
        {
            return Err(AppError::BadRequest(
                "Username or access code is incorrect. Try again".to_string(),
            ));
        }

        return Ok(PasswordGrantAuthContext {
            user,
            device_request,
            password_hash: None,
            needs_migration: false,
        });
    }

    let verification = user.verify_master_password(&password_hash).await?;
    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    Ok(PasswordGrantAuthContext {
        user,
        device_request,
        password_hash: Some(password_hash),
        needs_migration: verification.needs_migration(),
    })
}

async fn find_user_by_id(db: &crate::db::Db, user_id: &str) -> Result<Option<User>, AppError> {
    let user_value: Option<Value> = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    user_value
        .map(|user_value| serde_json::from_value(user_value).map_err(|_| AppError::Internal))
        .transpose()
}

async fn load_user_by_id(db: &crate::db::Db, user_id: &str) -> Result<User, AppError> {
    find_user_by_id(db, user_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("invalid_grant".to_string()))
}

async fn maybe_upgrade_password_hash(
    db: &crate::db::Db,
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

    d1_query!(
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
    auth_method: LoginAuthMethod,
) -> Result<Json<TokenResponse>, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let time_options = jwt_time_options();

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

    let refresh_token = if auth_method.issues_refresh_token() {
        let refresh_claims = JwtClaims::new(RefreshClaims {
            sub: RefreshAuthMethod::Password,
            device_token: device.refresh_token.clone(),
            sstamp: user.security_stamp.clone(),
        })
        .set_duration_and_issuance(&time_options, Duration::days(30))
        .set_not_before(now);
        let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
        let refresh_key = Hs256Key::new(jwt_refresh_secret.as_bytes());
        Some(
            jwt_compact::alg::Hs256
                .token(&Header::empty(), &refresh_claims, &refresh_key)
                .map_err(|_| AppError::Crypto("Failed to create refresh token".to_string()))?,
        )
    } else {
        None
    };

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
    headers: HeaderMap,
    Form(payload): Form<TokenRequest>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;

    match payload.grant_type.as_str() {
        "password" => {
            let username = required_field(payload.username.as_deref(), "username")?;

            enforce_rate_limit(
                env.as_ref(),
                "LOGIN_RATE_LIMITER",
                format!("login:{}", username.to_lowercase()),
                "Too many login attempts. Please try again later.",
            )
            .await?;
            enforce_ip_rate_limit(
                env.as_ref(),
                &headers,
                "LOGIN_RATE_LIMITER",
                "login-ip",
                "Too many login attempts. Please try again later.",
            )
            .await?;

            let PasswordGrantAuthContext {
                user,
                device_request,
                password_hash,
                needs_migration,
            } = authenticate_password_grant(env.as_ref(), &db, &headers, &payload, &username)
                .await?;

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

                        d1_query!(
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

                            d1_query!(&db, "DELETE FROM twofactor WHERE user_uuid = ?1", &user.id)
                                .map_err(|_| AppError::Database)?
                                .run()
                                .await
                                .map_err(|_| AppError::Database)?;
                            d1_query!(
                                &db,
                                "UPDATE users SET totp_recover = NULL WHERE id = ?1",
                                &user.id
                            )
                            .map_err(|_| AppError::Database)?
                            .run()
                            .await
                            .map_err(|_| AppError::Database)?;
                            d1_query!(
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

            let user = if let Some(password_hash) = password_hash {
                maybe_upgrade_password_hash(
                    &db,
                    env.as_ref(),
                    user,
                    &password_hash,
                    needs_migration,
                )
                .await?
            } else {
                user
            };
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
                LoginAuthMethod::Password,
            )
            .map(IntoResponse::into_response)
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
            generate_tokens_and_response(
                user,
                &device,
                &client_id,
                &env,
                None,
                LoginAuthMethod::Password,
            )
            .map(IntoResponse::into_response)
        }
        "client_credentials" => {
            // Personal API key login (`bw login --apikey`). Port of Vaultwarden's
            // `user_api_key_login`; organization API keys are not supported by this fork.
            //
            // Opt-in: without API_KEY_ENABLED this answers exactly like the unknown-grant
            // fallback below, before the rate limiters and before touching the database,
            // so the grant is indistinguishable from one that was never implemented.
            if !api_key_enabled(env.as_ref()) {
                return Err(AppError::BadRequest("Unsupported grant_type".to_string()));
            }

            let client_id = required_field(payload.client_id.as_deref(), "client_id")?;

            enforce_rate_limit(
                env.as_ref(),
                "LOGIN_RATE_LIMITER",
                format!("login:{}", client_id.to_lowercase()),
                "Too many login attempts. Please try again later.",
            )
            .await?;
            enforce_ip_rate_limit(
                env.as_ref(),
                &headers,
                "LOGIN_RATE_LIMITER",
                "login-ip",
                "Too many login attempts. Please try again later.",
            )
            .await?;

            let device_request = parse_api_key_device_request(&payload)?;
            // Validated before the user lookup (as upstream does) so a missing
            // client_secret cannot distinguish an existing user from an unknown one.
            let client_secret = required_field(payload.client_secret.as_deref(), "client_secret")?;

            let client_user_id = client_id
                .strip_prefix("user.")
                .filter(|user_id| !user_id.is_empty())
                .ok_or_else(|| AppError::BadRequest("Malformed client_id".to_string()))?;

            let user = match find_user_by_id(&db, client_user_id).await? {
                Some(user) => user,
                None => {
                    Delay::from(StdDuration::from_millis(login_missing_user_delay_ms(
                        env.as_ref(),
                    )))
                    .await;
                    return Err(AppError::Unauthorized("Invalid client_id".to_string()));
                }
            };

            // Check the API key. Note that API key logins bypass 2FA (as upstream does).
            // An empty stored key never authenticates.
            let api_key_valid = user
                .api_key
                .as_deref()
                .filter(|api_key| !api_key.is_empty())
                .is_some_and(|api_key| ct_eq(api_key, &client_secret));
            if !api_key_valid {
                return Err(AppError::Unauthorized(
                    "Incorrect client_secret".to_string(),
                ));
            }

            let mut device = Device::get_or_create(
                &db,
                device_request.identifier,
                user.id.clone(),
                device_request.name,
                device_request.r#type,
            )
            .await?;
            device.touch(&db).await?;

            generate_tokens_and_response(
                user,
                &device,
                &device_request.client_id,
                &env,
                None,
                LoginAuthMethod::UserApiKey,
            )
            .map(IntoResponse::into_response)
        }
        "send_access" => generate_send_access_token_response(env.as_ref(), &db, &headers, &payload)
            .await
            .map(IntoResponse::into_response),
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
