use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use chrono::Duration;
use constant_time_eq::constant_time_eq;
use jwt_compact::AlgorithmExt;
use jwt_compact::{alg::Hs256Key, TimeOptions, UntrustedToken};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use worker::Env;

use crate::db;
use crate::error::AppError;
use crate::models::device::Device;

pub(crate) const JWT_VALIDATION_LEEWAY_SECS: u64 = 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,    // User ID
    pub sstamp: String, // Security stamp

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub device: String,
    pub devicetype: String,
    pub client_id: String,
    pub scope: Vec<String>,
    pub amr: Vec<String>,
}

pub(crate) fn jwt_time_options() -> TimeOptions {
    let leeway = Duration::seconds(JWT_VALIDATION_LEEWAY_SECS as i64);
    TimeOptions::from_leeway(leeway)
}

/// AuthUser extractor - provides (user_id, email) tuple
pub struct AuthUser(
    pub String, // user_id
    #[allow(dead_code)] // email is not used in this simplified version
    pub  String, // email
);

impl FromRequestParts<Arc<Env>> for Claims {
    type Rejection = AppError;
    #[worker::send]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<Env>,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(bearer_token_from_header_value)
            .ok_or_else(|| AppError::Unauthorized("Missing or invalid token".to_string()))?;

        decode_access_token(state.as_ref(), &token).await
    }
}

impl FromRequestParts<Arc<Env>> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<Env>,
    ) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        Ok(AuthUser(claims.sub, claims.email))
    }
}

pub(crate) fn bearer_token_from_header_value(auth_value: &str) -> Option<String> {
    auth_value
        .strip_prefix("Bearer ")
        .map(|value| value.to_owned())
}

pub(crate) fn bearer_token_from_headers(
    headers: &worker::Headers,
) -> Result<Option<String>, AppError> {
    let value = headers
        .get("Authorization")
        .map_err(AppError::Worker)?
        .or_else(|| headers.get("authorization").ok().flatten());

    Ok(value.as_deref().and_then(bearer_token_from_header_value))
}

pub(crate) async fn decode_access_token(env: &Env, token: &str) -> Result<Claims, AppError> {
    let secret = env.secret("JWT_SECRET")?;

    let key = Hs256Key::new(secret.to_string().as_bytes());
    let token = UntrustedToken::new(token)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    let token = jwt_compact::alg::Hs256
        .validator::<Claims>(&key)
        .validate(&token)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    let time_options = jwt_time_options();
    token
        .claims()
        .validate_expiration(&time_options)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    token
        .claims()
        .validate_maturity(&time_options)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    let claims = token.into_parts().1.custom;

    let db = db::get_db(env)?;
    let current_sstamp = db
        .prepare("SELECT security_stamp FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first::<String>(Some("security_stamp"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("Invalid token".to_string()))?;

    if !constant_time_eq(claims.sstamp.as_bytes(), current_sstamp.as_bytes()) {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }

    let device = Device::find_by_identifier_and_user(&db, &claims.device, &claims.sub).await?;
    if device.is_none() {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }

    Ok(claims)
}
