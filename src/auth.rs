use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use worker::Env;

use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub exp: usize,  // Expiration time
    pub nbf: usize,  // Not before time

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub amr: Vec<String>,
}

/// AuthUser extractor - provides (user_id, email) tuple
pub struct AuthUser(pub String, pub String);

impl FromRequestParts<Arc<Env>> for Claims
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<Env>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| {
                if auth_value.starts_with("Bearer ") {
                    Some(auth_value[7..].to_owned())
                } else {
                    None
                }
            })
            .ok_or_else(|| AppError::Unauthorized("Missing or invalid token".to_string()))?;

        let secret = state.secret("JWT_SECRET")?;

        // Decode and validate the token
        let decoding_key = DecodingKey::from_secret(secret.to_string().as_ref());
        let token_data = decode::<Claims>(&token, &decoding_key, &Validation::default())
            .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

        Ok(token_data.claims)
    }
}

impl FromRequestParts<Arc<Env>> for AuthUser
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<Env>) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        Ok(AuthUser(claims.sub, claims.email))
    }
}
