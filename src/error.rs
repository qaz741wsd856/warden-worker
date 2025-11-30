use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("Database query failed")]
    Database,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error(transparent)]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error")]
    Internal,

    #[error("Two factor authentication required")]
    TwoFactorRequired(Value),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::TwoFactorRequired(json_body) => {
                // Return 400 Bad Request with the 2FA required JSON response
                // This is what Bitwarden clients expect
                (StatusCode::BAD_REQUEST, Json(json_body)).into_response()
            }
            _ => {
                let (status, error_message) = match self {
                    AppError::Worker(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Worker error: {}", e),
                    ),
                    AppError::Database => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Database error".to_string(),
                    ),
                    AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
                    AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
                    AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
                    AppError::Crypto(msg) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Crypto error: {}", msg),
                    ),
                    AppError::JsonWebToken(_) => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
                    AppError::Internal => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    ),
                    AppError::TwoFactorRequired(_) => unreachable!(),
                };

                let body = Json(json!({ "error": error_message }));
                (status, body).into_response()
            }
        }
    }
}
