use axum::{extract::State, Json};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{db, error::AppError};

/// GET /api/now
///
/// Mirrors vaultwarden's `/api/now`: returns current UTC timestamp as an RFC3339 string.
#[worker::send]
pub async fn now() -> Json<String> {
    Json(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// GET /api/alive
///
/// Simple healthcheck. Vaultwarden uses this to also verify DB connectivity.
#[worker::send]
pub async fn alive(State(env): State<Arc<Env>>) -> Result<Json<String>, AppError> {
    // Verify D1 binding is present + basic query works.
    let db = db::get_db(&env)?;
    db.prepare("SELECT 1 as ok")
        .first::<i32>(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(now().await)
}

/// GET /api/version
///
/// Returns a Bitwarden-server-like version string. Clients sometimes call this endpoint.
#[worker::send]
pub async fn version() -> Json<&'static str> {
    // Keep this in sync with `src/handlers/config.rs`'s `version`.
    Json("2026.3.1")
}

#[derive(Debug, Deserialize)]
pub struct HibpBreachQuery {
    #[allow(dead_code)] // stub endpoint doesn't use it yet
    pub username: String,
}

/// GET /api/hibp/breach?username=...
///
/// Vaultwarden can proxy HaveIBeenPwned if configured. This minimal server doesn't.
/// We return an empty array to indicate "no breach data" without surfacing an error in clients.
#[worker::send]
pub async fn hibp_breach(_query: axum::extract::Query<HibpBreachQuery>) -> Json<Value> {
    Json(json!([]))
}
