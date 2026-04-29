use axum::{extract::State, Json};
use log::warn;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::{query, Env};

use crate::handlers::ciphers::RawJson;
use crate::{
    auth::Claims,
    db,
    error::AppError,
    notifications::{self, UpdateType},
};

/// Build `globalEquivalentDomains` JSON (as a raw JSON string) in SQLite/D1.
///
/// - `include_excluded=true`  => returns all groups, each with `excluded` boolean (settings UI).
/// - `include_excluded=false` => returns only non-excluded groups, with `excluded=false` (sync payload).
///
/// This keeps the Worker from parsing the large upstream dataset.
pub(crate) async fn global_equivalent_domains_json(
    db: &worker::D1Database,
    excluded_globals_json: &str,
    include_excluded: bool,
) -> String {
    let sql = if include_excluded {
        r#"
SELECT COALESCE(
  (SELECT json_group_array(json(value))
   FROM (
     SELECT json_object(
              'type', g.type,
              'domains', json(g.domains_json),
              'excluded', CASE WHEN eg.value IS NULL THEN json('false') ELSE json('true') END
            ) AS value
     FROM global_equivalent_domains g
     LEFT JOIN json_each(?1) eg ON eg.value = g.type
     ORDER BY g.sort_order
   )),
  '[]'
) AS globals
"#
    } else {
        r#"
SELECT COALESCE(
  (SELECT json_group_array(json(value))
   FROM (
     SELECT json_object(
              'type', g.type,
              'domains', json(g.domains_json),
              'excluded', json('false')
            ) AS value
     FROM global_equivalent_domains g
     LEFT JOIN json_each(?1) eg ON eg.value = g.type
     WHERE eg.value IS NULL
     ORDER BY g.sort_order
   )),
  '[]'
) AS globals
"#
    };

    async fn run_once(db: &worker::D1Database, sql: &str, excluded: &str) -> Result<String, ()> {
        let row: Option<Value> = db
            .prepare(sql)
            .bind(&[excluded.to_string().into()])
            .map_err(|_| ())?
            .first(None)
            .await
            .map_err(|_| ())?;

        Ok(row
            .and_then(|r| {
                r.get("globals")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "[]".to_string()))
    }

    // If excluded_globals is invalid JSON, json_each() can fail.
    // Fallback to treating it as empty list.
    match run_once(db, sql, excluded_globals_json).await {
        Ok(s) => s,
        Err(_) => {
            if excluded_globals_json != "[]" {
                match run_once(db, sql, "[]").await {
                    Ok(s) => s,
                    Err(_) => {
                        warn!("Failed to build globalEquivalentDomains JSON (falling back to [])");
                        "[]".to_string()
                    }
                }
            } else {
                warn!("Failed to build globalEquivalentDomains JSON (falling back to [])");
                "[]".to_string()
            }
        }
    }
}

/// GET /api/settings/domains
///
/// Equivalent domains (eq_domains) are used by clients to treat some domains as interchangeable
/// for URI matching (e.g. `google.com` vs `youtube.com` in predefined "global" groups).
///
/// Vaultwarden persists per-user:
/// - `equivalentDomains`: custom groups set by the user
/// - `excludedGlobalEquivalentDomains`: which predefined groups are disabled
///
/// This server persists only the per-user settings in `users`.
/// The optional global dataset can be seeded into D1 (see README), and will then be
/// included in responses without parsing the large JSON in the Worker.
#[worker::send]
pub async fn get_domains(claims: Claims, State(env): State<Arc<Env>>) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;

    let row: Option<Value> = db
        .prepare("SELECT equivalent_domains, excluded_globals FROM users WHERE id = ?1")
        .bind(&[claims.sub.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let row = row.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let equivalent_domains = row
        .get("equivalent_domains")
        .and_then(|v| v.as_str())
        .unwrap_or("[]");
    let excluded_globals = row
        .get("excluded_globals")
        .and_then(|v| v.as_str())
        .unwrap_or("[]");

    // Include ALL global groups and mark `excluded` (settings UI semantics).
    // Falls back to [] if the dataset isn't seeded yet.
    let global_equivalent_domains =
        global_equivalent_domains_json(&db, excluded_globals, true).await;

    let response = format!(
        r#"{{"equivalentDomains":{},"globalEquivalentDomains":{},"object":"domains"}}"#,
        equivalent_domains, global_equivalent_domains
    );
    Ok(RawJson(response))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivDomainData {
    pub excluded_global_equivalent_domains: Option<Vec<i32>>,
    pub equivalent_domains: Option<Vec<Vec<String>>>,
}

/// POST /api/settings/domains
///
/// Persist per-user eq_domains settings (no notifications/push).
#[worker::send]
pub async fn post_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let excluded_globals = payload
        .excluded_global_equivalent_domains
        .unwrap_or_default();
    let equivalent_domains = payload.equivalent_domains.unwrap_or_default();

    let excluded_globals_json = serde_json::to_string(&excluded_globals)
        .map_err(|_| AppError::BadRequest("Invalid excluded globals".to_string()))?;
    let equivalent_domains_json = serde_json::to_string(&equivalent_domains)
        .map_err(|_| AppError::BadRequest("Invalid equivalent domains".to_string()))?;

    let now = db::now_string();
    query!(
        &db,
        "UPDATE users SET equivalent_domains = ?1, excluded_globals = ?2, updated_at = ?3 WHERE id = ?4",
        equivalent_domains_json,
        excluded_globals_json,
        now,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    notifications::publish_user_update(
        env.as_ref(),
        &claims.sub,
        UpdateType::SyncSettings,
        &now,
        Some(&claims.device),
    )
    .await;

    Ok(Json(json!({})))
}

/// PUT /api/settings/domains
///
/// Behaves like POST.
#[worker::send]
pub async fn put_domains(
    claims: Claims,
    State(env): State<Arc<Env>>,
    payload: Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    post_domains(claims, State(env), payload).await
}
