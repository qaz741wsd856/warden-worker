use axum::extract::{Query, State};
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::Claims,
    db,
    error::AppError,
    handlers::{
        attachments, ciphers, ciphers_default_row_query, domains, sync_response_prealloc_bytes,
        two_factor_enabled,
    },
    models::{
        folder::{Folder, FolderResponse},
        sync::Profile,
        user::User,
    },
};

use ciphers::RawJson;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    /// If true, set `domains` to null (vaultwarden behavior).
    #[serde(rename = "excludeDomains", default)]
    pub exclude_domains: bool,
}

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Query(query): Query<SyncQuery>,
) -> Result<RawJson, AppError> {
    let user_id = claims.sub;
    let db = db::get_db(&env)?;

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let two_factor_enabled = two_factor_enabled(&db, &user_id).await?;

    let has_master_password = !user.master_password_hash.is_empty();
    let equivalent_domains = user.equivalent_domains.clone();
    let excluded_globals = user.excluded_globals.clone();
    let master_password_unlock = if has_master_password {
        // Mirrors vaultwarden's `ciphers::sync` casing (lower camelCase).
        // We don't support SSO, so this is always derived from the current user record.
        json!({
            "kdf": {
                "kdfType": user.kdf_type,
                "iterations": user.kdf_iterations,
                "memory": user.kdf_memory,
                "parallelism": user.kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "masterKeyEncryptedUserKey": user.key,
            "masterKeyWrappedUserKey": user.key,
            "salt": user.email
        })
    } else {
        Value::Null
    };

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    // Fetch ciphers as raw JSON array string (no parsing in Rust!)
    let include_attachments = attachments::attachments_enabled(env.as_ref());
    let force_row_query = ciphers_default_row_query(env.as_ref());

    // Serialize profile and folders (small data, acceptable CPU cost)
    let mut profile = Profile::from_user(user, two_factor_enabled)?;
    // Match vaultwarden semantics: `_status` is `Invited` when no master password is set.
    // We don't implement org invitations, but this helps clients interpret the account state.
    profile.status = if has_master_password { 0 } else { 1 };
    let profile_json = serde_json::to_string(&profile).map_err(|_| AppError::Internal)?;
    let folders_json = serde_json::to_string(&folders).map_err(|_| AppError::Internal)?;

    // Build response JSON via string concatenation (ciphers already raw JSON)
    let user_decryption_json = serde_json::to_string(&json!({
        "masterPasswordUnlock": master_password_unlock
    }))
    .map_err(|_| AppError::Internal)?;

    const DEFAULT_SYNC_RESPONSE_PREALLOC_BYTES: usize = 1024 * 1024;

    let capacity = sync_response_prealloc_bytes(env.as_ref())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_SYNC_RESPONSE_PREALLOC_BYTES);

    // `/api/sync` response schema (Bitwarden-compatible):
    // {
    //   "profile": {...},
    //   "folders": [...],
    //   "collections": [],
    //   "policies": [],
    //   "ciphers": [...],
    //   "domains": {...} | null, // null when excludeDomains=true
    //   "sends": [],
    //   "userDecryption": {...},
    //   "object": "sync"
    // }
    //
    // We build this as a JSON string to avoid parsing/re-serializing the (potentially huge) ciphers array.
    let mut response = String::with_capacity(capacity);
    response.push_str("{\"profile\":");
    response.push_str(&profile_json);
    response.push_str(",\"folders\":");
    response.push_str(&folders_json);
    response.push_str(",\"collections\":[],\"policies\":[],\"ciphers\":");
    ciphers::append_cipher_json_array_raw(
        &mut response,
        &db,
        include_attachments,
        "WHERE c.user_id = ?1",
        &[user_id.clone().into()],
        "",
        force_row_query,
    )
    .await?;

    response.push_str(",\"domains\":");
    if query.exclude_domains {
        response.push_str("null");
    } else {
        // Match vaultwarden sync semantics:
        // - mark excluded in /api/settings/domains
        // - filter excluded out of sync payload
        let global_equivalent_domains =
            domains::global_equivalent_domains_json(&db, &excluded_globals, false).await;
        response.push_str("{\"equivalentDomains\":");
        response.push_str(&equivalent_domains);
        response.push_str(",\"globalEquivalentDomains\":");
        response.push_str(&global_equivalent_domains);
        response.push_str(",\"object\":\"domains\"}");
    }

    response.push_str(",\"sends\":[],\"userDecryption\":");
    response.push_str(&user_decryption_json);
    response.push_str(",\"object\":\"sync\"}");

    Ok(RawJson(response))
}
