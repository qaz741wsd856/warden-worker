pub mod accounts;
pub mod attachments;
pub mod ciphers;
pub mod config;
pub mod devices;
pub mod domains;
pub mod emergency_access;
pub mod folders;
pub mod identity;
pub mod import;
pub mod meta;
pub mod purge;
pub mod sync;
pub mod twofactor;
pub mod webauth;

/// Shared helper for reading an environment variable into usize.
pub(crate) fn get_env_usize(env: &worker::Env, var_name: &str, default: usize) -> usize {
    env.var(var_name)
        .ok()
        .and_then(|value| value.to_string().parse::<usize>().ok())
        .unwrap_or(default)
}

/// Convenience helper for cipher batch size using IMPORT_BATCH_SIZE.
pub(crate) fn get_batch_size(env: &worker::Env) -> usize {
    get_env_usize(env, "IMPORT_BATCH_SIZE", 30)
}

/// Per-user server-side PBKDF2 iterations (PASSWORD_ITERATIONS).
///
/// - Defaults to `MIN_SERVER_PBKDF2_ITERATIONS` (600k).
/// - Can be increased via env var, but will never be allowed below the minimum.
pub(crate) fn server_password_iterations(env: &worker::Env) -> u32 {
    let min = crate::crypto::MIN_SERVER_PBKDF2_ITERATIONS;

    match env.var("PASSWORD_ITERATIONS") {
        Ok(v) => {
            let raw = v.to_string();
            match raw.parse::<u32>() {
                Ok(iter) if iter >= min => iter,
                Ok(iter) => {
                    log::warn!(
                        "PASSWORD_ITERATIONS={} is below the minimum {}; clamping to {}",
                        iter,
                        min,
                        min
                    );
                    min
                }
                Err(err) => {
                    log::warn!(
                        "Invalid PASSWORD_ITERATIONS='{}' ({}); using minimum {}",
                        raw,
                        err,
                        min
                    );
                    min
                }
            }
        }
        Err(_) => min,
    }
}

/// Whether TOTP validation should allow ±1 time step drift.
/// Controlled via AUTHENTICATOR_DISABLE_TIME_DRIFT (truthy -> disable drift).
pub(crate) fn allow_totp_drift(env: &worker::Env) -> bool {
    env.var("AUTHENTICATOR_DISABLE_TIME_DRIFT")
        .ok()
        .map(|value| value.to_string().to_lowercase())
        .map(|value| !matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Whether to prefer fetching cipher JSON rows and building arrays in the Worker.
///
/// This avoids D1/SQLite `SQLITE_TOOBIG` errors when using `json_group_array` on large vaults.
/// Defaults to false (try the single-query aggregation, then fallback on `SQLITE_TOOBIG`).
pub(crate) fn ciphers_default_row_query(env: &worker::Env) -> bool {
    env.var("CIPHERS_DEFAULT_ROW_QUERY")
        .ok()
        .map(|value| value.to_string().to_lowercase())
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Optional capacity hint for building the `/api/sync` JSON response.
///
/// When set, this value is used as the initial `String` capacity (in bytes).
/// When unset (or invalid), the Worker uses a default capacity and grows as needed.
pub(crate) fn sync_response_prealloc_bytes(env: &worker::Env) -> Option<usize> {
    match env.var("SYNC_RESPONSE_PREALLOC_BYTES") {
        Ok(v) => {
            let raw = v.to_string();
            match raw.parse::<usize>() {
                Ok(value) => Some(value),
                Err(err) => {
                    log::warn!(
                        "Invalid SYNC_RESPONSE_PREALLOC_BYTES='{}' ({}); ignoring",
                        raw,
                        err
                    );
                    None
                }
            }
        }
        Err(_) => None,
    }
}

/// Whether the user has 2FA enabled.
pub(crate) async fn two_factor_enabled(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<bool, crate::error::AppError> {
    let twofactors = crate::handlers::twofactor::list_user_twofactors(db, user_id).await?;
    Ok(crate::handlers::twofactor::is_twofactor_enabled(
        &twofactors,
    ))
}
