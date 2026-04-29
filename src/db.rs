use crate::error::AppError;
use chrono::Utc;
use worker::{query, D1Database, D1PreparedStatement, Env, Error};

pub fn get_db(env: &Env) -> Result<D1Database, AppError> {
    env.d1("vault1").map_err(AppError::Worker)
}

/// Map D1 JSON parsing errors to 400 while leaving other errors untouched.
pub fn map_d1_json_error(err: Error) -> AppError {
    let msg = err.to_string();
    if msg.to_ascii_lowercase().contains("malformed json") {
        AppError::BadRequest("Malformed JSON in request body".to_string())
    } else {
        AppError::Worker(err)
    }
}

pub fn now_string() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// This is a helper function to update the user's `updated_at` field.
/// `now` is the current timestamp in the format "YYYY-MM-DDTHH:MM:SS.SSSZ".
/// This should be called after any operation that modifies user data (ciphers, folders, etc.)
pub async fn touch_user_updated_at(
    db: &D1Database,
    user_id: &str,
    now: &str,
) -> Result<(), AppError> {
    query!(
        db,
        "UPDATE users SET updated_at = ?1 WHERE id = ?2",
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(())
}

/// Execute D1 statements in batches, allowing batch_size 0 to run everything at once.
pub async fn execute_in_batches(
    db: &D1Database,
    statements: Vec<D1PreparedStatement>,
    batch_size: usize,
) -> Result<(), AppError> {
    if statements.is_empty() {
        return Ok(());
    }

    if batch_size == 0 {
        db.batch(statements).await?;
    } else {
        for chunk in statements.chunks(batch_size) {
            db.batch(chunk.to_vec()).await?;
        }
    }

    Ok(())
}
