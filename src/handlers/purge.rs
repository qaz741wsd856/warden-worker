//! Purge handler for cleaning up soft-deleted ciphers
//!
//! This module handles the automatic cleanup of ciphers that have been
//! soft-deleted (marked with deleted_at) for longer than the configured
//! retention period.

use crate::handlers::attachments;
use chrono::{Duration, Utc};
use std::collections::HashSet;
use worker::{query, D1Database, Env};

/// Default number of days to keep soft-deleted items before purging
const DEFAULT_PURGE_DAYS: i64 = 30;
/// Retain pending attachments for at most this many days before cleanup
const PENDING_RETENTION_DAYS: i64 = 1;

/// Get the purge threshold days from environment variable or use default
fn get_purge_days(env: &Env) -> i64 {
    env.var("TRASH_AUTO_DELETE_DAYS")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_PURGE_DAYS)
}

/// Purge pending attachments older than the configured retention window.
pub async fn purge_stale_pending_attachments(env: &Env) -> Result<u32, worker::Error> {
    let db: D1Database = env.d1("vault1")?;
    let now = Utc::now();
    let pending_cutoff = now - Duration::days(PENDING_RETENTION_DAYS);
    let pending_cutoff_str = pending_cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let pending_count_result = query!(
        &db,
        "SELECT COUNT(*) as count FROM attachments_pending WHERE created_at < ?1",
        pending_cutoff_str
    )?
    .first::<CountResult>(None)
    .await?;

    let pending_count = pending_count_result.map(|r| r.count).unwrap_or(0);

    if pending_count > 0 {
        query!(
            &db,
            "DELETE FROM attachments_pending WHERE created_at < ?1",
            pending_cutoff_str
        )?
        .run()
        .await?;
        log::info!(
            "Purged {} pending attachment(s) older than {} day(s)",
            pending_count,
            PENDING_RETENTION_DAYS
        );
    } else {
        log::info!("No pending attachments to purge");
    }

    Ok(pending_count)
}

/// Purge soft-deleted ciphers that are older than the configured threshold.
///
/// This function:
/// 1. Calculates the cutoff timestamp based on TRASH_AUTO_DELETE_DAYS env var (default: 30 days)
/// 2. Deletes all ciphers where deleted_at is not null and older than the cutoff
/// 3. Updates the affected users' updated_at to trigger client sync
/// 4. If TRASH_AUTO_DELETE_DAYS is set to 0 or negative, skips purging (disabled)
///
/// Returns the number of purged records on success.
pub async fn purge_deleted_ciphers(env: &Env) -> Result<u32, worker::Error> {
    let purge_days = get_purge_days(env);

    // If purge_days is 0 or negative, auto-purge is disabled
    if purge_days <= 0 {
        log::info!("Auto-purge is disabled (TRASH_AUTO_DELETE_DAYS <= 0)");
        return Ok(0);
    }

    let db: D1Database = env.d1("vault1")?;

    // Calculate the cutoff timestamp
    let now = Utc::now();
    let cutoff = now - Duration::days(purge_days);
    let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    log::info!(
        "Purging soft-deleted ciphers older than {} days (before {})",
        purge_days,
        cutoff_str
    );

    // First, get the list of affected user IDs before deletion
    let affected_users_result: Vec<AffectedUser> = query!(
        &db,
        "SELECT DISTINCT user_id FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1 AND user_id IS NOT NULL",
        cutoff_str
    )?
    .all()
    .await?
    .results()?;

    let affected_user_ids: HashSet<String> = affected_users_result
        .into_iter()
        .filter_map(|u| u.user_id)
        .collect();

    // Count the records to be deleted (for logging purposes)
    let count_result = query!(
        &db,
        "SELECT COUNT(*) as count FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
        cutoff_str
    )?
    .first::<CountResult>(None)
    .await?;

    let count = count_result.map(|r| r.count).unwrap_or(0);

    if count > 0 {
        if attachments::attachments_enabled(env) {
            let keys = attachments::list_attachment_keys_for_soft_deleted_before(&db, &cutoff_str)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            attachments::delete_storage_objects(env, &keys)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
        }

        // Delete the records
        query!(
            &db,
            "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
            cutoff_str
        )?
        .run()
        .await?;

        log::info!("Successfully purged {} soft-deleted cipher(s)", count);

        // Update the affected users' updated_at to trigger client sync
        for user_id in &affected_user_ids {
            query!(
                &db,
                "UPDATE users SET updated_at = ?1 WHERE id = ?2",
                now_str,
                user_id
            )?
            .run()
            .await?;
        }

        log::info!(
            "Updated revision date for {} affected user(s)",
            affected_user_ids.len()
        );
    } else {
        log::info!("No soft-deleted ciphers to purge");
    }

    Ok(count)
}

/// Helper struct for affected user query result
#[derive(serde::Deserialize)]
struct AffectedUser {
    user_id: Option<String>,
}

/// Helper struct for count query result
#[derive(serde::Deserialize)]
struct CountResult {
    count: u32,
}
