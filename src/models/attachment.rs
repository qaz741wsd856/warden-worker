use serde::{Deserialize, Serialize};
use worker::{query, D1Database};

use crate::{db, error::AppError};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttachmentDB {
    pub id: String,
    pub cipher_id: String,
    pub file_name: String,
    pub file_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub akey: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub file_name: String,
    pub size: String,
    pub size_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub object: String,
}

impl AttachmentDB {
    pub fn r2_key(&self) -> String {
        format!("{}/{}", self.cipher_id, self.id)
    }

    /// Atomically move a pending attachment record into the attachments table,
    /// delete the pending row, and touch cipher `updated_at` timestamps.
    /// Returns the `now` timestamp used.
    pub async fn finalize_pending(&mut self, db: &D1Database) -> Result<String, AppError> {
        let now = db::now_string();
        if self.created_at.is_empty() {
            self.created_at = now.clone();
        }
        self.updated_at = now.clone();

        db.batch(vec![
            query!(
                db,
                "INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                self.id,
                self.cipher_id,
                self.file_name,
                self.file_size,
                self.akey,
                self.created_at,
                self.updated_at,
                self.organization_id
            )
            .map_err(|_| AppError::Database)?,
            query!(db, "DELETE FROM attachments_pending WHERE id = ?1", self.id)
                .map_err(|_| AppError::Database)?,
            query!(db, "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2", &now, self.cipher_id)
                .map_err(|_| AppError::Database)?,
        ])
        .await?;

        Ok(now)
    }

    pub fn to_response(&self, url: Option<String>) -> AttachmentResponse {
        AttachmentResponse {
            id: self.id.clone(),
            url,
            file_name: self.file_name.clone(),
            size: self.file_size.to_string(),
            size_name: display_size(self.file_size),
            key: self.akey.clone(),
            object: "attachment".to_string(),
        }
    }
}

pub fn display_size(bytes: i64) -> String {
    if bytes < 0 {
        return "0 B".to_string();
    }

    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    format!("{:.2} {}", size, UNITS[unit])
}
