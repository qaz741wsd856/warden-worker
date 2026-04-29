use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use worker::{query, D1Database};

use crate::handlers::attachments::NumberOrString;
use crate::models::attachment::display_size;
use crate::{db, error::AppError};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SendType {
    Text = 0,
    File = 1,
}

pub enum SendAuthType {
    #[allow(dead_code)]
    Email = 0, // Not supported
    Password = 1,
    None = 2,
}

pub const SEND_INACCESSIBLE_MSG: &str = "Send does not exist or is no longer available";

const SEND_PBKDF2_ITERATIONS: u32 = 100_000;

// ── DB row struct (shared by `sends` and `sends_pending` tables) ────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendDB {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub notes: Option<String>,
    #[serde(rename = "type")]
    pub send_type: i32,
    pub data: String,
    pub akey: String,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub password_iter: Option<i32>,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub created_at: String,
    pub updated_at: String,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: i32,
    pub hide_email: i32,
}

// ── Constructor & field mutators ────────────────────────────────────

impl SendDB {
    pub fn new(
        user_id: String,
        send_type: i32,
        name: String,
        data: String,
        akey: String,
        deletion_date: String,
    ) -> Self {
        let now = db::now_string();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            name,
            notes: None,
            send_type,
            data,
            akey,
            password_hash: None,
            password_salt: None,
            password_iter: None,
            max_access_count: None,
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            expiration_date: None,
            deletion_date,
            disabled: 0,
            hide_email: 0,
        }
    }

    /// Hash and store a password, or clear it when `None`.
    /// Uses Web Crypto PBKDF2
    pub async fn set_password(&mut self, password: Option<&str>) -> Result<(), AppError> {
        match password.filter(|p| !p.is_empty()) {
            Some(pw) => {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

                let mut salt_bytes = [0u8; 16];
                getrandom::fill(&mut salt_bytes)
                    .map_err(|_| AppError::Crypto("RNG failed".into()))?;

                let dk = crate::crypto::webcrypto_pbkdf2_sha256(
                    pw.as_bytes(),
                    &salt_bytes,
                    SEND_PBKDF2_ITERATIONS,
                    256,
                )
                .await?;

                self.password_hash = Some(URL_SAFE_NO_PAD.encode(&dk));
                self.password_salt = Some(URL_SAFE_NO_PAD.encode(salt_bytes));
                self.password_iter = Some(SEND_PBKDF2_ITERATIONS as i32);
            }
            None => {
                self.password_hash = None;
                self.password_salt = None;
                self.password_iter = None;
            }
        }
        Ok(())
    }

    /// Verify a password against the stored hash.
    pub async fn check_password(&self, password: &str) -> Result<bool, AppError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use constant_time_eq::constant_time_eq;

        let (Some(hash), Some(salt), Some(iter)) =
            (&self.password_hash, &self.password_salt, self.password_iter)
        else {
            return Ok(false);
        };

        let salt_bytes = URL_SAFE_NO_PAD
            .decode(salt)
            .map_err(|_| AppError::Crypto("Invalid password salt".into()))?;

        let dk = crate::crypto::webcrypto_pbkdf2_sha256(
            password.as_bytes(),
            &salt_bytes,
            iter as u32,
            256,
        )
        .await?;

        let computed = URL_SAFE_NO_PAD.encode(&dk);
        Ok(constant_time_eq(computed.as_bytes(), hash.as_bytes()))
    }

    pub fn has_password(&self) -> bool {
        self.password_hash.is_some()
    }

    /// Validate that this send can be accessed.
    pub fn validate_access(&self) -> Result<(), AppError> {
        if self.disabled != 0 {
            return Err(inaccessible_error());
        }

        let now = db::now_string();

        if self.deletion_date <= now {
            return Err(inaccessible_error());
        }

        if let Some(ref exp) = self.expiration_date {
            if exp <= &now {
                return Err(inaccessible_error());
            }
        }

        if let Some(max) = self.max_access_count {
            if self.access_count >= max {
                return Err(inaccessible_error());
            }
        }

        Ok(())
    }

    /// Extract file_id from the `data` JSON (file-type sends only).
    pub fn file_id(&self) -> Option<String> {
        if self.send_type != SendType::File as i32 {
            return None;
        }
        serde_json::from_str::<Value>(&self.data)
            .ok()
            .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
    }

    /// Storage key for file sends: `sends/{id}/{file_id}`.
    pub fn storage_key(&self) -> Option<String> {
        self.file_id().map(|fid| format!("sends/{}/{fid}", self.id))
    }
}

// ── JSON serialization ──────────────────────────────────────────────

/// Lowercase the first character of all object keys (recursive), matching
/// Vaultwarden's `LowerCase` deserialization for client interop.
fn lowercase_first_char_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let new_key = lowercase_first_char(&k);
                new_map.insert(new_key, lowercase_first_char_keys(v));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(lowercase_first_char_keys).collect()),
        other => other,
    }
}

fn lowercase_first_char(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

impl SendDB {
    /// Convert `size` to string for mobile client compatibility and backfill
    /// `sizeName` using Vaultwarden's display format.
    fn normalize_data(data: &mut Value) {
        let size = data.get("size").and_then(|value| match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.parse::<i64>().ok(),
            _ => None,
        });

        if let (Some(size), Some(object)) = (size, data.as_object_mut()) {
            object.insert("size".into(), Value::String(size.to_string()));
            object.insert("sizeName".into(), Value::String(display_size(size)));
        }
    }

    pub fn to_json(&self) -> Value {
        let mut data: Value = serde_json::from_str(&self.data)
            .map(lowercase_first_char_keys)
            .unwrap_or(Value::Null);
        Self::normalize_data(&mut data);

        serde_json::json!({
            "id": self.id,
            "accessId": access_id_from_uuid(&self.id),
            "type": self.send_type,
            "name": self.name,
            "notes": self.notes,
            "text": if self.send_type == SendType::Text as i32 { Some(&data) } else { None },
            "file": if self.send_type == SendType::File as i32 { Some(&data) } else { None },
            "key": self.akey,
            "maxAccessCount": self.max_access_count,
            "accessCount": self.access_count,
            "revisionDate": self.updated_at,
            "expirationDate": self.expiration_date,
            "deletionDate": self.deletion_date,
            "disabled": self.disabled != 0,
            "hideEmail": self.hide_email != 0,
            "password": self.password_hash,
            "authType": if self.password_hash.is_some() { SendAuthType::Password as i32 } else { SendAuthType::None as i32 },
            "object": "send",
        })
    }

    pub fn to_access_json(&self, creator_identifier: Option<&str>) -> Value {
        let mut data: Value = serde_json::from_str(&self.data)
            .map(lowercase_first_char_keys)
            .unwrap_or(Value::Null);
        Self::normalize_data(&mut data);

        serde_json::json!({
            "id": self.id,
            "type": self.send_type,
            "name": self.name,
            "text": if self.send_type == SendType::Text as i32 { Some(&data) } else { None },
            "file": if self.send_type == SendType::File as i32 { Some(&data) } else { None },
            "expirationDate": self.expiration_date,
            "creatorIdentifier": creator_identifier,
            "object": "send-access",
        })
    }
}

// ── DB operations on `sends` table ──────────────────────────────────

impl SendDB {
    pub async fn insert(&self, db: &D1Database) -> Result<(), AppError> {
        query!(
            db,
            "INSERT INTO sends (id, user_id, name, notes, type, data, akey, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            self.id,
            self.user_id,
            self.name,
            self.notes,
            self.send_type,
            self.data,
            self.akey,
            self.password_hash,
            self.password_salt,
            self.password_iter,
            self.max_access_count,
            self.access_count,
            self.created_at,
            self.updated_at,
            self.expiration_date,
            self.deletion_date,
            self.disabled,
            self.hide_email
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        Ok(())
    }

    pub async fn update(&mut self, db: &D1Database) -> Result<(), AppError> {
        self.updated_at = db::now_string();
        query!(
            db,
            "UPDATE sends SET name = ?1, notes = ?2, data = ?3, akey = ?4, password_hash = ?5, password_salt = ?6, password_iter = ?7, max_access_count = ?8, expiration_date = ?9, deletion_date = ?10, disabled = ?11, hide_email = ?12, updated_at = ?13 WHERE id = ?14 AND user_id = ?15",
            self.name,
            self.notes,
            self.data,
            self.akey,
            self.password_hash,
            self.password_salt,
            self.password_iter,
            self.max_access_count,
            self.expiration_date,
            self.deletion_date,
            self.disabled,
            self.hide_email,
            self.updated_at,
            self.id,
            self.user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        Ok(())
    }

    pub async fn delete(&self, db: &D1Database) -> Result<(), AppError> {
        query!(
            db,
            "DELETE FROM sends WHERE id = ?1 AND user_id = ?2",
            self.id,
            self.user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        Ok(())
    }

    pub async fn increment_access_count(&mut self, db: &D1Database) -> Result<(), AppError> {
        self.access_count += 1;
        self.updated_at = db::now_string();
        query!(
            db,
            "UPDATE sends SET access_count = ?1, updated_at = ?2 WHERE id = ?3",
            self.access_count,
            self.updated_at,
            self.id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        Ok(())
    }

    // ── Finders (sends table) ───────────────────────────────────────

    pub async fn find_by_id(db: &D1Database, id: &str) -> Result<Option<Self>, AppError> {
        db.prepare("SELECT * FROM sends WHERE id = ?1")
            .bind(&[id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)
    }

    pub async fn find_by_id_and_user(
        db: &D1Database,
        id: &str,
        user_id: &str,
    ) -> Result<Option<Self>, AppError> {
        db.prepare("SELECT * FROM sends WHERE id = ?1 AND user_id = ?2")
            .bind(&[id.into(), user_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)
    }

    pub async fn find_by_access_id(
        db: &D1Database,
        access_id: &str,
    ) -> Result<Option<Self>, AppError> {
        let Ok(uuid) = uuid_from_access_id(access_id) else {
            return Ok(None);
        };
        Self::find_by_id(db, &uuid).await
    }

    pub async fn find_by_user(db: &D1Database, user_id: &str) -> Result<Vec<Self>, AppError> {
        db.prepare("SELECT * FROM sends WHERE user_id = ?1")
            .bind(&[user_id.into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(|_| AppError::Database)
    }

    pub async fn find_expired(db: &D1Database) -> Result<Vec<Self>, AppError> {
        let now = db::now_string();
        db.prepare("SELECT * FROM sends WHERE deletion_date <= ?1")
            .bind(&[now.into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(|_| AppError::Database)
    }

    /// Total file-send storage bytes used by a user (finalized + pending).
    pub async fn file_usage_by_user(db: &D1Database, user_id: &str) -> Result<i64, AppError> {
        let pending: Option<Value> = db
            .prepare("SELECT COALESCE(SUM(CAST(json_extract(data, '$.size') AS INTEGER)), 0) as total FROM sends_pending WHERE user_id = ?1")
            .bind(&[user_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        let pending_total = pending
            .and_then(|v| v.get("total").cloned())
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let finalized: Option<Value> = db
            .prepare("SELECT COALESCE(SUM(CAST(json_extract(data, '$.size') AS INTEGER)), 0) as total FROM sends WHERE user_id = ?1 AND type = 1")
            .bind(&[user_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        let finalized_total = finalized
            .and_then(|v| v.get("total").cloned())
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        Ok(pending_total + finalized_total)
    }

    pub async fn delete_all_by_user(db: &D1Database, user_id: &str) -> Result<(), AppError> {
        query!(db, "DELETE FROM sends_pending WHERE user_id = ?1", user_id)
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
        query!(db, "DELETE FROM sends WHERE user_id = ?1", user_id)
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
        Ok(())
    }

    /// Collect all storage keys for a user's file sends (finalized + pending).
    pub async fn storage_keys_by_user(
        db: &D1Database,
        user_id: &str,
    ) -> Result<Vec<String>, AppError> {
        let mut keys = Vec::new();

        let sends = Self::find_by_user(db, user_id).await?;
        for s in &sends {
            if let Some(k) = s.storage_key() {
                keys.push(k);
            }
        }

        let pending = Self::find_pending_by_user(db, user_id).await?;
        for p in &pending {
            if let Some(k) = p.storage_key() {
                keys.push(k);
            }
        }

        Ok(keys)
    }
}

// ── DB operations on `sends_pending` table ──────────────────────────

impl SendDB {
    pub async fn insert_pending(&self, db: &D1Database) -> Result<(), AppError> {
        query!(
            db,
            "INSERT INTO sends_pending (id, user_id, name, notes, type, data, akey, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            self.id,
            self.user_id,
            self.name,
            self.notes,
            self.send_type,
            self.data,
            self.akey,
            self.password_hash,
            self.password_salt,
            self.password_iter,
            self.max_access_count,
            self.access_count,
            self.created_at,
            self.updated_at,
            self.expiration_date,
            self.deletion_date,
            self.disabled,
            self.hide_email
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        Ok(())
    }

    /// Promote a pending send to finalized.
    /// Uses D1 batch to atomically DELETE from `sends_pending` and INSERT into `sends`.
    pub async fn finalize(&mut self, db: &D1Database) -> Result<(), AppError> {
        self.updated_at = db::now_string();

        let delete_stmt = query!(db, "DELETE FROM sends_pending WHERE id = ?1", self.id)
            .map_err(|_| AppError::Database)?;

        let insert_stmt = query!(
            db,
            "INSERT INTO sends (id, user_id, name, notes, type, data, akey, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            self.id,
            self.user_id,
            self.name,
            self.notes,
            self.send_type,
            self.data,
            self.akey,
            self.password_hash,
            self.password_salt,
            self.password_iter,
            self.max_access_count,
            self.access_count,
            self.created_at,
            self.updated_at,
            self.expiration_date,
            self.deletion_date,
            self.disabled,
            self.hide_email
        )
        .map_err(|_| AppError::Database)?;

        db.batch(vec![delete_stmt, insert_stmt]).await?;
        Ok(())
    }

    pub async fn find_pending_by_id_and_user(
        db: &D1Database,
        id: &str,
        user_id: &str,
    ) -> Result<Option<Self>, AppError> {
        db.prepare("SELECT * FROM sends_pending WHERE id = ?1 AND user_id = ?2")
            .bind(&[id.into(), user_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)
    }

    pub async fn find_pending_by_user(
        db: &D1Database,
        user_id: &str,
    ) -> Result<Vec<Self>, AppError> {
        db.prepare("SELECT * FROM sends_pending WHERE user_id = ?1")
            .bind(&[user_id.into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(|_| AppError::Database)
    }

    pub async fn find_stale_pending(db: &D1Database, cutoff: &str) -> Result<Vec<Self>, AppError> {
        db.prepare("SELECT * FROM sends_pending WHERE created_at < ?1")
            .bind(&[cutoff.into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(|_| AppError::Database)
    }

    pub async fn delete_stale_pending(db: &D1Database, cutoff: &str) -> Result<u32, AppError> {
        #[derive(Deserialize)]
        struct CountResult {
            count: u32,
        }
        let result = query!(
            db,
            "SELECT COUNT(*) as count FROM sends_pending WHERE created_at < ?1",
            cutoff
        )
        .map_err(|_| AppError::Database)?
        .first::<CountResult>(None)
        .await
        .map_err(|_| AppError::Database)?;
        let count = result.map(|r| r.count).unwrap_or(0);

        if count > 0 {
            query!(
                db,
                "DELETE FROM sends_pending WHERE created_at < ?1",
                cutoff
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
        }
        Ok(count)
    }
}

// ── API request structs ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequestData {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub send_type: i32,
    pub key: String,
    pub name: String,
    pub notes: Option<String>,
    pub text: Option<Value>,
    pub file: Option<Value>,
    pub file_length: Option<NumberOrString>,
    pub password: Option<String>,
    pub max_access_count: Option<NumberOrString>,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: Option<bool>,
    pub hide_email: Option<bool>,
}

const MAX_DELETION_DAYS: i64 = 31;

fn normalize_datetime(s: &str) -> Result<chrono::DateTime<Utc>, AppError> {
    use chrono::DateTime;
    DateTime::parse_from_rfc3339(s)
        .or_else(|_| DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| AppError::BadRequest(format!("Invalid date format: {s}")))
}

/// Normalize a date-time string to a consistent format matching `db::now_string()`.
fn format_normalized(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Parse and validate deletion_date / expiration_date from client strings.
/// Returns `(normalized_deletion_date, normalized_expiration_date)` on success.
pub fn validate_send_dates(
    deletion_date: &str,
    expiration_date: Option<&str>,
) -> Result<(String, Option<String>), AppError> {
    use chrono::TimeDelta;

    let del = normalize_datetime(deletion_date)
        .map_err(|_| AppError::BadRequest("Invalid deletion date format".into()))?;

    let now = Utc::now();

    if del <= now {
        return Err(AppError::BadRequest(
            "Deletion date must be in the future".into(),
        ));
    }

    let max_future =
        now + TimeDelta::try_days(MAX_DELETION_DAYS).ok_or_else(|| AppError::Internal)?;
    if del > max_future {
        return Err(AppError::BadRequest(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.".into(),
        ));
    }

    let normalized_exp = if let Some(exp_str) = expiration_date {
        let exp = normalize_datetime(exp_str)
            .map_err(|_| AppError::BadRequest("Invalid expiration date format".into()))?;

        if exp <= now {
            return Err(AppError::BadRequest(
                "Expiration date must be in the future".into(),
            ));
        }

        if exp > del {
            return Err(AppError::BadRequest(
                "Expiration date must be before deletion date".into(),
            ));
        }

        Some(format_normalized(&exp))
    } else {
        None
    };

    Ok((format_normalized(&del), normalized_exp))
}

// ── accessId helpers ────────────────────────────────────────────────

pub fn access_id_from_uuid(uuid: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let clean: String = uuid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if let Ok(bytes) = hex::decode(&clean) {
        URL_SAFE_NO_PAD.encode(bytes)
    } else {
        URL_SAFE_NO_PAD.encode(uuid.as_bytes())
    }
}

pub fn uuid_from_access_id(access_id: &str) -> Result<String, AppError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = URL_SAFE_NO_PAD
        .decode(access_id)
        .map_err(|_| AppError::BadRequest("Invalid access ID".into()))?;
    if bytes.len() != 16 {
        return Err(AppError::BadRequest("Invalid access ID length".into()));
    }
    let hex = hex::encode(&bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

// ── Error helpers ─────────────────────────────────────────────

fn inaccessible_error() -> AppError {
    AppError::NotFound(SEND_INACCESSIBLE_MSG.into())
}
