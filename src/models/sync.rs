use super::{folder::FolderResponse, user::User};
use crate::error::AppError;
use chrono::SecondsFormat;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub avatar_color: Option<String>,
    pub email: String,
    pub id: String,
    pub security_stamp: String,
    pub object: String,
    pub premium_from_organization: bool,
    pub culture: String,
    pub force_password_reset: bool,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub premium: bool,
    pub uses_key_connector: bool,
    pub creation_date: String,
    pub private_key: String,
    pub key: String,
    #[serde(default)]
    pub organizations: Vec<Value>,
    #[serde(default)]
    pub providers: Vec<Value>,
    #[serde(default)]
    pub provider_organizations: Vec<Value>,
    #[serde(rename = "_status")]
    pub status: i32,
}

impl Profile {
    pub fn from_user(user: User, two_factor_enabled: bool) -> Result<Self, AppError> {
        let creation_date = chrono::DateTime::parse_from_rfc3339(&user.created_at)
            .map_err(|_| AppError::Internal)?
            .to_rfc3339_opts(SecondsFormat::Micros, true);

        Ok(Self {
            id: user.id,
            name: user.name,
            avatar_color: user.avatar_color,
            email: user.email,
            security_stamp: user.security_stamp,
            object: "profile".to_string(),
            premium_from_organization: false,
            culture: "en-US".to_string(),
            force_password_reset: false,
            email_verified: true,
            two_factor_enabled,
            premium: true,
            uses_key_connector: false,
            creation_date,
            private_key: user.private_key,
            key: user.key,
            organizations: Vec::new(),
            providers: Vec::new(),
            provider_organizations: Vec::new(),
            status: 0,
        })
    }
}

/// Response for sync (GET /api/sync)
/// Now we don't use this struct, we use RawJson instead. But we keep it here for reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SyncResponse {
    pub profile: Profile,
    pub folders: Vec<FolderResponse>,
    #[serde(default)]
    pub collections: Vec<Value>,
    #[serde(default)]
    pub policies: Vec<Value>,
    pub ciphers: Vec<Value>,
    pub domains: Value,
    #[serde(default)]
    pub sends: Vec<Value>,
    pub object: String,
}
