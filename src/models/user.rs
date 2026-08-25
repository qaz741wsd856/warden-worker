use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::d1_query;
use crate::{crypto::verify_password, error::AppError};

fn default_json_array_string() -> String {
    "[]".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub avatar_color: Option<String>,
    pub email: String,
    #[serde(with = "bool_from_int")]
    pub email_verified: bool,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub password_salt: Option<String>, // Salt for server-side PBKDF2 (NULL for legacy users)
    pub password_iterations: i32, // Server-side PBKDF2 iterations used for master_password_hash
    pub key: String,
    pub private_key: String,
    pub public_key: String,
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>, // Argon2 memory parameter (15-1024 MB)
    pub kdf_parallelism: Option<i32>, // Argon2 parallelism parameter (1-16)
    pub security_stamp: String,
    /// JSON string of `Vec<Vec<String>>` storing user-defined equivalent domain groups.
    #[serde(default = "default_json_array_string")]
    pub equivalent_domains: String,
    /// JSON string of `Vec<i32>` storing excluded global group IDs (reserved for future global groups).
    #[serde(default = "default_json_array_string")]
    pub excluded_globals: String,
    pub totp_recover: Option<String>, // Recovery code for 2FA
    /// Personal API key for the `client_credentials` grant (`bw login --apikey`).
    ///
    /// `default` is required because users are loaded with `SELECT *` + `serde_json::from_value`:
    /// a worker deployed before migration `0014` is applied would otherwise fail to parse every
    /// user row. `skip_serializing` keeps this credential out of any struct-level serialization.
    #[serde(default, skip_serializing)]
    pub api_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerification {
    MatchCurrentScheme,
    MatchLegacyScheme,
    Mismatch,
}

impl PasswordVerification {
    pub fn is_valid(&self) -> bool {
        matches!(
            self,
            PasswordVerification::MatchCurrentScheme | PasswordVerification::MatchLegacyScheme
        )
    }

    pub fn needs_migration(&self) -> bool {
        matches!(self, PasswordVerification::MatchLegacyScheme)
    }
}

impl User {
    pub async fn find_by_email(db: &crate::db::Db, email: &str) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(db, "SELECT * FROM users WHERE email = ?1", email)
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        row.map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub async fn verify_master_password(
        &self,
        provided_hash: &str,
    ) -> Result<PasswordVerification, AppError> {
        if let Some(ref salt) = self.password_salt {
            let is_valid = verify_password(
                provided_hash,
                &self.master_password_hash,
                salt,
                self.password_iterations as u32,
            )
            .await?;
            Ok(if is_valid {
                PasswordVerification::MatchCurrentScheme
            } else {
                PasswordVerification::Mismatch
            })
        } else {
            let is_valid = constant_time_eq(
                self.master_password_hash.as_bytes(),
                provided_hash.as_bytes(),
            );

            Ok(if is_valid {
                PasswordVerification::MatchLegacyScheme
            } else {
                PasswordVerification::Mismatch
            })
        }
    }
}

mod bool_from_int {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(serde::de::Error::custom("expected integer 0 or 1")),
        }
    }

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *value {
            serializer.serialize_i64(1)
        } else {
            serializer.serialize_i64(0)
        }
    }
}

// For /accounts/prelogin response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
    pub kdf_settings: PreloginKdfSettings,
    pub salt: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginKdfSettings {
    pub iterations: i32,
    pub kdf_type: i32,
    pub memory: Option<i32>,
    pub parallelism: Option<i32>,
}

// For /accounts/register request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub email: String,
    pub master_password_hint: Option<String>,
    pub user_asymmetric_keys: KeyData,

    #[serde(flatten)]
    compat: RegisterRequestCompat,
}

impl RegisterRequest {
    pub(crate) fn master_password_hash(&self) -> &str {
        self.compat.fold(
            |legacy| &legacy.master_password_hash,
            |current| &current.master_password_authentication.hash,
        )
    }

    pub(crate) fn user_symmetric_key(&self) -> &str {
        self.compat.fold(
            |legacy| &legacy.user_symmetric_key,
            |current| &current.master_password_unlock.key,
        )
    }

    pub(crate) fn kdf(&self) -> &KdfParams {
        self.compat.fold(
            |legacy| &legacy.kdf,
            |current| &current.master_password_authentication.kdf,
        )
    }

    /// Newer clients (2026.5.0+) send separate authentication and unlock data. Both KDFs and
    /// salts must represent the same normalized email before the request is stored.
    pub(crate) fn has_valid_compat_format(&self) -> bool {
        match &self.compat {
            RegisterRequestCompat::Legacy(_) => true,
            RegisterRequestCompat::Current(current) => {
                let email = self.email.trim().to_lowercase();
                current.master_password_authentication.kdf == current.master_password_unlock.kdf
                    && current.master_password_authentication.salt == email
                    && current.master_password_unlock.salt == email
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequestLegacy {
    #[serde(flatten)]
    kdf: KdfParams,

    #[serde(alias = "key")]
    user_symmetric_key: String,

    master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequestCurrent {
    master_password_authentication: RegisterMasterPasswordAuthentication,
    master_password_unlock: RegisterMasterPasswordUnlock,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RegisterRequestCompat {
    Legacy(RegisterRequestLegacy),
    Current(RegisterRequestCurrent),
}

impl RegisterRequestCompat {
    fn fold<'a, T>(
        &'a self,
        legacy: impl FnOnce(&'a RegisterRequestLegacy) -> &'a T,
        current: impl FnOnce(&'a RegisterRequestCurrent) -> &'a T,
    ) -> &'a T {
        match self {
            Self::Legacy(legacy_data) => legacy(legacy_data),
            Self::Current(current_data) => current(current_data),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterMasterPasswordAuthentication {
    kdf: KdfParams,
    salt: String,

    #[serde(alias = "masterPasswordAuthenticationHash")]
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterMasterPasswordUnlock {
    kdf: KdfParams,
    salt: String,

    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
}

// For POST /accounts/password-hint request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHintRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    pub public_key: String,
    pub encrypted_private_key: String,
}

/// Request body for password-protected operations (delete account, purge vault, etc.)
/// Supports both master password hash and OTP verification.
/// Note: OTP verification is not implemented in this simplified version.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    #[allow(dead_code)] // OTP verification is not implemented in this simplified version
    pub otp: Option<String>,
}

// For POST /accounts/password request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub key: String,
}

// For POST /accounts/kdf request - Change KDF settings

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    #[serde(alias = "kdfType")]
    pub kdf: i32,
    #[serde(alias = "iterations")]
    pub kdf_iterations: i32,
    #[serde(alias = "memory")]
    pub kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    pub salt: String,
    pub kdf: KdfParams,
    pub master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockData {
    pub salt: String,
    pub kdf: KdfParams,
    pub master_key_wrapped_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    pub master_password_hash: String,
    pub authentication_data: AuthenticationData,
    pub unlock_data: UnlockData,
}

// For POST /accounts/key-management/rotate-user-account-keys request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateKeyRequest {
    pub account_unlock_data: RotateAccountUnlockData,
    pub account_keys: RotateAccountKeys,
    pub account_data: RotateAccountData,
    pub old_master_key_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountUnlockData {
    pub master_password_unlock_data: MasterPasswordUnlockData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlockData {
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: Option<i32>,
    pub kdf_memory: Option<i32>,
    pub email: String,
    pub master_key_authentication_hash: String,
    pub master_key_encrypted_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountKeys {
    pub user_key_encrypted_account_private_key: String,
    pub account_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountData {
    pub ciphers: Vec<crate::models::cipher::CipherRequestData>,
    pub folders: Vec<RotateFolderData>,
    #[serde(default)]
    pub sends: Vec<crate::models::send::SendRequestData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateFolderData {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow an Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    #[serde(default, deserialize_with = "super::deser_opt_nonempty_str")]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarData {
    pub avatar_color: Option<String>,
}
