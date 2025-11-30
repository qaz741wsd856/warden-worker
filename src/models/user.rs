use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};

use crate::{crypto::verify_password, error::AppError};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub email: String,
    #[serde(with = "bool_from_int")]
    pub email_verified: bool,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub password_salt: Option<String>, // Salt for server-side PBKDF2 (NULL for legacy users)
    pub key: String,
    pub private_key: String,
    pub public_key: String,
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub security_stamp: String,
    pub totp_recover: Option<String>, // Recovery code for 2FA
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
    pub async fn verify_master_password(
        &self,
        provided_hash: &str,
    ) -> Result<PasswordVerification, AppError> {
        if let Some(ref salt) = self.password_salt {
            let is_valid = verify_password(provided_hash, &self.master_password_hash, salt).await?;
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
}

// For /accounts/register request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub email: String,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub user_symmetric_key: String,
    pub user_asymmetric_keys: KeyData,
    pub kdf: i32,
    pub kdf_iterations: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    pub public_key: String,
    pub encrypted_private_key: String,
}

// For DELETE /accounts request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateFolderData {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow an Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    pub id: Option<String>,
    pub name: String,
}
