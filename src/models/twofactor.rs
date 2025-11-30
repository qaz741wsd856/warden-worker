use serde::{Deserialize, Serialize};

/// Two-factor authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TwoFactorType {
    Authenticator = 0, // TOTP
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    Webauthn = 7,
    RecoveryCode = 8,
}

impl TwoFactorType {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(TwoFactorType::Authenticator),
            1 => Some(TwoFactorType::Email),
            2 => Some(TwoFactorType::Duo),
            3 => Some(TwoFactorType::YubiKey),
            4 => Some(TwoFactorType::U2f),
            5 => Some(TwoFactorType::Remember),
            6 => Some(TwoFactorType::OrganizationDuo),
            7 => Some(TwoFactorType::Webauthn),
            8 => Some(TwoFactorType::RecoveryCode),
            _ => None,
        }
    }
}

/// TwoFactor database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub uuid: String,
    pub user_uuid: String,
    pub atype: i32,
    #[serde(with = "bool_from_int")]
    pub enabled: bool,
    pub data: String,
    pub last_used: i64,
}

impl TwoFactor {
    pub fn new(user_uuid: String, atype: TwoFactorType, data: String) -> Self {
        Self {
            uuid: uuid::Uuid::new_v4().to_string(),
            user_uuid,
            atype: atype as i32,
            enabled: true,
            data,
            last_used: 0,
        }
    }

    pub fn to_json_provider(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "type": self.atype,
            "object": "twoFactorProvider"
        })
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

// Request/Response types for 2FA endpoints

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    pub key: String,
    pub token: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorData {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverTwoFactor {
    pub master_password_hash: String,
    pub email: String,
    pub recovery_code: String,
}

