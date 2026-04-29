use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use worker::{query, D1Database};

use crate::{db, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub identifier: String,
    pub user_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub push_uuid: Option<String>,
    pub push_token: Option<String>,
    pub refresh_token: String,
    pub twofactor_remember: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Device {
    pub fn new(
        identifier: String,
        user_id: String,
        name: String,
        r#type: i32,
    ) -> Result<Self, AppError> {
        let now = db::now_string();
        Ok(Self {
            identifier,
            user_id,
            name,
            r#type,
            push_uuid: None,
            push_token: None,
            refresh_token: generate_refresh_token()?,
            twofactor_remember: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": &self.identifier,
            "name": &self.name,
            "type": self.r#type,
            "identifier": &self.identifier,
            "creationDate": &self.created_at,
            "isTrusted": false,
            "object": "device"
        })
    }

    pub async fn list_by_user(db: &D1Database, user_id: &str) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = query!(
            db,
            "SELECT * FROM devices WHERE user_id = ?1 ORDER BY updated_at DESC, created_at DESC",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

        rows.into_iter()
            .map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
            .collect()
    }

    pub async fn find_by_identifier_and_user(
        db: &D1Database,
        identifier: &str,
        user_id: &str,
    ) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = query!(
            db,
            "SELECT * FROM devices WHERE identifier = ?1 AND user_id = ?2",
            identifier,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

        row.map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub async fn find_by_refresh_token(
        db: &D1Database,
        refresh_token: &str,
    ) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = query!(
            db,
            "SELECT * FROM devices WHERE refresh_token = ?1",
            refresh_token
        )
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

        row.map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub fn is_push_device(&self) -> bool {
        matches!(
            DeviceType::from_i32(self.r#type),
            DeviceType::Android | DeviceType::Ios
        )
    }

    pub async fn insert(&self, db: &D1Database) -> Result<(), AppError> {
        query!(
            db,
            "INSERT INTO devices (identifier, user_id, name, type, push_uuid, push_token, refresh_token, twofactor_remember, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &self.identifier,
            &self.user_id,
            &self.name,
            self.r#type,
            self.push_uuid.as_deref(),
            self.push_token.as_deref(),
            &self.refresh_token,
            self.twofactor_remember.as_deref(),
            &self.created_at,
            &self.updated_at
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        Ok(())
    }

    pub async fn get_or_create(
        db: &D1Database,
        identifier: String,
        user_id: String,
        name: String,
        r#type: i32,
    ) -> Result<Self, AppError> {
        if let Some(mut device) =
            Self::find_by_identifier_and_user(db, &identifier, &user_id).await?
        {
            if device.name != name || device.r#type != r#type {
                let now = db::now_string();
                query!(
                    db,
                    "UPDATE devices SET name = ?1, type = ?2, updated_at = ?3 WHERE identifier = ?4 AND user_id = ?5",
                    &name,
                    r#type,
                    &now,
                    &identifier,
                    &user_id
                )
                .map_err(|_| AppError::Database)?
                .run()
                .await
                .map_err(|_| AppError::Database)?;
                device.name = name;
                device.r#type = r#type;
                device.updated_at = now;
            }

            return Ok(device);
        }

        let device = Self::new(identifier, user_id, name, r#type)?;
        device.insert(db).await?;
        Ok(device)
    }

    pub async fn touch(&mut self, db: &D1Database) -> Result<(), AppError> {
        let now = db::now_string();
        query!(
            db,
            "UPDATE devices SET updated_at = ?1 WHERE identifier = ?2 AND user_id = ?3",
            &now,
            &self.identifier,
            &self.user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        self.updated_at = now;
        Ok(())
    }

    pub async fn set_push_token(
        &mut self,
        db: &D1Database,
        push_token: Option<&str>,
    ) -> Result<(), AppError> {
        let now = db::now_string();
        query!(
            db,
            "UPDATE devices SET push_token = ?1, updated_at = ?2 WHERE identifier = ?3 AND user_id = ?4",
            push_token,
            &now,
            &self.identifier,
            &self.user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        self.push_token = push_token.map(str::to_owned);
        self.updated_at = now;
        Ok(())
    }

    pub async fn persist_push_uuid(&mut self, db: &D1Database) -> Result<(), AppError> {
        let now = db::now_string();
        query!(
            db,
            "UPDATE devices SET push_uuid = ?1, updated_at = ?2 WHERE identifier = ?3 AND user_id = ?4",
            self.push_uuid.as_deref(),
            &now,
            &self.identifier,
            &self.user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        self.updated_at = now;
        Ok(())
    }

    pub async fn set_twofactor_remember(
        &mut self,
        db: &D1Database,
        twofactor_remember: Option<&str>,
    ) -> Result<(), AppError> {
        let now = db::now_string();
        query!(
            db,
            "UPDATE devices SET twofactor_remember = ?1, updated_at = ?2 WHERE identifier = ?3 AND user_id = ?4",
            twofactor_remember,
            &now,
            &self.identifier,
            &self.user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        self.twofactor_remember = twofactor_remember.map(str::to_owned);
        self.updated_at = now;
        Ok(())
    }

    /// Delete all device rows for a user, effectively revoking all refresh tokens and
    /// logging out every active session.
    pub async fn delete_all_by_user(db: &D1Database, user_id: &str) -> Result<(), AppError> {
        query!(db, "DELETE FROM devices WHERE user_id = ?1", user_id)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
}

fn generate_refresh_token() -> Result<String, AppError> {
    let mut bytes = [0u8; 64];
    getrandom::fill(&mut bytes)
        .map_err(|err| AppError::Crypto(format!("Failed to generate refresh token: {err}")))?;
    Ok(URL_SAFE.encode(bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DeviceType {
    Android = 0,
    Ios = 1,
    ChromeExtension = 2,
    FirefoxExtension = 3,
    OperaExtension = 4,
    EdgeExtension = 5,
    WindowsDesktop = 6,
    MacOsDesktop = 7,
    LinuxDesktop = 8,
    ChromeBrowser = 9,
    FirefoxBrowser = 10,
    OperaBrowser = 11,
    EdgeBrowser = 12,
    IEBrowser = 13,
    UnknownBrowser = 14,
    AndroidAmazon = 15,
    Uwp = 16,
    SafariBrowser = 17,
    VivaldiBrowser = 18,
    VivaldiExtension = 19,
    SafariExtension = 20,
    Sdk = 21,
    Server = 22,
    WindowsCli = 23,
    MacOsCli = 24,
    LinuxCli = 25,
}

impl DeviceType {
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Android,
            1 => Self::Ios,
            2 => Self::ChromeExtension,
            3 => Self::FirefoxExtension,
            4 => Self::OperaExtension,
            5 => Self::EdgeExtension,
            6 => Self::WindowsDesktop,
            7 => Self::MacOsDesktop,
            8 => Self::LinuxDesktop,
            9 => Self::ChromeBrowser,
            10 => Self::FirefoxBrowser,
            11 => Self::OperaBrowser,
            12 => Self::EdgeBrowser,
            13 => Self::IEBrowser,
            14 => Self::UnknownBrowser,
            15 => Self::AndroidAmazon,
            16 => Self::Uwp,
            17 => Self::SafariBrowser,
            18 => Self::VivaldiBrowser,
            19 => Self::VivaldiExtension,
            20 => Self::SafariExtension,
            21 => Self::Sdk,
            22 => Self::Server,
            23 => Self::WindowsCli,
            24 => Self::MacOsCli,
            25 => Self::LinuxCli,
            _ => Self::UnknownBrowser,
        }
    }

    /// Normalize the client-supplied device type to the Bitwarden enum value.
    ///
    /// Bitwarden clients are inconsistent here: on iOS, `device_type` is sent as the literal
    /// string `"iOS"`, while most other clients send a number.
    /// We accept both forms and fall back to `Unknown Browser` (`14`) for anything invalid.
    pub fn from_str(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::UnknownBrowser;
        }

        if let Ok(value) = trimmed.parse::<i32>() {
            return Self::from_i32(value);
        }

        match trimmed.to_ascii_lowercase().as_str() {
            "android" => Self::Android,
            "ios" => Self::Ios,
            "chrome extension" => Self::ChromeExtension,
            "firefox extension" => Self::FirefoxExtension,
            "opera extension" => Self::OperaExtension,
            "edge extension" => Self::EdgeExtension,
            "windows" | "windows desktop" => Self::WindowsDesktop,
            "macos" | "macos desktop" => Self::MacOsDesktop,
            "linux" | "linux desktop" => Self::LinuxDesktop,
            "chrome" => Self::ChromeBrowser,
            "firefox" => Self::FirefoxBrowser,
            "opera" => Self::OperaBrowser,
            "edge" => Self::EdgeBrowser,
            "internet explorer" | "ie" => Self::IEBrowser,
            "unknown browser" => Self::UnknownBrowser,
            "uwp" => Self::Uwp,
            "safari" => Self::SafariBrowser,
            "vivaldi" => Self::VivaldiBrowser,
            "vivaldi extension" => Self::VivaldiExtension,
            "safari extension" => Self::SafariExtension,
            "sdk" => Self::Sdk,
            "server" => Self::Server,
            "windows cli" => Self::WindowsCli,
            "macos cli" => Self::MacOsCli,
            "linux cli" => Self::LinuxCli,
            _ => Self::UnknownBrowser,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Android => "Android",
            Self::Ios => "iOS",
            Self::ChromeExtension => "Chrome Extension",
            Self::FirefoxExtension => "Firefox Extension",
            Self::OperaExtension => "Opera Extension",
            Self::EdgeExtension => "Edge Extension",
            Self::WindowsDesktop => "Windows",
            Self::MacOsDesktop => "macOS",
            Self::LinuxDesktop => "Linux",
            Self::ChromeBrowser => "Chrome",
            Self::FirefoxBrowser => "Firefox",
            Self::OperaBrowser => "Opera",
            Self::EdgeBrowser => "Edge",
            Self::IEBrowser => "Internet Explorer",
            Self::UnknownBrowser => "Unknown Browser",
            Self::AndroidAmazon => "Android",
            Self::Uwp => "UWP",
            Self::SafariBrowser => "Safari",
            Self::VivaldiBrowser => "Vivaldi",
            Self::VivaldiExtension => "Vivaldi Extension",
            Self::SafariExtension => "Safari Extension",
            Self::Sdk => "SDK",
            Self::Server => "Server",
            Self::WindowsCli => "Windows CLI",
            Self::MacOsCli => "macOS CLI",
            Self::LinuxCli => "Linux CLI",
        }
    }

    pub fn as_i32(self) -> i32 {
        self as i32
    }
}
