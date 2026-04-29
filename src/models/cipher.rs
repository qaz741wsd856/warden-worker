use std::collections::HashMap;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::models::attachment::AttachmentResponse;

// Cipher types:
//   Login = 1,
//   SecureNote = 2,
//   Card = 3,
//   Identity = 4,
//   SshKey = 5

/// Common cipher type-specific fields shared across multiple cipher structures.
/// These represent the encrypted content fields that vary based on cipher type.
/// Used with `#[serde(flatten)]` to embed these fields into other structs.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherTypeFields {
    // Only one of these should exist, depending on cipher type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<Value>,
    // Common fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// This struct represents the data stored in the `data` column of the `ciphers` table.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherData {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub type_fields: CipherTypeFields,
}

// Custom deserialization function for booleans
fn deserialize_bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    // A visitor is used to handle different data types
    struct BoolOrIntVisitor;

    impl<'de> de::Visitor<'de> for BoolOrIntVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or an integer 0 or 1")
        }

        // Handles boolean values
        fn visit_bool<E>(self, value: bool) -> Result<bool, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        // Handles integer values (0 or 1)
        fn visit_u64<E>(self, value: u64) -> Result<bool, E>
        where
            E: de::Error,
        {
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(de::Error::invalid_value(
                    de::Unexpected::Unsigned(value),
                    &"0 or 1",
                )),
            }
        }
    }

    deserializer.deserialize_any(BoolOrIntVisitor)
}

// Custom deserialization function for cipher types
fn deserialize_cipher_type<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = i32::deserialize(deserializer)?;
    match value {
        1..=5 => Ok(value), // Valid cipher types: Login, SecureNote, Card, Identity, SshKey
        _ => Err(de::Error::invalid_value(
            de::Unexpected::Signed(value as i64),
            &"a valid cipher type (1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SshKey)",
        )),
    }
}

// The struct that is stored in the database and used in handlers.
// For serialization to JSON for the client, we implement a custom `Serialize`.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub data: Value,
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,

    // Bitwarden specific field for API responses
    #[serde(default = "default_object")]
    pub object: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub organization_use_totp: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub edit: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub view_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attachments: Option<Vec<AttachmentResponse>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherDBModel {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub r#type: i32,
    pub data: String,
    pub favorite: i32,
    pub folder_id: Option<String>,
    pub deleted_at: Option<String>,
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<CipherDBModel> for Cipher {
    fn from(val: CipherDBModel) -> Self {
        Cipher {
            id: val.id,
            user_id: Some(val.user_id),
            organization_id: val.organization_id,
            r#type: val.r#type,
            data: serde_json::from_str(&val.data).unwrap_or_default(),
            favorite: val.favorite != 0,
            folder_id: val.folder_id,
            deleted_at: val.deleted_at,
            archived_at: val.archived_at,
            created_at: val.created_at,
            updated_at: val.updated_at,
            object: default_object(),
            organization_use_totp: false,
            edit: true,
            view_password: true,
            collection_ids: None,
            attachments: None,
        }
    }
}

impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut response_map = Map::new();

        response_map.insert("object".to_string(), json!(self.object));
        response_map.insert("id".to_string(), json!(self.id));
        if self.user_id.is_some() {
            response_map.insert("userId".to_string(), json!(self.user_id));
        }
        response_map.insert("organizationId".to_string(), json!(self.organization_id));
        response_map.insert("folderId".to_string(), json!(self.folder_id));
        response_map.insert("type".to_string(), json!(self.r#type));
        response_map.insert("favorite".to_string(), json!(self.favorite));
        response_map.insert("edit".to_string(), json!(self.edit));
        response_map.insert("viewPassword".to_string(), json!(self.view_password));
        // new key "permissions" used by clients since v2025.6.0
        response_map.insert(
            "permissions".to_string(),
            json! ({
                "delete": self.edit,   // if edit is true, allow delete
                "restore": self.edit,  // if edit is true, allow restore
            }),
        );
        response_map.insert(
            "organizationUseTotp".to_string(),
            json!(self.organization_use_totp),
        );
        response_map.insert(
            "collectionIds".to_string(),
            json!(&self.collection_ids.as_deref().unwrap_or(&[])),
        );
        response_map.insert("revisionDate".to_string(), json!(self.updated_at));
        response_map.insert("creationDate".to_string(), json!(self.created_at));
        response_map.insert("deletedDate".to_string(), json!(self.deleted_at));
        response_map.insert("archivedDate".to_string(), json!(self.archived_at));
        response_map.insert("attachments".to_string(), json!(self.attachments));

        if let Some(data_obj) = self.data.as_object() {
            let data_clone = data_obj.clone();

            response_map.insert(
                "name".to_string(),
                data_clone.get("name").cloned().unwrap_or(Value::Null),
            );
            response_map.insert(
                "notes".to_string(),
                data_clone.get("notes").cloned().unwrap_or(Value::Null),
            );
            response_map.insert(
                "fields".to_string(),
                data_clone
                    .get("fields")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
            response_map.insert(
                "passwordHistory".to_string(),
                data_clone
                    .get("passwordHistory")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
            response_map.insert(
                "reprompt".to_string(),
                data_clone
                    .get("reprompt")
                    .cloned()
                    .unwrap_or(Value::Number(serde_json::Number::from_f64(0.0).unwrap())),
            );
            response_map.insert(
                "key".to_string(),
                data_clone.get("key").cloned().unwrap_or(Value::Null),
            );

            let mut login = Value::Null;
            let mut secure_note = Value::Null;
            let mut card = Value::Null;
            let mut identity = Value::Null;
            let mut ssh_key = Value::Null;

            match self.r#type {
                1 => login = data_clone.get("login").cloned().unwrap_or(Value::Null),
                2 => secure_note = data_clone.get("secureNote").cloned().unwrap_or(Value::Null),
                3 => card = data_clone.get("card").cloned().unwrap_or(Value::Null),
                4 => identity = data_clone.get("identity").cloned().unwrap_or(Value::Null),
                5 => ssh_key = data_clone.get("sshKey").cloned().unwrap_or(Value::Null),
                _ => {}
            }

            response_map.insert("login".to_string(), login);
            response_map.insert("secureNote".to_string(), secure_note);
            response_map.insert("card".to_string(), card);
            response_map.insert("identity".to_string(), identity);
            response_map.insert("sshKey".to_string(), ssh_key);
        } else {
            response_map.insert("name".to_string(), Value::Null);
            response_map.insert("notes".to_string(), Value::Null);
            response_map.insert("fields".to_string(), json!([]));
            response_map.insert("passwordHistory".to_string(), json!([]));
            response_map.insert("reprompt".to_string(), Value::Null);
            response_map.insert("login".to_string(), Value::Null);
            response_map.insert("secureNote".to_string(), Value::Null);
            response_map.insert("card".to_string(), Value::Null);
            response_map.insert("identity".to_string(), Value::Null);
            response_map.insert("sshKey".to_string(), Value::Null);
        }

        Value::Object(response_map).serialize(serializer)
    }
}

fn default_object() -> String {
    "cipherDetails".to_string()
}

fn default_true() -> bool {
    true
}

/// Represents the "Cipher" object within incoming request payloads.
/// Used for create, update, import, and key rotation scenarios.
/// Aligned with vaultwarden's CipherData structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequestData {
    // Id is optional as it is included only in bulk share / key rotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    // Folder id is not included in import (determined by folder_relationships)
    #[serde(default, deserialize_with = "super::deser_opt_nonempty_str")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(alias = "organizationID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    #[serde(deserialize_with = "deserialize_cipher_type")]
    pub r#type: i32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(flatten)]
    pub type_fields: CipherTypeFields,
    /// Used during key rotation to update attachment keys and encrypted filenames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments2: Option<HashMap<String, Attachments2Data>>,
    // The revision datetime (in ISO 8601 format) of the client's local copy
    // Used to prevent updating a cipher when client doesn't have the latest version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_revision_date: Option<String>,
}

/// Attachment metadata sent by clients during key rotation.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Attachments2Data {
    pub file_name: String,
    pub key: String,
}

/// Represents the full request payload for creating a cipher with collections.
/// Supports both camelCase and PascalCase for compatibility with different clients.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCipherRequest {
    #[serde(alias = "Cipher")]
    pub cipher: CipherRequestData,
    #[serde(default)]
    #[serde(alias = "CollectionIds")]
    pub collection_ids: Vec<String>,
}

/// Response for listing ciphers (GET /api/ciphers)
/// Now we don't use this struct, we use RawJson instead. But we keep it here for reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct CipherListResponse {
    pub data: Vec<Value>,
    pub object: String,
    pub continuation_token: Option<String>,
}

/// Request body for updating a cipher partially (PUT /api/ciphers/{id}/partial)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialCipherData {
    #[serde(default, deserialize_with = "super::deser_opt_nonempty_str")]
    pub folder_id: Option<String>,
    pub favorite: bool,
}
