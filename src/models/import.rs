use serde::Deserialize;

use crate::models::cipher::CipherRequestData;

/// Folder data structure for import requests.
/// Aligned with vaultwarden's FolderData.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportFolder {
    /// Optional folder ID - if provided and exists, the existing folder is used
    #[serde(default, deserialize_with = "super::deser_opt_nonempty_str")]
    pub id: Option<String>,
    pub name: String,
}

/// Relationship between cipher index and folder index in the import arrays.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FolderRelationship {
    /// Cipher index in the ciphers array
    pub key: usize,
    /// Folder index in the folders array
    pub value: usize,
}

/// Import request payload structure.
/// Aligned with vaultwarden's ImportData used in POST /ciphers/import.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub ciphers: Vec<CipherRequestData>,
    pub folders: Vec<ImportFolder>,
    #[serde(default)]
    pub folder_relationships: Vec<FolderRelationship>,
}
