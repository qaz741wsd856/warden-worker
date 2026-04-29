pub mod attachment;
pub mod cipher;
pub mod device;
pub mod folder;
pub mod import;
pub mod send;
pub mod sync;
pub mod twofactor;
pub mod user;

/// Deserialize `Option<String>` but treat `""` as `None`.
/// Newer Bitwarden clients send `""` instead of `null` for absent folder IDs.
pub fn deser_opt_nonempty_str<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(Option::<String>::deserialize(deserializer)?.filter(|s| !s.is_empty()))
}
