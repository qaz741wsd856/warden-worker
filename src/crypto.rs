use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use constant_time_eq::constant_time_eq;
use js_sys::Uint8Array;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};
use worker::js_sys;

use crate::error::AppError;

/// Minimum PBKDF2 iterations for server-side password hashing (new global minimum).
///
/// NOTE: Cloudflare Workers native WebCrypto PBKDF2 currently rejects iteration counts > 100_000.
/// We therefore run PBKDF2 in pure Rust/WASM so we can safely use higher iteration counts.
///
/// This is CPU-expensive and is expected to be executed inside a Durable Object for Free plan deployments.
pub const MIN_SERVER_PBKDF2_ITERATIONS: u32 = 600_000;

/// Salt length in bytes for server-side password hashing.
pub const PASSWORD_SALT_LENGTH: usize = 64;
/// Derived key length in bits
const KEY_LENGTH_BITS: u32 = 256;

/// Gets the Crypto interface from the global scope.
/// Works in Cloudflare Workers by using js_sys::Reflect instead of WorkerGlobalScope.
fn get_crypto() -> Result<Crypto, AppError> {
    let global = js_sys::global();
    let crypto_value = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|e| AppError::Crypto(format!("Failed to get crypto property: {:?}", e)))?;

    crypto_value
        .dyn_into::<Crypto>()
        .map_err(|_| AppError::Crypto("Failed to cast to Crypto".to_string()))
}

/// Gets the SubtleCrypto interface from the global scope.
fn subtle_crypto() -> Result<SubtleCrypto, AppError> {
    Ok(get_crypto()?.subtle())
}

/// Derives a key using PBKDF2-HMAC-SHA256 (pure Rust).
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length_bits: u32,
) -> Result<Vec<u8>, AppError> {
    if !key_length_bits.is_multiple_of(8) {
        return Err(AppError::Crypto(format!(
            "PBKDF2 key length must be a multiple of 8 bits (got {})",
            key_length_bits
        )));
    }

    let dk_len = (key_length_bits / 8) as usize;
    let mut out = vec![0u8; dk_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    Ok(out)
}

/// Derives a key using PBKDF2-HMAC-SHA256 via Web Crypto API (hardware-accelerated, zero CPU cost).
///
/// Workers WebCrypto limits PBKDF2 to <= 100,000 iterations.
/// Use for Send passwords and other low-iteration use cases.
pub async fn webcrypto_pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length_bits: u32,
) -> Result<Vec<u8>, AppError> {
    let subtle = subtle_crypto()?;
    // Import the password as a raw key material
    let password_array = Uint8Array::new_from_slice(password);
    let base_key = JsFuture::from(
        subtle
            .import_key_with_str(
                "raw",
                password_array.as_ref(),
                "PBKDF2",
                false,
                &js_sys::Array::of1(&JsValue::from_str("deriveBits")),
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key failed: {e:?}")))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key await failed: {e:?}")))?;
    let salt_array = Uint8Array::new_from_slice(salt);
    // Define PBKDF2 parameters
    let derive_params = web_sys::Pbkdf2Params::new(
        "PBKDF2",
        JsValue::from_str("SHA-256").as_ref(),
        iterations,
        salt_array.as_ref(),
    );
    // Derive the bits
    let derived = JsFuture::from(
        subtle
            .derive_bits_with_object(
                derive_params.as_ref(),
                &CryptoKey::from(base_key),
                key_length_bits,
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 deriveBits failed: {e:?}")))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 deriveBits await failed: {e:?}")))?;

    Ok(Uint8Array::new(&derived).to_vec())
}

/// Generates a cryptographically secure random salt.
pub fn generate_salt() -> Result<String, AppError> {
    let crypto = get_crypto()?;
    let salt = Uint8Array::new_with_length(PASSWORD_SALT_LENGTH as u32);
    crypto
        .get_random_values_with_array_buffer_view(&salt)
        .map_err(|e| AppError::Crypto(format!("Failed to generate random salt: {:?}", e)))?;

    Ok(BASE64.encode(salt.to_vec()))
}

/// Hashes the client-provided master password hash with server-side PBKDF2.
/// This adds an additional layer of security to the stored password hash.
pub async fn hash_password_for_storage(
    client_password_hash: &str,
    salt: &str,
    iterations: u32,
) -> Result<String, AppError> {
    let salt_bytes = BASE64
        .decode(salt)
        .map_err(|e| AppError::Crypto(format!("Failed to decode salt: {:?}", e)))?;

    let derived = pbkdf2_sha256(
        client_password_hash.as_bytes(),
        &salt_bytes,
        iterations,
        KEY_LENGTH_BITS,
    )?;

    Ok(BASE64.encode(derived))
}

/// Verifies a password against a stored hash.
/// Returns true if the password matches.
pub async fn verify_password(
    client_password_hash: &str,
    stored_hash: &str,
    salt: &str,
    iterations: u32,
) -> Result<bool, AppError> {
    let computed_hash = hash_password_for_storage(client_password_hash, salt, iterations).await?;
    Ok(constant_time_eq(
        computed_hash.as_bytes(),
        stored_hash.as_bytes(),
    ))
}

// ============================================================================
// TOTP Implementation using Web Crypto API
// ============================================================================

/// Decodes a Base32 encoded string into bytes.
/// Handles both uppercase and lowercase input.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, AppError> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: true }, input)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: false }, input))
        .ok_or_else(|| AppError::Crypto("Invalid Base32 input".to_string()))
}

/// Encodes bytes into a Base32 string (RFC 4648, uppercase).
pub fn base32_encode(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: true }, data)
}

/// Generates a random TOTP secret (20 bytes = 160 bits).
/// Returns the Base32 encoded secret.
pub fn generate_totp_secret() -> Result<String, AppError> {
    let crypto = get_crypto()?;
    let secret = Uint8Array::new_with_length(20);
    crypto
        .get_random_values_with_array_buffer_view(&secret)
        .map_err(|e| AppError::Crypto(format!("Failed to generate TOTP secret: {:?}", e)))?;

    Ok(base32_encode(&secret.to_vec()))
}

/// Computes HMAC-SHA1 using Web Crypto API.
async fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, AppError> {
    let subtle = subtle_crypto()?;

    // Create algorithm object for HMAC with SHA-1
    let algorithm = js_sys::Object::new();
    js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str("HMAC"),
    )
    .map_err(|e| AppError::Crypto(format!("Failed to set algorithm name: {:?}", e)))?;
    js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("hash"),
        &JsValue::from_str("SHA-1"),
    )
    .map_err(|e| AppError::Crypto(format!("Failed to set hash: {:?}", e)))?;

    // Import the key
    let key_array = Uint8Array::new_from_slice(key);
    let key_usages = js_sys::Array::of1(&JsValue::from_str("sign"));

    let crypto_key = JsFuture::from(
        subtle
            .import_key_with_object("raw", &key_array, &algorithm, false, &key_usages)
            .map_err(|e| AppError::Crypto(format!("HMAC import_key failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("HMAC import_key await failed: {:?}", e)))?;

    // Sign the data using sign_with_str_and_buffer_source
    let data_array = Uint8Array::new_from_slice(data);
    let signature = JsFuture::from(
        subtle
            .sign_with_str_and_buffer_source("HMAC", &CryptoKey::from(crypto_key), &data_array)
            .map_err(|e| AppError::Crypto(format!("HMAC sign failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("HMAC sign await failed: {:?}", e)))?;

    Ok(Uint8Array::new(&signature).to_vec())
}

/// Generates a TOTP code for the given secret and time.
///
/// # Arguments
/// * `secret` - Base32 encoded secret key
/// * `time_step` - Unix timestamp divided by 30 (or custom period)
///
/// # Returns
/// * 6-digit TOTP code as a string
pub async fn generate_totp(secret: &str, time_step: u64) -> Result<String, AppError> {
    let decoded_secret = base32_decode(secret)?;

    // Convert time_step to big-endian bytes
    let counter = time_step.to_be_bytes();

    // Compute HMAC-SHA1
    let hmac = hmac_sha1(&decoded_secret, &counter).await?;

    // Dynamic truncation (RFC 4226)
    let offset = (hmac[19] & 0x0f) as usize;
    let code = ((hmac[offset] & 0x7f) as u32) << 24
        | (hmac[offset + 1] as u32) << 16
        | (hmac[offset + 2] as u32) << 8
        | (hmac[offset + 3] as u32);

    // Get 6-digit code
    let otp = code % 1_000_000;
    Ok(format!("{:06}", otp))
}

/// Validates a TOTP code against a secret.
///
/// # Arguments
/// * `code` - The TOTP code to validate
/// * `secret` - Base32 encoded secret key
/// * `last_used` - The last used time step (for replay protection)
/// * `allow_drift` - Whether to allow 1 time step drift (±30 seconds)
///
/// # Returns
/// * `Ok(time_step)` if valid, with the time step that matched
/// * `Err` if invalid
pub async fn validate_totp(
    code: &str,
    secret: &str,
    last_used: i64,
    allow_drift: bool,
) -> Result<i64, AppError> {
    // Validate code format
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::BadRequest("Invalid TOTP code format".to_string()));
    }

    let current_time = chrono::Utc::now().timestamp();
    let current_step = current_time / 30;

    // Check drift range
    let steps: i64 = if allow_drift { 1 } else { 0 };

    for step_offset in -steps..=steps {
        let time_step = current_step + step_offset;

        // Skip if this time step was already used (replay protection)
        if time_step <= last_used {
            continue;
        }

        let expected = generate_totp(secret, time_step as u64).await?;

        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return Ok(time_step);
        }
    }

    Err(AppError::Unauthorized("Invalid TOTP code.".to_string()))
}

/// Generates a recovery code (20 characters, Base32 encoded).
pub fn generate_recovery_code() -> Result<String, AppError> {
    let crypto = get_crypto()?;
    let bytes = Uint8Array::new_with_length(20);
    crypto
        .get_random_values_with_array_buffer_view(&bytes)
        .map_err(|e| AppError::Crypto(format!("Failed to generate recovery code: {:?}", e)))?;

    Ok(base32_encode(&bytes.to_vec()))
}

/// Alphabet used for personal API keys ([A-Za-z0-9], 62 symbols).
const API_KEY_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Length of a personal API key, in characters (~178 bits of entropy).
const API_KEY_LENGTH: usize = 30;
/// Largest multiple of 62 that fits in a byte (256 - 256 % 62). Bytes at or above this
/// value are rejected so that the modulo below stays unbiased.
const API_KEY_REJECT_FROM: u8 = 248;

/// Maps uniformly random bytes onto the API key alphabet using rejection sampling.
/// Returns `None` when `bytes` did not contain enough accepted values.
fn map_api_key_bytes(bytes: &[u8], out: &mut String, length: usize) -> bool {
    for byte in bytes {
        if out.len() == length {
            return true;
        }
        if *byte >= API_KEY_REJECT_FROM {
            continue;
        }
        out.push(API_KEY_ALPHABET[(*byte % 62) as usize] as char);
    }

    out.len() == length
}

/// Generates a personal API key (30 alphanumeric characters, ~178 bits of entropy).
/// Matches Vaultwarden's `generate_api_key`.
pub fn generate_api_key() -> Result<String, AppError> {
    debug_assert_eq!(API_KEY_ALPHABET.len(), 62);
    debug_assert_eq!(API_KEY_REJECT_FROM as usize, 256 - 256 % 62);

    let crypto = get_crypto()?;
    let mut key = String::with_capacity(API_KEY_LENGTH);

    // Rejection sampling discards ~3% of the bytes, so a handful of rounds is plenty;
    // the bound only exists to avoid an unbounded loop if the RNG misbehaves.
    for _ in 0..16 {
        let bytes = Uint8Array::new_with_length(API_KEY_LENGTH as u32);
        crypto
            .get_random_values_with_array_buffer_view(&bytes)
            .map_err(|e| AppError::Crypto(format!("Failed to generate API key: {:?}", e)))?;

        if map_api_key_bytes(&bytes.to_vec(), &mut key, API_KEY_LENGTH) {
            return Ok(key);
        }
    }

    Err(AppError::Crypto(
        "Failed to generate API key: insufficient random data".to_string(),
    ))
}

/// Constant-time string comparison wrapper.
pub fn ct_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{map_api_key_bytes, API_KEY_ALPHABET, API_KEY_REJECT_FROM};

    #[test]
    fn api_key_alphabet_is_unbiased() {
        assert_eq!(API_KEY_ALPHABET.len(), 62);
        assert_eq!(API_KEY_REJECT_FROM as usize, 256 - 256 % 62);
        assert!(API_KEY_ALPHABET.iter().all(u8::is_ascii_alphanumeric));
    }

    #[test]
    fn api_key_mapper_rejects_biasing_bytes() {
        let mut key = String::new();
        assert!(!map_api_key_bytes(&[248, 249, 250, 255], &mut key, 2));
        assert!(key.is_empty());
    }

    #[test]
    fn api_key_mapper_maps_accepted_bytes() {
        let mut key = String::new();
        assert!(map_api_key_bytes(&[0, 61, 62, 247], &mut key, 4));
        assert_eq!(key, "A9A9");
    }

    #[test]
    fn api_key_mapper_stops_at_requested_length() {
        let mut key = String::new();
        assert!(map_api_key_bytes(&[0, 0, 0], &mut key, 2));
        assert_eq!(key, "AA");
    }
}
