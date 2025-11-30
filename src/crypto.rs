use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use constant_time_eq::constant_time_eq;
use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};
use worker::js_sys;

use crate::error::AppError;

/// Number of PBKDF2 iterations for server-side password hashing
const SERVER_PBKDF2_ITERATIONS: u32 = 100_000;
/// Salt length in bytes
const SALT_LENGTH: usize = 16;
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

/// Derives a key using PBKDF2-SHA256.
pub async fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length_bits: u32,
) -> Result<Vec<u8>, AppError> {
    let subtle = subtle_crypto()?;

    // Import the password as a raw key material
    let password_array = Uint8Array::new_from_slice(password);
    let password_obj = password_array.as_ref();
    let key_material = JsFuture::from(
        subtle
            .import_key_with_str(
                "raw",
                password_obj,
                "PBKDF2",
                false,
                &js_sys::Array::of1(&JsValue::from_str("deriveBits")),
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key await failed: {:?}", e)))?;

    let salt_array = Uint8Array::new_from_slice(salt);
    // Define PBKDF2 parameters
    let params = web_sys::Pbkdf2Params::new(
        "PBKDF2",
        JsValue::from_str("SHA-256").as_ref(),
        iterations,
        salt_array.as_ref(),
    );

    // Derive the bits
    let derived_bits = JsFuture::from(
        subtle
            .derive_bits_with_object(
                params.as_ref(),
                &CryptoKey::from(key_material),
                key_length_bits,
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 derive_bits failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 derive_bits await failed: {:?}", e)))?;

    Ok(js_sys::Uint8Array::new(&derived_bits).to_vec())
}

/// Generates a cryptographically secure random salt.
pub fn generate_salt() -> Result<String, AppError> {
    let crypto = get_crypto()?;
    let salt = Uint8Array::new_with_length(SALT_LENGTH as u32);
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
) -> Result<String, AppError> {
    let salt_bytes = BASE64
        .decode(salt)
        .map_err(|e| AppError::Crypto(format!("Failed to decode salt: {:?}", e)))?;

    let derived = pbkdf2_sha256(
        client_password_hash.as_bytes(),
        &salt_bytes,
        SERVER_PBKDF2_ITERATIONS,
        KEY_LENGTH_BITS,
    )
    .await?;

    Ok(BASE64.encode(derived))
}

/// Verifies a password against a stored hash.
/// Returns true if the password matches.
pub async fn verify_password(
    client_password_hash: &str,
    stored_hash: &str,
    salt: &str,
) -> Result<bool, AppError> {
    let computed_hash = hash_password_for_storage(client_password_hash, salt).await?;
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

/// Encodes bytes into a Base32 string (RFC 4648).
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
    js_sys::Reflect::set(&algorithm, &JsValue::from_str("name"), &JsValue::from_str("HMAC"))
        .map_err(|e| AppError::Crypto(format!("Failed to set algorithm name: {:?}", e)))?;
    js_sys::Reflect::set(&algorithm, &JsValue::from_str("hash"), &JsValue::from_str("SHA-1"))
        .map_err(|e| AppError::Crypto(format!("Failed to set hash: {:?}", e)))?;

    // Import the key
    let key_array = Uint8Array::new_from_slice(key);
    let key_usages = js_sys::Array::of1(&JsValue::from_str("sign"));
    
    let crypto_key = JsFuture::from(
        subtle
            .import_key_with_object(
                "raw",
                &key_array,
                &algorithm,
                false,
                &key_usages,
            )
            .map_err(|e| AppError::Crypto(format!("HMAC import_key failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("HMAC import_key await failed: {:?}", e)))?;

    // Sign the data using sign_with_str_and_buffer_source
    let data_array = Uint8Array::new_from_slice(data);
    let signature = JsFuture::from(
        subtle
            .sign_with_str_and_buffer_source(
                "HMAC",
                &CryptoKey::from(crypto_key),
                &data_array,
            )
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
    
    Err(AppError::Unauthorized(format!(
        "Invalid TOTP code. Server time: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )))
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

/// Constant-time string comparison wrapper.
pub fn ct_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}
