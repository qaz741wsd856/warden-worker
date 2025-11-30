use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use worker::Env;

use crate::handlers::{accounts, ciphers, config, devices, emergency_access, folders, identity, import, sync, twofactor, webauth};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        // Main data sync route
        .route("/api/sync", get(sync::get_sync_data))
        // For on-demand sync checks
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        // Delete account
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        // Change password
        .route("/api/accounts/password", post(accounts::post_password))
        // Rotate encryption keys
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(accounts::post_rotatekey),
        )
        // Ciphers CRUD
        .route("/api/ciphers", post(ciphers::create_cipher_simple))
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route("/api/ciphers/import", post(import::import_data))
        .route("/api/ciphers/{id}", put(ciphers::update_cipher))
        // Cipher soft delete (PUT sets deleted_at timestamp)
        .route("/api/ciphers/{id}/delete", put(ciphers::soft_delete_cipher))
        // Cipher hard delete (DELETE/POST permanently removes cipher)
        .route("/api/ciphers/{id}", delete(ciphers::hard_delete_cipher))
        .route(
            "/api/ciphers/{id}/delete",
            post(ciphers::hard_delete_cipher),
        )
        // Cipher bulk soft delete
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers_bulk),
        )
        // Cipher bulk hard delete
        .route(
            "/api/ciphers/delete",
            post(ciphers::hard_delete_ciphers_bulk),
        )
        .route("/api/ciphers", delete(ciphers::hard_delete_ciphers_bulk))
        // Cipher restore (clears deleted_at)
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        // Cipher bulk restore
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers_bulk))
        // Folders CRUD
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/config", get(config::config))
        // Emergency access (stub - returns empty lists, feature not supported)
        .route(
            "/api/emergency-access/trusted",
            get(emergency_access::get_trusted_contacts),
        )
        .route(
            "/api/emergency-access/granted",
            get(emergency_access::get_granted_access),
        )
        // Devices (stub - device tracking not implemented, JWT-based auth)
        .route("/api/devices", get(devices::get_devices))
        .route("/api/devices/knowndevice", get(devices::get_known_device))
        .route(
            "/api/devices/identifier/{device_id}",
            get(devices::get_device),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            post(devices::post_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            put(devices::put_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            put(devices::put_clear_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            post(devices::post_clear_device_token),
        )
        // WebAuthn (stub - prevents 404 errors, passkeys not supported)
        .route(
            "/api/webauthn",
            get(webauth::get_webauthn_credentials),
        )
        // Two-factor authentication
        .route("/api/two-factor", get(twofactor::get_twofactor))
        .route(
            "/api/two-factor/get-authenticator",
            post(twofactor::get_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            post(twofactor::activate_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            put(twofactor::activate_authenticator_put),
        )
        .route(
            "/api/two-factor/disable",
            post(twofactor::disable_twofactor),
        )
        .route(
            "/api/two-factor/disable",
            put(twofactor::disable_twofactor_put),
        )
        .route(
            "/api/two-factor/get-recover",
            post(twofactor::get_recover),
        )
        .route("/api/two-factor/recover", post(twofactor::recover))
        .with_state(app_state)
}
