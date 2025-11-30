-- Migration: Add twofactor table for two-factor authentication
-- Supports TOTP (Authenticator), Email, and other 2FA methods
--
-- TwoFactor types:
--   0 = Authenticator (TOTP)
--   1 = Email
--   5 = Remember (device trust token)
--   8 = RecoveryCode

CREATE TABLE IF NOT EXISTS twofactor (
    uuid TEXT PRIMARY KEY NOT NULL,
    user_uuid TEXT NOT NULL,
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL,
    last_used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_uuid) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_uuid, atype)
);

-- Add totp_recover column to users table for recovery codes
ALTER TABLE users ADD COLUMN totp_recover TEXT;

