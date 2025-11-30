-- Drop tables if they exist to ensure a clean slate
DROP TABLE IF EXISTS twofactor;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS ciphers;
DROP TABLE IF EXISTS users;

-- Users table to store user accounts and their master keys/hashes
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    master_password_hash TEXT NOT NULL,
    master_password_hint TEXT,
    password_salt TEXT, -- Salt for server-side PBKDF2 hashing (NULL for legacy users pending migration)
    key TEXT NOT NULL, -- The encrypted symmetric key
    private_key TEXT NOT NULL, -- encrypted asymmetric private_key
    public_key TEXT NOT NULL, -- asymmetric public_key
    kdf_type INTEGER NOT NULL DEFAULT 0, -- 0 for PBKDF2
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    security_stamp TEXT,
    totp_recover TEXT, -- Recovery code for 2FA
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Ciphers table for storing encrypted vault items
CREATE TABLE IF NOT EXISTS ciphers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT,
    organization_id TEXT,
    type INTEGER NOT NULL,
    data TEXT NOT NULL, -- JSON blob of all encrypted fields (name, notes, login, etc.)
    favorite BOOLEAN NOT NULL DEFAULT 0,
    folder_id TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- Folders table for organizing ciphers
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL, -- Encrypted folder name
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- TwoFactor table for two-factor authentication
-- Types: 0=Authenticator(TOTP), 1=Email, 5=Remember, 8=RecoveryCode
CREATE TABLE IF NOT EXISTS twofactor (
    uuid TEXT PRIMARY KEY NOT NULL,
    user_uuid TEXT NOT NULL,
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL, -- JSON data specific to the 2FA type (e.g., TOTP secret)
    last_used INTEGER NOT NULL DEFAULT 0, -- Unix timestamp or TOTP time step
    FOREIGN KEY (user_uuid) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_uuid, atype)
);
