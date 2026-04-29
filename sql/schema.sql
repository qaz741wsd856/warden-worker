-- Users table to store user accounts and their master keys/hashes
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    avatar_color TEXT,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    master_password_hash TEXT NOT NULL,
    master_password_hint TEXT,
    password_salt TEXT, -- Salt for server-side PBKDF2 hashing (NULL for legacy users pending migration)
    password_iterations INTEGER NOT NULL DEFAULT 600000, -- Per-user server-side PBKDF2 iteration count (migrated on login)
    key TEXT NOT NULL, -- The encrypted symmetric key
    private_key TEXT NOT NULL, -- encrypted asymmetric private_key
    public_key TEXT NOT NULL, -- asymmetric public_key
    kdf_type INTEGER NOT NULL DEFAULT 0, -- 0 for PBKDF2, 1 for Argon2id
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    kdf_memory INTEGER, -- Argon2 memory parameter in MB (15-1024), NULL for PBKDF2
    kdf_parallelism INTEGER, -- Argon2 parallelism parameter (1-16), NULL for PBKDF2
    security_stamp TEXT,
    equivalent_domains TEXT NOT NULL DEFAULT '[]', -- JSON: Vec<Vec<String>>
    excluded_globals TEXT NOT NULL DEFAULT '[]', -- JSON: Vec<i32> (reserved for future global groups)
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
    archived_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- Index to speed up common per-user cipher queries (sync/list/attachments joins)
CREATE INDEX IF NOT EXISTS idx_ciphers_user_id ON ciphers(user_id);

-- Attachments table for cipher file metadata
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id);

-- Pending attachments table for in-flight uploads
CREATE TABLE IF NOT EXISTS attachments_pending (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_pending_cipher ON attachments_pending(cipher_id);
CREATE INDEX IF NOT EXISTS idx_attachments_pending_created_at ON attachments_pending(created_at);

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

-- Devices table for device-bound auth, refresh tokens, and push registration.
CREATE TABLE IF NOT EXISTS devices (
    identifier TEXT NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type INTEGER NOT NULL,
    push_uuid TEXT,
    push_token TEXT,
    refresh_token TEXT NOT NULL,
    twofactor_remember TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (identifier, user_id),
    UNIQUE(refresh_token)
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_push_token ON devices(push_token);

-- Folders table for organizing ciphers
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL, -- Encrypted folder name
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_folders_user_id ON folders(user_id);

-- Global equivalent domains dataset (seeded separately, not bundled into the Worker)
CREATE TABLE IF NOT EXISTS global_equivalent_domains (
    type INTEGER PRIMARY KEY NOT NULL,
    sort_order INTEGER NOT NULL,
    domains_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_global_equivalent_domains_sort_order
    ON global_equivalent_domains(sort_order);

-- Send support: main sends table
CREATE TABLE IF NOT EXISTS sends (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  type INTEGER NOT NULL,
  data TEXT NOT NULL,
  akey TEXT NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  password_iter INTEGER,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sends_user_id ON sends(user_id);
CREATE INDEX IF NOT EXISTS idx_sends_deletion_date ON sends(deletion_date);

-- Staging table for file Sends whose upload has not yet completed.
CREATE TABLE IF NOT EXISTS sends_pending (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  type INTEGER NOT NULL,
  data TEXT NOT NULL,
  akey TEXT NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  password_iter INTEGER,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER NOT NULL DEFAULT 0
);
