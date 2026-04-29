-- Send support: main sends table and pending file upload staging table
-- Both tables share an identical schema so they can use one Rust model.

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
-- Identical schema to `sends`; file metadata lives in the `data` JSON column.
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

CREATE INDEX IF NOT EXISTS idx_sends_pending_user_id ON sends_pending(user_id);
