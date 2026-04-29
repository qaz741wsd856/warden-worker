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

DELETE FROM twofactor WHERE atype = 5;
