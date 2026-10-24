-- No authentication/registry endpoints use these tables yet. Defining durable
-- IDs now does not imply that account/device authorization is implemented.
CREATE TABLE hub_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE accounts (
    user_id TEXT PRIMARY KEY,
    handle TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE CASCADE,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE servers (
    server_id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES accounts(user_id),
    public_key BLOB UNIQUE NOT NULL,
    address TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('private', 'unlisted', 'public')),
    created_at INTEGER NOT NULL
);
