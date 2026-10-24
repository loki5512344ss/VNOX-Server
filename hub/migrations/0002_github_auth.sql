ALTER TABLE accounts ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN avatar_url TEXT;
CREATE TABLE external_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE CASCADE,
    linked_at INTEGER NOT NULL,
    PRIMARY KEY(provider, subject)
);
CREATE TABLE oauth_attempts (
    state_hash TEXT PRIMARY KEY,
    browser_hash TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX oauth_attempt_expiry ON oauth_attempts(expires_at);
CREATE TABLE web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX web_session_expiry ON web_sessions(expires_at);
