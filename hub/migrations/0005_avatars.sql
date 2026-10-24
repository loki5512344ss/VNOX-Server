-- One own avatar per account, stored as a re-encoded PNG (no source metadata). The row is
-- replaced on upload and removed on "remove photo" or when the account is deleted. `id` is the
-- hex SHA-256 of the stored bytes; it names the immutable public URL /v1/avatars/<id>.
-- accounts.avatar_url keeps the provider (GitHub) avatar as the fallback.
CREATE TABLE avatars (
    user_id TEXT PRIMARY KEY REFERENCES accounts(user_id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    content_type TEXT NOT NULL,
    bytes BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX avatars_by_id ON avatars(id);
