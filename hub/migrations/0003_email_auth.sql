-- Passwordless email sign-in. Email identities reuse external_identities
-- (provider='email', subject=normalized address): the (provider, subject) key already
-- guarantees one account per address and never collides with 'github.com' subjects,
-- so the two methods can never be merged implicitly.
--
-- One pending code per browser. Only keyed MACs are stored: neither the code, nor the
-- address of a pending attempt, nor the requester's network address.
CREATE TABLE email_attempts (
    attempt_id TEXT PRIMARY KEY,
    browser_hash TEXT NOT NULL UNIQUE,
    email_mac TEXT NOT NULL,
    code_mac TEXT NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL
);
CREATE INDEX email_attempt_expiry ON email_attempts(expires_at);

-- Sliding-window ledger for send rate limits, keyed by MAC of address / source.
CREATE TABLE email_send_log (
    email_mac TEXT NOT NULL,
    source_mac TEXT NOT NULL,
    sent_at INTEGER NOT NULL
);
CREATE INDEX email_send_by_address ON email_send_log(email_mac, sent_at);
CREATE INDEX email_send_by_source ON email_send_log(source_mac, sent_at);
CREATE INDEX email_send_by_time ON email_send_log(sent_at);
