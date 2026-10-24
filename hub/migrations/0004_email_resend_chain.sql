-- Resends from a browser with a live attempt may draw on a reserved global budget, but
-- only along a bounded chain: each attempt records how many resends led to it and when
-- the chain began.
ALTER TABLE email_attempts ADD COLUMN resends INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_attempts ADD COLUMN chain_started INTEGER NOT NULL DEFAULT 0;
