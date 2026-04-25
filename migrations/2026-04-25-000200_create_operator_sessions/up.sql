CREATE TABLE IF NOT EXISTS operator_sessions (
    id UUID PRIMARY KEY,
    operator_account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS operator_sessions_account_idx
ON operator_sessions (operator_account_id, expires_at DESC);
