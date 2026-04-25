CREATE TABLE IF NOT EXISTS operator_passkeys (
    id UUID PRIMARY KEY,
    operator_account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter BIGINT NOT NULL,
    transports JSONB NOT NULL,
    device_type TEXT NOT NULL,
    backed_up BOOLEAN NOT NULL,
    label TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS operator_passkeys_account_idx
ON operator_passkeys (operator_account_id, created_at DESC);
