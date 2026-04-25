CREATE TABLE IF NOT EXISTS operator_otp_codes (
    id UUID PRIMARY KEY,
    operator_account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS operator_otp_codes_account_idx
ON operator_otp_codes (operator_account_id, created_at DESC);
