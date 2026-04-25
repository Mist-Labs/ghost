CREATE TABLE IF NOT EXISTS operator_accounts (
    id UUID PRIMARY KEY,
    company_name TEXT NOT NULL,
    contact_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    webauthn_user_id TEXT NOT NULL UNIQUE,
    otp_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS operator_accounts_company_name_idx
ON operator_accounts (company_name);
