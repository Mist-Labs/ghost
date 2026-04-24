CREATE TABLE protocol_billing_accounts (
    id UUID PRIMARY KEY,
    protocol_id TEXT NOT NULL UNIQUE,
    protocol_name TEXT NOT NULL,
    tier TEXT NOT NULL,
    monthly_fee_usd INTEGER NOT NULL,
    billing_email TEXT NOT NULL,
    alert_webhook TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX protocol_billing_accounts_active_idx
ON protocol_billing_accounts (active, updated_at DESC);
