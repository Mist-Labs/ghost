CREATE TABLE intel_subscribers (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL,
    monthly_fee_usd INTEGER NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX intel_subscribers_email_idx
ON intel_subscribers (email);

CREATE INDEX intel_subscribers_active_idx
ON intel_subscribers (active, updated_at DESC);
