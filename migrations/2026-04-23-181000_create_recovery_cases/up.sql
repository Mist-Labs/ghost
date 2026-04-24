CREATE TABLE recovery_cases (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    protocol_id TEXT NOT NULL,
    total_stolen_usd BIGINT NOT NULL,
    total_recovered_usd BIGINT NOT NULL DEFAULT 0,
    recovery_method TEXT NOT NULL,
    fee_invoiced BOOLEAN NOT NULL DEFAULT FALSE,
    invoiced_fee_usd BIGINT NOT NULL DEFAULT 0,
    bounty_contract_address TEXT,
    billing_email TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX recovery_cases_bounty_contract_idx
ON recovery_cases (bounty_contract_address)
WHERE bounty_contract_address IS NOT NULL;

CREATE INDEX recovery_cases_protocol_idx
ON recovery_cases (protocol_id, updated_at DESC);
