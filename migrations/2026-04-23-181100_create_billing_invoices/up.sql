CREATE TABLE billing_invoices (
    id UUID PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    recovery_case_id UUID REFERENCES recovery_cases(id) ON DELETE SET NULL,
    invoice_kind TEXT NOT NULL,
    amount_usd INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL,
    external_invoice_id TEXT,
    recipient_email TEXT NOT NULL,
    description TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX billing_invoices_created_idx
ON billing_invoices (created_at DESC);

CREATE INDEX billing_invoices_status_idx
ON billing_invoices (status, updated_at DESC);
