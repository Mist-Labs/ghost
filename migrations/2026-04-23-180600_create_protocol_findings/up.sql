CREATE TABLE IF NOT EXISTS protocol_findings (
    id UUID PRIMARY KEY,
    scan_run_id UUID NOT NULL REFERENCES protocol_scan_runs(id) ON DELETE CASCADE,
    protocol_id TEXT NOT NULL,
    contract_address TEXT NOT NULL,
    signature_id UUID REFERENCES vulnerability_signatures(id) ON DELETE RESTRICT,
    finding_type TEXT NOT NULL DEFAULT 'signature_match',
    title TEXT NOT NULL DEFAULT '',
    confidence DOUBLE PRECISION NOT NULL,
    severity TEXT NOT NULL,
    matched_pattern TEXT NOT NULL,
    affected_functions JSONB NOT NULL,
    simulation_confirmed BOOLEAN NOT NULL,
    details JSONB NOT NULL,
    remediation TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE protocol_findings
    ADD COLUMN IF NOT EXISTS finding_type TEXT NOT NULL DEFAULT 'signature_match';
ALTER TABLE protocol_findings
    ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';
ALTER TABLE protocol_findings
    ALTER COLUMN signature_id DROP NOT NULL;

CREATE INDEX IF NOT EXISTS protocol_findings_created_idx
ON protocol_findings (created_at DESC);
