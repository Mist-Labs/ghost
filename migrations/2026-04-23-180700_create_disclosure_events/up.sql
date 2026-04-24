CREATE TABLE IF NOT EXISTS disclosure_events (
    id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES protocol_findings(id) ON DELETE CASCADE,
    protocol_id TEXT NOT NULL,
    state TEXT NOT NULL,
    contact_emails JSONB NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    first_response_due_at TIMESTAMPTZ,
    last_notified_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    escalated_at TIMESTAMPTZ,
    escalation_level INTEGER NOT NULL DEFAULT 0,
    evidence_backend TEXT,
    evidence_locator TEXT,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE disclosure_events
    ADD COLUMN IF NOT EXISTS first_response_due_at TIMESTAMPTZ;
ALTER TABLE disclosure_events
    ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE disclosure_events
    ADD COLUMN IF NOT EXISTS acknowledged_by TEXT;
ALTER TABLE disclosure_events
    ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ;
ALTER TABLE disclosure_events
    ADD COLUMN IF NOT EXISTS escalation_level INTEGER NOT NULL DEFAULT 0;
ALTER TABLE disclosure_events
    ADD COLUMN IF NOT EXISTS evidence_backend TEXT;
ALTER TABLE disclosure_events
    ADD COLUMN IF NOT EXISTS evidence_locator TEXT;

CREATE INDEX IF NOT EXISTS disclosure_events_due_idx
ON disclosure_events (due_at ASC);
