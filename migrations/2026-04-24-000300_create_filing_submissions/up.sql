CREATE TABLE IF NOT EXISTS filing_submissions (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL,
    filing_target TEXT NOT NULL,
    destination TEXT NOT NULL,
    status TEXT NOT NULL,
    request_payload JSONB NOT NULL,
    response_status_code INTEGER,
    response_body TEXT,
    error_message TEXT,
    submitted_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS filing_submissions_incident_idx
ON filing_submissions (incident_id, submitted_at DESC);

CREATE INDEX IF NOT EXISTS filing_submissions_target_idx
ON filing_submissions (filing_target, submitted_at DESC);
