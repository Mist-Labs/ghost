CREATE TABLE verification_jobs (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_job_id TEXT NOT NULL UNIQUE,
    gateway_url TEXT NOT NULL,
    model_id TEXT NOT NULL,
    input_features JSONB NOT NULL,
    status TEXT NOT NULL,
    proof_hash TEXT,
    vkey TEXT,
    output_score DOUBLE PRECISION,
    error_message TEXT,
    submitted_at TIMESTAMPTZ NOT NULL,
    settled_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX verification_jobs_incident_idx
    ON verification_jobs (incident_id, submitted_at DESC);
