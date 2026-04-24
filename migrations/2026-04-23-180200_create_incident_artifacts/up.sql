CREATE TABLE IF NOT EXISTS incident_artifacts (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    storage_backend TEXT NOT NULL,
    locator TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS incident_artifacts_incident_idx
ON incident_artifacts (incident_id, created_at DESC);
