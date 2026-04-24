CREATE TABLE IF NOT EXISTS protocol_scan_runs (
    id UUID PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    protocol_name TEXT NOT NULL,
    chain_name TEXT NOT NULL,
    scan_mode TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    signatures_checked INTEGER NOT NULL,
    findings_count INTEGER NOT NULL,
    clean BOOLEAN NOT NULL,
    metadata JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS protocol_scan_runs_completed_idx
ON protocol_scan_runs (completed_at DESC);
