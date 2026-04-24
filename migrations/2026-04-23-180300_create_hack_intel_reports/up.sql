CREATE TABLE IF NOT EXISTS hack_intel_reports (
    id UUID PRIMARY KEY,
    source TEXT NOT NULL,
    external_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL,
    loss_usd DOUBLE PRECISION,
    attack_vector TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    chain_name TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    source_url TEXT NOT NULL,
    raw_payload JSONB NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    UNIQUE(source, external_id)
);

CREATE INDEX IF NOT EXISTS hack_intel_reports_published_idx
ON hack_intel_reports (published_at DESC);
