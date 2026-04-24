CREATE TABLE IF NOT EXISTS monitor_snapshots (
    id UUID PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    monitor_kind TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    payload JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS monitor_snapshots_scope_idx
ON monitor_snapshots (protocol_id, monitor_kind, scope_key, observed_at DESC);
