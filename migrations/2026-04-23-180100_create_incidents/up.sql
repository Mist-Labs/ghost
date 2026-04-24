CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY,
    tx_hash TEXT NOT NULL UNIQUE,
    chain_name TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence TEXT NOT NULL,
    score INTEGER NOT NULL,
    protocol_id TEXT,
    protocol_name TEXT,
    attacker_address TEXT NOT NULL,
    protocol_address TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    last_updated_at TIMESTAMPTZ NOT NULL,
    signals JSONB NOT NULL,
    raw_transaction JSONB NOT NULL,
    summary TEXT
);

CREATE INDEX IF NOT EXISTS incidents_status_idx ON incidents (status);
CREATE INDEX IF NOT EXISTS incidents_detected_at_idx ON incidents (detected_at DESC);
CREATE INDEX IF NOT EXISTS incidents_confidence_idx ON incidents (confidence);
