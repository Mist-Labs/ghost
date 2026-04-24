CREATE TABLE intel_reports (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    published_at TIMESTAMPTZ NOT NULL,
    protocol_id TEXT,
    protocol_name TEXT NOT NULL,
    attack_vector TEXT NOT NULL,
    total_loss_usd BIGINT NOT NULL,
    recovered_usd BIGINT NOT NULL DEFAULT 0,
    attacker_skill_tier TEXT NOT NULL,
    used_private_mempool BOOLEAN NOT NULL DEFAULT FALSE,
    funded_via_mixer BOOLEAN NOT NULL DEFAULT FALSE,
    cex_deposit_detected BOOLEAN NOT NULL DEFAULT FALSE,
    chains_involved JSONB NOT NULL DEFAULT '[]'::jsonb,
    time_to_detection_secs INTEGER NOT NULL,
    time_to_mixer_secs INTEGER,
    bounty_outcome TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX intel_reports_published_idx
ON intel_reports (published_at DESC);
