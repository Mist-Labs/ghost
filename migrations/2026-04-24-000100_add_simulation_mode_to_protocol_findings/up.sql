ALTER TABLE protocol_findings
ADD COLUMN IF NOT EXISTS simulation_mode TEXT NOT NULL DEFAULT 'generic';

CREATE INDEX IF NOT EXISTS protocol_findings_simulation_mode_idx
ON protocol_findings (simulation_mode);
