DROP INDEX IF EXISTS protocol_findings_simulation_mode_idx;

ALTER TABLE protocol_findings
DROP COLUMN IF EXISTS simulation_mode;
