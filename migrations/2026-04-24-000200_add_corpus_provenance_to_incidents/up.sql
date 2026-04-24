ALTER TABLE incidents
ADD COLUMN IF NOT EXISTS corpus_provenance JSONB NOT NULL DEFAULT '{}'::jsonb;
