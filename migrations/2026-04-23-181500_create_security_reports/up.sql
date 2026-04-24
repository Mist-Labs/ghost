CREATE TABLE security_reports (
    id UUID PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    protocol_name TEXT NOT NULL,
    report_type TEXT NOT NULL,
    vulnerability_count INTEGER NOT NULL,
    vulnerabilities JSONB NOT NULL,
    report_body TEXT NOT NULL,
    email_recipient TEXT,
    email_sent BOOLEAN NOT NULL,
    email_error TEXT,
    generated_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ
);

CREATE INDEX security_reports_generated_idx
    ON security_reports (generated_at DESC);
CREATE INDEX security_reports_protocol_idx
    ON security_reports (protocol_id, generated_at DESC);
