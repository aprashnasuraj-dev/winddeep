-- P3 deterministic reporting and audited downstream submission lifecycle.
CREATE TABLE IF NOT EXISTS report_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    platform TEXT NOT NULL CHECK(platform IN ('hackerone', 'jira', 'github')),
    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
    status TEXT NOT NULL CHECK(status IN ('draft', 'queued', 'submitted', 'acknowledged', 'closed')),
    payload TEXT NOT NULL,
    external_id TEXT,
    external_url TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS report_submission_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL REFERENCES report_submissions(id) ON DELETE CASCADE,
    from_status TEXT,
    to_status TEXT NOT NULL CHECK(to_status IN ('draft', 'queued', 'submitted', 'acknowledged', 'closed')),
    audit_hash TEXT NOT NULL CHECK(length(audit_hash) = 64),
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_report_submissions_status ON report_submissions(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_submissions_finding ON report_submissions(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_submission_events_history ON report_submission_events(submission_id, id ASC);
