-- Immutable scan-report snapshot metadata.
-- Report body remains encrypted in reports.content; this table binds it to the
-- exact scan/evidence state used at generation time.
CREATE TABLE IF NOT EXISTS report_snapshots (
    report_id INTEGER PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
    renderer TEXT NOT NULL,
    evidence_state TEXT NOT NULL CHECK(evidence_state IN ('complete','partial','blocked')),
    closed_findings INTEGER NOT NULL DEFAULT 0 CHECK(closed_findings >= 0),
    incomplete_findings INTEGER NOT NULL DEFAULT 0 CHECK(incomplete_findings >= 0),
    blocked_findings INTEGER NOT NULL DEFAULT 0 CHECK(blocked_findings >= 0),
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_snapshots_scan ON report_snapshots(scan_id, report_id DESC);
CREATE INDEX IF NOT EXISTS idx_report_snapshots_state ON report_snapshots(evidence_state, created_at DESC);
