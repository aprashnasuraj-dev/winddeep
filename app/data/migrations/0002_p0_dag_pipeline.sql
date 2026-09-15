-- P0 DAG pipeline state. Additive only: no evidence-bearing table is dropped or rewritten.
CREATE TABLE IF NOT EXISTS scan_events (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY(scan_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_scan_events_replay ON scan_events(scan_id, seq);

CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool_run_id INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
    finding_fingerprint TEXT NOT NULL,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(scan_id, tool_run_id, finding_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id, finding_fingerprint);

CREATE TABLE IF NOT EXISTS scan_authorizations (
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    consent_ref TEXT NOT NULL,
    created_at REAL NOT NULL
);
