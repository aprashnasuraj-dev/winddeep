-- v3 P0: replayable scan events and idempotent per-tool finding persistence.
-- Additive only: no evidence-bearing table is dropped, rewritten, or truncated.
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    schema_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(scan_id, seq)
);

CREATE TABLE IF NOT EXISTS tool_finding_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool_run_id INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    finding_fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(scan_id, tool_run_id, finding_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_scan_events_replay ON scan_events(scan_id, seq);
CREATE INDEX IF NOT EXISTS idx_tool_finding_refs_scan ON tool_finding_refs(scan_id, tool_run_id);
CREATE INDEX IF NOT EXISTS idx_tool_finding_refs_fingerprint ON tool_finding_refs(finding_fingerprint);
