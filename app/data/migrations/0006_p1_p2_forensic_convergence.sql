-- P1→P2 forensic convergence. Additive only; legacy P2 bundles remain readable.
CREATE TABLE IF NOT EXISTS forensic_evidence_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL,
    schema_version TEXT NOT NULL CHECK(schema_version IN ('windeep.evidence-bundle.v2')),
    bundle_sha256 TEXT NOT NULL CHECK(length(bundle_sha256) = 64),
    completeness_score REAL NOT NULL CHECK(completeness_score >= 0 AND completeness_score <= 1),
    state TEXT NOT NULL CHECK(state IN ('incomplete', 'closed')),
    payload TEXT NOT NULL,
    supersedes_id INTEGER REFERENCES forensic_evidence_bundles(id) ON DELETE RESTRICT,
    created_at REAL NOT NULL,
    UNIQUE(finding_id, bundle_sha256)
);
CREATE INDEX IF NOT EXISTS idx_forensic_bundles_finding ON forensic_evidence_bundles(finding_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_forensic_bundles_scan ON forensic_evidence_bundles(scan_id, finding_id);
CREATE INDEX IF NOT EXISTS idx_forensic_bundles_hash ON forensic_evidence_bundles(bundle_sha256);
