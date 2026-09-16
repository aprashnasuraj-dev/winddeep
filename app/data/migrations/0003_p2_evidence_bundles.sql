-- P2 evidence bundles. Additive only; no evidence-bearing table is rewritten.
-- evidence_blobs is the minimum encrypted content-addressed primitive P2 needs
-- to verify a cited raw detector slice. Full P1 HAR/custody remains separate.
CREATE TABLE IF NOT EXISTS evidence_blobs (
    sha256 TEXT PRIMARY KEY,
    origin_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    origin_tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    media_type TEXT NOT NULL,
    size INTEGER NOT NULL CHECK(size >= 0),
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL,
    schema_version TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    completeness_score REAL NOT NULL CHECK(completeness_score >= 0 AND completeness_score <= 1),
    state TEXT NOT NULL CHECK(state IN ('incomplete', 'closed')),
    payload TEXT NOT NULL,
    supersedes_id INTEGER REFERENCES evidence_bundles(id) ON DELETE RESTRICT,
    created_at REAL NOT NULL,
    UNIQUE(finding_id, bundle_sha256)
);

CREATE INDEX IF NOT EXISTS idx_evidence_blobs_origin ON evidence_blobs(origin_scan_id, sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_bundles_finding ON evidence_bundles(finding_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_bundles_scan ON evidence_bundles(scan_id, finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_bundles_hash ON evidence_bundles(bundle_sha256);
