-- P1 operational tables: submissions, program scopes, LLM accounting/cache, evidence custody.
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    program_name TEXT NOT NULL,
    external_id TEXT,
    external_url TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    bounty_amount REAL,
    bounty_currency TEXT,
    submitted_at REAL,
    resolved_at REAL,
    notes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS program_scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    program_handle TEXT NOT NULL,
    asset_identifier TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    eligible INTEGER NOT NULL DEFAULT 1 CHECK (eligible IN (0, 1)),
    max_severity TEXT,
    instructions TEXT NOT NULL DEFAULT '',
    tos_url TEXT,
    tos_snapshot_sha256 TEXT,
    imported_at REAL NOT NULL,
    UNIQUE(platform, program_handle, asset_identifier, asset_type)
);

CREATE TABLE IF NOT EXISTS llm_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cached INTEGER NOT NULL DEFAULT 0 CHECK (cached IN (0, 1)),
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_cache (
    cache_key TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    flow_id INTEGER REFERENCES flows(id) ON DELETE SET NULL,
    artifact_type TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    signature TEXT,
    created_at REAL NOT NULL,
    UNIQUE(relative_path, sha256)
);

CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_submissions_target ON submissions(target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_program_scopes_program ON program_scopes(platform, program_handle);
CREATE INDEX IF NOT EXISTS idx_llm_usage_scan ON llm_usage(scan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_llm_usage_created ON llm_usage(created_at);
CREATE INDEX IF NOT EXISTS idx_llm_cache_expiry ON llm_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_artifacts(finding_id, created_at);
