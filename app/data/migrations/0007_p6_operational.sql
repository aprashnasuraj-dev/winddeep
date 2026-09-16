-- P6 operational recovery/observability. Additive only.
CREATE TABLE IF NOT EXISTS scan_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    stage TEXT NOT NULL CHECK(stage IN ('capture','dedup','chain','rank','hypothesis','bundle','report','complete')),
    payload TEXT NOT NULL,
    committed_at REAL NOT NULL,
    UNIQUE(scan_id, stage)
);

CREATE TABLE IF NOT EXISTS scan_budgets (
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE RESTRICT,
    started_at REAL NOT NULL,
    wall_clock_seconds REAL NOT NULL CHECK(wall_clock_seconds > 0),
    artifact_byte_limit INTEGER NOT NULL CHECK(artifact_byte_limit >= 0),
    artifact_bytes_used INTEGER NOT NULL CHECK(artifact_bytes_used >= 0),
    llm_token_limit INTEGER NOT NULL CHECK(llm_token_limit >= 0),
    llm_tokens_used INTEGER NOT NULL CHECK(llm_tokens_used >= 0),
    per_tool_seconds REAL NOT NULL CHECK(per_tool_seconds > 0),
    status TEXT NOT NULL CHECK(status IN ('active','incomplete','complete'))
);

CREATE TABLE IF NOT EXISTS scan_tool_budgets (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    tool_run_id INTEGER NOT NULL,
    elapsed_seconds REAL NOT NULL CHECK(elapsed_seconds >= 0),
    limit_seconds REAL NOT NULL CHECK(limit_seconds > 0),
    status TEXT NOT NULL CHECK(status IN ('active','incomplete','complete')),
    PRIMARY KEY(scan_id, tool_run_id)
);

CREATE TABLE IF NOT EXISTS structured_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    task_id TEXT,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    payload TEXT NOT NULL,
    wall_time REAL NOT NULL,
    monotonic_time REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_checkpoints_scan ON scan_checkpoints(scan_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_tool_budgets_scan ON scan_tool_budgets(scan_id, tool_run_id);
CREATE INDEX IF NOT EXISTS idx_structured_logs_scan ON structured_logs(scan_id, id ASC);
