-- P1 forensic raw-capture, custody, redaction, retention, and Merkle sealing.
CREATE TABLE IF NOT EXISTS scan_evidence_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL UNIQUE,
    wrapped_key BLOB,
    created_at REAL NOT NULL,
    retired_at REAL,
    destroyed_at REAL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE INDEX IF NOT EXISTS idx_scan_evidence_keys_active ON scan_evidence_keys(scan_id, active, created_at DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    schema_version TEXT NOT NULL DEFAULT 'windeep.artifact.v1',
    kind TEXT NOT NULL,
    media_type TEXT NOT NULL,
    size INTEGER NOT NULL CHECK(size >= 0),
    created_at REAL NOT NULL,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL,
    encryption_key_id TEXT NOT NULL REFERENCES scan_evidence_keys(key_id),
    chunk_count INTEGER NOT NULL CHECK(chunk_count >= 1),
    metadata TEXT NOT NULL,
    supersedes_id INTEGER REFERENCES artifacts(id) ON DELETE SET NULL,
    tombstoned_at REAL,
    UNIQUE(scan_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_scan_sha256 ON artifacts(scan_id, sha256);
CREATE INDEX IF NOT EXISTS idx_artifacts_tool_run ON artifacts(tool_run_id, created_at);

CREATE TABLE IF NOT EXISTS artifact_chunks (
    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    plaintext_size INTEGER NOT NULL CHECK(plaintext_size >= 0),
    compressed_size INTEGER NOT NULL CHECK(compressed_size >= 0),
    chunk_sha256 TEXT NOT NULL CHECK(length(chunk_sha256) = 64),
    PRIMARY KEY(artifact_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS tool_run_evidence (
    tool_run_id INTEGER PRIMARY KEY REFERENCES tool_runs(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    stdout_sha256 TEXT NOT NULL CHECK(length(stdout_sha256) = 64),
    stderr_sha256 TEXT NOT NULL CHECK(length(stderr_sha256) = 64),
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS flow_evidence (
    flow_id INTEGER PRIMARY KEY REFERENCES flows(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL,
    task_id TEXT,
    raw_request_sha256 TEXT NOT NULL CHECK(length(raw_request_sha256) = 64),
    raw_response_sha256 TEXT NOT NULL CHECK(length(raw_response_sha256) = 64),
    flow_sha256 TEXT NOT NULL CHECK(length(flow_sha256) = 64),
    http_version TEXT NOT NULL DEFAULT 'HTTP/1.1',
    stream_id INTEGER,
    pseudo_headers TEXT NOT NULL,
    timings TEXT NOT NULL,
    server_ip TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flow_evidence_scan ON flow_evidence(scan_id, flow_id);

CREATE TABLE IF NOT EXISTS redaction_map (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    path TEXT NOT NULL,
    span_start INTEGER NOT NULL,
    span_end INTEGER NOT NULL,
    placeholder TEXT NOT NULL,
    applied_at REAL NOT NULL,
    UNIQUE(scan_id, source_sha256, rule_id, path, span_start, span_end)
);
CREATE INDEX IF NOT EXISTS idx_redaction_map_source ON redaction_map(scan_id, source_sha256, id);

CREATE TABLE IF NOT EXISTS redaction_runs (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
    path TEXT NOT NULL,
    operator_terms_sha256 TEXT NOT NULL CHECK(length(operator_terms_sha256) = 64),
    redacted_sha256 TEXT NOT NULL CHECK(length(redacted_sha256) = 64),
    map_sha256 TEXT NOT NULL CHECK(length(map_sha256) = 64),
    created_at REAL NOT NULL,
    PRIMARY KEY(scan_id, source_sha256, path, operator_terms_sha256)
);

CREATE TABLE IF NOT EXISTS scan_evidence_roots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    merkle_root TEXT NOT NULL CHECK(length(merkle_root) = 64),
    leaf_count INTEGER NOT NULL CHECK(leaf_count >= 0),
    audit_hash TEXT NOT NULL CHECK(length(audit_hash) = 64),
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_evidence_roots_scan ON scan_evidence_roots(scan_id, id DESC);

CREATE TABLE IF NOT EXISTS scan_retention (
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    policy TEXT NOT NULL DEFAULT 'keep-forever',
    updated_at REAL NOT NULL
);
