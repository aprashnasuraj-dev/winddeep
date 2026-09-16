"""Windeep v3 release migration.

This migration is intentionally Python-backed because v3 needs a paired, explicit
up/down contract while preserving P8's existing SQL migration semantics. The down
path never drops or rewrites evidence-bearing tables; it only deactivates the v3
release marker and removes the frozen contract seed.
"""
from __future__ import annotations

VERSION = 30
NAME = "v3_release"

UP_SQL = r"""
CREATE TABLE IF NOT EXISTS v3_release_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    applied_at REAL NOT NULL,
    reverted_at REAL
);

CREATE TABLE IF NOT EXISTS v3_contract_freeze (
    contract_name TEXT PRIMARY KEY,
    contract_version TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    frozen_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS v3_pipeline_checkpoint (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    stage TEXT NOT NULL,
    payload TEXT NOT NULL,
    committed_at REAL NOT NULL,
    PRIMARY KEY(scan_id, stage)
);

CREATE TABLE IF NOT EXISTS v3_scan_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_record (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id) ON DELETE RESTRICT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    bundle_sha256 TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(finding_id, bundle_sha256, artifact_sha256)
);

CREATE TABLE IF NOT EXISTS verification_claim (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER NOT NULL REFERENCES verification_record(id) ON DELETE RESTRICT,
    claim_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('verified','partially_verified','needs-review')),
    evidence_refs TEXT NOT NULL,
    plan TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(record_id, claim_key)
);

CREATE TABLE IF NOT EXISTS v3_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    class TEXT NOT NULL,
    value TEXT NOT NULL,
    ports TEXT NOT NULL,
    sni TEXT NOT NULL,
    host_header TEXT NOT NULL,
    consent_token_id TEXT NOT NULL,
    justification TEXT NOT NULL,
    max_hosts INTEGER,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS handling_classification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT UNIQUE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    asset_class TEXT NOT NULL CHECK(asset_class IN ('http','https','ipv4','ipv6')),
    disposition TEXT NOT NULL CHECK(disposition IN ('actionable','needs-review','not-actionable','informational')),
    tester_priority REAL NOT NULL CHECK(tester_priority >= 0 AND tester_priority <= 100),
    duplicate_risk TEXT NOT NULL CHECK(duplicate_risk IN ('low','medium','high')),
    rationale TEXT NOT NULL,
    score REAL NOT NULL,
    classified_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v3_transition_scan ON v3_scan_transitions(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_verification_finding ON verification_record(finding_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_v3_target_scan ON v3_targets(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_handling_scan ON handling_classification(scan_id, score DESC, finding_id);
"""

DOWN_SQL = r"""
DELETE FROM v3_contract_freeze;
UPDATE v3_release_migrations SET active = 0, reverted_at = strftime('%s','now') WHERE version = 30;
"""
