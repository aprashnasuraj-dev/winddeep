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

CREATE TABLE IF NOT EXISTS handling_policy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    imported_at REAL NOT NULL,
    raw_artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    version TEXT NOT NULL,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS handling_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL REFERENCES handling_policy(id) ON DELETE RESTRICT,
    rule_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('accepted','documented_exclusion','known_issue','deferred','informational','severity_matrix','duplicate_policy')),
    matcher TEXT NOT NULL,
    severity_floor TEXT,
    priority_band TEXT,
    notes TEXT NOT NULL,
    reference_url TEXT,
    UNIQUE(policy_id, rule_id)
);

CREATE TABLE IF NOT EXISTS handling_classification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    policy_id INTEGER REFERENCES handling_policy(id) ON DELETE RESTRICT,
    policy_version TEXT NOT NULL,
    disposition TEXT NOT NULL,
    handling_rule_ids TEXT NOT NULL,
    acceptance_likelihood TEXT NOT NULL,
    rationale TEXT NOT NULL,
    duplicate_risk TEXT NOT NULL,
    severity_floor_met INTEGER NOT NULL CHECK(severity_floor_met IN (0,1)),
    priority_floor_met INTEGER NOT NULL CHECK(priority_floor_met IN (0,1)),
    triage_readiness TEXT NOT NULL,
    score REAL NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(finding_id, policy_version)
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
