-- P5 immutable Web3 audit provenance. Additive only.
CREATE TABLE IF NOT EXISTS web3_source_artifact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    contract_address TEXT NOT NULL,
    chain_id INTEGER NOT NULL CHECK(chain_id > 0),
    block_number INTEGER,
    provider TEXT NOT NULL,
    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
    compiler_version TEXT,
    supersedes_id INTEGER REFERENCES web3_source_artifact(id) ON DELETE RESTRICT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web3_source_scan ON web3_source_artifact(scan_id, contract_address, chain_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_web3_source_sha ON web3_source_artifact(source_sha256);

CREATE TABLE IF NOT EXISTS web3_engine_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    source_artifact_id INTEGER REFERENCES web3_source_artifact(id) ON DELETE SET NULL,
    engine TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
    output_sha256 TEXT NOT NULL CHECK(length(output_sha256) = 64),
    supersedes_id INTEGER REFERENCES web3_engine_run(id) ON DELETE RESTRICT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web3_engine_scan ON web3_engine_run(scan_id, engine, id DESC);

CREATE TABLE IF NOT EXISTS web3_finding_provenance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id) ON DELETE RESTRICT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    engine_run_id INTEGER NOT NULL REFERENCES web3_engine_run(id) ON DELETE RESTRICT,
    detector_id TEXT NOT NULL,
    function_name TEXT,
    source_location TEXT NOT NULL,
    corroborated INTEGER NOT NULL DEFAULT 0 CHECK(corroborated IN (0,1)),
    supersedes_id INTEGER REFERENCES web3_finding_provenance(id) ON DELETE RESTRICT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web3_provenance_finding ON web3_finding_provenance(finding_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_web3_provenance_scan ON web3_finding_provenance(scan_id, engine_run_id);
