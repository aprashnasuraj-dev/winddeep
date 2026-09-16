-- P5 deep web3 provenance. Additive, immutable evidence references only.
CREATE TABLE IF NOT EXISTS web3_source_artifact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    contract_address TEXT NOT NULL,
    chain_id INTEGER NOT NULL CHECK(chain_id > 0),
    block_number INTEGER NOT NULL CHECK(block_number > 0),
    resolver TEXT NOT NULL,
    resolver_response_hash TEXT,
    solc_version TEXT,
    optimizer_runs INTEGER,
    evm_version TEXT,
    abi_hash TEXT,
    source_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    bytecode_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    disassembly_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    project_solc_version TEXT,
    compiler_divergence INTEGER NOT NULL DEFAULT 0 CHECK(compiler_divergence IN (0, 1)),
    supersedes_id INTEGER REFERENCES web3_source_artifact(id) ON DELETE RESTRICT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS web3_engine_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL,
    engine_name TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    detector_set_version TEXT,
    source_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    raw_output_artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    started_at REAL NOT NULL,
    ended_at REAL NOT NULL,
    exit_code INTEGER NOT NULL,
    seed TEXT,
    supersedes_id INTEGER REFERENCES web3_engine_run(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS web3_finding_provenance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    engine_run_id INTEGER NOT NULL REFERENCES web3_engine_run(id) ON DELETE RESTRICT,
    detector_id TEXT NOT NULL,
    swc_id TEXT,
    affected_function TEXT,
    source_file TEXT,
    line_start INTEGER,
    line_end INTEGER,
    bytecode_offset_start INTEGER,
    bytecode_offset_end INTEGER,
    corroborated INTEGER NOT NULL DEFAULT 0 CHECK(corroborated IN (0, 1)),
    corroborating_engine_run_id INTEGER REFERENCES web3_engine_run(id) ON DELETE RESTRICT,
    upstream_source TEXT NOT NULL,
    call_path_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    state_context_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    cross_contract_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    supersedes_id INTEGER REFERENCES web3_finding_provenance(id) ON DELETE RESTRICT,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_web3_source_scan_contract ON web3_source_artifact(scan_id, chain_id, contract_address, block_number, id);
CREATE INDEX IF NOT EXISTS idx_web3_engine_scan ON web3_engine_run(scan_id, engine_name, id);
CREATE INDEX IF NOT EXISTS idx_web3_provenance_finding ON web3_finding_provenance(finding_id, id);
