-- V6 reconnaissance observation inventory.
-- Recon output is evidence/inventory, not a vulnerability finding. Additive only.
CREATE TABLE IF NOT EXISTS scan_asset_observations (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool_run_id INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
    observation_fingerprint TEXT NOT NULL,
    tool TEXT NOT NULL,
    endpoint TEXT,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(scan_id, tool_run_id, observation_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_scan_asset_observations_scan
ON scan_asset_observations(scan_id, tool, observation_fingerprint);
