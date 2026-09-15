-- P6 operational durability state. Additive only.
CREATE TABLE IF NOT EXISTS scan_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    stage TEXT NOT NULL,
    state TEXT NOT NULL,
    committed_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_checkpoints_scan ON scan_checkpoints(scan_id, id DESC);

CREATE TABLE IF NOT EXISTS scan_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_operations_scan ON scan_operations(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_scan_operations_task ON scan_operations(scan_id, task_id, id);
