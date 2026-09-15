-- Evidence-preserving v3 runtime down marker.
-- This intentionally does not remove P1/P2/P5/P6 forensic data. A downgraded
-- application may ignore newer tables, while retained evidence remains available
-- for a future compatible reader.
CREATE TABLE IF NOT EXISTS migration_tombstones (
    tombstone_id TEXT PRIMARY KEY,
    phase TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at REAL NOT NULL
);
INSERT OR IGNORE INTO migration_tombstones(tombstone_id, phase, note, created_at)
VALUES (
    'v3-runtime-retained',
    'v3',
    'Runtime compatibility downgraded; v3 evidence tables retained without destructive rewrite.',
    CAST(strftime('%s','now') AS REAL)
);
