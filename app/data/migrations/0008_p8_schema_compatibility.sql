-- P8 schema/API compatibility metadata. Additive only.
CREATE TABLE IF NOT EXISTS schema_compatibility (
    component TEXT PRIMARY KEY,
    writer_version INTEGER NOT NULL CHECK(writer_version > 0),
    min_reader_version INTEGER NOT NULL CHECK(min_reader_version > 0),
    current_reader_version INTEGER NOT NULL CHECK(current_reader_version >= min_reader_version),
    api_version TEXT NOT NULL,
    previous_api_version TEXT NOT NULL,
    deprecation_note TEXT NOT NULL,
    created_at REAL NOT NULL
);

INSERT OR IGNORE INTO schema_compatibility(
    component, writer_version, min_reader_version, current_reader_version,
    api_version, previous_api_version, deprecation_note, created_at
) VALUES (
    'core', 2, 1, 2,
    'v2', 'v1',
    'Breaking API changes require a deprecation window and migration note; v1 remains readable while all new writes use v2.',
    0.0
);
