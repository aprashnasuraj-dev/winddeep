-- Safe rollback for P8 compatibility metadata.
-- The compatibility table is intentionally retained; only the P8 contract row is removed.
DELETE FROM schema_compatibility WHERE component = 'core';
