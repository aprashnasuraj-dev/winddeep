# Windeep schema and API compatibility

Windeep v3 uses an explicit compatibility window instead of assuming that every stored record or client upgrades at the same moment.

## Schema envelope policy

Readers support **current + previous** schema versions. For the core v3 contract that means readers accept schema versions `1` and `2`. Writers always emit the **current** schema version (`2`). A previous-version record may be read and transformed in memory, but new persisted output must use the current writer contract.

The persisted `schema_compatibility` registry records the writer version, minimum/current reader versions, current API version, previous API version, and the deprecation note. Code must fail closed when a requested version falls outside that window.

## API version policy

`v2` is the current API contract and `v1` is the supported previous read contract during its deprecation window. New writes use `v2`. A breaking API change must include both a deprecation window and a migration note before the previous version is removed.

The P8 compatibility metadata is intentionally independent from network routing: existing `/api/v2/...` endpoints remain current, while compatibility-aware callers can use the shared `APICompatibility` contract to decide whether a stored/client version is still supported.

## Migration policy

Forward migrations remain checksummed and ordered. P8 adds **paired down migration** support only for migrations that explicitly provide a matching file under `app/data/migrations_down/`.

A down migration is not a general-purpose destructive rollback mechanism. Before execution Windeep:

1. requires an exact version/name paired down migration;
2. creates a consistent SQLite backup;
3. statically rejects table drops, truncation, dangerous database administration statements, deletes from evidence-bearing tables, and alterations of evidence-bearing tables;
4. executes the accepted down migration and migration-ledger update as one SQLite transaction;
5. leaves historical evidence in place.

Migration `0008` therefore rolls back only the compatibility contract row. It deliberately leaves the compatibility table and all evidence tables untouched. Reapplying `0008` restores the current contract without rewriting findings, flows, artifacts, bundles, web3 provenance, or scan-event evidence.

## Evidence preservation

Evidence is append-oriented across P1-P7. A schema rollback must never be used to erase evidence in order to make an older binary appear compatible. When an older reader cannot understand a newer evidence schema, it must refuse that record rather than mutate or discard it.

## Release rule

A schema/API bump is incomplete until the current writer, current+previous readers, paired safe down migration (when rollback is supported), deprecation policy, migration note, and compatibility tests are all present. The v3.0.0 release closes P8 with that contract.
