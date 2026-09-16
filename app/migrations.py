"""Checksummed SQLite schema migrations with evidence-preserving rollback support."""

from __future__ import annotations

import hashlib
import re
import shutil
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_MIGRATION_RE = re.compile(r"^(?P<version>\d{4})_(?P<name>[a-z0-9][a-z0-9_-]*)\.sql$")
_EVIDENCE_TABLES = {
    "findings",
    "flows",
    "scan_events",
    "scan_findings",
    "artifacts",
    "artifact_chunks",
    "artifact_manifests",
    "artifact_access_log",
    "custody_log",
    "evidence_blobs",
    "evidence_bundles",
    "web3_source_artifact",
    "web3_engine_run",
    "web3_finding_provenance",
}
_DROP_TABLE_RE = re.compile(r"\bDROP\s+TABLE\b", re.I)
_TRUNCATE_RE = re.compile(r"\bTRUNCATE\b", re.I)
_DANGEROUS_ADMIN_RE = re.compile(r"\b(?:VACUUM\s+INTO|ATTACH\s+DATABASE|DETACH\s+DATABASE|PRAGMA\s+writable_schema)\b", re.I)
_DELETE_RE = re.compile(r"\bDELETE\s+FROM\s+[`\"\[]?(?P<table>[a-zA-Z0-9_]+)", re.I)
_ALTER_RE = re.compile(r"\bALTER\s+TABLE\s+[`\"\[]?(?P<table>[a-zA-Z0-9_]+)", re.I)


class MigrationError(RuntimeError):
    """Base class for migration planning or execution failures."""


class MigrationChecksumError(MigrationError):
    """Raised when an already-applied migration has changed on disk."""


class MigrationOrderError(MigrationError):
    """Raised when a migration would violate the forward-only version rule."""


class MigrationSafetyError(MigrationError):
    """Raised when a down migration is missing or could destroy evidence."""


@dataclass(frozen=True, slots=True)
class Migration:
    """One immutable migration file and its SHA-256 checksum."""

    version: int
    name: str
    path: Path
    checksum: str

    @property
    def sql(self) -> str:
        """Return migration SQL as UTF-8 text."""
        return self.path.read_text(encoding="utf-8")


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    """Non-mutating description of migrations that would be applied."""

    current_version: int
    pending: tuple[Migration, ...]

    @property
    def target_version(self) -> int:
        """Return the target schema version after applying this plan."""
        return self.pending[-1].version if self.pending else self.current_version


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    """Description of an executed evidence-preserving rollback."""

    from_version: int
    target_version: int
    reverted_versions: tuple[int, ...]
    backup_path: Path | None


class MigrationManager:
    """Discover, verify, back up, apply, and safely roll back SQLite migrations."""

    def __init__(
        self,
        database_path: str | Path,
        migrations_dir: str | Path = "app/data/migrations",
        *,
        backup_dir: str | Path | None = None,
        down_migrations_dir: str | Path | None = None,
    ) -> None:
        self.database_path = Path(database_path)
        self.migrations_dir = Path(migrations_dir)
        self.backup_dir = Path(backup_dir) if backup_dir is not None else self.database_path.parent / "backups"
        self.down_migrations_dir = (
            Path(down_migrations_dir)
            if down_migrations_dir is not None
            else self.migrations_dir.parent / "migrations_down"
        )

    def discover(self) -> tuple[Migration, ...]:
        """Discover uniquely versioned migration files in ascending order."""
        if not self.migrations_dir.exists():
            return ()
        migrations: list[Migration] = []
        seen_versions: set[int] = set()
        for path in sorted(self.migrations_dir.glob("*.sql")):
            match = _MIGRATION_RE.match(path.name)
            if match is None:
                raise MigrationError(f"invalid migration filename: {path.name}")
            version = int(match.group("version"))
            if version in seen_versions:
                raise MigrationError(f"duplicate migration version: {version:04d}")
            seen_versions.add(version)
            raw = path.read_bytes()
            migrations.append(
                Migration(
                    version=version,
                    name=match.group("name"),
                    path=path,
                    checksum=hashlib.sha256(raw).hexdigest(),
                )
            )
        return tuple(sorted(migrations, key=lambda item: item.version))

    def plan(self) -> MigrationPlan:
        """Return a dry-run plan without creating tables or modifying the database."""
        migrations = self.discover()
        applied = self._read_applied()
        by_version = {item.version: item for item in migrations}
        for version, (_, checksum) in applied.items():
            migration = by_version.get(version)
            if migration is None:
                continue
            if migration.checksum != checksum:
                raise MigrationChecksumError(
                    f"migration {version:04d} checksum changed: database={checksum} file={migration.checksum}"
                )
        current = max(applied, default=0)
        stale_new = [item.version for item in migrations if item.version <= current and item.version not in applied]
        if stale_new:
            formatted = ", ".join(f"{value:04d}" for value in stale_new)
            raise MigrationOrderError(f"new migrations cannot be inserted behind current version {current:04d}: {formatted}")
        pending = tuple(item for item in migrations if item.version > current)
        return MigrationPlan(current_version=current, pending=pending)

    def dry_run(self) -> MigrationPlan:
        """Alias for :meth:`plan`, emphasizing that no state is changed."""
        return self.plan()

    def apply(self) -> MigrationPlan:
        """Back up the database and atomically apply every pending migration."""
        plan = self.plan()
        if not plan.pending:
            return plan
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.database_path.exists():
            self.backup()
        with sqlite3.connect(self.database_path, timeout=30.0) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 30000")
            self._ensure_ledger(conn)
            for migration in plan.pending:
                self._apply_one(conn, migration)
        return plan

    def rollback(self, *, target_version: int) -> RollbackPlan:
        """Roll back only through paired, evidence-preserving down migrations.

        Down scripts are intentionally more restricted than forward migrations.
        They may remove compatibility metadata or reverse non-evidence state, but
        destructive table operations and evidence-row deletion/alteration fail
        closed before SQLite executes anything.
        """
        target = int(target_version)
        if target < 0:
            raise MigrationSafetyError("rollback target_version cannot be negative")
        applied = self._read_applied()
        current = max(applied, default=0)
        if target > current:
            raise MigrationSafetyError(f"rollback target {target:04d} is ahead of current version {current:04d}")
        versions = tuple(sorted((version for version in applied if version > target), reverse=True))
        if not versions:
            return RollbackPlan(current, target, (), None)
        if not self.database_path.exists():
            raise MigrationSafetyError("cannot rollback a missing database")

        scripts: list[tuple[int, str]] = []
        for version in versions:
            name = applied[version][0]
            path = self.down_migrations_dir / f"{version:04d}_{name}.sql"
            if not path.exists():
                raise MigrationSafetyError(f"missing down migration for {version:04d}_{name}")
            sql = path.read_text(encoding="utf-8")
            self._validate_down_sql(sql, version=version)
            scripts.append((version, sql))

        backup_path = self.backup()
        chunks = ["BEGIN IMMEDIATE;"]
        for version, sql in scripts:
            chunks.append(sql.rstrip())
            chunks.append(f"DELETE FROM schema_migrations WHERE version = {int(version)};")
        chunks.append("COMMIT;")
        script = "\n".join(chunks) + "\n"
        with sqlite3.connect(self.database_path, timeout=30.0) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 30000")
            self._ensure_ledger(conn)
            try:
                conn.executescript(script)
            except Exception:
                conn.rollback()
                raise
        return RollbackPlan(current, target, versions, backup_path)

    @staticmethod
    def _validate_down_sql(sql: str, *, version: int) -> None:
        if not sql.strip():
            raise MigrationSafetyError(f"down migration {version:04d} is empty")
        if _DROP_TABLE_RE.search(sql) or _TRUNCATE_RE.search(sql) or _DANGEROUS_ADMIN_RE.search(sql):
            raise MigrationSafetyError(f"down migration {version:04d} contains destructive SQL")
        for match in _DELETE_RE.finditer(sql):
            table = match.group("table").casefold()
            if table in _EVIDENCE_TABLES:
                raise MigrationSafetyError(
                    f"down migration {version:04d} cannot delete evidence table rows: {table}"
                )
        for match in _ALTER_RE.finditer(sql):
            table = match.group("table").casefold()
            if table in _EVIDENCE_TABLES:
                raise MigrationSafetyError(
                    f"down migration {version:04d} cannot alter evidence table: {table}"
                )

    def backup(self) -> Path:
        """Create a consistent SQLite online backup and return its path."""
        if not self.database_path.exists():
            raise MigrationError(f"database does not exist: {self.database_path}")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        candidate = self.backup_dir / f"{self.database_path.stem}-{stamp}.sqlite3"
        suffix = 1
        while candidate.exists():
            candidate = self.backup_dir / f"{self.database_path.stem}-{stamp}-{suffix}.sqlite3"
            suffix += 1
        with sqlite3.connect(self.database_path) as source, sqlite3.connect(candidate) as destination:
            source.backup(destination)
        return candidate

    def restore_backup(self, backup_path: str | Path) -> None:
        """Restore a backup only when explicitly requested by an operator."""
        source = Path(backup_path)
        if not source.exists():
            raise MigrationError(f"backup does not exist: {source}")
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.database_path.with_suffix(self.database_path.suffix + ".restore")
        shutil.copy2(source, temporary)
        temporary.replace(self.database_path)

    def _read_applied(self) -> dict[int, tuple[str, str]]:
        if not self.database_path.exists():
            return {}
        with sqlite3.connect(self.database_path) as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = ? AND name = ?",
                ("table", "schema_migrations"),
            ).fetchone()
            if exists is None:
                return {}
            rows = conn.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
        return {int(version): (str(name), str(checksum)) for version, name, checksum in rows}

    @staticmethod
    def _ensure_ledger(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at REAL NOT NULL
            )
            """
        )

    @staticmethod
    def _apply_one(conn: sqlite3.Connection, migration: Migration) -> None:
        try:
            conn.executescript("BEGIN IMMEDIATE;\n" + migration.sql)
            conn.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                (migration.version, migration.name, migration.checksum, time.time()),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def migration_checksums(migrations: Iterable[Migration]) -> dict[int, str]:
    """Return version-to-checksum mapping for diagnostics and release manifests."""
    return {migration.version: migration.checksum for migration in migrations}
