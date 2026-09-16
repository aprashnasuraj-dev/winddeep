"""P8 schema-envelope and API compatibility contracts for Windeep v3."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping


class SchemaCompatibilityError(ValueError):
    """Raised when a schema/API version falls outside the supported window."""


@dataclass(frozen=True, slots=True)
class APICompatibility:
    """One-current/one-previous API compatibility window."""

    current: str
    previous: str
    migration_note: str

    @classmethod
    def default(cls) -> "APICompatibility":
        return cls(
            current="v2",
            previous="v1",
            migration_note=(
                "Migrate clients to /api/v2 endpoints and versioned v2 schemas. "
                "The previous v1 read contract remains supported for the deprecation window; "
                "new writes must use v2."
            ),
        )

    @property
    def supported_read_versions(self) -> tuple[str, str]:
        return (self.previous, self.current)

    @property
    def writer_version(self) -> str:
        return self.current

    def is_supported(self, version: str) -> bool:
        return version in self.supported_read_versions

    def metadata(self) -> dict[str, Any]:
        return {
            "current": self.current,
            "supported_read_versions": list(self.supported_read_versions),
            "writer_version": self.writer_version,
            "deprecation": {
                "version": self.previous,
                "replacement": self.current,
                "migration_note": self.migration_note,
                "policy": "Breaking API changes require a deprecation window and migration note before removal.",
            },
        }


class VersionedEnvelopeCodec:
    """Canonical JSON envelope: readers accept current+previous; writers current only."""

    def __init__(self, *, current_version: int, previous_version: int) -> None:
        if current_version <= 0 or previous_version <= 0 or previous_version >= current_version:
            raise SchemaCompatibilityError("schema versions must be positive with previous < current")
        self.current_version = int(current_version)
        self.previous_version = int(previous_version)

    @property
    def readable_versions(self) -> tuple[int, int]:
        return (self.previous_version, self.current_version)

    def encode(self, payload: Mapping[str, Any], *, version: int | None = None) -> str:
        selected = self.current_version if version is None else int(version)
        if selected != self.current_version:
            raise SchemaCompatibilityError(
                f"writers emit only current schema version {self.current_version}; requested {selected}"
            )
        if not isinstance(payload, Mapping):
            raise SchemaCompatibilityError("schema payload must be an object")
        return json.dumps(
            {"schema_version": self.current_version, "payload": dict(payload)},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

    def decode(self, encoded: str | bytes) -> dict[str, Any]:
        try:
            raw = encoded.decode("utf-8") if isinstance(encoded, bytes) else str(encoded)
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise SchemaCompatibilityError("invalid versioned schema envelope") from exc
        if not isinstance(document, Mapping):
            raise SchemaCompatibilityError("schema envelope must be an object")
        try:
            version = int(document["schema_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SchemaCompatibilityError("schema envelope is missing a valid schema_version") from exc
        if version not in self.readable_versions:
            raise SchemaCompatibilityError(
                f"unsupported schema version {version}; readers accept {self.previous_version} and {self.current_version}"
            )
        payload = document.get("payload")
        if not isinstance(payload, Mapping):
            raise SchemaCompatibilityError("schema envelope payload must be an object")
        return dict(payload)


class SchemaCompatibilityRegistry:
    """Read the persisted compatibility contract installed by migration 0008."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def get(self, component: str) -> dict[str, Any]:
        name = component.strip()
        if not name:
            raise SchemaCompatibilityError("component is required")
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM schema_compatibility WHERE component = ?",
                (name,),
            ).fetchone()
        if row is None:
            raise SchemaCompatibilityError(f"schema compatibility contract not found: {name}")
        return dict(row)

    def can_read(self, component: str, version: int) -> bool:
        row = self.get(component)
        selected = int(version)
        return int(row["min_reader_version"]) <= selected <= int(row["current_reader_version"])

    def can_write(self, component: str, version: int) -> bool:
        row = self.get(component)
        return int(version) == int(row["writer_version"])
