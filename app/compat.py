"""P8 schema compatibility and evidence-preserving migration discipline."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class UnsupportedSchemaVersion(ValueError):
    """Raised when a reader encounters a schema outside its compatibility window."""


@dataclass(frozen=True, slots=True)
class SchemaWindow:
    current: str
    previous: str
    deprecation: str
    migration_note: str


_WINDOWS: dict[str, SchemaWindow] = {
    "artifact": SchemaWindow("1", "0", "legacy pre-v1 artifact compatibility retained through v3.x", "Writers emit windeep.artifact.v1; legacy imports are normalized before custody."),
    "bundle": SchemaWindow("2", "1", "bundle v1 reader retained through the v3 major line", "New forensic bundles emit windeep.evidence-bundle.v2; v1 legacy bundles remain read-only."),
    "flow": SchemaWindow("1", "0", "legacy flow compatibility retained through v3.x", "Writers emit windeep.flow-evidence.v1 with raw request/response hashes."),
    "redaction_map": SchemaWindow("1", "0", "legacy redaction metadata compatibility retained through v3.x", "Writers emit deterministic v1 redaction-map records."),
    "sse": SchemaWindow("1", "0", "public SSE v0 compatibility/deprecation window ends no earlier than v4.0.0", "Clients should migrate to windeep.sse.v1 monotonic sequence events."),
    "report": SchemaWindow("1", "0", "legacy report payloads remain readable through v3.x", "Writers emit evidence-grounded report v1 payloads."),
    "har_extension": SchemaWindow("1", "0", "legacy HAR extension fields remain accepted through v3.x", "Writers emit windeep.har-extension.v1 in HAR _windeep metadata."),
}


class SchemaCompatibilityRegistry:
    """One compatibility window for evidence and public v3 schemas."""

    def _window(self, name: str) -> SchemaWindow:
        try:
            return _WINDOWS[str(name)]
        except KeyError as exc:
            raise KeyError(f"unknown schema family: {name}") from exc

    def current(self, name: str) -> str:
        return self._window(name).current

    def previous(self, name: str) -> str:
        return self._window(name).previous

    def writer_version(self, name: str) -> str:
        return self.current(name)

    def accepts(self, name: str, version: str) -> bool:
        window = self._window(name)
        return str(version) in {window.current, window.previous}

    def require(self, name: str, version: str) -> str:
        value = str(version)
        if not self.accepts(name, value):
            window = self._window(name)
            raise UnsupportedSchemaVersion(
                f"unsupported {name} schema {value}; accepted={window.previous},{window.current}"
            )
        return value

    def manifest(self) -> dict[str, dict[str, str]]:
        return {
            name: {
                "current": window.current,
                "previous": window.previous,
                "deprecation": window.deprecation,
                "migration_note": window.migration_note,
            }
            for name, window in sorted(_WINDOWS.items())
        }

    def normalize(self, name: str, version: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Accept current/previous payloads and mark normalized writer version."""
        supplied = self.require(name, version)
        output = dict(payload)
        output.setdefault("_compat", {})
        compat = output["_compat"] if isinstance(output["_compat"], dict) else {}
        compat.update({"family": name, "read_version": supplied, "writer_version": self.current(name)})
        output["_compat"] = compat
        return output


class MigrationDiscipline:
    """Static release audit for destructive SQL affecting forensic state."""

    _FORBIDDEN = (
        re.compile(r"\bdrop\s+table\b", re.I),
        re.compile(r"\bdrop\s+column\b", re.I),
        re.compile(r"\btruncate\b", re.I),
        re.compile(r"\bdelete\s+from\b", re.I),
        re.compile(r"\balter\s+table\b[^;]*\bdrop\b", re.I | re.S),
    )

    @staticmethod
    def _strip_comments(sql: str) -> str:
        no_blocks = re.sub(r"/\*.*?\*/", "", sql, flags=re.S)
        return "\n".join(line.split("--", 1)[0] for line in no_blocks.splitlines())

    def validate(self, sql: str, *, path: str = "<migration>", down: bool = False) -> None:
        text = self._strip_comments(str(sql))
        for pattern in self._FORBIDDEN:
            match = pattern.search(text)
            if match:
                direction = "down migration" if down else "migration"
                raise ValueError(f"destructive SQL is forbidden in {direction} {path}: {match.group(0)}")
        lowered = text.casefold()
        if "vacuum into" in lowered:
            raise ValueError(f"migration may not copy the database to an uncontrolled path: {path}")
        if down and re.search(r"\b(update|replace)\s+artifacts\b", lowered):
            raise ValueError(f"down migration may not rewrite artifact custody rows: {path}")


__all__ = [
    "MigrationDiscipline",
    "SchemaCompatibilityRegistry",
    "SchemaWindow",
    "UnsupportedSchemaVersion",
]
