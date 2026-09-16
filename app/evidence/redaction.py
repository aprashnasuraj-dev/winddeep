"""P1 deterministic secret redaction with persisted reproducibility maps."""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Sequence

from app.evidence.raw_store import RawArtifactStore

_RULE_VERSION = "1"


@dataclass(frozen=True, slots=True)
class RedactionEntry:
    rule_id: str
    rule_version: str
    path: str
    span_start: int
    span_end: int
    placeholder: str


@dataclass(frozen=True, slots=True)
class RedactionResult:
    content: bytes
    entries: tuple[RedactionEntry, ...]
    redacted_sha256: str
    map_sha256: str


class EvidenceRedactor:
    """Create stable redacted views without mutating encrypted raw evidence."""

    _HEADER = re.compile(r"(?im)^(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*([^\r\n]+)")
    _BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+\-/]+=*)")
    _SECRET_VALUE = re.compile(
        r"(?i)(?:[\"']?(?:api[_-]?key|token|password|passwd|secret|credential|session)[\"']?\s*[:=]\s*[\"']?)([^\"'\s,;&\r\n}\]]+)"
    )

    def __init__(self, store: RawArtifactStore) -> None:
        self.store = store

    @staticmethod
    def _operator_digest(terms: Sequence[str]) -> str:
        normalized = sorted({str(term) for term in terms if str(term)})
        return hashlib.sha256(json.dumps(normalized, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()

    @staticmethod
    def _placeholder(scan_id: int, rule_id: str, occurrence: int) -> str:
        token = hashlib.sha256(f"{scan_id}\x1f{rule_id}\x1f{occurrence}".encode("utf-8")).hexdigest()[:12]
        return f"[REDACTED:{rule_id}:{token}]"

    def redact_artifact(
        self,
        source_sha256: str,
        *,
        scan_id: int,
        path: str,
        operator_terms: Sequence[str] = (),
    ) -> RedactionResult:
        raw = self.store.read(source_sha256, scan_id=scan_id, reason=f"redaction source: {path}")
        text = raw.decode("utf-8", errors="replace")
        candidates: list[tuple[int, int, str]] = []

        for match in self._HEADER.finditer(text):
            candidates.append((match.start(2), match.end(2), f"header.{match.group(1).casefold()}"))
        for match in self._BEARER.finditer(text):
            candidates.append((match.start(1), match.end(1), "bearer"))
        for match in self._SECRET_VALUE.finditer(text):
            candidates.append((match.start(1), match.end(1), "secret-value"))
        for term_index, term in enumerate(sorted({str(value) for value in operator_terms if str(value)}), start=1):
            for match in re.finditer(re.escape(term), text):
                candidates.append((match.start(), match.end(), f"operator.{term_index}"))

        candidates.sort(key=lambda item: (item[0], -(item[1] - item[0]), item[2]))
        selected: list[tuple[int, int, str]] = []
        occupied_until = -1
        for start, end, rule_id in candidates:
            if start < occupied_until or end <= start:
                continue
            selected.append((start, end, rule_id))
            occupied_until = end

        counts: dict[str, int] = {}
        entries: list[RedactionEntry] = []
        parts: list[str] = []
        cursor = 0
        for start, end, rule_id in selected:
            parts.append(text[cursor:start])
            counts[rule_id] = counts.get(rule_id, 0) + 1
            placeholder = self._placeholder(scan_id, rule_id, counts[rule_id])
            parts.append(placeholder)
            entries.append(
                RedactionEntry(
                    rule_id=rule_id,
                    rule_version=_RULE_VERSION,
                    path=path,
                    span_start=start,
                    span_end=end,
                    placeholder=placeholder,
                )
            )
            cursor = end
        parts.append(text[cursor:])
        redacted = "".join(parts).encode("utf-8")

        now = time.time()
        with self.store.database._connect() as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO redaction_map(
                    scan_id, source_sha256, rule_id, rule_version, path,
                    span_start, span_end, placeholder, applied_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        source_sha256,
                        entry.rule_id,
                        entry.rule_version,
                        entry.path,
                        entry.span_start,
                        entry.span_end,
                        entry.placeholder,
                        now,
                    )
                    for entry in entries
                ],
            )

        map_payload = {
            "schema": "windeep.redaction-map.v1",
            "scan_id": scan_id,
            "source_sha256": source_sha256,
            "path": path,
            "entries": [
                {
                    "rule_id": entry.rule_id,
                    "rule_version": entry.rule_version,
                    "path": entry.path,
                    "span_start": entry.span_start,
                    "span_end": entry.span_end,
                    "placeholder": entry.placeholder,
                }
                for entry in entries
            ],
        }
        map_bytes = json.dumps(map_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        redacted_ref = self.store.put(
            scan_id=scan_id,
            tool_run_id=None,
            kind="redacted_view",
            media_type="application/octet-stream",
            content=redacted,
            reason=f"persist redacted view: {path}",
            metadata={"source_sha256": source_sha256, "path": path},
        )
        map_ref = self.store.put(
            scan_id=scan_id,
            tool_run_id=None,
            kind="redaction_map",
            media_type="application/json",
            content=map_bytes,
            reason=f"persist redaction map: {path}",
            metadata={"source_sha256": source_sha256, "path": path},
        )
        operator_digest = self._operator_digest(operator_terms)
        with self.store.database._connect() as conn:
            conn.execute(
                """
                INSERT INTO redaction_runs(
                    scan_id, source_sha256, path, operator_terms_sha256,
                    redacted_sha256, map_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, source_sha256, path, operator_terms_sha256) DO UPDATE SET
                    redacted_sha256 = excluded.redacted_sha256,
                    map_sha256 = excluded.map_sha256
                """,
                (scan_id, source_sha256, path, operator_digest, redacted_ref.sha256, map_ref.sha256, now),
            )
        return RedactionResult(
            content=redacted,
            entries=tuple(entries),
            redacted_sha256=redacted_ref.sha256,
            map_sha256=map_ref.sha256,
        )


__all__ = ["EvidenceRedactor", "RedactionEntry", "RedactionResult"]
