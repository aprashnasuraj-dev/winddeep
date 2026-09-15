"""LanceDB-backed long-term finding memory for the Windeep Brain."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.database import Database

_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")
_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s,;]+"),
)


class HashEmbedding:
    """Small deterministic feature-hash embedding suitable for offline similarity."""

    def __init__(self, dimensions: int = 256) -> None:
        if dimensions < 32:
            raise ValueError("dimensions must be >= 32")
        self.dimensions = dimensions

    def embed(self, text: str) -> list[float]:
        """Return a normalized deterministic vector for text."""
        vector = [0.0] * self.dimensions
        tokens = [token.casefold() for token in _TOKEN_RE.findall(text)]
        if not tokens:
            return vector
        features = tokens + [f"{a}::{b}" for a, b in zip(tokens, tokens[1:])]
        for feature in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=16).digest()
            bucket = int.from_bytes(digest[:8], "big") % self.dimensions
            sign = 1.0 if digest[8] & 1 else -1.0
            vector[bucket] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return vector
        return [value / norm for value in vector]


class MemoryStore:
    """Persist and query finding/rejection memories using LanceDB vectors."""

    def __init__(
        self,
        path: str | Path = "app/data/memory.lancedb",
        *,
        database: Database | None = None,
        dimensions: int = 256,
        table_name: str = "brain_memory",
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        self.embedder = HashEmbedding(dimensions)
        self.table_name = table_name
        self._lock = threading.Lock()

    async def embed_finding(
        self,
        finding: Mapping[str, Any],
        *,
        kind: str = "finding",
        target_id: int | None = None,
        finding_id: int | None = None,
    ) -> str:
        """Embed a finding and persist it in LanceDB, returning the memory id."""
        try:
            text = self._finding_text(finding)
            metadata = {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "vuln_type": finding.get("vuln_type"),
                "endpoint": finding.get("endpoint"),
                "tool": finding.get("tool"),
                "verified": finding.get("verified"),
            }
            return await self._add(
                text,
                kind=kind,
                target_id=target_id,
                finding_id=finding_id or self._coerce_int(finding.get("id")),
                metadata=metadata,
            )
        except asyncio.CancelledError:
            raise

    async def find_similar(
        self,
        finding_or_text: Mapping[str, Any] | str,
        *,
        limit: int = 5,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return nearest memories ordered by cosine similarity."""
        try:
            if limit < 1 or limit > 100:
                raise ValueError("limit must be between 1 and 100")
            text = (
                self._finding_text(finding_or_text)
                if isinstance(finding_or_text, Mapping)
                else str(finding_or_text)
            )
            vector = self.embedder.embed(self._sanitize(text))
            rows = await asyncio.to_thread(self._search_sync, vector, limit * 3)
            result: list[dict[str, Any]] = []
            for row in rows:
                if kind is not None and row.get("kind") != kind:
                    continue
                distance = float(row.get("_distance", 1.0))
                item = dict(row)
                item["similarity"] = max(0.0, min(1.0, 1.0 - distance))
                item["metadata"] = self._decode_metadata(item.pop("metadata_json", "{}"))
                result.append(item)
                if len(result) >= limit:
                    break
            return result
        except asyncio.CancelledError:
            raise

    async def learn_from_rejection(
        self,
        finding: Mapping[str, Any],
        rejection: Mapping[str, Any] | str,
        *,
        target_id: int | None = None,
    ) -> str:
        """Store a sanitized generalized lesson from a rejected finding/report."""
        try:
            if isinstance(rejection, Mapping):
                reason = json.dumps(dict(rejection), ensure_ascii=False, sort_keys=True)
            else:
                reason = str(rejection)
            text = (
                f"Rejected finding pattern: {finding.get('vuln_type') or 'unknown'}; "
                f"title={finding.get('title') or ''}; reason={reason}"
            )
            metadata = {
                "title": finding.get("title"),
                "vuln_type": finding.get("vuln_type"),
                "endpoint": finding.get("endpoint"),
                "rejection": rejection if isinstance(rejection, Mapping) else {"reason": rejection},
            }
            return await self._add(
                text,
                kind="rejection",
                target_id=target_id,
                finding_id=self._coerce_int(finding.get("id")),
                metadata=metadata,
            )
        except asyncio.CancelledError:
            raise

    async def _add(
        self,
        text: str,
        *,
        kind: str,
        target_id: int | None,
        finding_id: int | None,
        metadata: Mapping[str, Any],
    ) -> str:
        try:
            sanitized = self._sanitize(text)
            memory_id = uuid.uuid4().hex
            record = {
                "id": memory_id,
                "text": sanitized,
                "vector": self.embedder.embed(sanitized),
                "kind": kind,
                "target_id": target_id if target_id is not None else -1,
                "finding_id": finding_id if finding_id is not None else -1,
                "metadata_json": json.dumps(dict(metadata), ensure_ascii=False, sort_keys=True, default=str),
                "created_at": time.time(),
            }
            await asyncio.to_thread(self._insert_sync, record)
            if self.database is not None:
                self.database.add_learning(
                    kind=kind,
                    content=sanitized,
                    metadata=metadata,
                    target_id=target_id,
                    finding_id=finding_id,
                    embedding_ref=memory_id,
                )
            return memory_id
        except asyncio.CancelledError:
            raise

    def _insert_sync(self, record: Mapping[str, Any]) -> None:
        lancedb = self._import_lancedb()
        with self._lock:
            db = lancedb.connect(str(self.path))
            if self._has_table(db):
                table = db.open_table(self.table_name)
                table.add([dict(record)])
            else:
                db.create_table(self.table_name, data=[dict(record)])

    def _search_sync(self, vector: Sequence[float], limit: int) -> list[dict[str, Any]]:
        lancedb = self._import_lancedb()
        with self._lock:
            db = lancedb.connect(str(self.path))
            if not self._has_table(db):
                return []
            table = db.open_table(self.table_name)
            query = table.search(list(vector)).metric("cosine").limit(limit)
            rows = query.to_list()
        return [dict(row) for row in rows]

    def _has_table(self, db: Any) -> bool:
        if hasattr(db, "table_names"):
            try:
                return self.table_name in set(db.table_names())
            except TypeError:
                pass
        listing = db.list_tables()
        names = getattr(listing, "tables", listing)
        return self.table_name in set(names)

    @staticmethod
    def _import_lancedb() -> Any:
        try:
            import lancedb
        except ImportError as exc:
            raise RuntimeError(
                "LanceDB is required for Brain memory; install requirements.txt"
            ) from exc
        return lancedb

    def _finding_text(self, finding: Mapping[str, Any]) -> str:
        parts = [
            str(finding.get("title") or ""),
            str(finding.get("vuln_type") or ""),
            str(finding.get("endpoint") or ""),
            str(finding.get("description") or ""),
            str(finding.get("impact") or ""),
            json.dumps(finding.get("evidence") or {}, ensure_ascii=False, sort_keys=True, default=str),
        ]
        return self._sanitize("\n".join(part for part in parts if part))

    @staticmethod
    def _sanitize(text: str) -> str:
        value = text
        for pattern in _SECRET_PATTERNS:
            value = pattern.sub(r"\1<redacted>", value)
        return value[:32_000]

    @staticmethod
    def _decode_metadata(value: Any) -> dict[str, Any]:
        try:
            decoded = json.loads(str(value))
            return decoded if isinstance(decoded, dict) else {}
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None
