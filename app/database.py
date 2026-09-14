"""SQLite persistence, migrations, deduplication, and CVSS scoring for Windeep."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_JSON_SEPARATORS = (",", ":")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=_JSON_SEPARATORS, sort_keys=True)


def _json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _round_up_1(value: float) -> float:
    return math.ceil(value * 10.0 - 1e-10) / 10.0


def cvss31_base_score(vector: str) -> tuple[float, str]:
    """Return the CVSS v3.1 base score and qualitative severity for a vector."""
    metrics = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    scope_weights = {
        "U": {"PR": {"N": 0.85, "L": 0.62, "H": 0.27}},
        "C": {"PR": {"N": 0.85, "L": 0.68, "H": 0.50}},
    }
    parts = vector.strip().split("/")
    if not parts or parts[0] not in {"CVSS:3.1", "CVSS:3.0"}:
        raise ValueError("vector must start with CVSS:3.1 or CVSS:3.0")
    parsed: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"invalid CVSS metric: {part}")
        key, value = part.split(":", 1)
        parsed[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required.difference(parsed)
    if missing:
        raise ValueError(f"missing CVSS metrics: {sorted(missing)}")
    scope = parsed["S"]
    if scope not in scope_weights:
        raise ValueError(f"invalid CVSS scope: {scope}")
    try:
        av = metrics["AV"][parsed["AV"]]
        ac = metrics["AC"][parsed["AC"]]
        pr = scope_weights[scope]["PR"][parsed["PR"]]
        ui = metrics["UI"][parsed["UI"]]
        c = metrics["C"][parsed["C"]]
        i = metrics["I"][parsed["I"]]
        a = metrics["A"][parsed["A"]]
    except KeyError as exc:
        raise ValueError(f"invalid CVSS metric value: {exc}") from exc

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _round_up_1(min(impact + exploitability, 10.0))
    else:
        score = _round_up_1(min(1.08 * (impact + exploitability), 10.0))

    if score == 0:
        severity = "info"
    elif score < 4.0:
        severity = "low"
    elif score < 7.0:
        severity = "medium"
    elif score < 9.0:
        severity = "high"
    else:
        severity = "critical"
    return score, severity


def finding_fingerprint(
    *,
    target_id: int,
    title: str,
    vuln_type: str,
    endpoint: str | None,
) -> str:
    """Return a stable SHA-256 fingerprint for logical finding deduplication."""
    payload = "\x1f".join(
        [
            str(target_id),
            title.strip().casefold(),
            vuln_type.strip().casefold(),
            (endpoint or "").strip().casefold(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Database:
    """Thread-safe SQLite access layer with idempotent schema initialization."""

    def __init__(self, path: str | Path = "app/data/windeep.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migration_lock = threading.Lock()
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def initialize(self) -> None:
        """Create all tables and indexes required by the current schema."""
        with self._migration_lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT '[]',
                    out_of_scope TEXT NOT NULL DEFAULT '[]',
                    notes TEXT NOT NULL DEFAULT '',
                    tags TEXT NOT NULL DEFAULT '[]',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    scan_type TEXT NOT NULL,
                    modules TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'pending',
                    progress REAL NOT NULL DEFAULT 0,
                    started_at REAL,
                    finished_at REAL,
                    log TEXT NOT NULL DEFAULT '',
                    results_summary TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    vuln_type TEXT NOT NULL DEFAULT 'informational',
                    tool TEXT NOT NULL DEFAULT '',
                    endpoint TEXT,
                    description TEXT NOT NULL DEFAULT '',
                    evidence TEXT NOT NULL DEFAULT '{}',
                    request TEXT NOT NULL DEFAULT '',
                    response TEXT NOT NULL DEFAULT '',
                    steps TEXT NOT NULL DEFAULT '',
                    impact TEXT NOT NULL DEFAULT '',
                    remediation TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'new',
                    duplicate_of INTEGER REFERENCES findings(id) ON DELETE SET NULL,
                    fingerprint TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 0.5,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    template TEXT NOT NULL,
                    content TEXT NOT NULL,
                    format TEXT NOT NULL DEFAULT 'markdown',
                    finding_ids TEXT NOT NULL DEFAULT '[]',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    timestamp REAL NOT NULL,
                    level TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    scheme TEXT NOT NULL DEFAULT '',
                    host TEXT NOT NULL,
                    port INTEGER,
                    path TEXT NOT NULL,
                    query TEXT NOT NULL DEFAULT '',
                    request_headers TEXT NOT NULL DEFAULT '{}',
                    request_body BLOB,
                    status INTEGER,
                    response_headers TEXT NOT NULL DEFAULT '{}',
                    response_body BLOB,
                    timing_ms REAL,
                    tls_info TEXT NOT NULL DEFAULT '{}',
                    client_ip TEXT,
                    tags TEXT NOT NULL DEFAULT '[]',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS hypotheses (
                    id TEXT PRIMARY KEY,
                    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                    test_class TEXT NOT NULL,
                    endpoint TEXT,
                    parameters TEXT NOT NULL DEFAULT '{}',
                    rationale TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity_hint TEXT NOT NULL,
                    chain_hints TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'new',
                    source TEXT NOT NULL DEFAULT 'brain',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                    source_finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    target_finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    edge_type TEXT NOT NULL,
                    weight REAL NOT NULL,
                    rationale TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    UNIQUE(source_finding_id, target_finding_id, edge_type)
                );

                CREATE TABLE IF NOT EXISTS tool_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                    tool_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    command TEXT NOT NULL DEFAULT '[]',
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    exit_code INTEGER,
                    stdout_tail TEXT NOT NULL DEFAULT '',
                    stderr_tail TEXT NOT NULL DEFAULT '',
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS learnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
                    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
                    kind TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    embedding_ref TEXT,
                    created_at REAL NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
                CREATE INDEX IF NOT EXISTS idx_findings_endpoint_vuln ON findings(endpoint, vuln_type);
                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
                CREATE INDEX IF NOT EXISTS idx_flows_target ON flows(target_id);
                CREATE INDEX IF NOT EXISTS idx_flows_host_path ON flows(host, path);
                CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
                CREATE INDEX IF NOT EXISTS idx_hypotheses_confidence ON hypotheses(confidence DESC);
                CREATE INDEX IF NOT EXISTS idx_tool_runs_name ON tool_runs(tool_name);
                CREATE INDEX IF NOT EXISTS idx_scan_logs_scan ON scan_logs(scan_id, timestamp);
                """
            )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def create_target(
        self,
        name: str,
        target_type: str,
        target: str,
        *,
        scope: Sequence[str] = (),
        out_of_scope: Sequence[str] = (),
        notes: str = "",
        tags: Sequence[str] = (),
    ) -> int:
        """Create a target and return its row id."""
        now = time.time()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO targets(name, type, target, scope, out_of_scope, notes, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (name, target_type, target, _json_dumps(list(scope)), _json_dumps(list(out_of_scope)), notes, _json_dumps(list(tags)), now, now),
            )
            return int(cursor.lastrowid)

    def get_target(self, target_id: int) -> dict[str, Any] | None:
        """Return one target by id."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        item = self._row(row)
        if item is not None:
            item["scope"] = _json_loads(item["scope"], [])
            item["out_of_scope"] = _json_loads(item["out_of_scope"], [])
            item["tags"] = _json_loads(item["tags"], [])
        return item

    def list_targets(self) -> list[dict[str, Any]]:
        """Return targets newest first."""
        with self._connect() as conn:
            rows = conn.execute("SELECT id FROM targets ORDER BY id DESC").fetchall()
        return [item for row in rows if (item := self.get_target(int(row["id"]))) is not None]

    def create_scan(self, target_id: int, scan_type: str, modules: Sequence[str]) -> int:
        """Create a scan record."""
        now = time.time()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans(target_id, scan_type, modules, status, progress, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (target_id, scan_type, _json_dumps(list(modules)), "pending", 0.0, now),
            )
            return int(cursor.lastrowid)

    def update_scan(self, scan_id: int, **changes: Any) -> None:
        """Update whitelisted scan columns."""
        allowed = {"status", "progress", "started_at", "finished_at", "log", "results_summary"}
        invalid = set(changes).difference(allowed)
        if invalid:
            raise ValueError(f"unsupported scan fields: {sorted(invalid)}")
        if not changes:
            return
        if "results_summary" in changes and not isinstance(changes["results_summary"], str):
            changes["results_summary"] = _json_dumps(changes["results_summary"])
        columns = ", ".join(f"{key} = ?" for key in changes)
        values = [changes[key] for key in changes]
        with self._connect() as conn:
            conn.execute(f"UPDATE scans SET {columns} WHERE id = ?", (*values, scan_id))

    def add_scan_log(self, scan_id: int, message: str, level: str = "info", module: str = "core") -> int:
        """Append a structured scan log entry."""
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_logs(scan_id, timestamp, level, module, message) VALUES (?, ?, ?, ?, ?)",
                (scan_id, time.time(), level, module, message),
            )
            return int(cursor.lastrowid)

    def create_finding(
        self,
        target_id: int,
        title: str,
        severity: str | None = None,
        *,
        scan_id: int | None = None,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        vuln_type: str = "informational",
        tool: str = "",
        endpoint: str | None = None,
        description: str = "",
        evidence: Mapping[str, Any] | None = None,
        request: str = "",
        response: str = "",
        steps: str = "",
        impact: str = "",
        remediation: str = "",
        status: str = "new",
        confidence: float = 0.5,
    ) -> tuple[int, bool]:
        """Insert a deduplicated finding and return ``(id, created)``."""
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        computed_severity = severity.lower() if severity else None
        if cvss_vector and cvss_score is None:
            cvss_score, vector_severity = cvss31_base_score(cvss_vector)
            computed_severity = computed_severity or vector_severity
        computed_severity = computed_severity or "info"
        if computed_severity not in _SEVERITIES:
            raise ValueError(f"invalid severity: {computed_severity}")
        fingerprint = finding_fingerprint(
            target_id=target_id,
            title=title,
            vuln_type=vuln_type,
            endpoint=endpoint,
        )
        now = time.time()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO findings(
                    scan_id, target_id, title, severity, cvss_score, cvss_vector,
                    vuln_type, tool, endpoint, description, evidence, request,
                    response, steps, impact, remediation, status, fingerprint,
                    confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target_id,
                    title,
                    computed_severity,
                    cvss_score,
                    cvss_vector,
                    vuln_type,
                    tool,
                    endpoint,
                    description,
                    _json_dumps(dict(evidence or {})),
                    request,
                    response,
                    steps,
                    impact,
                    remediation,
                    status,
                    fingerprint,
                    confidence,
                    now,
                    now,
                ),
            )
            if cursor.rowcount == 1:
                return int(cursor.lastrowid), True
            row = conn.execute("SELECT id FROM findings WHERE fingerprint = ?", (fingerprint,)).fetchone()
            if row is None:
                raise RuntimeError("failed to resolve deduplicated finding")
            return int(row["id"]), False

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        """Return one finding by id."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        item = self._row(row)
        if item is not None:
            item["evidence"] = _json_loads(item["evidence"], {})
        return item

    def list_findings(
        self,
        *,
        target_id: int | None = None,
        severity: str | None = None,
        status: str | None = None,
        vuln_type: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return findings using bound filters and a bounded result size."""
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (("target_id", target_id), ("severity", severity), ("status", status), ("vuln_type", vuln_type)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings{where} ORDER BY id DESC LIMIT ?",
                (*values, limit),
            ).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            item["evidence"] = _json_loads(item["evidence"], {})
        return items

    def insert_flow(self, flow: Mapping[str, Any]) -> int:
        """Insert a captured HTTP/HTTPS flow and return its id."""
        required = {"method", "url", "host", "path"}
        missing = required.difference(flow)
        if missing:
            raise ValueError(f"missing flow fields: {sorted(missing)}")
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO flows(
                    target_id, scan_id, method, url, scheme, host, port, path,
                    query, request_headers, request_body, status, response_headers,
                    response_body, timing_ms, tls_info, client_ip, tags, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.get("target_id"),
                    flow.get("scan_id"),
                    str(flow["method"]),
                    str(flow["url"]),
                    str(flow.get("scheme") or ""),
                    str(flow["host"]),
                    flow.get("port"),
                    str(flow["path"]),
                    str(flow.get("query") or ""),
                    _json_dumps(dict(flow.get("request_headers") or {})),
                    flow.get("request_body"),
                    flow.get("status"),
                    _json_dumps(dict(flow.get("response_headers") or {})),
                    flow.get("response_body"),
                    flow.get("timing_ms"),
                    _json_dumps(dict(flow.get("tls_info") or {})),
                    flow.get("client_ip"),
                    _json_dumps(list(flow.get("tags") or [])),
                    float(flow.get("created_at") or time.time()),
                ),
            )
            return int(cursor.lastrowid)

    def create_hypothesis(self, hypothesis: Mapping[str, Any], *, target_id: int | None = None, scan_id: int | None = None) -> str:
        """Upsert a Brain hypothesis using its stable string id."""
        hypothesis_id = str(hypothesis["id"])
        confidence = float(hypothesis["confidence"])
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("hypothesis confidence must be between 0 and 1")
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO hypotheses(
                    id, target_id, scan_id, test_class, endpoint, parameters,
                    rationale, confidence, severity_hint, chain_hints, status,
                    source, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    endpoint = excluded.endpoint,
                    parameters = excluded.parameters,
                    rationale = excluded.rationale,
                    confidence = excluded.confidence,
                    severity_hint = excluded.severity_hint,
                    chain_hints = excluded.chain_hints,
                    status = excluded.status,
                    source = excluded.source,
                    updated_at = excluded.updated_at
                """,
                (
                    hypothesis_id,
                    target_id,
                    scan_id,
                    str(hypothesis["test_class"]),
                    hypothesis.get("endpoint"),
                    _json_dumps(dict(hypothesis.get("parameters") or {})),
                    str(hypothesis["rationale"]),
                    confidence,
                    str(hypothesis.get("severity_hint") or "info"),
                    _json_dumps(list(hypothesis.get("chain_hints") or [])),
                    str(hypothesis.get("status") or "new"),
                    str(hypothesis.get("source") or "brain"),
                    now,
                    now,
                ),
            )
        return hypothesis_id

    def list_hypotheses(self, *, target_id: int | None = None, min_confidence: float = 0.0, limit: int = 500) -> list[dict[str, Any]]:
        """Return hypotheses ordered by confidence descending."""
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        if target_id is None:
            sql = "SELECT * FROM hypotheses WHERE confidence >= ? ORDER BY confidence DESC LIMIT ?"
            params: tuple[Any, ...] = (min_confidence, limit)
        else:
            sql = "SELECT * FROM hypotheses WHERE target_id = ? AND confidence >= ? ORDER BY confidence DESC LIMIT ?"
            params = (target_id, min_confidence, limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            item["parameters"] = _json_loads(item["parameters"], {})
            item["chain_hints"] = _json_loads(item["chain_hints"], [])
        return items

    def upsert_chain_edge(
        self,
        *,
        source_finding_id: int,
        target_finding_id: int,
        edge_type: str,
        weight: float,
        rationale: str = "",
        target_id: int | None = None,
        scan_id: int | None = None,
    ) -> int:
        """Insert or update one weighted finding-chain edge."""
        if source_finding_id == target_finding_id:
            raise ValueError("chain edge cannot be self-referential")
        if not 0.0 <= weight <= 1.0:
            raise ValueError("chain edge weight must be between 0 and 1")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO chains(target_id, scan_id, source_finding_id, target_finding_id, edge_type, weight, rationale, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_finding_id, target_finding_id, edge_type)
                DO UPDATE SET weight = excluded.weight, rationale = excluded.rationale
                """,
                (target_id, scan_id, source_finding_id, target_finding_id, edge_type, weight, rationale, time.time()),
            )
            row = conn.execute(
                "SELECT id FROM chains WHERE source_finding_id = ? AND target_finding_id = ? AND edge_type = ?",
                (source_finding_id, target_finding_id, edge_type),
            ).fetchone()
            if row is None:
                raise RuntimeError("failed to resolve chain edge")
            return int(row["id"])

    def create_tool_run(self, *, tool_name: str, status: str, scan_id: int | None = None, target_id: int | None = None, command: Sequence[str] = (), started_at: float | None = None) -> int:
        """Create a tool execution audit record."""
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO tool_runs(scan_id, target_id, tool_name, status, command, started_at) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, target_id, tool_name, status, _json_dumps(list(command)), started_at or time.time()),
            )
            return int(cursor.lastrowid)

    def finish_tool_run(self, run_id: int, *, status: str, exit_code: int | None = None, stdout_tail: str = "", stderr_tail: str = "", error: str | None = None) -> None:
        """Finalize a tool execution audit record."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE tool_runs
                SET status = ?, finished_at = ?, exit_code = ?, stdout_tail = ?, stderr_tail = ?, error = ?
                WHERE id = ?
                """,
                (status, time.time(), exit_code, stdout_tail[-8000:], stderr_tail[-8000:], error, run_id),
            )

    def add_learning(
        self,
        *,
        kind: str,
        content: str,
        metadata: Mapping[str, Any] | None = None,
        target_id: int | None = None,
        finding_id: int | None = None,
        embedding_ref: str | None = None,
    ) -> int:
        """Persist a Brain learning or rejection lesson."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO learnings(target_id, finding_id, kind, content, metadata, embedding_ref, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (target_id, finding_id, kind, content, _json_dumps(dict(metadata or {})), embedding_ref, time.time()),
            )
            return int(cursor.lastrowid)


_DEFAULT_DB: Database | None = None


def get_database(path: str | Path | None = None) -> Database:
    """Return the process-default database, or a dedicated database for ``path``."""
    global _DEFAULT_DB
    if path is not None:
        return Database(path)
    if _DEFAULT_DB is None:
        _DEFAULT_DB = Database()
    return _DEFAULT_DB
