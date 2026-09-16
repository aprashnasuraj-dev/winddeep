"""Immutable P5 web3 provenance persistence over P1 artifact references."""
from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any


class Web3EvidenceStore:
    """Persist source resolution, engine runs, and finding provenance append-only."""

    def __init__(self, database: Any, artifacts: Any, audit: Any) -> None:
        self.database = database
        self.artifacts = artifacts
        self.audit = audit

    @staticmethod
    def _positive(name: str, value: int) -> int:
        parsed = int(value)
        if parsed <= 0:
            raise ValueError(f"{name} must be positive")
        return parsed

    @staticmethod
    def _hash_or_none(name: str, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip().casefold()
        if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
            raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        return text

    def record_source_resolution(
        self,
        *,
        scan_id: int,
        contract_address: str,
        chain_id: int,
        block_number: int,
        resolver: str,
        resolver_response_hash: str | None,
        solc_version: str | None,
        optimizer_runs: int | None,
        evm_version: str | None,
        abi_hash: str | None,
        source_artifact_id: int | None,
        bytecode_artifact_id: int | None,
        disassembly_artifact_id: int | None,
        project_solc_version: str | None = None,
        compiler_divergence: bool = False,
        supersedes_id: int | None = None,
    ) -> int:
        chain_id = self._positive("chain_id", chain_id)
        block_number = self._positive("block_number", block_number)
        response_hash = self._hash_or_none("resolver_response_hash", resolver_response_hash)
        normalized_abi = self._hash_or_none("abi_hash", abi_hash)
        address = contract_address.strip()
        if not address:
            raise ValueError("contract_address is required")
        now = time.time()
        with self.database._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO web3_source_artifact(
                    scan_id, contract_address, chain_id, block_number, resolver,
                    resolver_response_hash, solc_version, optimizer_runs, evm_version,
                    abi_hash, source_artifact_id, bytecode_artifact_id,
                    disassembly_artifact_id, project_solc_version, compiler_divergence,
                    supersedes_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(scan_id),
                    address,
                    chain_id,
                    block_number,
                    resolver.strip().casefold(),
                    response_hash,
                    solc_version,
                    int(optimizer_runs) if optimizer_runs is not None else None,
                    evm_version,
                    normalized_abi,
                    source_artifact_id,
                    bytecode_artifact_id,
                    disassembly_artifact_id,
                    project_solc_version,
                    1 if compiler_divergence else 0,
                    supersedes_id,
                    now,
                ),
            )
            record_id = int(cursor.lastrowid)
        self.audit.append(
            "p5.web3.source_resolution",
            {
                "record_id": record_id,
                "scan_id": int(scan_id),
                "address": address,
                "chain_id": chain_id,
                "block_number": block_number,
                "resolver": resolver.strip().casefold(),
                "resolver_response_hash": response_hash,
                "supersedes_id": supersedes_id,
            },
        )
        return record_id

    def record_engine_run(
        self,
        *,
        scan_id: int,
        tool_run_id: int | None,
        engine_name: str,
        engine_version: str,
        detector_set_version: str | None,
        source_artifact_id: int | None,
        raw_output_artifact_id: int,
        started_at: float,
        ended_at: float,
        exit_code: int,
        seed: str | None = None,
        supersedes_id: int | None = None,
    ) -> int:
        name = engine_name.strip().casefold()
        version = engine_version.strip()
        if not name or not version:
            raise ValueError("engine_name and engine_version are required")
        if ended_at < started_at:
            raise ValueError("engine run end precedes start")
        with self.database._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO web3_engine_run(
                    scan_id, tool_run_id, engine_name, engine_version,
                    detector_set_version, source_artifact_id, raw_output_artifact_id,
                    started_at, ended_at, exit_code, seed, supersedes_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(scan_id),
                    tool_run_id,
                    name,
                    version,
                    detector_set_version,
                    source_artifact_id,
                    int(raw_output_artifact_id),
                    float(started_at),
                    float(ended_at),
                    int(exit_code),
                    seed,
                    supersedes_id,
                ),
            )
            run_id = int(cursor.lastrowid)
        self.audit.append(
            "p5.web3.engine_run",
            {
                "engine_run_id": run_id,
                "scan_id": int(scan_id),
                "engine": name,
                "version": version,
                "raw_output_artifact_id": int(raw_output_artifact_id),
                "exit_code": int(exit_code),
            },
        )
        return run_id

    def record_finding_provenance(
        self,
        *,
        finding_id: int,
        engine_run_id: int,
        detector_id: str,
        swc_id: str | None,
        affected_function: str | None,
        source_file: str | None,
        line_start: int | None,
        line_end: int | None,
        bytecode_offset_start: int | None,
        bytecode_offset_end: int | None,
        corroborated: bool,
        corroborating_engine_run_id: int | None,
        upstream_source: str,
        call_path_artifact_id: int | None = None,
        state_context_artifact_id: int | None = None,
        cross_contract_artifact_id: int | None = None,
        supersedes_id: int | None = None,
    ) -> int:
        detector = detector_id.strip()
        upstream = upstream_source.strip()
        if not detector or not upstream:
            raise ValueError("detector_id and upstream_source are required")
        if line_start is not None and line_end is not None and int(line_end) < int(line_start):
            raise ValueError("source line range is reversed")
        if bytecode_offset_start is not None and bytecode_offset_end is not None and int(bytecode_offset_end) < int(bytecode_offset_start):
            raise ValueError("bytecode offset range is reversed")
        with self.database._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO web3_finding_provenance(
                    finding_id, engine_run_id, detector_id, swc_id, affected_function,
                    source_file, line_start, line_end, bytecode_offset_start,
                    bytecode_offset_end, corroborated, corroborating_engine_run_id,
                    upstream_source, call_path_artifact_id, state_context_artifact_id,
                    cross_contract_artifact_id, supersedes_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(finding_id),
                    int(engine_run_id),
                    detector,
                    swc_id,
                    affected_function,
                    source_file,
                    line_start,
                    line_end,
                    bytecode_offset_start,
                    bytecode_offset_end,
                    1 if corroborated else 0,
                    corroborating_engine_run_id,
                    upstream,
                    call_path_artifact_id,
                    state_context_artifact_id,
                    cross_contract_artifact_id,
                    supersedes_id,
                    time.time(),
                ),
            )
            record_id = int(cursor.lastrowid)
        self.audit.append(
            "p5.web3.finding_provenance",
            {
                "record_id": record_id,
                "finding_id": int(finding_id),
                "engine_run_id": int(engine_run_id),
                "detector_id": detector,
                "swc_id": swc_id,
                "corroborated": bool(corroborated),
            },
        )
        return record_id

    def provenance_graph(self, finding_id: int) -> dict[str, Any]:
        """Return deterministic engine→detector provenance for a finding."""
        with self.database._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    p.id, p.detector_id, p.swc_id, p.affected_function,
                    p.source_file, p.line_start, p.line_end,
                    p.bytecode_offset_start, p.bytecode_offset_end,
                    p.corroborated, p.corroborating_engine_run_id,
                    p.upstream_source, p.call_path_artifact_id,
                    p.state_context_artifact_id, p.cross_contract_artifact_id,
                    r.id AS engine_run_id, r.engine_name, r.engine_version,
                    r.detector_set_version, r.raw_output_artifact_id, r.seed
                FROM web3_finding_provenance p
                JOIN web3_engine_run r ON r.id = p.engine_run_id
                WHERE p.finding_id = ?
                ORDER BY r.engine_name ASC, p.detector_id ASC, p.id ASC
                """,
                (int(finding_id),),
            ).fetchall()
        nodes = [dict(row) for row in rows]
        return {
            "finding_id": int(finding_id),
            "nodes": nodes,
            "edges": [
                {
                    "from": f"engine:{row['engine_run_id']}",
                    "to": f"detector:{row['id']}",
                    "relation": "emitted",
                }
                for row in nodes
            ],
        }

    def latest_source_resolution(self, *, scan_id: int, contract_address: str, chain_id: int) -> dict[str, Any] | None:
        with self.database._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM web3_source_artifact
                WHERE scan_id = ? AND contract_address = ? AND chain_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (int(scan_id), contract_address, int(chain_id)),
            ).fetchone()
        return dict(row) if row is not None else None
