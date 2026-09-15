"""P1 forensic evidence store: encrypted, content-addressed, chunked, and auditable."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import zstandard as zstd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EvidenceStoreError(RuntimeError):
    """Raised when P1 evidence cannot be stored or verified safely."""


class EvidenceKeyDestroyedError(EvidenceStoreError):
    """Raised when retention key destruction makes evidence intentionally unreadable."""


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """Stable reference to one immutable raw artifact."""

    id: int
    sha256: str
    size: int
    kind: str
    media_type: str
    scan_id: int
    tool_run_id: int | None
    encryption_key_id: str
    chunk_count: int


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _merkle_root(leaves: Sequence[str]) -> str:
    nodes = [bytes.fromhex(value) for value in sorted(leaves)]
    if not nodes:
        return hashlib.sha256(b"").hexdigest()
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [hashlib.sha256(nodes[index] + nodes[index + 1]).digest() for index in range(0, len(nodes), 2)]
    return nodes[0].hex()


class ScanKeyring:
    """Manage per-scan DEKs wrapped by the application's existing master DEK."""

    def __init__(self, database: Any, crypto: Any) -> None:
        self.database = database
        self.crypto = crypto

    def ensure(self, scan_id: int) -> tuple[str, bytes]:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT key_id, wrapped_key, destroyed_at FROM scan_evidence_keys WHERE scan_id = ? AND active = 1 ORDER BY id DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
        if row is not None:
            if row["destroyed_at"] is not None or row["wrapped_key"] is None:
                raise EvidenceKeyDestroyedError(f"scan {scan_id} evidence key was destroyed")
            return str(row["key_id"]), self._unwrap(scan_id, str(row["key_id"]), bytes(row["wrapped_key"]))
        return self.rotate(scan_id)

    def rotate(self, scan_id: int) -> tuple[str, bytes]:
        now = time.time()
        key = AESGCM.generate_key(bit_length=256)
        key_id = hashlib.sha256(os.urandom(32) + scan_id.to_bytes(8, "big", signed=False)).hexdigest()
        wrapped = self.crypto.encrypt_bytes(key, aad=f"windeep:p1:scan-key:{scan_id}:{key_id}".encode("utf-8"))
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE scan_evidence_keys SET active = 0, retired_at = ? WHERE scan_id = ? AND active = 1",
                (now, scan_id),
            )
            conn.execute(
                "INSERT INTO scan_evidence_keys(scan_id, key_id, wrapped_key, created_at, active) VALUES (?, ?, ?, ?, 1)",
                (scan_id, key_id, wrapped, now),
            )
        return key_id, key

    def get(self, scan_id: int, key_id: str) -> bytes:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT wrapped_key, destroyed_at FROM scan_evidence_keys WHERE scan_id = ? AND key_id = ?",
                (scan_id, key_id),
            ).fetchone()
        if row is None:
            raise EvidenceStoreError(f"evidence key not found: {key_id}")
        if row["destroyed_at"] is not None or row["wrapped_key"] is None:
            raise EvidenceKeyDestroyedError(f"scan {scan_id} evidence key was destroyed")
        return self._unwrap(scan_id, key_id, bytes(row["wrapped_key"]))

    def destroy_scan(self, scan_id: int) -> None:
        now = time.time()
        with self.database._connect() as conn:
            conn.execute(
                "UPDATE scan_evidence_keys SET wrapped_key = NULL, destroyed_at = ?, active = 0 WHERE scan_id = ? AND destroyed_at IS NULL",
                (now, scan_id),
            )

    def _unwrap(self, scan_id: int, key_id: str, wrapped: bytes) -> bytes:
        value = self.crypto.decrypt_bytes(wrapped, aad=f"windeep:p1:scan-key:{scan_id}:{key_id}".encode("utf-8"))
        if len(value) != 32:
            raise EvidenceStoreError("per-scan evidence key must be 32 bytes")
        return value


class RawArtifactStore:
    """Content-addressed encrypted artifact store with custody and retention controls."""

    def __init__(self, database: Any, crypto: Any, audit: Any, *, chunk_size: int = 8 * 1024 * 1024) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        self.database = database
        self.crypto = crypto
        self.audit = audit
        self.chunk_size = int(chunk_size)
        self.keyring = ScanKeyring(database, crypto)
        self._compressor = zstd.ZstdCompressor(level=3)
        self._decompressor = zstd.ZstdDecompressor()

    def _enc_text(self, value: str, *, field: str) -> str:
        encoder = getattr(self.database, "_enc", None)
        return encoder(value, field=field) if callable(encoder) else self.crypto.encrypt_text(value, aad=f"windeep:{field}".encode("utf-8"))

    def _dec_text(self, value: str, *, field: str) -> str:
        decoder = getattr(self.database, "_dec", None)
        return decoder(value, field=field) if callable(decoder) else self.crypto.decrypt_text(value, aad=f"windeep:{field}".encode("utf-8"))

    def _custody(
        self,
        *,
        action: str,
        scan_id: int,
        content_hash: str,
        reason: str,
        actor: str = "operator",
        artifact_id: int | None = None,
    ) -> str:
        return self.audit.append(
            "evidence.custody",
            {
                "actor": actor,
                "action": action,
                "scan_id": int(scan_id),
                "artifact_id": artifact_id,
                "content_hash": content_hash,
                "reason": reason,
                "wall": time.time(),
                "monotonic": time.monotonic(),
            },
        )

    def put(
        self,
        *,
        scan_id: int,
        tool_run_id: int | None,
        kind: str,
        media_type: str,
        content: bytes,
        reason: str,
        actor: str = "operator",
        metadata: Mapping[str, Any] | None = None,
        supersedes_id: int | None = None,
    ) -> ArtifactRef:
        raw = bytes(content)
        digest = _sha256(raw)
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE scan_id = ? AND sha256 = ?",
                (scan_id, digest),
            ).fetchone()
        if row is not None:
            item = self._artifact_ref(dict(row))
            self._custody(action="create", scan_id=scan_id, content_hash=digest, reason=reason, actor=actor, artifact_id=item.id)
            return item

        key_id, key = self.keyring.ensure(scan_id)
        chunks = [raw[index : index + self.chunk_size] for index in range(0, len(raw), self.chunk_size)] or [b""]
        encrypted_chunks: list[tuple[int, bytes, int, int, str]] = []
        aes = AESGCM(key)
        for index, chunk in enumerate(chunks):
            compressed = self._compressor.compress(chunk)
            nonce = os.urandom(12)
            aad = f"windeep:p1:artifact:{scan_id}:{digest}:{index}".encode("utf-8")
            ciphertext = nonce + aes.encrypt(nonce, compressed, aad)
            encrypted_chunks.append((index, ciphertext, len(chunk), len(compressed), _sha256(chunk)))
        now = time.time()
        metadata_text = self._enc_text(
            _canonical(dict(metadata or {})).decode("utf-8"),
            field="artifact.metadata",
        )
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                INSERT INTO artifacts(
                    sha256, schema_version, kind, media_type, size, created_at,
                    scan_id, tool_run_id, encryption_key_id, chunk_count, metadata,
                    supersedes_id, tombstoned_at
                ) VALUES (?, 'windeep.artifact.v1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (digest, kind, media_type, len(raw), now, scan_id, tool_run_id, key_id, len(chunks), metadata_text, supersedes_id),
            )
            artifact_id = int(cursor.lastrowid)
            conn.executemany(
                """
                INSERT INTO artifact_chunks(artifact_id, chunk_index, ciphertext, plaintext_size, compressed_size, chunk_sha256)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [(artifact_id, *item) for item in encrypted_chunks],
            )
        ref = ArtifactRef(
            id=artifact_id,
            sha256=digest,
            size=len(raw),
            kind=kind,
            media_type=media_type,
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            encryption_key_id=key_id,
            chunk_count=len(chunks),
        )
        self._custody(action="create", scan_id=scan_id, content_hash=digest, reason=reason, actor=actor, artifact_id=artifact_id)
        return ref

    @staticmethod
    def _artifact_ref(item: Mapping[str, Any]) -> ArtifactRef:
        return ArtifactRef(
            id=int(item["id"]),
            sha256=str(item["sha256"]),
            size=int(item["size"]),
            kind=str(item["kind"]),
            media_type=str(item["media_type"]),
            scan_id=int(item["scan_id"]),
            tool_run_id=int(item["tool_run_id"]) if item.get("tool_run_id") is not None else None,
            encryption_key_id=str(item["encryption_key_id"]),
            chunk_count=int(item["chunk_count"]),
        )

    def _resolve_row(self, sha256: str, scan_id: int | None) -> dict[str, Any]:
        with self.database._connect() as conn:
            if scan_id is None:
                rows = conn.execute("SELECT * FROM artifacts WHERE sha256 = ? ORDER BY id DESC", (sha256,)).fetchall()
                if len(rows) != 1:
                    raise EvidenceStoreError("scan_id is required when an artifact hash is absent or ambiguous")
                row = rows[0]
            else:
                row = conn.execute(
                    "SELECT * FROM artifacts WHERE scan_id = ? AND sha256 = ?",
                    (scan_id, sha256),
                ).fetchone()
        if row is None:
            raise KeyError(f"artifact not found: {sha256}")
        return dict(row)

    def _read_no_audit(self, sha256: str, *, scan_id: int | None) -> tuple[dict[str, Any], bytes]:
        item = self._resolve_row(sha256, scan_id)
        scan = int(item["scan_id"])
        key = self.keyring.get(scan, str(item["encryption_key_id"]))
        if item.get("tombstoned_at") is not None:
            raise EvidenceKeyDestroyedError(f"artifact is tombstoned: {sha256}")
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM artifact_chunks WHERE artifact_id = ? ORDER BY chunk_index ASC",
                (int(item["id"]),),
            ).fetchall()
        if len(rows) != int(item["chunk_count"]):
            raise EvidenceStoreError("artifact chunk count mismatch")
        aes = AESGCM(key)
        output = bytearray()
        for row in rows:
            index = int(row["chunk_index"])
            blob = bytes(row["ciphertext"])
            if len(blob) < 13:
                raise EvidenceStoreError("artifact ciphertext is truncated")
            nonce, payload = blob[:12], blob[12:]
            aad = f"windeep:p1:artifact:{scan}:{sha256}:{index}".encode("utf-8")
            compressed = aes.decrypt(nonce, payload, aad)
            if len(compressed) != int(row["compressed_size"]):
                raise EvidenceStoreError("artifact compressed-size mismatch")
            chunk = self._decompressor.decompress(compressed)
            if len(chunk) != int(row["plaintext_size"]) or _sha256(chunk) != str(row["chunk_sha256"]):
                raise EvidenceStoreError("artifact chunk integrity failure")
            output.extend(chunk)
        raw = bytes(output)
        if len(raw) != int(item["size"]) or _sha256(raw) != sha256:
            raise EvidenceStoreError("artifact content integrity failure")
        return item, raw

    def read(self, sha256: str, *, scan_id: int | None, reason: str, actor: str = "operator") -> bytes:
        item, raw = self._read_no_audit(sha256, scan_id=scan_id)
        self._custody(
            action="access",
            scan_id=int(item["scan_id"]),
            content_hash=sha256,
            reason=reason,
            actor=actor,
            artifact_id=int(item["id"]),
        )
        return raw

    def export(self, sha256: str, *, scan_id: int | None, reason: str, actor: str = "operator") -> bytes:
        item, raw = self._read_no_audit(sha256, scan_id=scan_id)
        self._custody(
            action="export",
            scan_id=int(item["scan_id"]),
            content_hash=sha256,
            reason=reason,
            actor=actor,
            artifact_id=int(item["id"]),
        )
        return raw

    def metadata(self, sha256: str, *, scan_id: int) -> dict[str, Any]:
        item = self._resolve_row(sha256, scan_id)
        text = self._dec_text(str(item["metadata"]), field="artifact.metadata")
        try:
            metadata = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvidenceStoreError("artifact metadata is corrupt") from exc
        return {**item, "metadata": metadata}

    def record_tool_run(
        self,
        *,
        scan_id: int,
        tool_run_id: int,
        argv: Sequence[str],
        stdout: bytes,
        stderr: bytes,
        exit_code: int,
        started_at_wall: float,
        finished_at_wall: float,
        started_at_monotonic: float,
        finished_at_monotonic: float,
        tool_name: str,
        tool_version: str,
        resolved_binary_sha256: str,
        environment_allowlist_sha256: str,
        working_directory: str,
    ) -> dict[str, Any]:
        stdout_ref = self.put(
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            kind="tool.stdout",
            media_type="application/octet-stream",
            content=stdout,
            reason="capture tool stdout",
        )
        stderr_ref = self.put(
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            kind="tool.stderr",
            media_type="application/octet-stream",
            content=stderr,
            reason="capture tool stderr",
        )
        exact_argv = [str(item) for item in argv]
        export_argv = [exact_argv[0]] if exact_argv else []
        export_argv.extend("<scope-bound target>" if index == 1 else value for index, value in enumerate(exact_argv[1:], start=1))
        payload = {
            "schema": "windeep.tool-run-evidence.v1",
            "argv": exact_argv,
            "export_argv": export_argv,
            "exit_code": int(exit_code),
            "started_at_wall": float(started_at_wall),
            "finished_at_wall": float(finished_at_wall),
            "started_at_monotonic": float(started_at_monotonic),
            "finished_at_monotonic": float(finished_at_monotonic),
            "tool_name": str(tool_name),
            "tool_version": str(tool_version),
            "resolved_binary_sha256": str(resolved_binary_sha256),
            "environment_allowlist_sha256": str(environment_allowlist_sha256),
            "working_directory": str(working_directory),
            "stdout_sha256": stdout_ref.sha256,
            "stderr_sha256": stderr_ref.sha256,
        }
        encrypted = self._enc_text(_canonical(payload).decode("utf-8"), field="tool_run_evidence.payload")
        with self.database._connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_run_evidence(tool_run_id, scan_id, payload, stdout_sha256, stderr_sha256, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tool_run_id) DO UPDATE SET
                    payload = excluded.payload,
                    stdout_sha256 = excluded.stdout_sha256,
                    stderr_sha256 = excluded.stderr_sha256
                """,
                (tool_run_id, scan_id, encrypted, stdout_ref.sha256, stderr_ref.sha256, time.time()),
            )
        return payload

    def read_tool_run(self, tool_run_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM tool_run_evidence WHERE tool_run_id = ?", (tool_run_id,)).fetchone()
        if row is None:
            raise KeyError(f"tool-run evidence not found: {tool_run_id}")
        payload = json.loads(self._dec_text(str(row["payload"]), field="tool_run_evidence.payload"))
        scan_id = int(row["scan_id"])
        payload["stdout"] = self.read(str(row["stdout_sha256"]), scan_id=scan_id, reason="read tool stdout")
        payload["stderr"] = self.read(str(row["stderr_sha256"]), scan_id=scan_id, reason="read tool stderr")
        return payload

    def evidence_hashes(self, scan_id: int) -> list[str]:
        with self.database._connect() as conn:
            artifact_rows = conn.execute(
                "SELECT sha256 FROM artifacts WHERE scan_id = ? AND tombstoned_at IS NULL ORDER BY sha256",
                (scan_id,),
            ).fetchall()
            flow_rows = conn.execute(
                "SELECT flow_sha256 FROM flow_evidence WHERE scan_id = ? ORDER BY flow_sha256",
                (scan_id,),
            ).fetchall()
        return [str(row[0]) for row in artifact_rows] + [str(row[0]) for row in flow_rows]

    def seal_scan(self, scan_id: int, *, reason: str, actor: str = "operator") -> dict[str, Any]:
        leaves = self.evidence_hashes(scan_id)
        root = _merkle_root(leaves)
        audit_hash = self.audit.append(
            "evidence.scan_sealed",
            {
                "scan_id": scan_id,
                "merkle_root": root,
                "leaf_count": len(leaves),
                "reason": reason,
                "actor": actor,
                "wall": time.time(),
                "monotonic": time.monotonic(),
            },
        )
        with self.database._connect() as conn:
            conn.execute(
                "INSERT INTO scan_evidence_roots(scan_id, merkle_root, leaf_count, audit_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (scan_id, root, len(leaves), audit_hash, time.time()),
            )
        return {"scan_id": scan_id, "merkle_root": root, "leaf_count": len(leaves), "audit_hash": audit_hash}

    def verify_scan_root(self, scan_id: int) -> bool:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT merkle_root, leaf_count FROM scan_evidence_roots WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
        if row is None:
            return False
        leaves = self.evidence_hashes(scan_id)
        return len(leaves) == int(row["leaf_count"]) and _merkle_root(leaves) == str(row["merkle_root"])

    def set_retention(self, scan_id: int, policy: str) -> None:
        normalized = policy.strip().casefold()
        if normalized not in {"keep-forever", "delete-on-request"} and not normalized.startswith("days:"):
            raise ValueError("unsupported retention policy")
        with self.database._connect() as conn:
            conn.execute(
                "INSERT INTO scan_retention(scan_id, policy, updated_at) VALUES (?, ?, ?) ON CONFLICT(scan_id) DO UPDATE SET policy = excluded.policy, updated_at = excluded.updated_at",
                (scan_id, normalized, time.time()),
            )

    def delete_scan_evidence(self, scan_id: int, *, reason: str, actor: str = "operator") -> None:
        with self.database._connect() as conn:
            root_row = conn.execute(
                "SELECT merkle_root FROM scan_evidence_roots WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
            artifacts = conn.execute(
                "SELECT id, sha256 FROM artifacts WHERE scan_id = ? AND tombstoned_at IS NULL ORDER BY id",
                (scan_id,),
            ).fetchall()
        invalidated = str(root_row["merkle_root"]) if root_row is not None else _merkle_root(self.evidence_hashes(scan_id))
        now = time.time()
        with self.database._connect() as conn:
            conn.execute("UPDATE artifacts SET tombstoned_at = ? WHERE scan_id = ? AND tombstoned_at IS NULL", (now, scan_id))
        for row in artifacts:
            self._custody(
                action="delete",
                scan_id=scan_id,
                content_hash=str(row["sha256"]),
                reason=reason,
                actor=actor,
                artifact_id=int(row["id"]),
            )
        self.keyring.destroy_scan(scan_id)
        self.audit.append(
            "evidence.scan_deleted",
            {
                "scan_id": scan_id,
                "reason": reason,
                "actor": actor,
                "invalidated_merkle_root": invalidated,
                "wall": time.time(),
                "monotonic": time.monotonic(),
            },
        )


__all__ = [
    "ArtifactRef",
    "EvidenceKeyDestroyedError",
    "EvidenceStoreError",
    "RawArtifactStore",
    "ScanKeyring",
]
