"""Captured tool execution for the v3 forensic pipeline.

Execution remains routed through generated ToolWrapper instances.  This layer
intercepts the wrapper's own process runner to preserve exact stdout/stderr and
records a deterministic adapter transcript for built-in integrations.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.tools import builtin_integrations
from app.v2_pipeline import FindingBatchWriter
from app.v3.evidence import ForensicEvidenceBundleStore, GuardedEvidenceVault


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class CapturedToolExecutor:
    """Execute one catalog wrapper with P1 custody and automatic P2 bundle attempts."""

    def __init__(
        self,
        *,
        database: Any,
        vault: GuardedEvidenceVault,
        wrapper_classes: Mapping[str, Any],
        tools_dir: str | Path,
        scope_validator: Any,
        environment: Mapping[str, str],
        cancel_check: Any = None,
    ) -> None:
        self.database = database
        self.vault = vault
        self.wrapper_classes = dict(wrapper_classes)
        self.tools_dir = Path(tools_dir)
        self.scope_validator = scope_validator
        self.environment = dict(environment)
        self.cancel_check = cancel_check
        self.writer = FindingBatchWriter(database)
        self.writer.ensure_schema()
        self.bundles = ForensicEvidenceBundleStore(database, vault)

    @staticmethod
    def _version(wrapper: Any) -> str:
        return str(
            getattr(wrapper, "release_version", "")
            or getattr(wrapper, "tool_version", "")
            or getattr(wrapper, "version", "")
            or ("builtin" if getattr(wrapper, "adapter_kind", "") == "builtin" else "unknown")
        )

    @staticmethod
    def _environment_hash(wrapper: Any) -> str:
        names = sorted(set(getattr(wrapper, "required_env", ()) or ()) | {"PATH"})
        selected = {name: str(wrapper.environment.get(name, "")) for name in names}
        return hashlib.sha256(_canonical(selected)).hexdigest()

    @staticmethod
    def _binary_hash(wrapper: Any) -> str:
        resolved = wrapper.resolve_binary()
        if resolved is not None and Path(resolved).is_file():
            return _file_sha256(Path(resolved))
        return hashlib.sha256(f"{wrapper.adapter_kind}:{wrapper.tool_name}".encode("utf-8")).hexdigest()

    async def execute(
        self,
        *,
        tool_name: str,
        target: str,
        target_id: int,
        scan_id: int,
        options: Mapping[str, Any] | None = None,
        try_close_bundles: bool = True,
    ) -> dict[str, Any]:
        if tool_name not in self.wrapper_classes:
            raise KeyError(f"unknown tool wrapper: {tool_name}")
        self.vault.authorize("tool.execute")
        cls = self.wrapper_classes[tool_name]
        wrapper = cls(
            tools_dir=self.tools_dir,
            scope_validator=self.scope_validator,
            environment=self.environment,
            cancel_check=self.cancel_check,
        )
        run_id = self.database.create_tool_run(
            tool_name=tool_name,
            status="running",
            scan_id=scan_id,
            target_id=target_id,
            command=[tool_name, "<scope-bound target>"],
        )
        started_wall = time.time()
        started_mono = time.monotonic()
        captured: dict[str, Any] = {"argv": None, "stdout": "", "stderr": "", "exit_code": 0}
        original_process = getattr(wrapper, "_run_process")

        async def recording_process(argv: Any, stdin_data: bytes | None = None):
            self.vault.authorize("tool.subprocess")
            captured["argv"] = [str(item) for item in argv]
            stdout, stderr, returncode = await original_process(argv, stdin_data)
            captured["stdout"] = stdout
            captured["stderr"] = stderr
            captured["exit_code"] = int(returncode)
            return stdout, stderr, returncode

        setattr(wrapper, "_run_process", recording_process)
        try:
            findings = await wrapper.run(target, options=options)
            if captured["argv"] is None:
                # Built-in integrations have no child process. Preserve the exact normalized
                # adapter response as a deterministic transcript rather than inventing CLI output.
                captured["argv"] = [f"builtin:{tool_name}", target]
                captured["stdout"] = "\n".join(
                    json.dumps(item.model_dump(), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
                    for item in findings
                )
                captured["stderr"] = ""
                captured["exit_code"] = 0
            finished_wall = time.time()
            finished_mono = time.monotonic()
            custody = self.vault.record_tool_run(
                scan_id=scan_id,
                tool_run_id=run_id,
                argv=captured["argv"],
                stdout=str(captured["stdout"]).encode("utf-8"),
                stderr=str(captured["stderr"]).encode("utf-8"),
                exit_code=int(captured["exit_code"]),
                started_at_wall=started_wall,
                finished_at_wall=finished_wall,
                started_at_monotonic=started_mono,
                finished_at_monotonic=finished_mono,
                tool_name=tool_name,
                tool_version=self._version(wrapper),
                resolved_binary_sha256=self._binary_hash(wrapper),
                environment_allowlist_sha256=self._environment_hash(wrapper),
                working_directory=str(Path.cwd()),
            )
            payloads = [finding.model_dump() for finding in findings]
            persisted = self.writer.persist(
                scan_id=scan_id,
                tool_run_id=run_id,
                target_id=target_id,
                tool_name=tool_name,
                findings=payloads,
            )
            self.database.finish_tool_run(
                run_id,
                status="completed",
                exit_code=int(captured["exit_code"]),
                stdout_tail=f"{len(persisted)} normalized result(s); forensic stdout={custody['stdout_sha256']}",
                stderr_tail=str(captured["stderr"])[-2000:],
            )
            bundle_rows: list[dict[str, Any]] = []
            for item in persisted:
                finding = self.database.get_finding(int(item["finding_id"]))
                if finding is None:
                    continue
                try:
                    bundle_rows.append(
                        self.bundles.build_from_run(
                            finding=finding,
                            scan_id=scan_id,
                            tool_run_id=run_id,
                            close=try_close_bundles,
                        )
                    )
                except Exception as exc:
                    # Missing supporting flow is expected for static/non-HTTP tools. Persist
                    # the explicit incomplete bundle rather than fabricating evidence.
                    if try_close_bundles:
                        try:
                            bundle_rows.append(
                                self.bundles.build_from_run(
                                    finding=finding,
                                    scan_id=scan_id,
                                    tool_run_id=run_id,
                                    close=False,
                                )
                            )
                            continue
                        except Exception:
                            pass
                    self.vault.audit.append(
                        "v3.bundle.failed",
                        {"scan_id": scan_id, "tool_run_id": run_id, "finding_id": int(item["finding_id"]), "reason": type(exc).__name__},
                    )
            return {"tool_run_id": run_id, "findings": persisted, "bundles": bundle_rows, "custody": custody}
        except Exception as exc:
            finished_wall = time.time()
            finished_mono = time.monotonic()
            try:
                if captured["argv"] is None:
                    captured["argv"] = [tool_name, target]
                self.vault.record_tool_run(
                    scan_id=scan_id,
                    tool_run_id=run_id,
                    argv=captured["argv"],
                    stdout=str(captured["stdout"]).encode("utf-8"),
                    stderr=(str(captured["stderr"]) or str(exc)).encode("utf-8"),
                    exit_code=int(captured.get("exit_code") or 1),
                    started_at_wall=started_wall,
                    finished_at_wall=finished_wall,
                    started_at_monotonic=started_mono,
                    finished_at_monotonic=finished_mono,
                    tool_name=tool_name,
                    tool_version=self._version(wrapper),
                    resolved_binary_sha256=self._binary_hash(wrapper),
                    environment_allowlist_sha256=self._environment_hash(wrapper),
                    working_directory=str(Path.cwd()),
                )
            finally:
                self.database.finish_tool_run(run_id, status="failed", exit_code=int(captured.get("exit_code") or 1), error=str(exc))
            raise


__all__ = ["CapturedToolExecutor"]
