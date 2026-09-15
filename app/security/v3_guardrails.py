"""P7 threat-model controls for the Windeep v3 platform."""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit


class V3ThreatControls:
    """Small fail-closed validators used at trust boundaries."""

    def __init__(self, *, max_redaction_terms: int = 128, max_redaction_term_chars: int = 256) -> None:
        if max_redaction_terms < 1:
            raise ValueError("max_redaction_terms must be positive")
        if max_redaction_term_chars < 1:
            raise ValueError("max_redaction_term_chars must be positive")
        self.max_redaction_terms = int(max_redaction_terms)
        self.max_redaction_term_chars = int(max_redaction_term_chars)

    def assert_external_target(self, value: str) -> None:
        parsed = urlsplit(str(value).strip())
        if parsed.scheme not in {"http", "https"}:
            raise PermissionError("only http/https external targets are allowed")
        host = (parsed.hostname or "").strip().casefold().rstrip(".")
        if not host:
            raise PermissionError("target hostname is required")
        if host in {"localhost", "localhost.localdomain", "ip6-localhost", "0.0.0.0"} or host.endswith(".localhost"):
            raise PermissionError("loopback/local control-plane target is forbidden")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if address.is_loopback or address.is_link_local or address.is_unspecified:
            raise PermissionError("loopback/link-local target is forbidden")

    @staticmethod
    def validate_artifact_label(value: str) -> str:
        text = str(value).strip()
        if not text or len(text) > 255:
            raise ValueError("artifact label must be 1..255 characters")
        if text in {".", ".."}:
            raise ValueError("artifact label cannot be a traversal segment")
        if "/" in text or "\\" in text:
            raise ValueError("artifact label must be a filename, not a path")
        if PurePosixPath(text).is_absolute() or PureWindowsPath(text).is_absolute():
            raise ValueError("absolute artifact paths are forbidden")
        windows = PureWindowsPath(text)
        if windows.drive or len(windows.parts) != 1 or len(PurePath(text).parts) != 1:
            raise ValueError("artifact label contains path semantics")
        if any(ord(ch) < 32 for ch in text):
            raise ValueError("artifact label contains control characters")
        return text

    def validate_redaction_terms(self, values: Sequence[str]) -> list[str]:
        if len(values) > self.max_redaction_terms:
            raise ValueError(f"too many redaction terms; max={self.max_redaction_terms}")
        output: list[str] = []
        seen: set[str] = set()
        for value in values:
            if not isinstance(value, str):
                raise TypeError("redaction terms must be literal strings")
            if not value:
                continue
            if len(value) > self.max_redaction_term_chars:
                raise ValueError(f"redaction term exceeds max chars={self.max_redaction_term_chars}")
            if value not in seen:
                seen.add(value)
                output.append(value)
        return output

    @staticmethod
    def validate_model_plan(plan: Mapping[str, Any], *, allowed_task_ids: set[str]) -> list[str]:
        if not isinstance(plan, Mapping):
            raise TypeError("model plan must be a JSON object")
        unexpected = sorted(str(key) for key in plan if str(key) != "task_ids")
        if unexpected:
            raise ValueError(f"model plan contains executable/unexpected fields: {', '.join(unexpected)}")
        values = plan.get("task_ids", [])
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise ValueError("model plan task_ids must be a list of strings")
        result: list[str] = []
        seen: set[str] = set()
        for task_id in values:
            if task_id not in allowed_task_ids:
                raise PermissionError(f"model-selected task is not pre-approved: {task_id}")
            if task_id not in seen:
                seen.add(task_id)
                result.append(task_id)
        return result

    @staticmethod
    def validate_tool_output(value: Any, *, max_items: int = 10_000, max_text_chars: int = 2_000_000) -> Any:
        """Bound parsed tool output without evaluating target-controlled content."""
        counts = {"items": 0, "chars": 0}

        def walk(node: Any, depth: int = 0) -> Any:
            if depth > 32:
                raise ValueError("tool output exceeds nesting depth")
            if node is None or isinstance(node, (bool, int, float)):
                return node
            if isinstance(node, str):
                counts["chars"] += len(node)
                if counts["chars"] > max_text_chars:
                    raise ValueError("tool output text budget exceeded")
                return node
            if isinstance(node, Mapping):
                output: dict[str, Any] = {}
                for key, child in node.items():
                    counts["items"] += 1
                    if counts["items"] > max_items:
                        raise ValueError("tool output item budget exceeded")
                    output[str(key)[:256]] = walk(child, depth + 1)
                return output
            if isinstance(node, (list, tuple)):
                output = []
                for child in node:
                    counts["items"] += 1
                    if counts["items"] > max_items:
                        raise ValueError("tool output item budget exceeded")
                    output.append(walk(child, depth + 1))
                return output
            return walk(str(node), depth + 1)

        return walk(value)


__all__ = ["V3ThreatControls"]
