"""Frozen Windeep v3 public wire-format contracts."""
from __future__ import annotations

import hashlib
import json
from typing import Any

PUBLIC_CONTRACTS = {
    "sse": "windeep.sse.v1",
    "har_extension": "windeep.har-extension.v1",
    "evidence_bundle": "windeep.evidence-bundle.v1",
    "artifact": "windeep.artifact.v1",
    "report": "windeep.report.v1",
    "verification": "windeep.verification.v1",
}

V3_EVENT_TYPES = (
    "finding",
    "progress",
    "log",
    "evidence",
    "chain",
    "ranked",
    "verification",
    "disposition",
    "target",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def frozen_contract_manifest() -> dict[str, Any]:
    """Return a deterministic manifest used by release audits and support tooling."""
    payload = {
        "release": "3.0.0",
        "contracts": dict(PUBLIC_CONTRACTS),
        "sse_event_types": list(V3_EVENT_TYPES),
        "post_freeze_change_policy": "v3.0.x patch",
    }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return {**payload, "manifest_sha256": digest}
