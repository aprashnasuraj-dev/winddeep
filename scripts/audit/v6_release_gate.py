"""Fail-closed V6 release contract audit.

This is a source/runtime contract gate, not a substitute for pytest, browser
stress, Windows packaging, or the human release checklist.  In final mode it
also requires the canonical ten-item checklist to be closed and VERSION to be
6.x.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from app.engine.event_bus import EventBus
from app.engine.tool_wrapper import ToolWrapperFactory
from app.evidence.proof_validators import ControlledProofValidator


ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"


def _result(name: str, ok: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def audit(*, mode: str) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    checklist = (ROOT / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    ui = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
    pipeline = (ROOT / "app" / "v2_pipeline.py").read_text(encoding="utf-8")
    submission = (ROOT / "app" / "reporting" / "submission.py").read_text(encoding="utf-8")
    fallbacks = (ROOT / "app" / "tools" / "builtin_fallbacks.py").read_text(encoding="utf-8")

    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    recon = {name: cls for name, cls in classes.items() if cls.category in {"recon_passive", "recon_active"}}
    critical = re.findall(r"^- \[[ xX]\] \*\*V6-(\d{2})\b", checklist, flags=re.MULTILINE)
    closed = re.findall(r"^- \[[xX]\] \*\*V6-(\d{2})\b", checklist, flags=re.MULTILINE)

    checks.append(_result("catalog_137", len(classes) == 137, f"{len(classes)} integrations registered"))
    checks.append(_result("recon_observation_only", bool(recon) and all(cls.result_role == "observation" for cls in recon.values()), f"{len(recon)} recon integrations"))
    checks.append(_result("five_proof_classes", len(ControlledProofValidator.SUPPORTED_CLASSES) >= 5, ", ".join(sorted(ControlledProofValidator.SUPPORTED_CLASSES))))
    checks.append(_result("event_bus_backpressure_metrics", callable(getattr(EventBus, "stats", None)), "EventBus.stats present"))
    checks.append(_result("durable_ui_reconcile", "DURABLE_RECONCILE_MS=5000" in ui and "terminalTransition" in ui, "durable DB reconciliation + terminal refresh"))
    checks.append(_result("runtime_probe_before_run", "runnable=Boolean(t.compatible&&t.ready)" in ui and "Probe runtime" in ui, "unverified tools cannot Run"))
    checks.append(_result("recon_not_submission", "source_is_reconnaissance_observation" in submission and "source_explicitly_not_submission_candidate" in submission, "submission fail-closed"))
    checks.append(_result("matched_control_required", "matched_control_missing" in submission and "expected_behavior_missing" in submission and "observed_behavior_missing" in submission, "proof context required"))
    checks.append(_result("runtime_metrics", '"runtime_metrics": runtime_metrics' in pipeline and "memory_delta_bytes" in pipeline and "backends" in pipeline, "backend/resource telemetry present"))
    checks.append(_result("wayback_paginated", '"showResumeKey": "true"' in fallbacks and '"limit": "500"' not in fallbacks, "resume-key pagination; no 500 total cap"))
    checks.append(_result("canonical_ten_gates", critical == [f"{index:02d}" for index in range(1, 11)], f"{len(critical)} canonical gates"))

    if mode == "final":
        checks.append(_result("version_6", bool(re.fullmatch(r"6\.\d+\.\d+", version)), f"VERSION={version}"))
        checks.append(_result("checklist_ready", "Status: **READY FOR RELEASE**." in checklist, "canonical release status"))
        checks.append(_result("all_ten_closed", closed == [f"{index:02d}" for index in range(1, 11)], f"{len(closed)}/10 closed"))

    decision = "GO" if all(item["ok"] for item in checks) else "NO-GO"
    return {
        "schema": "windeep.v6.release-gate.v1",
        "mode": mode,
        "version": version,
        "decision": decision,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("preflight", "final"), default="preflight")
    parser.add_argument("--output", default="reports/v6_release_gate.json")
    args = parser.parse_args()
    payload = audit(mode=args.mode)
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["decision"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
