"""One-shot static-review corrections for PR #6."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fix_server() -> None:
    path = ROOT / "app" / "server.py"
    text = path.read_text(encoding="utf-8")
    start = text.index("    def _sse_safe(event_type: str, data: dict[str, Any]) -> dict[str, Any]:\n")
    end = text.index("    def broadcast(event_type: str, data: dict[str, Any], scan_id: int | None = None) -> None:\n", start)
    helpers = '''    def _sse_safe(event_type: str, data: dict[str, Any]) -> dict[str, Any]:\n        safe = dict(data)\n        if event_type == "finding" and isinstance(safe.get("finding"), dict):\n            finding = dict(safe["finding"])\n            for key in ("evidence", "request", "response", "description", "steps", "impact", "remediation"):\n                finding.pop(key, None)\n            safe["finding"] = finding\n        for key in list(safe):\n            lowered = key.casefold()\n            if any(marker in lowered for marker in ("authorization", "cookie", "password", "secret", "token", "api_key")):\n                safe[key] = "<redacted>"\n        return safe\n\n    def _wire_replay_event(row: dict[str, Any]) -> str:\n        payload = _sse_safe(str(row["event_type"]), dict(row["payload"]))\n        envelope = {\n            "type": str(row["event_type"]),\n            "scan_id": int(row["scan_id"]),\n            "schema_version": str(row["schema_version"]),\n            "seq": int(row["seq"]),\n            **payload,\n        }\n        return json.dumps(envelope, separators=(",", ":"), sort_keys=True, default=str)\n\n    def _sse_frame(payload: str) -> str:\n        decoded = _json_value(payload, {})\n        event_type = str(decoded.get("type") or "message")\n        seq = decoded.get("seq")\n        event_id = f"id: {int(seq)}\\n" if isinstance(seq, int) else ""\n        return f"{event_id}event: {event_type}\\ndata: {payload}\\n\\n"\n\n'''
    text = text[:start] + helpers + text[end:]
    extension_marker = '    app.extensions["windeep.database"] = database\n'
    if 'app.extensions["windeep.pipeline_store"]' not in text:
        text = text.replace(extension_marker, extension_marker + '    app.extensions["windeep.pipeline_store"] = pipeline_store\n', 1)
    path.write_text(text, encoding="utf-8", newline="\n")


def fix_scheduler() -> None:
    path = ROOT / "app" / "engine" / "scheduler.py"
    text = path.read_text(encoding="utf-8")
    old = '''                        await self._preflight.acquire_rate(tool_key, cost=spec.rate_cost)\n                        acquire_host_rate = getattr(self._preflight, "acquire_host_rate", None)\n                        if callable(acquire_host_rate):\n                            await acquire_host_rate(target, cost=spec.rate_cost)\n'''
    new = '''                        acquire_layered_rate = getattr(self._preflight, "acquire_tool_and_host_rate", None)\n                        if callable(acquire_layered_rate):\n                            await acquire_layered_rate(tool_key, target, cost=spec.rate_cost)\n                        else:\n                            await self._preflight.acquire_rate(tool_key, cost=spec.rate_cost)\n                            acquire_host_rate = getattr(self._preflight, "acquire_host_rate", None)\n                            if callable(acquire_host_rate):\n                                await acquire_host_rate(target, cost=spec.rate_cost)\n'''
    if old not in text:
        if "acquire_layered_rate" in text:
            return
        raise RuntimeError("scheduler rate marker changed")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    fix_server()
    fix_scheduler()
