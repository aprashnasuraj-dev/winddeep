"""Apply the narrow v3 P0 wiring patch to the existing v2/server surfaces.

This script exists only because the release branch is edited through GitHub's
contents API.  Replacements are marker-bounded and fail closed if the expected
v2 source shape is not present.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_between(text: str, start: str, end: str, replacement: str) -> str:
    left = text.find(start)
    if left < 0:
        raise RuntimeError(f"start marker not found: {start!r}")
    right = text.find(end, left)
    if right < 0:
        raise RuntimeError(f"end marker not found: {end!r}")
    return text[:left] + replacement + text[right:]


def patch_v2() -> None:
    path = ROOT / "app" / "v2_api.py"
    text = path.read_text(encoding="utf-8")
    import_marker = "from app.engine.tool_wrapper import ToolCancelledError, ToolExecutionError\n"
    imports = (
        import_marker
        + "from app.engine.scan_runtime import RegisteredScanRuntime\n"
        + "from app.engine.v3_scan_pipeline import V3ScanPipeline\n"
    )
    if "from app.engine.v3_scan_pipeline import V3ScanPipeline" not in text:
        if import_marker not in text:
            raise RuntimeError("v2 tool-wrapper import marker changed")
        text = text.replace(import_marker, imports, 1)

    start = "    async def execute_tool(\n"
    end = "    @app.get(\"/api/v2/tools\")\n"
    if start in text:
        replacement = '''    scan_runtime = RegisteredScanRuntime()\n    pipeline = V3ScanPipeline(\n        database=database,\n        wrapper_classes=wrapper_classes,\n        tools_dir=tools_dir,\n        target_scope=target_scope,\n        preflight_for=preflight_for,\n        runtime_environment=runtime_environment,\n        broadcast=broadcast,\n    )\n\n    def worker(\n        scan_id: int,\n        target_row: dict[str, Any],\n        plan: dict[str, Any],\n        consent_id: str,\n        tool_options: Mapping[str, Any],\n        cancel_event: threading.Event,\n    ) -> None:\n        try:\n            pipeline.run_sync(\n                scan_id=scan_id,\n                target_row=target_row,\n                selected=list(plan[\"selected\"]),\n                consent_id=consent_id,\n                tool_options=tool_options,\n                cancel_event=cancel_event,\n                mode=str(plan[\"mode\"]),\n                skipped=list(plan[\"skipped\"]),\n            )\n        except asyncio.CancelledError:\n            database.update_scan(scan_id, status=\"cancelled\", finished_at=time.time())\n            broadcast(\"progress\", {\"status\": \"cancelled\", \"reason\": \"operator cancellation\"}, scan_id)\n        except Exception as exc:\n            database.add_scan_log(scan_id, str(exc), \"error\", \"v3-orchestrator\")\n            database.update_scan(\n                scan_id,\n                status=\"failed\",\n                finished_at=time.time(),\n                results_summary={\"errors\": [{\"tool\": \"v3-orchestrator\", \"error\": str(exc)}]},\n            )\n            broadcast(\"progress\", {\"status\": \"failed\", \"error\": str(exc)}, scan_id)\n        finally:\n            with cancel_lock:\n                cancel_events.pop(scan_id, None)\n\n'''
        text = replace_between(text, start, end, replacement)

    old_thread = '''            threading.Thread(\n                target=worker,\n                args=(scan_id, target_row, plan, consent_id, tool_options, event),\n                daemon=True,\n                name=f\"windeep-v2-scan-{scan_id}\",\n            ).start()\n'''
    new_thread = '''            scan_runtime.start(\n                scan_id,\n                worker,\n                args=(scan_id, target_row, plan, consent_id, tool_options, event),\n            )\n'''
    if old_thread in text:
        text = text.replace(old_thread, new_thread, 1)
    elif "scan_runtime.start(" not in text:
        raise RuntimeError("v2 background-thread handoff marker changed")

    path.write_text(text, encoding="utf-8", newline="\n")


def patch_server() -> None:
    path = ROOT / "app" / "server.py"
    text = path.read_text(encoding="utf-8")
    import_marker = "from app.engine.tool_wrapper import ToolExecutionError, ToolWrapperFactory\n"
    if "from app.engine.pipeline_store import PipelineStore" not in text:
        if import_marker not in text:
            raise RuntimeError("server tool-wrapper import marker changed")
        text = text.replace(import_marker, "from app.engine.pipeline_store import PipelineStore\n" + import_marker, 1)

    db_marker = "    database = SecureDatabase(state / \"windeep.db\", crypto=crypto)\n"
    if "    pipeline_store = PipelineStore(database)\n" not in text:
        if db_marker not in text:
            raise RuntimeError("server database marker changed")
        text = text.replace(db_marker, db_marker + "    pipeline_store = PipelineStore(database)\n", 1)

    start = "    def broadcast(event_type: str, data: dict[str, Any], scan_id: int | None = None) -> None:\n"
    end = "    def target_scope(target_row: dict[str, Any]) -> ScopeEnforcer:\n"
    if start in text:
        replacement = '''    def _sse_safe(event_type: str, data: dict[str, Any]) -> dict[str, Any]:\n        safe = dict(data)\n        if event_type == \"finding\" and isinstance(safe.get(\"finding\"), dict):\n            finding = dict(safe[\"finding\"])\n            for key in (\"evidence\", \"request\", \"response\", \"description\", \"steps\", \"impact\", \"remediation\"):\n                finding.pop(key, None)\n            safe[\"finding\"] = finding\n        for key in list(safe):\n            lowered = key.casefold()\n            if any(marker in lowered for marker in (\"authorization\", \"cookie\", \"password\", \"secret\", \"token\", \"api_key\")):\n                safe[key] = \"<redacted>\"\n        return safe\n\n    def _wire_replay_event(row: dict[str, Any]) -> str:\n        payload = _sse_safe(str(row[\"event_type\"]), dict(row[\"payload\"]))\n        envelope = {\n            \"type\": str(row[\"event_type\"]),\n            \"scan_id\": int(row[\"scan_id\"]),\n            \"schema_version\": str(row[\"schema_version\"]),\n            \"seq\": int(row[\"seq\"]),\n            **payload,\n        }\n        return json.dumps(envelope, separators=(\",\", \":\"), sort_keys=True, default=str)\n\n    def _sse_frame(payload: str) -> str:\n        decoded = _json_value(payload, {})\n        event_type = str(decoded.get(\"type\") or \"message\")\n        seq = decoded.get(\"seq\")\n        event_id = f\"id: {int(seq)}\\n\" if isinstance(seq, int) else \"\"\n        return f\"{event_id}event: {event_type}\\ndata: {payload}\\n\\n\"\n\n    def broadcast(event_type: str, data: dict[str, Any], scan_id: int | None = None) -> None:\n        clean = dict(data)\n        persisted_seq = clean.pop(\"_sse_seq\", None)\n        persisted_schema = clean.pop(\"_sse_schema\", None)\n        clean = _sse_safe(event_type, clean)\n        if scan_id is not None:\n            if persisted_seq is None:\n                event = pipeline_store.append_scan_event(\n                    scan_id, event_type, clean, schema_version=str(persisted_schema or \"windeep.sse.v1\")\n                )\n                seq = int(event[\"seq\"])\n                schema_version = str(event[\"schema_version\"])\n            else:\n                seq = int(persisted_seq)\n                schema_version = str(persisted_schema or \"windeep.sse.v1\")\n            envelope = {\n                \"type\": event_type,\n                \"scan_id\": scan_id,\n                \"schema_version\": schema_version,\n                \"seq\": seq,\n                **clean,\n            }\n        else:\n            envelope = {\"type\": event_type, \"scan_id\": None, **clean}\n        payload = json.dumps(envelope, separators=(\",\", \":\"), sort_keys=True, default=str)\n        with sse_lock:\n            recipients = set(sse_global)\n            if scan_id is not None:\n                recipients.update(sse_scans.get(scan_id, set()))\n        for channel in recipients:\n            try:\n                channel.put_nowait(payload)\n            except queue.Full:\n                try:\n                    channel.get_nowait()\n                    channel.put_nowait(payload)\n                except (queue.Empty, queue.Full):\n                    pass\n\n    def subscribe(scan_id: int | None = None, *, after_seq: int = 0):\n        channel: queue.Queue[str] = queue.Queue(maxsize=256)\n        with sse_lock:\n            if scan_id is None:\n                sse_global.add(channel)\n            else:\n                sse_scans.setdefault(scan_id, set()).add(channel)\n        last_seq = max(0, int(after_seq))\n        try:\n            if scan_id is not None:\n                for event in pipeline_store.list_scan_events(scan_id, after_seq=last_seq):\n                    payload = _wire_replay_event(event)\n                    last_seq = int(event[\"seq\"])\n                    yield _sse_frame(payload)\n            while True:\n                try:\n                    payload = channel.get(timeout=25.0)\n                    decoded = _json_value(payload, {})\n                    seq = decoded.get(\"seq\")\n                    if scan_id is not None and isinstance(seq, int):\n                        if seq <= last_seq:\n                            continue\n                        if seq > last_seq + 1:\n                            for event in pipeline_store.list_scan_events(scan_id, after_seq=last_seq):\n                                event_seq = int(event[\"seq\"])\n                                if event_seq > seq:\n                                    break\n                                last_seq = event_seq\n                                yield _sse_frame(_wire_replay_event(event))\n                            continue\n                        last_seq = seq\n                    yield _sse_frame(payload)\n                except queue.Empty:\n                    yield \"event: heartbeat\\ndata: {}\\n\\n\"\n        finally:\n            with sse_lock:\n                sse_global.discard(channel)\n                if scan_id is not None:\n                    channels = sse_scans.get(scan_id)\n                    if channels is not None:\n                        channels.discard(channel)\n                        if not channels:\n                            sse_scans.pop(scan_id, None)\n\n'''
        text = replace_between(text, start, end, replacement)

    old_stream = '''    @app.get("/api/stream/<int:scan_id>")\n    @authenticated\n    def stream_scan(scan_id: int) -> Response:\n        return Response(stream_with_context(subscribe(scan_id)), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})\n'''
    new_stream = '''    @app.get("/api/stream/<int:scan_id>")\n    @authenticated\n    def stream_scan(scan_id: int) -> Response:\n        raw_last = request.headers.get("Last-Event-ID", "0").strip() or "0"\n        try:\n            after_seq = max(0, int(raw_last))\n        except ValueError:\n            after_seq = 0\n        return Response(stream_with_context(subscribe(scan_id, after_seq=after_seq)), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})\n'''
    if old_stream in text:
        text = text.replace(old_stream, new_stream, 1)
    elif "subscribe(scan_id, after_seq=after_seq)" not in text:
        raise RuntimeError("server scan stream marker changed")

    path.write_text(text, encoding="utf-8", newline="\n")


def patch_emit() -> None:
    path = ROOT / "app" / "engine" / "v3_scan_pipeline.py"
    text = path.read_text(encoding="utf-8")
    old = '''        wire = {\n            "schema_version": event["schema_version"],\n            "seq": event["seq"],\n            "payload": dict(payload),\n        }\n        self.broadcast(event_type, wire, scan_id)\n'''
    new = '''        wire = dict(payload)\n        wire["_sse_schema"] = event["schema_version"]\n        wire["_sse_seq"] = event["seq"]\n        self.broadcast(event_type, wire, scan_id)\n'''
    if old in text:
        text = text.replace(old, new, 1)
    elif 'wire["_sse_seq"]' not in text:
        raise RuntimeError("v3 emit marker changed")
    path.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    patch_v2()
    patch_server()
    patch_emit()
