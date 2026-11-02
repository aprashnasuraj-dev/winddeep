"""Exercise an installed Windeep process using an owned local fixture only."""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class SmokeError(RuntimeError):
    """A packaged product failed the local report workflow."""


def run_smoke(base_url: str, fixture: Path, *, timeout: float = 60.0) -> dict[str, Any]:
    """Scan one synthetic local file and verify both guarded export paths."""
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise ValueError("the smoke test requires a loopback HTTP endpoint")
    base_url = f"http://127.0.0.1:{parsed.port}"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    marker = "abcdefghijklmnopqrstuvwxyz012345"
    fixture.write_text(f"api_key = {marker}\n", encoding="utf-8")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    csrf = ""

    def call(method: str, path: str, body: dict[str, Any] | None = None, *, expected: int = 200) -> bytes:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if method != "GET" and csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(base_url + path, data=payload, method=method, headers=headers)
        try:
            with opener.open(request, timeout=10) as response:
                status, data = response.status, response.read()
        except urllib.error.HTTPError as exc:
            status, data = exc.code, exc.read()
        if status != expected:
            raise SmokeError(f"{method} {path} returned {status}, expected {expected}: {data[:400]!r}")
        return data

    def object_call(method: str, path: str, body: dict[str, Any] | None = None, *, expected: int = 200) -> Any:
        return json.loads(call(method, path, body, expected=expected))

    csrf = str(object_call("POST", "/api/handshake", {})["csrf_token"])
    path = str(fixture.resolve())
    target = object_call("POST", "/api/targets", {"name": "Owned release fixture", "type": "repo", "target": path,
                                                     "scope": [path], "out_of_scope": []}, expected=201)
    consent = object_call("POST", "/api/consent", {"target": path, "scope": [path], "out_of_scope": [],
                                                      "authorized_by": "Release smoke test", "purpose": "Owned local fixture",
                                                      "ttl_seconds": 600}, expected=201)
    scan = object_call("POST", "/api/v2/scans", {"target_id": target["id"], "consent_id": consent["id"],
                                                     "mode": "selected", "tools": ["custom_regex"], "modules": []}, expected=202)
    scan_id = int(scan["scan_id"])
    deadline = time.monotonic() + timeout
    while True:
        status = object_call("GET", f"/api/scans/{scan_id}")
        if status["status"] in {"completed", "failed", "cancelled", "completed_with_errors"}:
            break
        if time.monotonic() >= deadline:
            raise SmokeError(f"owned fixture scan did not finish within {timeout:.0f} seconds")
        time.sleep(0.25)
    if status["status"] != "completed":
        raise SmokeError(f"owned fixture scan ended {status['status']}")
    findings = object_call("GET", f"/api/findings?target_id={int(target['id'])}")
    if not findings:
        raise SmokeError("owned fixture produced no finding")
    finding_id = int(findings[0]["id"])
    submission = f"/api/v3/scans/{scan_id}/findings/{finding_id}/submission?platform=generic"
    draft = object_call("GET", submission)
    readiness = draft.get("payload", {}).get("readiness", {})
    if readiness.get("state") != "human_review_required" or not readiness.get("evidence_bundle_closed_and_revalidated"):
        raise SmokeError("submission draft lacks the expected evidence and review state")
    archive_data = call("GET", submission + "&format=zip")
    with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
        names = set(archive.namelist())
        if not {"report.md", "report.html", "evidence.har", "manifest.json", "submission.json"} <= names:
            raise SmokeError("submission ZIP is missing required files")
        manifest = json.loads(archive.read("manifest.json"))
        for entry in manifest["files"]:
            if hashlib.sha256(archive.read(entry["name"])).hexdigest() != entry["sha256"]:
                raise SmokeError("submission ZIP contains a hash mismatch")
        if any(marker.encode("ascii") in archive.read(name) for name in names):
            raise SmokeError("synthetic secret was not redacted in the submission ZIP")
    report = object_call("POST", "/api/v2/reports/generate", {"target_id": target["id"]}, expected=201)
    legacy_zip = call("GET", f"/api/v2/reports/{int(report['id'])}/evidence")
    with zipfile.ZipFile(io.BytesIO(legacy_zip)) as archive:
        if not {"README.md", "report.md", "findings.json"} <= set(archive.namelist()):
            raise SmokeError("legacy evidence ZIP is missing required files")
    return {"status": "pass", "scan_id": scan_id, "finding_id": finding_id, "submission_sha256": hashlib.sha256(archive_data).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run_smoke(args.base_url, args.fixture), sort_keys=True))
    except Exception as exc:
        print(f"Packaged report smoke failed: {type(exc).__name__}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
