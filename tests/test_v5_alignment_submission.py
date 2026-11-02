"""Cross-tool execution and scan-bound submission regression coverage."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import string
import zipfile
from collections import Counter
from functools import wraps
from pathlib import Path

import pytest
from flask import Flask, jsonify, request

from app.brain.finding_ranker import FindingRanker
from app.engine.tool_wrapper import ToolWrapperFactory, _jsonl_parser
from app.evidence.bundles import EvidenceBundleStore
from app.reporting.redaction import redact_body, redact_text, redact_url
from app.reporting.submission import _block
from app.security.audit import AuditLog
from app.v2_pipeline import FindingBatchWriter
from app.v3.api import register_v3_api
from test_p3_reporting import _fixture, _provenance
from test_v2_product import session, target_and_consent, v2_client, wait_scan

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTICS = {
    "drozer", "adb", "frida_server", "checkra1n", "corellium", "tshark", "metasploit",
    "radare2", "john", "hashcat", "testssl", "sslscan", "rustscan", "jq", "yq", "openssl",
    "git", "python_runtime", "node", "ripgrep", "sevenzip", "sqlite3", "grpcurl",
}


def test_catalog_target_binding_and_diagnostic_classification() -> None:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    assert len(classes) == 137
    assert {name for name, cls in classes.items() if cls.result_role == "diagnostic"} == DIAGNOSTICS
    assert Counter(cls.output_parser.__name__ for cls in classes.values()) == {"_line_parser": 130, "_jsonl_parser": 7}
    for name, cls in classes.items():
        refs = {
            field
            for template in (*cls.args_template, *((cls.stdin_template,) if cls.stdin_template else ()))
            for _, field, _, _ in string.Formatter().parse(template)
            if field
        }
        assert refs <= set(cls.input_schema.model_fields), name
        if name in DIAGNOSTICS:
            assert "target" not in refs and not cls.scan_default and not cls.builtin_fallback
        else:
            assert "target" in refs or cls.builtin_fallback, name


@pytest.mark.asyncio
async def test_all_wrappers_reject_target_in_options_before_backend_execution() -> None:
    classes = ToolWrapperFactory(ROOT / "tools_config.json").load()
    for cls in classes.values():
        wrapper = cls(scope_validator=lambda value: value == "allowed.example")
        with pytest.raises(ValueError, match="cannot override"):
            await wrapper.run_with_evidence("allowed.example", {"target": "other.example"})


@pytest.mark.asyncio
async def test_diagnostic_retains_raw_output_without_creating_findings() -> None:
    cls = ToolWrapperFactory(ROOT / "tools_config.json").get("python_runtime")

    class Backend:
        key = "stub"
        tier = "native"
        def can_run(self, wrapper):
            return True
        async def exec(self, wrapper, args, stdin, timeout):
            return "Python 3.12.0\n", "", 0

    class Resolver:
        backends = {"stub": Backend()}
        def ordered_keys(self, wrapper):
            return ["stub"]

    result = await cls(scope_validator=lambda target: True, resolver=Resolver()).run_with_evidence("owned.example")
    assert result.stdout == "Python 3.12.0\n"
    assert result.findings == ()


def test_structured_fields_and_zero_confidence_survive_normalization(tmp_path: Path) -> None:
    raw = json.dumps({"title": "Marker", "confidence": 0, "steps": "Step one", "impact": "Observed impact",
                      "remediation": "Remove marker", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                      "verified": True})
    parsed = _jsonl_parser(raw, "fixture", "owned.test")[0].model_dump()
    assert parsed["confidence"] == 0
    assert parsed["steps"] == "Step one" and parsed["impact"] == "Observed impact"
    assert parsed["remediation"] == "Remove marker" and parsed["cvss_vector"].startswith("CVSS:3.1/")
    assert "verified" not in parsed  # A tool cannot self-certify verification.
    crypto, database, _generator, target_id, scan_id, _fid, _second, _flow, _second_flow = _fixture(tmp_path)
    run_id = database.create_tool_run(tool_name="fixture", status="completed", scan_id=scan_id, target_id=target_id)
    rows = FindingBatchWriter(database).persist(scan_id=scan_id, tool_run_id=run_id, target_id=target_id,
                                                tool_name="fixture", findings=[parsed])
    assert rows[0]["confidence"] == 0
    stored = database.get_finding(rows[0]["finding_id"])
    assert stored["confidence"] == 0 and stored["steps"] == "Step one" and stored["impact"] == "Observed impact"


def test_ranker_handles_missing_malformed_and_nonfinite_confidence() -> None:
    ranker = FindingRanker()
    assert ranker.score({"confidence": {"score": 0.8}}).confidence == 0.8
    for value in (None, "bad", "nan", "inf", {}):
        item = ranker.score({"severity": "medium", "confidence": value, "cvss_score": "nan"})
        assert item.confidence == 0.5 and item.impact == 0.6
    assert ranker.score({"confidence": 0}).score == 0


def test_redacts_url_credentials_fragments_form_bodies_and_embedded_urls() -> None:
    url = "https://user:pass@example.test/path?access_token=secretvalue&ok=1#fragmentsecret"
    for rendered in (redact_url(url), redact_text("see " + url)):
        assert all(secret not in rendered for secret in ("user:pass", "secretvalue", "fragmentsecret"))
    assert "secretvalue" not in redact_body("access_token=secretvalue&ok=1", content_type="application/x-www-form-urlencoded")
    assert "abc123" not in redact_text("Authorization: Basic abc123\nmore")
    assert _block("one\n```\nINJECTED\n```").startswith("````text\n")


@pytest.fixture
def submission_client(tmp_path: Path):
    crypto, database, _generator, target_id, scan_id, finding_id, second_id, flow_id, _second_flow = _fixture(tmp_path)
    database.update_scan(scan_id, status="completed")
    consent = "local-test-consent"
    with database._connect() as conn:
        conn.execute("INSERT INTO scan_authorizations(scan_id, target_id, consent_ref, created_at) VALUES (?, ?, ?, ?)",
                     (scan_id, target_id, crypto.encrypt_text(consent, aad=f"windeep:scan_auth:{scan_id}".encode()), 1.0))
    app = Flask(__name__)
    allowed = {"value": True}

    def authenticated(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            if request.headers.get("X-Test-Session") != "yes":
                return jsonify({"error": "authentication required"}), 401
            return fn(*args, **kwargs)
        return inner

    def preflight(target, consent_id):
        if not allowed["value"] or consent_id != consent:
            raise PermissionError("consent is unavailable")

    audit = AuditLog(tmp_path / "audit" / "submission.jsonl")
    register_v3_api(app, crypto=crypto, audit=audit, database=database, authenticated=authenticated,
                    preflight_for=preflight, event_publisher=None)
    app.config.update(TESTING=True)
    return app.test_client(), crypto, database, allowed, target_id, scan_id, finding_id, flow_id


def test_submission_api_auth_redaction_unscored_and_package_hashes(submission_client) -> None:
    client, _crypto, database, allowed, _target_id, scan_id, finding_id, _flow_id = submission_client
    url = f"/api/v3/scans/{scan_id}/findings/{finding_id}/submission"
    assert client.get(url).status_code == 401
    headers = {"X-Test-Session": "yes"}
    allowed["value"] = False
    assert client.get(url, headers=headers).status_code == 403
    allowed["value"] = True
    with database._connect() as conn:
        conn.execute("UPDATE findings SET cvss_vector = NULL, cvss_score = NULL WHERE id = ?", (finding_id,))
    response = client.get(url + "?platform=bugcrowd", headers=headers)
    assert response.status_code == 200
    payload = response.get_json()["payload"]
    assert payload["readiness"]["state"] == "human_review_required"
    assert payload["readiness"]["evidence_bundle_closed_and_revalidated"] is True
    assert payload["cvss_score"] is None and "not recorded" in payload["body"]
    assert "expected" in payload["body"].casefold()
    archive_response = client.get(url + "?format=zip&platform=bugcrowd", headers=headers)
    assert archive_response.status_code == 200 and archive_response.headers["Cache-Control"] == "no-store"
    with zipfile.ZipFile(io.BytesIO(archive_response.data)) as archive:
        assert {"report.md", "report.html", "evidence.har", "manifest.json", "submission.json"} <= set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        for entry in manifest["files"]:
            assert hashlib.sha256(archive.read(entry["name"])).hexdigest() == entry["sha256"]
        joined = b"\n".join(archive.read(name) for name in archive.namelist())
        assert b"request-super-secret" not in joined and b"response-super-secret" not in joined


def test_submission_selects_authorized_scan_and_rejects_cross_scan_evidence(submission_client) -> None:
    client, crypto, database, _allowed, target_id, first_scan, finding_id, first_flow = submission_client
    headers = {"X-Test-Session": "yes"}
    second_scan = database.create_scan(target_id, "fixture", ["fixture"])
    database.update_scan(second_scan, status="completed")
    run_id = database.create_tool_run(tool_name="fixture", status="completed", scan_id=second_scan, target_id=target_id)
    finding = database.get_finding(finding_id)
    store = EvidenceBundleStore(database, crypto)
    artifact = store.put_artifact(scan_id=second_scan, tool_run_id=run_id, kind="fixture", media_type="text/plain", content=b"second scan marker\n")
    # Historical APIs allow a malformed bundle to cite a flow from a different scan.
    store.build(finding=finding, scan_id=second_scan, tool_run_id=run_id, flow_ids=[first_flow],
                artifact_sha256=artifact["sha256"], line_start=1, line_end=1, provenance=_provenance("other.scan"),
                exploitability="observed", close=True)
    with database._connect() as conn:
        conn.execute("INSERT INTO scan_authorizations(scan_id, target_id, consent_ref, created_at) VALUES (?, ?, ?, ?)",
                     (second_scan, target_id, crypto.encrypt_text("local-test-consent", aad=f"windeep:scan_auth:{second_scan}".encode()), 1.0))
        conn.execute("INSERT INTO scan_findings(scan_id, tool_run_id, finding_fingerprint, finding_id, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (second_scan, run_id, finding["fingerprint"], finding_id, database._enc("{}", field="scan_finding.payload"), 1.0, 1.0))
    first_url = f"/api/v3/scans/{first_scan}/findings/{finding_id}/submission"
    second_url = f"/api/v3/scans/{second_scan}/findings/{finding_id}/submission"
    assert client.get(first_url, headers=headers).status_code == 200  # Does not pick the newer bundle.
    denied = client.get(second_url, headers=headers)
    assert denied.status_code == 409 and "different scan" in denied.get_json()["error"]
    assert client.get(f"/api/v3/scans/{first_scan}/findings/999999/submission", headers=headers).status_code == 404

    second_flow = database.insert_flow({
        "target_id": target_id, "scan_id": second_scan, "method": "GET", "url": finding["endpoint"],
        "scheme": "https", "host": "example.test", "port": 443, "path": "/api/object/7", "query": "",
        "request_headers": {}, "response_headers": {}, "request_body": b"", "response_body": b"second-scan-only",
        "status": 200, "timing_ms": 1.0, "tls_info": {}, "tags": [], "created_at": 1_700_000_100.0,
    })
    observation = {"title": finding["title"], "severity": finding["severity"], "vuln_type": finding["vuln_type"],
                   "endpoint": finding["endpoint"], "description": "Description from second scan only.",
                   "steps": "Second scan instructions.", "impact": "Second scan impact.", "evidence": {},
                   "confidence": 0.8}
    persisted = FindingBatchWriter(database).persist(scan_id=second_scan, tool_run_id=run_id, target_id=target_id,
                                                      tool_name="fixture", findings=[observation])
    assert persisted[0]["finding_id"] == finding_id
    store.build(finding=finding, scan_id=second_scan, tool_run_id=run_id, flow_ids=[second_flow],
                artifact_sha256=artifact["sha256"], line_start=1, line_end=1, provenance=_provenance("second.scan"),
                exploitability="observed", close=True)
    second = client.get(second_url, headers=headers)
    assert second.status_code == 200
    body = second.get_json()["payload"]["body"]
    assert "Description from second scan only." in body and "Second scan impact." in body
    assert "Read-only response differed from the authorized baseline." not in body


def test_owned_source_scan_to_submission_draft_through_product_api(v2_client) -> None:
    client, tmp_path = v2_client
    headers = session(client)
    source = tmp_path / "owned-source.txt"
    source.write_text("api_key = abcdefghijklmnopqrstuvwxyz012345\n", encoding="utf-8")
    target, consent = target_and_consent(client, headers, target=str(source), target_type="repo")
    started = client.post(
        "/api/v2/scans",
        json={"target_id": target["id"], "consent_id": consent["id"], "mode": "selected", "tools": ["custom_regex"], "modules": []},
        headers=headers,
    )
    assert started.status_code == 202
    scan_id = started.get_json()["scan_id"]
    assert wait_scan(client, scan_id, {"completed", "failed"})["status"] == "completed"
    finding = client.get(f"/api/findings?target_id={target['id']}").get_json()[0]
    url = f"/api/v3/scans/{scan_id}/findings/{finding['id']}/submission"
    draft = client.get(url + "?platform=bugcrowd")
    assert draft.status_code == 200, draft.get_data(as_text=True)
    assert draft.get_json()["payload"]["readiness"]["state"] == "human_review_required"
    exported = client.get(url + "?format=zip&platform=bugcrowd")
    assert exported.status_code == 200
    with zipfile.ZipFile(io.BytesIO(exported.data)) as archive:
        assert b"abcdefghijklmnopqrstuvwxyz012345" not in b"\n".join(archive.read(name) for name in archive.namelist())
