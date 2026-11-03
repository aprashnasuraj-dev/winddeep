from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.engine.tool_wrapper import ToolWrapperFactory
from app.tools.source_parsers import parse_gosec_json, parse_govulncheck_json, parse_staticcheck_jsonl


def _factory() -> ToolWrapperFactory:
    return ToolWrapperFactory(Path(__file__).parents[1] / "tools_config.json")


def test_go_audit_tools_are_registered_pinned_and_module_root_bound() -> None:
    factory = _factory()
    gosec = factory.get("gosec")
    vuln = factory.get("govulncheck")
    static = factory.get("staticcheck")
    assert gosec.working_directory_template == "{target}"
    assert vuln.working_directory_template == "{target}"
    assert static.working_directory_template == "{target}"
    assert gosec.provision["version"] == "v2.29.0"
    assert vuln.provision["version"] == "v1.9.0"
    assert static.provision["version"] == "v0.8.2"
    assert all(x.execution_preference[:2] == ("local_binary", "provisioned_binary") for x in (gosec, vuln, static))


def test_gosec_parser_preserves_rule_cwe_and_location() -> None:
    raw = json.dumps({"Issues":[{"rule_id":"G304","severity":"HIGH","confidence":"HIGH","details":"Potential file inclusion via variable","file":"rpc/api.go","line":"42","column":"7","cwe":{"id":"22"}}]})
    findings = parse_gosec_json(raw, "gosec", "/repo")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.evidence["rule_id"] == "G304"
    assert f.evidence["cwe"]["id"] == "22"
    assert f.source_file == "rpc/api.go"
    assert f.source_line == 42


def test_govulncheck_parser_prefers_symbol_reachability() -> None:
    records = [
        {"finding":{"osv":"GO-2026-9999","fixed_version":"v1.2.3","trace":[{"module":"example.org/mod","version":"v1.0.0"}]}},
        {"osv":{"id":"GO-2026-9999","summary":"reachable crypto flaw"}},
        {"finding":{"osv":"GO-2026-9999","fixed_version":"v1.2.3","trace":[{"module":"example.org/mod","package":"example.org/mod/crypto","function":"Verify","position":{"filename":"crypto/verify.go","line":88}}]}},
    ]
    findings = parse_govulncheck_json("\n".join(json.dumps(x) for x in records), "govulncheck", "/repo")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.evidence["reachability"] == "symbol"
    assert f.evidence["fixed_version"] == "v1.2.3"
    assert f.source_file == "crypto/verify.go"
    assert f.source_line == 88


def test_staticcheck_parser_preserves_check_and_location() -> None:
    raw = json.dumps({"code":"SA2000","severity":"error","location":{"file":"consensus/core.go","line":73,"column":4},"message":"sync.WaitGroup.Add called from inside new goroutine"})
    findings = parse_staticcheck_jsonl(raw, "staticcheck", "/repo")
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["check"] == "SA2000"
    assert f.source_file == "consensus/core.go"
    assert f.source_line == 73


def test_working_directory_is_target_bound(tmp_path: Path) -> None:
    wrapper = _factory().get("gosec")()
    wrapper.current_target = str(tmp_path)
    assert wrapper._working_directory() == tmp_path.resolve()
    bad = tmp_path / "not-a-directory"
    bad.write_text("x")
    wrapper.current_target = str(bad)
    with pytest.raises(ValueError):
        wrapper._working_directory()
