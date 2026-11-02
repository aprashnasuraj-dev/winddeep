"""Release-workflow invariants for the v5 candidate and publication path."""
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v5_release_requires_candidate_validation_and_main_push() -> None:
    workflow = (ROOT / ".github/workflows/release-v5.yml").read_text(encoding="utf-8")
    assert "  pull_request:\n    branches: [main]" in workflow
    assert "  push:\n    branches: [main]" in workflow
    assert "--cov-fail-under=85" in workflow
    assert 'if ($LASTEXITCODE -ne 0) { throw "pytest or total coverage gate failed:' in workflow
    assert "windows_install_audit.ps1" in workflow
    assert workflow.index("windows_install_audit.ps1") < workflow.index("G23 Publish verified GitHub Release")
    publish = workflow.split("      - name: G23 Publish verified GitHub Release", 1)[1]
    assert "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" in publish
    assert "target_commitish: ${{ github.sha }}" in publish
    assert "tag_name: ${{ needs.version-check.outputs.tag }}" in publish
    assert "Refuse an existing release tag" in workflow


def test_v4_release_skips_v5_versions_and_generic_gate_checks_pytest() -> None:
    workflow = (ROOT / ".github/workflows/release-v4.yml").read_text(encoding="utf-8")
    assert "if: needs.version-check.outputs.is_v4 == 'true'" in workflow
    match = re.search(r'\[\[ "\$version" =~ ([^ ]+) \]\]', workflow)
    assert match is not None
    assert re.fullmatch(match.group(1), "4.1.2") is not None
    assert re.fullmatch(match.group(1), "5.0.0") is None
    legacy = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert 'if ($LASTEXITCODE -ne 0) { throw "pytest or total coverage gate failed:' in legacy
