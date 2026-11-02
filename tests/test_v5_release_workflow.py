"""Release-workflow invariants for the v5 candidate and publication path."""
from __future__ import annotations

import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


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


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is required")
@pytest.mark.parametrize("staging_succeeds", [True, False])
def test_v5_staging_step_uses_real_powershell_script_result(tmp_path: Path, staging_succeeds: bool) -> None:
    """Exercise the workflow step with successful and failed staging scripts."""
    workflow = (ROOT / ".github/workflows/release-v5.yml").read_text(encoding="utf-8")
    step = workflow.split("      - name: G12 Download, checksum and liveness-verify portable tools", 1)[1]
    step = step.split("\n      - name:", 1)[0].split("        run: |\n", 1)[1]
    command = "$ErrorActionPreference = 'Stop'\n" + textwrap.dedent(step)

    installer = tmp_path / "installer"
    installer.mkdir()
    (installer / "setup_tools.ps1").write_text(
        "Write-Host 'staged'\n" if staging_succeeds else "throw 'staging failed'\n", encoding="utf-8"
    )
    audit = tmp_path / "scripts" / "audit"
    audit.mkdir(parents=True)
    (audit / "release_audit.py").write_text(
        "from pathlib import Path\nPath('audit-ran').write_text('yes')\n", encoding="utf-8"
    )

    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (result.returncode == 0) is staging_succeeds, result.stdout + result.stderr
    assert (tmp_path / "audit-ran").exists() is staging_succeeds
