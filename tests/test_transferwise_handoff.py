"""Offline regression tests for Wise scheduled-worker handoff readiness."""
import hashlib
import sys
import zipfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.audit import transferwise_handoff as h


def fixture(folder: Path):
    for name in sorted(h.REQUIRED):
        (folder / name).write_text(name + ": synthetic local reproduction with honest control\n")
    for name in ("POC/reproduce.py", "EVIDENCE/actual.txt", "EVIDENCE/CONTROL/negative.txt"):
        p = folder / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("Local, harmless synthetic fixture\n")


def metadata():
    return {"lane": "A", "repo": "transferwise/example", "commit": "a" * 40,
            "severity": "P2", "verification_state": "STRUCTURE_ONLY_NOT_CONFIRMED"}


def test_five_lanes_and_public_gate():
    assert h.repo_check(ROOT) == []


def test_package_roundtrip(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    fixture(source)
    target = tmp_path / "proof.zip"
    h.pack(source, target, metadata())
    manifest = h.verify(target)
    assert manifest["verification_state"] == "STRUCTURE_ONLY_NOT_CONFIRMED"
    assert len(manifest["files"]) == len(h.REQUIRED) + 3
    assert len(hashlib.sha256(target.read_bytes()).hexdigest()) == 64


def test_missing_negative_control(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    fixture(source)
    (source / "EVIDENCE/CONTROL/negative.txt").unlink()
    with pytest.raises(ValueError, match="negative CONTROL"):
        h.pack(source, tmp_path / "bad.zip", metadata())


def test_scope_and_no_false_confirmation():
    for repo in ("transferwise/pipelinewise", "other-org/example"):
        with pytest.raises(ValueError, match="scope"):
            h.check_metadata({**metadata(), "repo": repo})
    with pytest.raises(ValueError, match="cannot certify"):
        h.check_metadata({**metadata(), "verification_state": "CONFIRMED"})


def test_public_artifact_guard():
    assert h.private_git_path("transferwise/B/submissions/private.zip")
    assert h.private_git_path("transferwise/C/evidence/log.txt")
    assert h.private_git_path("transferwise/E/POC/reproduce.py")
    assert not h.private_git_path("transferwise/D/PROBES.json")


def test_symlink_source_rejected(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    fixture(source)
    (source / "POC/link.py").symlink_to(source / "POC/reproduce.py")
    with pytest.raises(ValueError, match="Symlink"):
        h.source_files(source)


def test_tampered_zip_rejected(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    fixture(source)
    good = tmp_path / "good.zip"
    h.pack(source, good, metadata())
    bad = tmp_path / "tampered.zip"
    with zipfile.ZipFile(good) as original, zipfile.ZipFile(bad, "w") as changed:
        for name in original.namelist():
            data = original.read(name)
            changed.writestr(name, b"tampered" if name == "REPORT.md" else data)
    with pytest.raises(ValueError, match="checksum"):
        h.verify(bad)


def test_zip_traversal_rejected(tmp_path):
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("../escape.txt", "unsafe")
    with pytest.raises(ValueError, match="unsafe ZIP path"):
        h.verify(bad)
