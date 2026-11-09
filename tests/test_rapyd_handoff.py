"""Structural evidence tests, purely synthetic and offline (not security findings)."""
from pathlib import Path
import zipfile
import pytest
from scripts.audit import rapyd_handoff as h

ROOT=Path(__file__).resolve().parents[1]

def seed(folder):
    for n in h.REQUIRED:
        (folder/n).write_text("Synthetic evidence for structural verifier only\n")
    for n in ("POC/test.py","EVIDENCE/positive.txt","EVIDENCE/CONTROL/negative.txt"):
        p=folder/n
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text("SAFE LOCAL FIXTURE\n")

def meta():
    return {"lane":"A","asset":"api.rapyd.net","snapshot_sha256":"a"*64,
            "priority":"P2","policy_reviewed":True,
            "verification_state":"STRUCTURE_ONLY_NOT_CONFIRMED"}

def test_branch_metadata_gate():
    assert h.repo_check(ROOT)==[]

def test_private_pack_and_hash(tmp_path):
    source=tmp_path/"source";source.mkdir();seed(source)
    z=tmp_path/"proof.zip"
    h.pack(source,z,meta())
    manifest=h.verify(z)
    assert manifest["asset"]=="api.rapyd.net"
    assert manifest["verification_state"]=="STRUCTURE_ONLY_NOT_CONFIRMED"

def test_explicit_exclusion_and_verification_state():
    for host in ("docs.rapyd.net","sandbox.rapyd.net","a.neat.hk","other.example"):
        with pytest.raises(ValueError,match="scope"):
            h.check_metadata({**meta(),"asset":host})
    with pytest.raises(ValueError,match="policy review"):
        h.check_metadata({**meta(),"policy_reviewed":False})
    with pytest.raises(ValueError,match="cannot certify"):
        h.check_metadata({**meta(),"verification_state":"CONFIRMED"})

def test_no_negative_control(tmp_path):
    source=tmp_path/"source";source.mkdir();seed(source)
    (source/"EVIDENCE/CONTROL/negative.txt").unlink()
    with pytest.raises(ValueError,match="negative CONTROL"):
        h.pack(source,tmp_path/"bad.zip",meta())

def test_public_private_separation():
    assert h.private_git_path("rapyd/A/submissions/secret.zip")
    assert h.private_git_path("rapyd/B/evidence/log.txt")
    assert not h.private_git_path("rapyd/C/PROBES.json")

def test_tampered_zip(tmp_path):
    source=tmp_path/"source";source.mkdir();seed(source)
    valid=tmp_path/"good.zip";h.pack(source,valid,meta())
    bad=tmp_path/"bad.zip"
    with zipfile.ZipFile(valid) as origin,zipfile.ZipFile(bad,"w") as corrupt:
        for name in origin.namelist():
            corrupt.writestr(name,b"tamper" if name=="REPORT.md" else origin.read(name))
    with pytest.raises(ValueError,match="checksum"):
        h.verify(bad)

def test_zip_traversal(tmp_path):
    z=tmp_path/"bad.zip"
    with zipfile.ZipFile(z,"w") as f:
        f.writestr("../unsafe","no")
    with pytest.raises(ValueError,match="unsafe ZIP path"):
        h.verify(z)
