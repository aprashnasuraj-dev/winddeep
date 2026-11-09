"""Self-contained, network-free packaging and readiness regression tests."""
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/audit/transferwise_workspace.py"

def cmd(*args):
    return subprocess.run([sys.executable,str(SCRIPT),*map(str,args)],
                          cwd=ROOT,capture_output=True,text=True)

def source(root,repo="transferwise/idempotence4j",control=True):
    root.mkdir()
    names=["REPORT.md","REPRODUCE.md","SCOPE.md","IMPACT.md",
           "DUPLICATE_REVIEW.md","ENVIRONMENT.md","POC/demo.py","EVIDENCE/run.log"]
    if control:
        names.append("EVIDENCE/CONTROL/rejected.log")
    for name in names:
        p=root/name
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text("Isolated offline simulated proof fixture.\n")
    (root/"MANIFEST.json").write_text(json.dumps({
        "lane":"A","target_repo":repo,"target_commit":"a"*40,
        "severity":"P2","status":"CONFIRMED",
        "gates":{f"G{i}":True for i in range(5)},
        "independent_reproduction_executed":True,
        "negative_control_executed":True}))

class TestWorkspace(unittest.TestCase):
    def test_preflight(self):
        r=cmd("doctor","--check")
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("WORKSPACE_READY",r.stdout)

    def test_pack_verify_and_determinism(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"src"
            source(root)
            a,b=Path(td)/"one.zip",Path(td)/"two.zip"
            self.assertEqual(cmd("pack","--source",root,"--output",a).returncode,0)
            self.assertEqual(cmd("verify","--zip",a).returncode,0)
            self.assertEqual(cmd("pack","--source",root,"--output",b).returncode,0)
            self.assertEqual(a.read_bytes(),b.read_bytes())
            with zipfile.ZipFile(a,"a") as z:
                z.writestr("POC/demo.py","tampered")
            self.assertNotEqual(cmd("verify","--zip",a).returncode,0)

    def test_fail_closed_scope_and_control(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"src"
            source(root,repo="transferwise/pipelinewise",control=False)
            dest=Path(td)/"bundle.zip"
            r=cmd("pack","--source",root,"--output",dest)
            self.assertNotEqual(r.returncode,0)
            self.assertIn("out-of-scope",r.stderr)
            data=json.loads((root/"MANIFEST.json").read_text())
            data["target_repo"]="transferwise/idempotence4j"
            (root/"MANIFEST.json").write_text(json.dumps(data))
            r=cmd("pack","--source",root,"--output",dest)
            self.assertNotEqual(r.returncode,0)
            self.assertIn("negative-control",r.stderr)

if __name__=="__main__":
    unittest.main()
