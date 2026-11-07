"""Offline, synthetic and deterministic guards for fresh-process evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[2]/"reports/electroneum/shared/run_fresh_matrix.py"
COMMIT="7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"
TREE="de7f3c75a2db7e87a89918f1257820703d5b731e"
FAKE=r'''
import argparse,hashlib,json,os
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument("--class",dest="owner");p.add_argument("--matrix")
p.add_argument("--repeat",type=int);p.add_argument("--output")
a=p.parse_args();d=Path(a.output);d.mkdir(exist_ok=True,parents=True)
n=int(d.name.split("-")[-1])
f=d/"test.log";f.write_text("--- PASS: TestSynthetic (0.00s)\nHONEST\nMALICIOUS_REJECTED\n")
h=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
markers={"HONEST":1,"MALICIOUS_REJECTED":1}
if os.getenv("BAD_MARKER")==str(n):markers["MALICIOUS_REJECTED"]=0
if os.getenv("BAD_COUNT")==str(n):markers["HONEST"]=2
rec={"id":"synthetic","owner":a.owner,"test":"TestSynthetic","package":"./core",
"source_fixture":"reports/electroneum/A/tests/synthetic_test.go",
"fixture_sha256":("b"*64 if os.getenv("DRIFT")==str(n) else "a"*64),
"classification":"isolated fixture only","outcome":"PASS_REGRESSION_ONLY","exit_code":0,
"expected_repetitions":1,"successful_top_level_repetitions":1,
"positive_negative_controls_seen":markers,"log":"test.log",
"log_sha256":("f"*64 if os.getenv("BAD_HASH")==str(n) else h(f))}
out={"class":a.owner,"status":"PASSED_REGRESSIONS_NOT_FINDINGS",
"certified_source_commit":("0"*40 if os.getenv("BAD_CERT")==str(n) else "7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"),
"certified_source_tree":"de7f3c75a2db7e87a89918f1257820703d5b731e",
"github_run_id":os.getenv("GITHUB_RUN_ID"),"probes":[rec]}
(d/"result.json").write_text(json.dumps(out))
'''

class GateTests(unittest.TestCase):
    def scenario(self,changes=None):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)
            (root/"fake.py").write_text(FAKE)
            env=os.environ.copy()
            env.pop("GITHUB_SHA",None)
            env.pop("GITHUB_RUN_ID",None)
            env.update({"WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT":COMMIT,
                        "WINDEEP_ETN_SOURCE_TREE_SHA":TREE})
            env.update(changes or {})
            proc=subprocess.run([sys.executable,str(SCRIPT),"--class","A",
                                 "--runner","fake.py","--output",str(root/"out"),
                                 "--timeout-sec","30"],cwd=root,env=env,
                                capture_output=True,text=True)
            obj=json.loads((root/"out/fresh-evidence.json").read_text())
            return proc,obj

    def test_three_distinct_processes(self):
        p,r=self.scenario()
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        self.assertEqual(r["status"],"PASSED_INDEPENDENT_REGRESSIONS_NOT_FINDINGS")
        self.assertEqual(len(r["attempts"]),3)
        self.assertEqual(len({x["process_id"] for x in r["attempts"]}),3)

    def test_missing_adversarial_control(self):
        p,r=self.scenario({"BAD_MARKER":"2"})
        self.assertNotEqual(p.returncode,0)
        self.assertIn("missing required control",r["error"])

    def test_bad_digest(self):
        p,r=self.scenario({"BAD_HASH":"3"})
        self.assertNotEqual(p.returncode,0)
        self.assertIn("tampered native log",r["error"])

    def test_false_control_count(self):
        p,r=self.scenario({"BAD_COUNT":"2"})
        self.assertNotEqual(p.returncode,0)
        self.assertIn("contradicts log",r["error"])

    def test_fixture_changed_between_processes(self):
        p,r=self.scenario({"DRIFT":"3"})
        self.assertNotEqual(p.returncode,0)
        self.assertIn("drifted",r["error"])

    def test_wrong_tree_or_commit(self):
        p,r=self.scenario({"BAD_CERT":"1"})
        self.assertNotEqual(p.returncode,0)
        self.assertIn("identity mismatch",r["error"])

    def test_missing_certified_environment(self):
        p,r=self.scenario({"WINDEEP_ETN_SOURCE_TREE_SHA":"WRONG"})
        self.assertNotEqual(p.returncode,0)
        self.assertIn("source environment",r["error"])

if __name__=="__main__":unittest.main()
