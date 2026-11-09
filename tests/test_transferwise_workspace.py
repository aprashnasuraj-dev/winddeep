"""Offline environment preflight regression checks."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit/transferwise_workspace.py"

class ReadinessTests(unittest.TestCase):
    def test_doctor_reports_tools_and_canonical_helper(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "doctor"],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        data = json.loads(run.stdout)
        self.assertTrue(data["python_compatible"])
        self.assertTrue(data["tool_available"]["git"])
        self.assertTrue(data["private_evidence_only"])
        self.assertEqual(data["canonical_bundle_helper"],
                         "scripts/audit/transferwise_handoff.py")

    def test_repository_gate(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "doctor", "--check"],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        data = json.loads(run.stdout)
        self.assertTrue(data["repository_gate_passed"])

if __name__ == "__main__":
    unittest.main()
