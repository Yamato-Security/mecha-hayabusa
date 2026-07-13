"""report.py coverage-gate behavior: refusal on failing gates, the UNVERIFIED
naming/banner for forced reports, and the clean path when gates pass."""

from __future__ import annotations

import csv
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "skill" / "investigate" / "scripts"
STATE_PY = SCRIPTS / "state.py"
REPORT_PY = SCRIPTS / "report.py"

CSV_HEADER = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "Details"]
CSV_ROWS = [
    ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688", "2", "Cmdline: benign.exe ¦ User: alice"],
    ["2024-01-01 00:01:00.000 +00:00", "Beta", "high", "HOST-B", "Sysmon", "1", "7", "Image: C:\\Users\\Public\\tool.exe"],
]


def run_cli(script: pathlib.Path, *argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), *argv],
        input=stdin_data,
        capture_output=True,
        text=True,
    )


class ReportGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.state_dir = tmpdir / "state"
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(CSV_ROWS)
        result = run_cli(STATE_PY, "init", "--csv", str(self.csv_path), "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def render(self, *, force: bool = False, output_name: str = "report.html") -> tuple[subprocess.CompletedProcess, pathlib.Path]:
        output = self.state_dir / output_name
        payload = {
            "content": "# Incident Report\n\n## 1. Summary\n\nbody text\n",
            "output": str(output),
            "state_dir": str(self.state_dir),
            "force": force,
        }
        result = run_cli(REPORT_PY, stdin_data=json.dumps(payload, ensure_ascii=False))
        return result, output

    def complete_investigation(self) -> None:
        """Drive the state to all-gates-green."""
        entries = [
            {"rule_title": "Alpha", "verdict": "attack",
             "rationale": "malicious commandline observed on HOST-A",
             "record_ids": ["2"]},
            {"rule_title": "Beta", "verdict": "attack",
             "rationale": "tool dropped in user-writable path on HOST-B",
             "record_ids": ["7"]},
        ]
        result = run_cli(STATE_PY, "triage", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps(entries))
        self.assertEqual(result.returncode, 0, result.stderr)
        finding = [{
            "title": "malicious execution", "summary": "attacker ran tools on both hosts",
            "hosts": ["HOST-A", "HOST-B"], "rules": ["Alpha", "Beta"],
            "record_ids": ["2", "7"],
        }]
        result = run_cli(STATE_PY, "finding", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps(finding))
        self.assertEqual(result.returncode, 0, result.stderr)
        for host in ("HOST-A", "HOST-B"):
            result = run_cli(STATE_PY, "host", "--dir", str(self.state_dir),
                             "--name", host, "--status", "investigated")
            self.assertEqual(result.returncode, 0, result.stderr)
        result = run_cli(STATE_PY, "cluster", "--dir", str(self.state_dir),
                         "--id", "c1", "--verdict", "attack", "--note", "single wave")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run_cli(STATE_PY, "verify", "--dir", str(self.state_dir),
                         "--target-type", "finding", "--target", "f1",
                         "--verdict", "attack", "--note", "independently confirmed via refs")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run_cli(STATE_PY, "check", "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failing_gates_refuse_report(self) -> None:
        result, output = self.render(force=False)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(output.exists())
        self.assertIn("FAILED", result.stderr)

    def test_force_writes_unverified_artifact(self) -> None:
        result, output = self.render(force=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        unverified = output.with_name("report_UNVERIFIED.html")
        self.assertTrue(unverified.exists(), "forced report must get the _UNVERIFIED suffix")
        self.assertFalse(output.exists(), "forced report must NOT use the certified filename")
        html = unverified.read_text(encoding="utf-8")
        self.assertIn("unverified-banner", html)
        self.assertIn("UNVERIFIED", html)
        self.assertIn("G1", html)  # the failing gate is named in the banner
        self.assertIn("[UNVERIFIED]", html)  # title prefix
        self.assertIn(str(unverified), result.stdout)

    def test_passing_gates_write_certified_report(self) -> None:
        self.complete_investigation()
        result, output = self.render(force=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.exists())
        html = output.read_text(encoding="utf-8")
        self.assertNotIn("unverified-banner", html)
        # The coverage appendix is embedded (gate table renders G0..G9)
        self.assertIn("G9", html)

    def test_force_with_passing_gates_stays_certified(self) -> None:
        self.complete_investigation()
        result, output = self.render(force=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.exists())
        self.assertFalse(output.with_name("report_UNVERIFIED.html").exists())


if __name__ == "__main__":
    unittest.main()
