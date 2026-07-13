"""Report/state consistency: the false-positive table and indeterminate list
are generated from state via markers, a false_positive rule can never appear
as a timeline row, and state IOCs missing from the body produce warnings."""

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
    ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688", "2",
     "Cmdline: evil.exe ¦ User: bob"],
    ["2024-01-01 00:01:00.000 +00:00", "Gamma", "high", "HOST-A", "Sec", "7045", "3",
     "Svc: PrintSpooler ¦ Path: svchost.exe -k print"],
]

BODY_WITH_MARKERS = """# Incident Report

## 1. Summary

An attacker executed evil.exe on HOST-A.

## 3. Compromise Timeline

| Time (UTC) | Host | Event (RuleTitle) | Level |
|---|---|---|---|
| 00:00:00 | HOST-A | Alpha | high |

## 9. Notes

### False Positives

<!--STATE:FP_TABLE-->

### Indeterminate Events

<!--STATE:INDETERMINATE_LIST-->
"""


def run_cli(script: pathlib.Path, *argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), *argv],
        input=stdin_data,
        capture_output=True,
        text=True,
    )


class ReportConsistencyTests(unittest.TestCase):
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
        self.complete_investigation()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def complete_investigation(self) -> None:
        entries = [
            {"rule_title": "Alpha", "verdict": "attack",
             "rationale": "malicious commandline observed on HOST-A",
             "record_ids": ["2"]},
            {"rule_title": "Gamma", "verdict": "false_positive",
             "rationale": "legitimate Windows print service path",
             "record_ids": ["3"],
             "excerpt": "Path: svchost.exe -k print"},
        ]
        result = run_cli(STATE_PY, "triage", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps(entries))
        self.assertEqual(result.returncode, 0, result.stderr)
        finding = [{
            "title": "malicious execution", "summary": "attacker ran evil.exe",
            "hosts": ["HOST-A"], "rules": ["Alpha"], "record_ids": ["2"],
        }]
        result = run_cli(STATE_PY, "finding", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps(finding))
        self.assertEqual(result.returncode, 0, result.stderr)
        run_cli(STATE_PY, "host", "--dir", str(self.state_dir), "--name", "HOST-A", "--status", "investigated")
        run_cli(STATE_PY, "cluster", "--dir", str(self.state_dir), "--id", "c1", "--verdict", "attack", "--note", "wave")
        run_cli(STATE_PY, "verify", "--dir", str(self.state_dir),
                "--target-type", "finding", "--target", "f1", "--verdict", "attack", "--note", "confirmed")
        result = run_cli(STATE_PY, "check", "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def render(self, content: str, *, force: bool = False) -> tuple[subprocess.CompletedProcess, pathlib.Path]:
        output = self.state_dir / "report.html"
        payload = {
            "content": content,
            "output": str(output),
            "state_dir": str(self.state_dir),
            "force": force,
        }
        result = run_cli(REPORT_PY, stdin_data=json.dumps(payload, ensure_ascii=False))
        return result, output

    def test_markers_render_state_generated_tables(self) -> None:
        result, output = self.render(BODY_WITH_MARKERS)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = output.read_text(encoding="utf-8")
        self.assertIn("Gamma", html)                       # FP rule in generated table
        self.assertIn("svchost.exe -k print", html)        # verbatim excerpt shown
        self.assertIn("no rules were triaged as indeterminate", html)
        self.assertNotIn("STATE:FP_TABLE", html)           # marker consumed

    def test_missing_fp_marker_refused(self) -> None:
        content = BODY_WITH_MARKERS.replace("<!--STATE:FP_TABLE-->\n", "")
        result, output = self.render(content)
        self.assertEqual(result.returncode, 4)
        self.assertIn("FP_TABLE", result.stderr)
        self.assertFalse(output.exists())

    def test_fp_rule_in_timeline_refused(self) -> None:
        content = BODY_WITH_MARKERS.replace(
            "| 00:00:00 | HOST-A | Alpha | high |",
            "| 00:00:00 | HOST-A | Alpha | high |\n| 00:01:00 | HOST-A | Gamma | high |",
        )
        result, output = self.render(content)
        self.assertEqual(result.returncode, 4)
        self.assertIn("timeline", result.stderr)
        self.assertIn("Gamma", result.stderr)
        self.assertFalse(output.exists())

    def test_forced_consistency_failure_writes_unverified(self) -> None:
        content = BODY_WITH_MARKERS.replace("<!--STATE:FP_TABLE-->\n", "")
        result, output = self.render(content, force=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        unverified = output.with_name("report_UNVERIFIED.html")
        self.assertTrue(unverified.exists())
        html = unverified.read_text(encoding="utf-8")
        self.assertIn("report consistency", html)

    def test_state_ioc_missing_from_body_warns(self) -> None:
        result = run_cli(STATE_PY, "ioc", "--dir", str(self.state_dir),
                         "--type", "ip", "--value", "198.51.100.7",
                         "--record-ids", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        result, output = self.render(BODY_WITH_MARKERS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("198.51.100.7", result.stderr)
        self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
