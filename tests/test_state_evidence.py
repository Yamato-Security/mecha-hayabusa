"""Evidence requirements of state.py: qualified refs for every verdict,
ambiguity-aware G6 resolution, verbatim excerpts, and the G7/G8/G9 gates."""

from __future__ import annotations

import csv
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_PY = REPO_ROOT / "skill" / "investigate" / "scripts" / "state.py"

CSV_HEADER = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "Details"]

# RecordID 100 denotes two DIFFERENT events (HOST-A/Sec vs HOST-B/Sysmon).
# RecordID 3 denotes ONE event detected by rules Gamma and Delta.
# RecordIDs 2 and 7 are globally unique.
CSV_ROWS = [
    ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688", "100", "Cmdline: evil.exe -x ¦ User: bob"],
    ["2024-01-01 00:01:00.000 +00:00", "Beta", "high", "HOST-B", "Sysmon", "1", "100", "Image: C:\\Windows\\legit.exe"],
    ["2024-01-01 00:02:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688", "2", "Cmdline: benign.exe ¦ User: alice"],
    ["2024-01-01 00:03:00.000 +00:00", "Gamma", "low", "HOST-A", "Sec", "4624", "3", "TgtUser: svc"],
    ["2024-01-01 00:03:00.000 +00:00", "Delta", "med", "HOST-A", "Sec", "4624", "3", "TgtUser: svc ¦ LogonType: 3"],
    ["2024-01-01 00:04:00.000 +00:00", "Beta", "high", "HOST-C", "Sysmon", "1", "7", "Image: C:\\Users\\Public\\tool.exe"],
]


def run_state(*argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STATE_PY), *argv],
        input=stdin_data,
        capture_output=True,
        text=True,
    )


class StateEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.state_dir = tmpdir / "state"
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(CSV_ROWS)
        result = run_state("init", "--csv", str(self.csv_path), "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------

    def triage_batch(self, entries: list[dict]) -> subprocess.CompletedProcess:
        return run_state("triage", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps(entries, ensure_ascii=False))

    def finding_batch(self, entries: list[dict]) -> subprocess.CompletedProcess:
        return run_state("finding", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps(entries, ensure_ascii=False))

    def gates(self) -> dict[str, dict]:
        result = run_state("check", "--dir", str(self.state_dir), "--json")
        payload = json.loads(result.stdout)
        return {g["id"]: g for g in payload["gates"]}

    # -- record-time validation ------------------------------------------

    def test_every_verdict_requires_refs(self) -> None:
        for verdict in ("attack", "false_positive", "indeterminate"):
            result = self.triage_batch([{
                "rule_title": "Alpha", "verdict": verdict,
                "rationale": "some substantive reason here",
                "excerpt": "Cmdline: benign.exe",
            }])
            self.assertEqual(result.returncode, 2, f"{verdict} accepted without refs")
            self.assertIn("refs", result.stderr)

    def test_stub_rationale_rejected(self) -> None:
        result = self.triage_batch([{
            "rule_title": "Alpha", "verdict": "false_positive",
            "rationale": "reviewed", "record_ids": ["2"],
            "excerpt": "Cmdline: benign.exe",
        }])
        self.assertEqual(result.returncode, 2)
        self.assertIn("too thin", result.stderr)

    def test_false_positive_requires_excerpt(self) -> None:
        result = self.triage_batch([{
            "rule_title": "Alpha", "verdict": "false_positive",
            "rationale": "benign admin activity by alice", "record_ids": ["2"],
        }])
        self.assertEqual(result.returncode, 2)
        self.assertIn("excerpt", result.stderr)

    def test_finding_requires_refs(self) -> None:
        result = self.finding_batch([{
            "title": "t", "summary": "s", "hosts": ["HOST-A"], "rules": ["Alpha"],
        }])
        self.assertEqual(result.returncode, 2)
        self.assertIn("refs", result.stderr)

    # -- G6: ref resolution ------------------------------------------------

    def test_bare_ambiguous_ref_fails_g6(self) -> None:
        result = self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["100"],
        }])
        self.assertEqual(result.returncode, 0, result.stderr)
        g6 = self.gates()["G6"]
        self.assertEqual(g6["status"], "FAIL")
        self.assertTrue(any("ambiguous" in gap for gap in g6["gaps"]), g6["gaps"])

    def test_qualified_ref_passes_g6(self) -> None:
        result = self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "refs": [{"record_id": "100", "computer": "HOST-A"}],
        }])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.gates()["G6"]["status"], "PASS")

    def test_compact_string_ref_form(self) -> None:
        result = self.triage_batch([{
            "rule_title": "Beta", "verdict": "attack",
            "rationale": "tool dropped in user-writable path",
            "record_ids": ["100@HOST-B@Sysmon"],
        }])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.gates()["G6"]["status"], "PASS")

    def test_bare_unique_ref_still_passes(self) -> None:
        result = self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["2"],
        }])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.gates()["G6"]["status"], "PASS")

    def test_wrong_computer_fails_g6(self) -> None:
        self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "refs": [{"record_id": "100", "computer": "HOST-Z"}],
        }])
        g6 = self.gates()["G6"]
        self.assertEqual(g6["status"], "FAIL")
        self.assertTrue(any("no such event" in gap for gap in g6["gaps"]), g6["gaps"])

    def test_ref_to_other_rules_event_fails_g6(self) -> None:
        # RecordID 7 exists but was detected by Beta, not Alpha.
        self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["7"],
        }])
        g6 = self.gates()["G6"]
        self.assertEqual(g6["status"], "FAIL")
        self.assertTrue(any("not detected by the cited rule" in gap for gap in g6["gaps"]), g6["gaps"])

    def test_nonexistent_record_id_fails_g6(self) -> None:
        self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["99999"],
        }])
        g6 = self.gates()["G6"]
        self.assertEqual(g6["status"], "FAIL")
        self.assertTrue(any("not found in dataset" in gap for gap in g6["gaps"]), g6["gaps"])

    def test_excerpt_must_be_verbatim(self) -> None:
        self.triage_batch([{
            "rule_title": "Alpha", "verdict": "false_positive",
            "rationale": "benign admin activity by alice",
            "record_ids": ["2"],
            "excerpt": "alice ran a benign process",  # paraphrase, not a quote
        }])
        g6 = self.gates()["G6"]
        self.assertEqual(g6["status"], "FAIL")
        self.assertTrue(any("verbatim" in gap for gap in g6["gaps"]), g6["gaps"])

    def test_verbatim_excerpt_passes(self) -> None:
        self.triage_batch([{
            "rule_title": "Alpha", "verdict": "false_positive",
            "rationale": "benign admin activity by alice",
            "record_ids": ["2"],
            "excerpt": "Cmdline: benign.exe ¦ User: alice",
        }])
        self.assertEqual(self.gates()["G6"]["status"], "PASS")

    # -- G7: evidence presence for every verdict ---------------------------

    def test_g7_flags_legacy_verdicts_without_refs(self) -> None:
        # Simulate a v1 state file written before evidence was mandatory.
        triage_path = self.state_dir / "rule_triage.json"
        data = json.loads(triage_path.read_text(encoding="utf-8"))
        for rule in data["rules"]:
            if rule["rule_title"] == "Alpha":
                rule["status"] = "verified"
                rule["verdict"] = "false_positive"
                rule["rationale"] = "reviewed"
        triage_path.write_text(json.dumps(data), encoding="utf-8")
        g7 = self.gates()["G7"]
        self.assertEqual(g7["status"], "FAIL")
        self.assertTrue(any("Alpha" in gap and "no refs" in gap for gap in g7["gaps"]), g7["gaps"])

    # -- G8: findings cannot cite false-positive rules ---------------------

    def test_finding_citing_fp_rule_fails_g8(self) -> None:
        self.triage_batch([{
            "rule_title": "Gamma", "verdict": "false_positive",
            "rationale": "routine service logon pattern",
            "refs": [{"record_id": "3", "computer": "HOST-A"}],
            "excerpt": "TgtUser: svc",
        }])
        result = self.finding_batch([{
            "title": "svc logon abuse", "summary": "claims Gamma as evidence",
            "hosts": ["HOST-A"], "rules": ["Gamma"],
            "refs": [{"record_id": "3", "computer": "HOST-A"}],
        }])
        self.assertEqual(result.returncode, 0, result.stderr)
        g8 = self.gates()["G8"]
        self.assertEqual(g8["status"], "FAIL")
        self.assertTrue(any("false_positive" in gap for gap in g8["gaps"]), g8["gaps"])

    # -- G9: finding hosts must be backed by cited events -------------------

    def test_unbacked_finding_host_fails_g9(self) -> None:
        self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["2"],
        }])
        self.finding_batch([{
            "title": "execution on B", "summary": "claims HOST-B without evidence there",
            "hosts": ["HOST-B"], "rules": ["Alpha"], "record_ids": ["2"],
        }])
        g9 = self.gates()["G9"]
        self.assertEqual(g9["status"], "FAIL")
        self.assertTrue(any("HOST-B" in gap for gap in g9["gaps"]), g9["gaps"])

    def test_backed_finding_host_passes_g9(self) -> None:
        self.triage_batch([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["2"],
        }])
        self.finding_batch([{
            "title": "execution on A", "summary": "evidence on the named host",
            "hosts": ["HOST-A"], "rules": ["Alpha"], "record_ids": ["2"],
        }])
        self.assertEqual(self.gates()["G9"]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
