"""Independent-verification votes (gate G11): every finding and every
high-volume false_positive/mixed verdict needs a consistent fresh-context
vote; cannot_verify confirms nothing; an attack vote always blocks an FP."""

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


def build_rows() -> list[list[str]]:
    rows = [
        ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688", "2",
         "Cmdline: evil.exe -x ¦ User: bob"],
    ]
    # "Noisy": 24 benign-looking events (above the variant threshold of 20).
    for i in range(24):
        rows.append(["2024-01-01 01:00:00.000 +00:00", "Noisy", "high", "HOST-A", "Sysmon",
                     "10", str(1000 + i), "SrcProc: veeam.exe ¦ TgtProc: lsass.exe"])
    return rows


def run_state(*argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STATE_PY), *argv],
        input=stdin_data,
        capture_output=True,
        text=True,
    )


class VerificationVoteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.state_dir = tmpdir / "state"
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(build_rows())
        result = run_state("init", "--csv", str(self.csv_path), "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def gates(self) -> dict[str, dict]:
        result = run_state("check", "--dir", str(self.state_dir), "--json")
        payload = json.loads(result.stdout)
        return {g["id"]: g for g in payload["gates"]}

    def vote(self, target_type: str, target: str, verdict: str) -> subprocess.CompletedProcess:
        return run_state("verify", "--dir", str(self.state_dir),
                         "--target-type", target_type, "--target", target,
                         "--verdict", verdict, "--note", "verifier summary")

    def add_finding(self) -> None:
        result = run_state("triage", "--dir", str(self.state_dir), "--batch", stdin_data=json.dumps([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["2"],
        }]))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run_state("finding", "--dir", str(self.state_dir), "--batch", stdin_data=json.dumps([{
            "title": "evil execution", "summary": "attacker ran evil.exe",
            "hosts": ["HOST-A"], "rules": ["Alpha"], "record_ids": ["2"],
        }]))
        self.assertEqual(result.returncode, 0, result.stderr)

    def triage_noisy_fp(self) -> None:
        result = run_state("triage", "--dir", str(self.state_dir), "--batch", stdin_data=json.dumps([{
            "rule_title": "Noisy", "verdict": "false_positive",
            "rationale": "veeam backup accessing lsass on every run",
            "refs": [{"record_id": "1000", "computer": "HOST-A"}],
            "excerpt": "SrcProc: veeam.exe ¦ TgtProc: lsass.exe",
            "variants": {
                "fields": ["SrcProc", "TgtProc"],
                "groups": [{"key": {"SrcProc": "veeam.exe", "TgtProc": "lsass.exe"},
                            "count": 24, "verdict": "benign", "note": "backup agent"}],
            },
        }]))
        self.assertEqual(result.returncode, 0, result.stderr)

    # -- findings ----------------------------------------------------------

    def test_finding_without_vote_fails_g11(self) -> None:
        self.add_finding()
        g11 = self.gates()["G11"]
        self.assertEqual(g11["status"], "FAIL")
        self.assertTrue(any("no verification vote" in gap for gap in g11["gaps"]), g11["gaps"])

    def test_finding_with_attack_vote_passes(self) -> None:
        self.add_finding()
        self.assertEqual(self.vote("finding", "f1", "attack").returncode, 0)
        self.assertEqual(self.gates()["G11"]["status"], "PASS")

    def test_cannot_verify_confirms_nothing(self) -> None:
        self.add_finding()
        self.vote("finding", "f1", "cannot_verify")
        g11 = self.gates()["G11"]
        self.assertEqual(g11["status"], "FAIL")
        self.assertTrue(any("cannot_verify" in gap for gap in g11["gaps"]), g11["gaps"])

    def test_conflict_requires_majority_of_three(self) -> None:
        self.add_finding()
        self.vote("finding", "f1", "attack")
        self.vote("finding", "f1", "false_positive")
        g11 = self.gates()["G11"]
        self.assertEqual(g11["status"], "FAIL")
        self.assertTrue(any("escalate" in gap for gap in g11["gaps"]), g11["gaps"])
        # Escalation: two more attack votes -> 3:1 strict majority.
        self.vote("finding", "f1", "attack")
        self.vote("finding", "f1", "attack")
        self.assertEqual(self.gates()["G11"]["status"], "PASS")

    # -- high-volume rule verdicts ------------------------------------------

    def test_high_volume_fp_needs_vote(self) -> None:
        self.triage_noisy_fp()
        g11 = self.gates()["G11"]
        self.assertEqual(g11["status"], "FAIL")
        self.assertTrue(any("Noisy" in gap for gap in g11["gaps"]), g11["gaps"])
        self.assertEqual(self.vote("rule", "Noisy", "false_positive").returncode, 0)
        self.assertEqual(self.gates()["G11"]["status"], "PASS")

    def test_attack_vote_blocks_fp_even_when_outnumbered(self) -> None:
        self.triage_noisy_fp()
        self.vote("rule", "Noisy", "false_positive")
        self.vote("rule", "Noisy", "false_positive")
        self.vote("rule", "Noisy", "attack")
        g11 = self.gates()["G11"]
        self.assertEqual(g11["status"], "FAIL")
        self.assertTrue(any("re-triage" in gap for gap in g11["gaps"]), g11["gaps"])

    def test_small_rules_need_no_vote(self) -> None:
        # Only the 1-event Alpha rule is triaged (attack); no finding yet, so
        # G11 has nothing report-bound to require. (G4 will fail instead.)
        result = run_state("triage", "--dir", str(self.state_dir), "--batch", stdin_data=json.dumps([{
            "rule_title": "Alpha", "verdict": "attack",
            "rationale": "malicious commandline observed",
            "record_ids": ["2"],
        }]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.gates()["G11"]["status"], "PASS")

    # -- CLI validation -----------------------------------------------------

    def test_verify_rejects_unknown_target(self) -> None:
        result = self.vote("finding", "f99", "attack")
        self.assertEqual(result.returncode, 2)
        result = self.vote("rule", "NoSuchRule", "attack")
        self.assertEqual(result.returncode, 2)

    def test_verify_rejects_bad_verdict(self) -> None:
        self.add_finding()
        result = self.vote("finding", "f1", "maybe")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
