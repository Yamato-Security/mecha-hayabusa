"""Evidence handling for Hayabusa count-based correlation rules.

Those rules emit one aggregated row per correlation window with an EMPTY RecordID,
so no single event can be cited for them. A triage entry may declare
"refs_unavailable": true; gate G7 must honour that claim only when the dataset
agrees that the rule has no citable rows, and must reject it otherwise.
"""

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

# "Citable" carries RecordIDs like any ordinary rule.
# "Aggregated" is a count-correlation rule: every row has an EMPTY RecordID and
# its Details use "Key:Value" with no space, exactly as Hayabusa writes them.
CSV_ROWS = [
    ["2024-01-01 00:00:00.000 +00:00", "Citable", "high", "HOST-A", "Sec", "4688", "10", "Cmdline: evil.exe ¦ User: bob"],
    ["2024-01-01 00:01:00.000 +00:00", "Citable", "high", "HOST-A", "Sec", "4688", "11", "Cmdline: evil.exe ¦ User: bob"],
    ["2024-01-01 00:02:00.000 +00:00", "Aggregated", "high", "HOST-A", "Sec", "4625", "", "Count:5 ¦ TargetUserName:a/b/c ¦ Workstation:HOST-A"],
    ["2024-01-01 00:03:00.000 +00:00", "Aggregated", "high", "HOST-B", "Sec", "4625", "", "Count:3 ¦ TargetUserName:d/e ¦ Workstation:HOST-B"],
]


def run_state(*argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STATE_PY), *argv],
        input=stdin_data,
        capture_output=True,
        text=True,
    )


class AggregationRuleEvidenceTests(unittest.TestCase):
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

    def _triage(self, entries: list[dict]) -> subprocess.CompletedProcess:
        return run_state("triage", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps(entries))

    def _triage_citable(self) -> None:
        """Settle the other in-scope rule so the coverage gates can reach PASS.

        Recorded false_positive rather than attack so no finding is required (G4)."""
        result = self._triage([{
            "rule_title": "Citable", "verdict": "false_positive",
            "rationale": "Vendor binary in its canonical path; benign in this fixture.",
            "excerpt": "Cmdline: evil.exe ¦ User: bob",
            "refs": [{"record_id": "10", "computer": "HOST-A"}],
        }])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_aggregation_rule_cannot_be_triaged_without_the_flag(self) -> None:
        """The rule has no citable row, so a bare verdict is still rejected."""
        result = self._triage([{
            "rule_title": "Aggregated", "verdict": "indeterminate",
            "rationale": "Aggregated failed-logon counts; no single event to inspect.",
        }])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refs_unavailable", result.stdout + result.stderr)

    def test_refs_unavailable_lets_an_uncitable_rule_be_triaged(self) -> None:
        """Declaring refs_unavailable records the verdict and G7 accepts it."""
        self._triage_citable()
        result = self._triage([{
            "rule_title": "Aggregated", "verdict": "indeterminate",
            "rationale": "Count-correlation rows carry no RecordID, so no event is citable.",
            "refs_unavailable": True,
        }])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        # Scope the assertion to G7: the other coverage gates (hosts, clusters,
        # findings) are out of scope for this fixture and tested elsewhere.
        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("[PASS] G7", check.stdout, check.stdout)
        self.assertNotIn("refs_unavailable", check.stdout)

    def test_refs_unavailable_is_rejected_when_the_rule_has_recordids(self) -> None:
        """The claim is verified against the dataset, not taken on trust."""
        result = self._triage([{
            "rule_title": "Citable", "verdict": "false_positive",
            "rationale": "Asserting the rule cannot be cited, which the dataset contradicts.",
            "excerpt": "Cmdline: evil.exe ¦ User: bob",
            "refs_unavailable": True,
        }])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        check = run_state("check", "--dir", str(self.state_dir))
        self.assertNotEqual(check.returncode, 0)
        self.assertIn("[FAIL] G7", check.stdout)
        self.assertIn("claims refs_unavailable but the rule has rows with RecordIDs", check.stdout)

    def test_refs_unavailable_does_not_waive_the_excerpt_requirement(self) -> None:
        """A false_positive verdict still needs a verbatim excerpt."""
        result = self._triage([{
            "rule_title": "Aggregated", "verdict": "false_positive",
            "rationale": "Benign aggregated counts, but no excerpt supplied.",
            "refs_unavailable": True,
        }])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("excerpt", result.stdout + result.stderr)

    def test_refs_and_refs_unavailable_together_are_rejected(self) -> None:
        """The flag means 'no citable row exists'; it cannot coexist with refs."""
        result = self._triage([{
            "rule_title": "Citable", "verdict": "false_positive",
            "rationale": "Contradictory entry: cites a row and claims none exists.",
            "excerpt": "Cmdline: evil.exe ¦ User: bob",
            "refs": [{"record_id": "10", "computer": "HOST-A"}],
            "refs_unavailable": True,
        }])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("also cites refs", result.stdout + result.stderr)

    def test_refs_unavailable_must_be_a_real_boolean(self) -> None:
        """A JSON string would otherwise switch the escape hatch on via truthiness."""
        result = self._triage([{
            "rule_title": "Aggregated", "verdict": "indeterminate",
            "rationale": "Flag supplied as a string rather than a boolean.",
            "refs_unavailable": "false",
        }])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be a JSON boolean", result.stdout + result.stderr)

    def test_excerpt_of_an_uncitable_rule_is_still_verified(self) -> None:
        """G6 has no ref to resolve, so it checks the quote against the rule's own rows."""
        self._triage_citable()
        result = self._triage([{
            "rule_title": "Aggregated", "verdict": "false_positive",
            "rationale": "Benign aggregated counts, with a fabricated supporting quote.",
            "excerpt": "Count:5 ¦ TargetUserName:THIS-TEXT-IS-NOT-IN-ANY-ROW",
            "refs_unavailable": True,
        }])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("[FAIL] G6", check.stdout, check.stdout)
        self.assertIn("not a verbatim substring of any row of this rule", check.stdout)

    def test_a_verbatim_excerpt_of_an_uncitable_rule_passes_g6(self) -> None:
        self._triage_citable()
        result = self._triage([{
            "rule_title": "Aggregated", "verdict": "false_positive",
            "rationale": "Benign aggregated counts, quoted verbatim from a real row.",
            "excerpt": "Count:5 ¦ TargetUserName:a/b/c ¦ Workstation:HOST-A",
            "refs_unavailable": True,
        }])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("[PASS] G6", check.stdout, check.stdout)
        self.assertIn("[PASS] G7", check.stdout, check.stdout)

    def test_g7_reports_uncitable_rules_separately_from_cited_ones(self) -> None:
        """The coverage appendix must not claim an uncited verdict cited evidence."""
        self._triage_citable()
        self._triage([{
            "rule_title": "Aggregated", "verdict": "indeterminate",
            "rationale": "Count-correlation rows carry no RecordID.",
            "refs_unavailable": True,
        }])
        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("1/2 verdicts and findings cite evidence refs", check.stdout)
        self.assertIn("1 rule(s) verified uncitable", check.stdout)

    def test_refs_unavailable_fails_closed_when_the_dataset_is_unreadable(self) -> None:
        """Without the CSV the claim cannot be verified, so it must not pass."""
        self._triage_citable()
        self._triage([{
            "rule_title": "Aggregated", "verdict": "indeterminate",
            "rationale": "Count-correlation rows carry no RecordID.",
            "refs_unavailable": True,
        }])
        self.csv_path.rename(self.csv_path.with_suffix(".moved"))
        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("[FAIL] G7", check.stdout, check.stdout)
        self.assertIn("dataset could not be read", check.stdout)

    def test_single_rule_cli_can_set_refs_unavailable(self) -> None:
        """The error message tells analysts to set the flag; the CLI must allow it."""
        result = run_state(
            "triage", "--dir", str(self.state_dir), "--rule", "Aggregated",
            "--verdict", "indeterminate", "--refs-unavailable",
            "--rationale", "Count-correlation rows carry no RecordID to cite.",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
