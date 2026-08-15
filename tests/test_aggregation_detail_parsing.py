"""Detail parsing and host attribution for Hayabusa count-based correlation rules.

Those rules render fields as "Key:Value" with no space after the colon, and can
aggregate several machines into one Computer value joined by the detail
separator. Both forms have to be understood without changing how the ordinary
"Key: Value" form parses.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_PY = REPO_ROOT / "skill" / "investigate" / "scripts" / "state.py"

_spec = importlib.util.spec_from_file_location("hb_state_under_test", STATE_PY)
state = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(state)

CSV_HEADER = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "Details"]


def run_state(*argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(STATE_PY), *argv],
                          input=stdin_data, capture_output=True, text=True)


class DetailParsingTests(unittest.TestCase):
    def test_spaced_form_is_unchanged(self) -> None:
        self.assertEqual(
            state._parse_detail_fields("Proc: C:\\Windows\\cmd.exe ¦ User: bob"),
            {"Proc": "C:\\Windows\\cmd.exe", "User": "bob"},
        )

    def test_aggregation_form_is_parsed(self) -> None:
        self.assertEqual(
            state._parse_detail_fields("Count:21 ¦ ServiceName:AnyDesk MSI Service"),
            {"Count": "21", "ServiceName": "AnyDesk MSI Service"},
        )

    def test_a_drive_letter_fragment_is_not_treated_as_a_field(self) -> None:
        """A one-character key is what a mis-split Windows path looks like."""
        self.assertEqual(state._parse_detail_fields("C:\\Windows\\foo.exe"), {})

    def test_a_value_containing_colons_keeps_its_colons(self) -> None:
        parsed = state._parse_detail_fields("Path: amsi:_\\Device\\HarddiskVolume1\\x.exe")
        self.assertEqual(parsed, {"Path": "amsi:_\\Device\\HarddiskVolume1\\x.exe"})

    def test_task_paths_beginning_with_a_backslash_survive(self) -> None:
        """Scheduled task names legitimately start with a backslash."""
        self.assertEqual(
            state._parse_detail_fields("TaskName:\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot"),
            {"TaskName": "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot"},
        )

    def test_a_pair_with_no_colon_yields_nothing(self) -> None:
        self.assertEqual(state._parse_detail_fields("HKLM\\SOFTWARE\\Microsoft"), {})


class AggregatedHostTests(unittest.TestCase):
    """A row that aggregates several machines must not become a pseudo-host."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.state_dir = tmpdir / "state"
        rows = [
            ["2024-01-01 00:00:00.000 +00:00", "Aggregated", "high",
             "HOST-A ¦ HOST-B", "Sec", "4625", "", "Count:5 ¦ TargetUserName:a/b"],
        ]
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            w.writerows(rows)
        result = run_state("init", "--csv", str(self.csv_path), "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_g2_asks_for_the_constituent_hosts(self) -> None:
        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("HOST-A", check.stdout)
        self.assertIn("HOST-B", check.stdout)
        self.assertNotIn("HOST-A ¦ HOST-B", check.stdout)

    def test_covering_the_real_hosts_satisfies_g2(self) -> None:
        for host in ("HOST-A", "HOST-B"):
            r = run_state("host", "--dir", str(self.state_dir), "--name", host,
                          "--status", "investigated", "--note", "Reviewed via rule triage.")
            self.assertEqual(r.returncode, 0, r.stderr)
        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("[PASS] G2", check.stdout, check.stdout)


class AggregatedVariantEvidenceTests(unittest.TestCase):
    """The payoff: variant evidence becomes possible for a high-volume correlation rule.

    G10 requires variant evidence for a false_positive over 20 events, and an
    all-empty variant key can never be benign. Before the detail-parsing fix these
    rules yielded no fields at all, so that verdict was structurally unreachable.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.state_dir = tmpdir / "state"
        rows = [
            ["2024-01-01 00:00:00.000 +00:00", "Rare Service Installations", "high",
             "HOST-A", "Sys", "7045", "", f"Count:1 ¦ ServiceName:MpKsl{i:04x}"]
            for i in range(25)
        ]
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            w.writerows(rows)
        result = run_state("init", "--csv", str(self.csv_path), "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_variants_over_a_parsed_aggregation_field_satisfy_g10(self) -> None:
        groups = [{"key": {"ServiceName": f"MpKsl{i:04x}"}, "count": 1,
                   "verdict": "benign", "note": "Defender kernel filter service instance."}
                  for i in range(25)]
        entry = {
            "rule_title": "Rare Service Installations", "verdict": "false_positive",
            "rationale": "Every installation is a Defender kernel-filter service instance.",
            "excerpt": "Count:1 ¦ ServiceName:MpKsl0000",
            "refs_unavailable": True,
            "variants": {"fields": ["ServiceName"], "groups": groups},
        }
        result = run_state("triage", "--dir", str(self.state_dir), "--batch",
                           stdin_data=json.dumps([entry]))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        check = run_state("check", "--dir", str(self.state_dir))
        self.assertIn("[PASS] G10", check.stdout, check.stdout)
        self.assertIn("[PASS] G7", check.stdout, check.stdout)
        self.assertIn("[PASS] G6", check.stdout, check.stdout)


if __name__ == "__main__":
    unittest.main()
