"""Evtx reachability: how much of the corpus the timeline could ever surface.

A Hayabusa timeline contains only events that matched a rule, so a
`(channel, event id)` present in the evtx but absent from the timeline can
never appear in an investigation no matter how it is queried. These tests pin
the measurement of that gap, and the guards that stop it recording a figure
that is simply wrong.
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
CSV_ROWS = [
    ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688", "1", "Cmdline: evil.exe"],
    ["2024-01-01 00:01:00.000 +00:00", "Beta", "med", "HOST-A", "Sec", "4624", "2", "TgtUser: svc"],
]

# `hayabusa eid-metrics` over the ORIGINAL evtx. Sec/4688 and Sec/4624 also
# appear in the timeline; Sys/1014 and Shell-Core/9707 never matched a rule.
EID_METRICS = [
    ["Total", "%", "Channel", "ID", "Event"],
    ["9000", "60.0", "Sys", "1014", "DNS resolution timeout"],
    ["4000", "26.7", "Sec", "4688", "Process creation"],
    ["1500", "10.0", "MS-Win-Shell-Core/Op", "9707", "Shell command"],
    ["500", "3.3", "Sec", "4624", "Logon"],
]


def run_state(*argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(STATE_PY), *argv],
                          input=stdin_data, capture_output=True, text=True)


class ReachabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "timeline.csv"
        self.metrics_path = tmpdir / "eid-metrics.csv"
        self.state_dir = tmpdir / "state"
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            w.writerows(CSV_ROWS)
        with self.metrics_path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(EID_METRICS)
        result = run_state("init", "--csv", str(self.csv_path), "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def reach(self, *argv: str) -> subprocess.CompletedProcess:
        return run_state("reach", "--dir", str(self.state_dir), *argv)

    def write_metrics(self, name: str, rows: list[list[str]]) -> pathlib.Path:
        path = self.state_dir.parent / name
        with path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows([["Total", "%", "Channel", "ID", "Event"], *rows])
        return path

    # -- measurement -----------------------------------------------------

    def test_eid_metrics_import_computes_absent_pairs(self) -> None:
        result = self.reach("--eid-metrics", str(self.metrics_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["corpus_events"], 15000)
        self.assertEqual(corpus["corpus_pairs"], 4)
        self.assertEqual(corpus["timeline_rows"], 2)
        self.assertEqual(corpus["timeline_pairs"], 2)
        # Sys/1014 (9000) and Shell-Core/9707 (1500) are absent from the timeline.
        self.assertEqual(corpus["uncovered_pairs"], 2)
        self.assertEqual(corpus["uncovered_events"], 10500)
        self.assertEqual(corpus["uncovered"][0]["channel"], "Sys")

    def test_metric_uses_corpus_events_on_both_sides(self) -> None:
        # Rows/events would double-count (one row per event x matching rule) and
        # could exceed 100%; corpus/corpus cannot.
        self.reach("--eid-metrics", str(self.metrics_path))
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["unreachable_pct"], 70.0)
        self.assertLessEqual(corpus["unreachable_pct"], 100.0)

    def test_channel_case_differences_are_not_gaps(self) -> None:
        # hayabusa spells the same channel differently across subcommands
        # (MS-Win-appxDeploySvr vs MS-Win-AppXDeploySvr); that is not a gap.
        metrics = self.write_metrics("cased.csv", [["100", "50.0", "SEC", "4688", "x"],
                                                   ["100", "50.0", "sec", "4624", "y"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["uncovered_pairs"], 0)

    def test_original_channel_spelling_is_preserved_for_display(self) -> None:
        self.reach("--eid-metrics", str(self.metrics_path))
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertIn("MS-Win-Shell-Core/Op",
                      [e["channel"] for e in corpus["uncovered"]])

    # -- guards ----------------------------------------------------------

    def test_a_timeline_csv_is_not_accepted_as_metrics(self) -> None:
        # A timeline also has a Channel column; importing one would compare the
        # timeline against itself and report perfect coverage.
        result = self.reach("--eid-metrics", str(self.csv_path))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("eid-metrics", result.stderr + result.stdout)

    def test_timeline_pair_missing_from_metrics_is_refused(self) -> None:
        # A partial overlap means the two files do not describe the same evtx,
        # or spell channels differently; recording it would be a false metric.
        metrics = self.write_metrics("partial.csv", [["100", "50.0", "Sec", "4688", "x"],
                                                     ["100", "50.0", "Other", "1", "y"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("absent from", r.stderr + r.stdout)

    def test_channel_representation_mismatch_is_explained(self) -> None:
        metrics = self.write_metrics("full.csv", [["100", "50.0", "Security", "4688", "x"],
                                                  ["100", "50.0", "Security", "4624", "y"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("channel representations", r.stderr + r.stdout)

    # -- unavailable corpus ----------------------------------------------

    def test_declaring_unavailable_requires_a_reason(self) -> None:
        result = self.reach("--none")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--reason", result.stderr + result.stdout)

    def test_recording_coverage_clears_a_prior_unavailable_declaration(self) -> None:
        self.reach("--none", "--reason", "corpus not shipped yet")
        self.reach("--eid-metrics", str(self.metrics_path))
        state = json.loads((self.state_dir / "reachability.json").read_text())
        self.assertFalse(state["declared_unavailable"])

    # -- reporting -------------------------------------------------------

    def test_appendix_states_reachability_was_not_measured(self) -> None:
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("not measured", out.stdout)

    def test_appendix_reports_measured_coverage_with_the_filter_caveat(self) -> None:
        self.reach("--eid-metrics", str(self.metrics_path))
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertIn("absent from the supplied timeline", out.stdout)
        self.assertIn("filtered timeline", out.stdout)

    def test_appendix_reports_an_unavailable_corpus(self) -> None:
        self.reach("--none", "--reason", "only the CSV was provided")
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertIn("only the CSV was provided", out.stdout)


if __name__ == "__main__":
    unittest.main()
