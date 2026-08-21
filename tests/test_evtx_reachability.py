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

    def make_timeline(self, name: str, rows: list[list[str]]) -> pathlib.Path:
        path = self.state_dir.parent / name
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            w.writerows(rows)
        return path

    def measure(self, timeline: pathlib.Path, metrics: pathlib.Path, tag: str):
        state = self.state_dir.parent / f"st_{tag}"
        self.assertEqual(run_state("init", "--csv", str(timeline), "--dir", str(state)).returncode, 0)
        r = run_state("reach", "--dir", str(state), "--eid-metrics", str(metrics))
        return r, state

    def test_tab_separated_aggregate_values_are_understood(self) -> None:
        # hayabusa -S joins aggregated values with TAB instead of " ¦ ".
        tl = self.make_timeline("tabbed.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1", "Sec", "4688\t4624", "", "Count:9"]])
        r, state = self.measure(tl, self.metrics_path, "tabbed")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["uncovered_pairs"], 2)  # only Sys/1014 and Shell-Core

    def test_duplicate_metrics_pairs_are_refused(self) -> None:
        m = self.write_metrics("dupe.csv", [["1", "50", "Sec", "4688", "a"],
                                            ["1", "50", "SEC", "4688", "b"]])
        r = self.reach("--eid-metrics", str(m))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("duplicate", r.stderr + r.stdout)

    def test_non_utf8_metrics_are_refused(self) -> None:
        m = self.state_dir.parent / "latin.csv"
        m.write_bytes(b"Total,%,Channel,ID,Event\n1,100,Bad\xffChan,9999,x\n")
        r = self.reach("--eid-metrics", str(m))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not valid UTF-8", r.stderr + r.stdout)

    def test_quoted_decimal_comma_total_is_refused(self) -> None:
        m = self.write_metrics("comma.csv", [["1,2", "100", "Sec", "4688", "a"]])
        r = self.reach("--eid-metrics", str(m))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("positive decimal integer", r.stderr + r.stdout)

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

    def test_timeline_without_channel_or_eventid_is_refused(self) -> None:
        # Otherwise every pair looks absent and 100% of the corpus is recorded
        # as unreachable, from a CSV that simply has different columns.
        bad = self.state_dir.parent / "nochan.csv"
        with bad.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "RuleTitle", "Level", "Computer", "RecordID", "Details"])
            w.writerow(["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "1", "x"])
        state2 = self.state_dir.parent / "state2"
        self.assertEqual(run_state("init", "--csv", str(bad), "--dir", str(state2)).returncode, 0)
        r = run_state("reach", "--dir", str(state2), "--eid-metrics", str(self.metrics_path))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("missing timeline column", r.stderr + r.stdout)

    def test_malformed_metrics_rows_are_rejected_not_skipped(self) -> None:
        for label, rows in [
            ("non-integer", [["abc", "0", "Sec", "4688", "x"]]),
            ("negative", [["-50", "0", "Sec", "4688", "x"]]),
            ("blank channel", [["10", "0", "", "4688", "x"]]),
            ("blank id", [["10", "0", "Sec", "", "x"]]),
            ("header only", []),
        ]:
            with self.subTest(label):
                metrics = self.write_metrics(f"bad_{label.replace(' ', '_')}.csv", rows)
                r = self.reach("--eid-metrics", str(metrics))
                self.assertNotEqual(r.returncode, 0, f"accepted {label}")

    def test_percentage_cannot_exceed_100(self) -> None:
        # Negative totals previously produced 150%. The bound is now a property
        # of the code rather than an assumption about the input.
        metrics = self.write_metrics("negs.csv", [["-50", "0", "Sec", "4688", "a"],
                                                  ["-50", "0", "Sec", "4624", "b"],
                                                  ["200", "0", "Sys", "1014", "c"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.state_dir / "reachability.json").exists())

    def test_every_absent_pair_is_persisted(self) -> None:
        rows = [["100", "0", "Sec", "4688", "x"], ["100", "0", "Sec", "4624", "y"]]
        rows += [["1", "0", "Chan%d" % i, str(i), "z"] for i in range(250)]
        metrics = self.write_metrics("many.csv", rows)
        self.assertEqual(self.reach("--eid-metrics", str(metrics)).returncode, 0)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["uncovered_pairs"], 250)
        self.assertEqual(len(corpus["uncovered"]), 250)
        out = self.reach("--list")
        self.assertIn("240 more", out.stdout)

    def test_correlation_rows_never_attest_a_pair(self) -> None:
        # A correlation row has no RecordID: it summarises many events and its
        # Channel/EventID are joined, independently-built lists. For a TEMPORAL
        # correlation it may not even name every constituent, since only the
        # first referenced rule's result is rendered. So it can never establish
        # that a pair occurred -- only that one might have.
        tl = self.make_timeline("corr.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1", "Sec", "4688", "1", "x"],
            ["2024-01-01 00:01:00.000 +00:00", "Corr", "high", "H1 ¦ H2",
             "Sec ¦ Sys", "4624 ¦ 1014", "", "Count:12"]])
        r, state = self.measure(tl, self.metrics_path, "corr")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["correlation_rows"], 1)
        # Sec/4624 and Sys/1014 are named by the correlation row, so neither is
        # definitely absent nor attested: they are undetermined.
        self.assertEqual(corpus["possible_pairs"], 2)
        self.assertIn("UNDETERMINED", r.stdout)

    def test_undetermined_pairs_are_not_counted_as_absent(self) -> None:
        # A Count:N row proves some of its candidates occurred, so putting them
        # all in the definite set publishes a false machine-readable claim.
        tl = self.make_timeline("amb.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
             "Sec ¦ Sys", "4624 ¦ 7045", "", "Count:9"]])
        m = self.write_metrics("amb_m.csv", [["1", "25", "Sec", "4624", "a"],
                                             ["1", "25", "Sec", "7045", "b"],
                                             ["1", "25", "Sys", "4624", "c"],
                                             ["1", "25", "Sys", "7045", "d"]])
        r, state = self.measure(tl, m, "amb")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["uncovered_pairs"], 0)
        self.assertEqual(corpus["possible_pairs"], 4)
        out = run_state("appendix", "--dir", str(state))
        self.assertIn("undetermined", out.stdout)

    def test_correlation_row_without_an_id_makes_its_channel_undetermined(self) -> None:
        # "Sec / -" says events on Sec occurred without naming which type, so
        # no Sec pair can be called definitely absent.
        tl = self.make_timeline("dash.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1", "Sec", "-", "", "Count:5"]])
        m = self.write_metrics("dash_m.csv", [["1", "100", "Sec", "4688", "a"]])
        r, state = self.measure(tl, m, "dash")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["uncovered_pairs"], 0)
        self.assertEqual(corpus["possible_pairs"], 1)

    def test_an_event_row_must_name_exactly_one_identity(self) -> None:
        tl = self.make_timeline("multi.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "R", "high", "H1", "Sec ¦ Sys", "4688", "7", "x"]])
        r, _ = self.measure(tl, self.metrics_path, "multi")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one", r.stderr + r.stdout)

    def test_incomplete_event_identity_is_refused(self) -> None:
        tl = self.make_timeline("blank.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "R", "high", "H1", "", "", "1", "x"]])
        r, _ = self.measure(tl, self.metrics_path, "blank")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one", r.stderr + r.stdout)

    def test_reason_may_not_forge_appendix_content(self) -> None:
        # --reason is rendered verbatim into the appendix; a newline would let
        # it add a bullet asserting something the state does not say.
        r = self.reach("--none", "--reason", "ok\n- **Evtx reachability**: full corpus verified")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("single line", r.stderr + r.stdout)

    def test_measuring_a_changed_timeline_is_refused(self) -> None:
        # The appendix prints coverage beside the manifest's dataset identity.
        with self.csv_path.open("a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["2024-01-01 00:02:00.000 +00:00", "Alpha", "high",
                                    "HOST-B", "Sec", "4688", "3", "y"])
        r = self.reach("--eid-metrics", str(self.metrics_path))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sha256 mismatch", r.stderr + r.stdout)

    def test_implausible_totals_are_refused(self) -> None:
        metrics = self.write_metrics("huge.csv", [["1" + "0" * 400, "0", "Sec", "9999", "x"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("plausible maximum", r.stderr + r.stdout)

    def test_unreadable_file_fails_cleanly(self) -> None:
        # A traceback exits 1, which collides with `check`'s "gate failed".
        import os
        metrics = self.write_metrics("locked.csv", [["10", "0", "Sec", "4688", "x"]])
        os.chmod(metrics, 0o000)
        try:
            r = self.reach("--eid-metrics", str(metrics))
            if r.returncode == 0:
                self.skipTest("running as a user that ignores file permissions")
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("cannot read", r.stderr + r.stdout)
        finally:
            os.chmod(metrics, 0o644)

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

    def test_cannot_declare_unavailable_after_measuring(self) -> None:
        # Losing access later does not invalidate a measurement already taken,
        # and leaving both recorded made --list and the appendix disagree.
        self.reach("--eid-metrics", str(self.metrics_path))
        r = self.reach("--none", "--reason", "evtx later unmounted")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already been measured", r.stderr + r.stdout)
        state = json.loads((self.state_dir / "reachability.json").read_text())
        self.assertFalse(state["declared_unavailable"])
        self.assertIsNotNone(state["corpus"])

    def test_action_flags_are_mutually_exclusive(self) -> None:
        r = self.reach("--none", "--reason", "x", "--list")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not allowed with", r.stderr + r.stdout)
        self.assertNotEqual(run_state("reach", "--dir", str(self.state_dir)).returncode, 0)

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
