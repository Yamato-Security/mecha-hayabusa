"""Evtx-to-timeline identity representation and its uncertainty bounds.

A Hayabusa timeline is a rule-output artifact rather than a copy of every
source event.  These tests measure which `(channel, event id)` identities are
literally represented in its output fields, preserve ambiguous correlation
mappings as a range, and pin the guards that prevent a false exact figure.
"""

from __future__ import annotations

import csv
import json
import os
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
# appear in the timeline; Sys/1014 and Shell-Core/9707 do not.
EID_METRICS = [
    ["Total", "%", "Channel", "ID", "Event"],
    ["9000", "60.0%", "Sys", "1014", "DNS resolution timeout"],
    ["4000", "26.7%", "Sec", "4688", "Process creation"],
    ["1500", "10.0%", "MS-Win-Shell-Core/Op", "9707", "Shell command"],
    ["500", "3.3%", "Sec", "4624", "Logon"],
]


def run_state(*argv: str, stdin_data: str | None = None,
              env_overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = None
    if env_overrides:
        env = os.environ.copy()
        env.update(env_overrides)
    return subprocess.run([sys.executable, str(STATE_PY), *argv],
                          input=stdin_data, capture_output=True, text=True, env=env)


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
        self.assertEqual(corpus["represented_pairs"], 2)
        # Sys/1014 (9000) and Shell-Core/9707 (1500) are absent from the timeline.
        self.assertEqual(corpus["definite_absent_pairs"], 2)
        self.assertEqual(corpus["definite_absent_events"], 10500)
        self.assertEqual(corpus["definite_absent"][0]["channel"], "Sys")

    def test_metric_uses_corpus_events_on_both_sides(self) -> None:
        # Rows/events would double-count (one row per event x matching rule) and
        # could exceed 100%; corpus/corpus cannot.
        self.reach("--eid-metrics", str(self.metrics_path))
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["absent_pct_lower"], 70.0)
        self.assertLessEqual(corpus["absent_pct_lower"], 100.0)

    def test_channel_case_differences_are_not_gaps(self) -> None:
        # hayabusa spells the same channel differently across subcommands
        # (MS-Win-appxDeploySvr vs MS-Win-AppXDeploySvr); that is not a gap.
        metrics = self.write_metrics("cased.csv", [["100", "50.0%", "SEC", "4688", "x"],
                                                   ["100", "50.0%", "sec", "4624", "y"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["definite_absent_pairs"], 0)

    def test_original_channel_spelling_is_preserved_for_display(self) -> None:
        self.reach("--eid-metrics", str(self.metrics_path))
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertIn("MS-Win-Shell-Core/Op",
                      [e["channel"] for e in corpus["definite_absent"]])

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
        self.assertEqual(corpus["definite_absent_pairs"], 2)  # only Sys/1014 and Shell-Core

    def test_duplicate_metrics_pairs_are_refused(self) -> None:
        m = self.write_metrics("dupe.csv", [["1", "50.0%", "Sec", "4688", "a"],
                                            ["1", "50.0%", "SEC", "4688", "b"]])
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
        m = self.write_metrics("comma.csv", [["1,2", "100.0%", "Sec", "4688", "a"]])
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
        metrics = self.write_metrics("partial.csv", [["100", "50.0%", "Sec", "4688", "x"],
                                                     ["100", "50.0%", "Other", "1", "y"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("absent from", r.stderr + r.stdout)

    def test_channel_representation_mismatch_is_explained(self) -> None:
        metrics = self.write_metrics("full.csv", [["100", "50.0%", "Security", "4688", "x"],
                                                  ["100", "50.0%", "Security", "4624", "y"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("channel representations", r.stderr + r.stdout)

    def test_timeline_without_channel_or_eventid_is_refused(self) -> None:
        # Otherwise every pair looks absent and a false 100% gap is recorded
        # from a CSV that simply has different columns.
        bad = self.state_dir.parent / "nochan.csv"
        with bad.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "RuleTitle", "Level", "Computer", "RecordID", "Details"])
            w.writerow(["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "1", "x"])
        state2 = self.state_dir.parent / "state2"
        self.assertEqual(run_state("init", "--csv", str(bad), "--dir", str(state2)).returncode, 0)
        r = run_state("reach", "--dir", str(state2), "--eid-metrics", str(self.metrics_path))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("missing column(s) needed to compare coverage", r.stderr + r.stdout)

    def test_malformed_metrics_rows_are_rejected_not_skipped(self) -> None:
        for label, rows in [
            ("non-integer", [["abc", "0.0%", "Sec", "4688", "x"]]),
            ("negative", [["-50", "0.0%", "Sec", "4688", "x"]]),
            ("blank channel", [["10", "0.0%", "", "4688", "x"]]),
            ("blank id", [["10", "0.0%", "Sec", "", "x"]]),
            ("header only", []),
        ]:
            with self.subTest(label):
                metrics = self.write_metrics(f"bad_{label.replace(' ', '_')}.csv", rows)
                r = self.reach("--eid-metrics", str(metrics))
                self.assertNotEqual(r.returncode, 0, f"accepted {label}")

    def test_percentage_cannot_exceed_100(self) -> None:
        # Negative totals previously produced 150%. The bound is now a property
        # of the code rather than an assumption about the input.
        metrics = self.write_metrics("negs.csv", [["-50", "0.0%", "Sec", "4688", "a"],
                                                  ["-50", "0.0%", "Sec", "4624", "b"],
                                                  ["200", "100.0%", "Sys", "1014", "c"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.state_dir / "reachability.json").exists())

    def test_every_absent_pair_is_persisted(self) -> None:
        rows = [["100", "22.2%", "Sec", "4688", "x"],
                ["100", "22.2%", "Sec", "4624", "y"]]
        rows += [["1", "0.2%", "Chan%d" % i, str(i), "z"] for i in range(250)]
        metrics = self.write_metrics("many.csv", rows)
        self.assertEqual(self.reach("--eid-metrics", str(metrics)).returncode, 0)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["definite_absent_pairs"], 250)
        self.assertEqual(len(corpus["definite_absent"]), 250)
        out = self.reach("--list")
        self.assertIn("240 more", out.stdout)

    def test_ambiguous_correlation_candidates_are_not_attested(self) -> None:
        # A multi-by-multi correlation whose corpus graph has several edges per
        # displayed value cannot establish which candidate pairs occurred.
        tl = self.make_timeline("corr.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1", "Sec", "4688", "1", "x"],
            ["2024-01-01 00:01:00.000 +00:00", "Corr", "high", "H1 ¦ H2",
             "Sec ¦ Sys", "4624 ¦ 1014", "", "Count:12"]])
        metrics = self.write_metrics("corr_m.csv", [
            ["1", "20.0%", "Sec", "4688", "event row"],
            ["1", "20.0%", "Sec", "4624", "candidate"],
            ["1", "20.0%", "Sec", "1014", "candidate"],
            ["1", "20.0%", "Sys", "4624", "candidate"],
            ["1", "20.0%", "Sys", "1014", "candidate"],
        ])
        r, state = self.measure(tl, metrics, "corr")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["correlation_rows"], 1)
        self.assertEqual(corpus["recordid_pairs"], 1)
        self.assertEqual(corpus["correlation_forced_pairs"], 0)
        self.assertEqual(corpus["ambiguous_correlation_rows"], 1)
        self.assertEqual(corpus["undetermined_pairs"], 4)
        self.assertIn("undetermined", r.stdout.casefold())

    def test_undetermined_pairs_are_not_counted_as_absent(self) -> None:
        # A Count:N row proves some of its candidates occurred, so putting them
        # all in the definite set publishes a false machine-readable claim.
        tl = self.make_timeline("amb.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
             "Sec ¦ Sys", "4624 ¦ 7045", "", "Count:9"]])
        m = self.write_metrics("amb_m.csv", [["1", "25.0%", "Sec", "4624", "a"],
                                             ["1", "25.0%", "Sec", "7045", "b"],
                                             ["1", "25.0%", "Sys", "4624", "c"],
                                             ["1", "25.0%", "Sys", "7045", "d"]])
        r, state = self.measure(tl, m, "amb")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["definite_absent_pairs"], 0)
        self.assertEqual(corpus["undetermined_pairs"], 4)
        self.assertIn("ambiguous", r.stdout.casefold())
        self.assertIn("undetermined", r.stdout.casefold())
        out = run_state("appendix", "--dir", str(state))
        self.assertIn("undetermined", out.stdout)

    def test_correlation_row_without_an_id_makes_its_channel_undetermined(self) -> None:
        # "Sec / -" says events on Sec occurred without naming which type, so
        # no Sec pair can be called definitely absent.
        tl = self.make_timeline("dash.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1", "Sec", "-", "", "Count:5"]])
        m = self.write_metrics("dash_m.csv", [["1", "100.0%", "Sec", "4688", "a"]])
        r, state = self.measure(tl, m, "dash")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["definite_absent_pairs"], 0)
        self.assertEqual(corpus["undetermined_pairs"], 1)

    def test_missing_id_channel_outside_metrics_is_not_a_corpus_mismatch(self) -> None:
        # eid-metrics omits records with no EventID. A channel displayed only
        # by such a record therefore need not occur in its pair corpus.
        tl = self.make_timeline("missing_id_channel.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
            "Rare", "-", "", "Count:1",
        ]])
        m = self.write_metrics("missing_id_channel_m.csv", [
            ["1", "100.0%", "Sys", "1", "other event"],
        ])
        r, state = self.measure(tl, m, "missing_id_channel")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 0)
        self.assertEqual(corpus["undetermined_pairs"], 0)
        self.assertEqual(corpus["definite_absent_pairs"], 1)

    def test_missing_id_component_does_not_require_its_channel_in_metrics(self) -> None:
        # The leading empty components describe one no-ID/no-channel base
        # record, while the concrete Sec/4688 projection remains forced.
        tl = self.make_timeline("mixed_missing_id.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
            "¦ Sec", "¦ 4688", "", "Count:2",
        ]])
        m = self.write_metrics("mixed_missing_id_m.csv", [
            ["1", "50.0%", "Sec", "4688", "process creation"],
            ["1", "50.0%", "Sys", "1", "other event"],
        ])
        r, state = self.measure(tl, m, "mixed_missing_id")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 1)
        self.assertEqual(corpus["undetermined_pairs"], 0)
        self.assertEqual(corpus["definite_absent_pairs"], 1)

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
        metrics = self.write_metrics("huge.csv", [["1" + "0" * 400, "100.0%", "Sec", "9999", "x"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("plausible maximum", r.stderr + r.stdout)

    def test_unreadable_file_fails_cleanly(self) -> None:
        # A traceback exits 1, which collides with `check`'s "gate failed".
        metrics = self.write_metrics("locked.csv", [["10", "100.0%", "Sec", "4688", "x"]])
        os.chmod(metrics, 0o000)
        try:
            r = self.reach("--eid-metrics", str(metrics))
            if r.returncode == 0:
                self.skipTest("running as a user that ignores file permissions")
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("cannot", r.stderr + r.stdout)
            self.assertIn("eid-metrics CSV", r.stderr + r.stdout)
        finally:
            os.chmod(metrics, 0o644)

    def test_timeline_without_recordid_is_refused(self) -> None:
        # RecordID is what separates a real event from a correlation summary,
        # so without it every row would be taken as attested.
        bad = self.state_dir.parent / "norec.csv"
        with bad.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "Details"])
            w.writerow(["2024-01-01 00:00:00.000 +00:00", "R", "high", "H1", "Sec", "4688", "x"])
        state2 = self.state_dir.parent / "norec_state"
        self.assertEqual(run_state("init", "--csv", str(bad), "--dir", str(state2)).returncode, 0)
        r = run_state("reach", "--dir", str(state2), "--eid-metrics", str(self.metrics_path))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("RecordID", r.stderr + r.stdout)

    def test_singleton_channel_determines_every_pair_it_names(self) -> None:
        # The displayed sets come from real base records, so one channel with
        # several ids fixes each pair; calling them undetermined would widen an
        # exact 0% to 0%-100% for no reason.
        tl = self.make_timeline("single.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1", "Sec", "4688 ¦ 4624", "", "Count:9"]])
        m = self.write_metrics("single_m.csv", [["1", "50.0%", "Sec", "4688", "a"],
                                                ["1", "50.0%", "Sec", "4624", "b"]])
        r, state = self.measure(tl, m, "single")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["definite_absent_pairs"], 0)
        self.assertEqual(corpus["undetermined_pairs"], 0)
        self.assertIn("resolved", r.stdout.casefold())
        self.assertNotIn("cannot attest a pair", r.stdout.casefold())
        self.assertNotIn("undetermined", r.stdout.casefold())

    def test_correlation_channel_absent_from_metrics_is_refused(self) -> None:
        # "System" vs "Sys": the candidate would silently miss and the pair
        # would be reported as definitely absent.
        tl = self.make_timeline("spell.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "R", "high", "H1", "Sec", "4688", "7", "x"],
            ["2024-01-01 00:01:00.000 +00:00", "Corr", "high", "H1", "System", "7045", "", "Count:3"]])
        m = self.write_metrics("spell_m.csv", [["1", "50.0%", "Sec", "4688", "a"],
                                               ["1", "50.0%", "Sys", "7045", "b"]])
        r, _ = self.measure(tl, m, "spell")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("channel representation", (r.stderr + r.stdout).casefold())

    def test_ambiguous_correlation_id_absent_from_metrics_is_refused(self) -> None:
        # Every value rendered by a correlation comes from a base record. An ID
        # missing from eid-metrics therefore proves that the files cannot cover
        # the same corpus; silently dropping it narrows the uncertainty range.
        tl = self.make_timeline("missing_id.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
             "Sec ¦ Sys", "4688 ¦ 9999", "", "Count:3"]])
        m = self.write_metrics("missing_id_m.csv", [
            ["1", "50.0%", "Sec", "4688", "a"],
            ["1", "50.0%", "Sys", "1014", "b"],
        ])
        r, state = self.measure(tl, m, "missing_id")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("9999", r.stderr + r.stdout)
        self.assertFalse((state / "reachability.json").exists())

    def test_id_only_correlation_value_absent_from_metrics_is_refused(self) -> None:
        # The channel may be unavailable on an aggregate row, but its advertised
        # event IDs must still occur somewhere in the same-corpus metrics.
        tl = self.make_timeline("id_only_bad.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
             "", "9999", "", "Count:3"]])
        m = self.write_metrics("id_only_bad_m.csv", [
            ["1", "100.0%", "-", "4688", "a"],
        ])
        r, state = self.measure(tl, m, "id_only_bad")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("9999", r.stderr + r.stdout)
        self.assertFalse((state / "reachability.json").exists())

    def test_each_correlation_group_must_project_onto_the_corpus(self) -> None:
        # Global channel/ID membership is insufficient: values from a different
        # correlation row must not cross-satisfy this row's candidate graph.
        tl = self.make_timeline("per_group.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr-A", "high", "H1",
             "Sec ¦ Sys", "4624 ¦ 7045", "", "Count:3"],
            ["2024-01-01 00:01:00.000 +00:00", "Corr-B", "high", "H1",
             "Other ¦ App", "1 ¦ 2", "", "Count:3"],
        ])
        # All four channels and IDs exist globally, but every edge crosses from
        # one correlation group into the other; neither row has a corpus edge.
        m = self.write_metrics("per_group_m.csv", [
            ["1", "25.0%", "Sec", "1", "a"],
            ["1", "25.0%", "Sys", "2", "b"],
            ["1", "25.0%", "Other", "4624", "c"],
            ["1", "25.0%", "App", "7045", "d"],
        ])
        r, state = self.measure(tl, m, "per_group")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((state / "reachability.json").exists())

    def test_sparse_corpus_forces_a_multi_by_multi_mapping(self) -> None:
        # Although both displayed dimensions have several values, the corpus
        # graph has one edge incident to every vertex, so the mapping is exact.
        tl = self.make_timeline("forced_sparse.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
             "Sec ¦ Sys", "4624 ¦ 7045", "", "Count:3"]])
        m = self.write_metrics("forced_sparse_m.csv", [
            ["1", "50.0%", "Sec", "4624", "a"],
            ["1", "50.0%", "Sys", "7045", "b"],
        ])
        r, state = self.measure(tl, m, "forced_sparse")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 2)
        self.assertEqual(corpus["undetermined_pairs"], 0)
        self.assertEqual(corpus["definite_absent_pairs"], 0)
        self.assertEqual(corpus["absent_pct_lower"], corpus["absent_pct_upper"])

    def test_row_ambiguity_is_not_erased_by_other_correlation_rows(self) -> None:
        # Other rows can establish every optional pair globally without making
        # this row's independent channel/ID pairing any less ambiguous.
        tl = self.make_timeline("row_local_ambiguity.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Ambiguous", "high", "H1",
             "A ¦ B", "1 ¦ 2", "", "Count:4"],
            ["2024-01-01 00:01:00.000 +00:00", "A pairs", "high", "H1",
             "A", "1 ¦ 2", "", "Count:2"],
            ["2024-01-01 00:02:00.000 +00:00", "B pairs", "high", "H1",
             "B", "1 ¦ 2", "", "Count:2"],
        ])
        m = self.write_metrics("row_local_ambiguity_m.csv", [
            ["1", "25.0%", "A", "1", "a1"],
            ["1", "25.0%", "A", "2", "a2"],
            ["1", "25.0%", "B", "1", "b1"],
            ["1", "25.0%", "B", "2", "b2"],
        ])
        r, state = self.measure(tl, m, "row_local_ambiguity")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 4)
        self.assertEqual(corpus["undetermined_pairs"], 0)
        self.assertEqual(corpus["resolved_correlation_rows"], 2)
        self.assertEqual(corpus["ambiguous_correlation_rows"], 1)

    def test_missing_channel_component_parses_in_every_output_mode(self) -> None:
        # A missing channel is an empty joined component, represented as '-' by
        # eid-metrics. Default, -M and -S vary both whitespace and separator.
        cases = (
            ("broken_bar", "¦ Sec", "1014 ¦ 4688"),
            ("spaced_broken_bar", " ¦ Sec", "1014 ¦ 4688"),
            ("crlf", "\r\nSec", "1014\r\n4688"),
            ("lf", "\nSec", "1014\n4688"),
            ("tab", "\tSec", "1014\t4688"),
        )
        for label, channel_value, event_id_value in cases:
            with self.subTest(label):
                tl = self.make_timeline(f"missing_channel_{label}.csv", [
                    ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
                     channel_value, event_id_value, "", "Count:3"]])
                m = self.write_metrics(f"missing_channel_{label}_m.csv", [
                    ["1", "50.0%", "-", "1014", "unknown channel"],
                    ["1", "50.0%", "Sec", "4688", "process creation"],
                ])
                r, state = self.measure(tl, m, f"missing_channel_{label}")
                self.assertEqual(r.returncode, 0, r.stderr)
                corpus = json.loads((state / "reachability.json").read_text())["corpus"]
                self.assertEqual(corpus["represented_pairs"], 2)
                self.assertEqual(corpus["correlation_forced_pairs"], 2)
                self.assertEqual(corpus["resolved_correlation_rows"], 1)
                self.assertEqual(corpus["ambiguous_correlation_rows"], 0)
                self.assertEqual(corpus["undetermined_pairs"], 0)
                self.assertEqual(corpus["definite_absent_pairs"], 0)
                self.assertEqual((corpus["absent_pct_lower"],
                                  corpus["absent_pct_upper"]), (0.0, 0.0))

    def test_correlation_row_naming_nothing_is_refused(self) -> None:
        tl = self.make_timeline("nada.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1", "", "-", "", "Count:3"]])
        r, _ = self.measure(tl, self.metrics_path, "nada")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("neither a comparable channel nor eventid",
                      (r.stderr + r.stdout).casefold())

    def test_malformed_timeline_quoting_is_refused(self) -> None:
        # An unterminated quote swallowed a real event row and turned it into a
        # false 100% gap.
        bad = self.state_dir.parent / "quote.csv"
        bad.write_text(
            ",".join(CSV_HEADER) + "\n"
            '2024-01-01 00:00:00.000 +00:00,R,high,H1,"Sec,4688,7,x\n',
            encoding="utf-8")
        state2 = self.state_dir.parent / "quote_state"
        run_state("init", "--csv", str(bad), "--dir", str(state2))
        r = run_state("reach", "--dir", str(state2), "--eid-metrics", str(self.metrics_path))
        self.assertNotEqual(r.returncode, 0)

    def test_duplicate_required_timeline_headers_are_refused(self) -> None:
        # DictReader silently keeps the final value of a duplicate name. Even
        # identical values are ambiguous input and must not pass schema checks.
        for field in ("Channel", "EventID", "RecordID"):
            with self.subTest(field):
                index = CSV_HEADER.index(field)
                duplicate = self.state_dir.parent / f"duplicate_{field}.csv"
                with duplicate.open("w", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerows([
                        [*CSV_HEADER, field],
                        [*CSV_ROWS[0], CSV_ROWS[0][index]],
                ])
                state = self.state_dir.parent / f"duplicate_{field}_state"
                initialized = run_state("init", "--csv", str(duplicate), "--dir", str(state))
                if initialized.returncode != 0:
                    self.assertIn("duplicate",
                                  (initialized.stderr + initialized.stdout).casefold())
                    continue
                metrics = self.write_metrics(f"duplicate_{field}_m.csv", [
                    ["1", "100.0%", "Sec", "4688", "x"],
                ])
                r = run_state("reach", "--dir", str(state),
                              "--eid-metrics", str(metrics))
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("duplicate", (r.stderr + r.stdout).casefold())
                self.assertFalse((state / "reachability.json").exists())

    def test_shifted_padded_metrics_row_is_rejected_atomically(self) -> None:
        # Hayabusa emits percentages as one-decimal strings with a percent sign.
        # A four-logical-field row padded to five columns used to shift Sys into
        # %, then accept 1014/DNS timeout as a fabricated channel/ID pair.
        first = self.reach("--eid-metrics", str(self.metrics_path))
        self.assertEqual(first.returncode, 0, first.stderr)
        state_path = self.state_dir / "reachability.json"
        before = state_path.read_bytes()

        malformed = self.state_dir.parent / "shifted-padded.csv"
        malformed.write_text(
            "Total,%,Channel,ID,Event\n"
            "1,1.0%,Sec,4688,Process creation\n"
            "1,1.0%,Sec,4624,Logon\n"
            "100,98.0%,1014,DNS timeout,\n",
            encoding="utf-8")
        r = self.reach("--eid-metrics", str(malformed))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("event", (r.stderr + r.stdout).casefold())
        self.assertEqual(state_path.read_bytes(), before)

    def test_undetermined_pair_order_is_stable_when_counts_tie(self) -> None:
        # Set iteration is hash-seed dependent. Persist a canonical channel/ID
        # tie-break so identical evidence produces the same machine-readable list.
        channels = ("Alpha", "Beta", "Gamma")
        event_ids = ("1", "2", "3")
        tl = self.make_timeline("stable_undetermined.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
            " ¦ ".join(channels), " ¦ ".join(event_ids), "", "Count:9",
        ]])
        m = self.write_metrics("stable_undetermined_m.csv", [
            ["1", "11.1%", channel, event_id, "x"]
            for channel in reversed(channels) for event_id in reversed(event_ids)
        ])
        expected = [(channel, event_id)
                    for channel in channels for event_id in event_ids]

        for seed in ("1", "2", "3", "4"):
            with self.subTest(seed=seed):
                state = self.state_dir.parent / f"stable_undetermined_{seed}"
                initialized = run_state("init", "--csv", str(tl), "--dir", str(state))
                self.assertEqual(initialized.returncode, 0, initialized.stderr)
                r = run_state("reach", "--dir", str(state), "--eid-metrics", str(m),
                              env_overrides={"PYTHONHASHSEED": seed})
                self.assertEqual(r.returncode, 0, r.stderr)
                corpus = json.loads((state / "reachability.json").read_text())["corpus"]
                actual = [(e["channel"], e["event_id"])
                          for e in corpus["undetermined"]]
                self.assertEqual(actual, expected)

    def test_undetermined_range_is_identical_everywhere(self) -> None:
        # import, --list and the appendix must state the same bounds.
        tl = self.make_timeline("rng.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
             "Sec ¦ Sys", "4624 ¦ 7045", "", "Count:9"]])
        m = self.write_metrics("rng_m.csv", [["1", "25.0%", "Sec", "4624", "a"],
                                             ["1", "25.0%", "Sec", "7045", "b"],
                                             ["1", "25.0%", "Sys", "4624", "c"],
                                             ["1", "25.0%", "Sys", "7045", "d"]])
        r, state = self.measure(tl, m, "rng")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        low, high = corpus["absent_pct_lower"], corpus["absent_pct_upper"]
        self.assertEqual((low, high), (0.0, 100.0))
        self.assertEqual(len(corpus["undetermined"]), 4)
        self.assertIn(f"between {low}% and {high}%", r.stdout)
        listed = run_state("reach", "--dir", str(state), "--list")
        self.assertIn(f"{low}% – {high}%", listed.stdout)
        appendix = run_state("appendix", "--dir", str(state))
        self.assertIn(f"between {low}% and {high}%", appendix.stdout)

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

    def test_reason_is_rejected_without_none(self) -> None:
        for action in (("--list",), ("--eid-metrics", str(self.metrics_path))):
            with self.subTest(action=action[0]):
                r = self.reach(*action, "--reason", "ignored")
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("only valid", r.stderr + r.stdout)

    # -- reporting -------------------------------------------------------

    def test_appendix_states_reachability_was_not_measured(self) -> None:
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("not measured", out.stdout)

    def test_appendix_reports_measured_coverage_with_the_filter_caveat(self) -> None:
        self.reach("--eid-metrics", str(self.metrics_path))
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(len(corpus["source_sha256"]), 64)
        self.assertEqual(len(corpus["timeline_sha256"]), 64)
        listed = self.reach("--list")
        self.assertIn(corpus["source_sha256"], listed.stdout)
        self.assertIn(corpus["timeline_sha256"], listed.stdout)
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertIn("absent from the supplied timeline", out.stdout)
        self.assertIn("filtering can inflate this gap", out.stdout)
        self.assertIn(corpus["source_sha256"][:16], out.stdout)

    def test_appendix_reports_an_unavailable_corpus(self) -> None:
        self.reach("--none", "--reason", "only the CSV was provided")
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertIn("only the CSV was provided", out.stdout)

    def test_legacy_reachability_state_is_reported_without_a_traceback(self) -> None:
        # Pre-schema development builds used different field names and weaker
        # correlation semantics. Do not reinterpret that evidence or crash.
        legacy = {
            "corpus": {
                "source_path": str(self.metrics_path),
                "corpus_events": 15000,
                "corpus_pairs": 4,
                "timeline_rows": 2,
                "timeline_pairs": 2,
                "unreachable_pct": 70.0,
                "uncovered_pairs": 2,
                "uncovered_events": 10500,
                "uncovered": [],
                "possible_pairs": 0,
                "possible_events": 0,
                "possible": [],
            },
            "declared_unavailable": False,
            "unavailable_reason": "",
        }
        (self.state_dir / "reachability.json").write_text(
            json.dumps(legacy), encoding="utf-8"
        )
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertNotIn("Traceback", listed.stderr)
        self.assertIn("obsolete", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertNotIn("Traceback", appendix.stderr)
        self.assertIn("obsolete", appendix.stdout)


if __name__ == "__main__":
    unittest.main()
