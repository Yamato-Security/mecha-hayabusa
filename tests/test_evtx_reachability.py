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
from fractions import Fraction

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

    def assertNoCorpus(self, state_dir: pathlib.Path) -> None:
        """A refused measurement must leave no corpus recorded.

        `init` seeds an empty reachability.json so a re-init cannot inherit the
        previous dataset's figure, so absence of the file is no longer the
        signal -- absence of a corpus inside it is.
        """
        path = state_dir / "reachability.json"
        if not path.exists():
            return
        self.assertIsNone(json.loads(path.read_text())["corpus"])

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

    def test_repeated_metrics_pairs_are_summed(self) -> None:
        # eid-metrics groups on the RAW channel but abbreviates when writing, so
        # channels that collapse to one displayed name (the four AppLocker
        # sub-channels, the two Security-Mitigations ones) arrive as several
        # rows sharing a displayed key. Refusing them rejects hayabusa's own
        # unedited output; the rows describe one collapsed identity and sum.
        m = self.write_metrics("dupe.csv", [["1", "10.0%", "Sec", "4688", "a"],
                                            ["4", "40.0%", "SEC", "4688", "b"],
                                            ["5", "50.0%", "Sec", "4624", "c"]])
        r = self.reach("--eid-metrics", str(m))
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["corpus_pairs"], 2)
        self.assertEqual(corpus["corpus_events"], 10)
        # Sec/4688 is in the timeline, so the summed pair counts as represented.
        self.assertEqual(corpus["represented_pairs"], 2)
        self.assertEqual(corpus["definite_absent_events"], 0)

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
        self.assertNoCorpus(self.state_dir)

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

    def test_omitted_aggregate_id_does_not_make_its_channel_a_wildcard(self) -> None:
        # A blank aggregate component denotes an omitted projection, not an
        # arbitrary concrete ID on that channel.
        tl = self.make_timeline("dash.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1", "Sec", "", "", "Count:5"]])
        m = self.write_metrics("dash_m.csv", [["1", "100.0%", "Sec", "4688", "a"]])
        r, state = self.measure(tl, m, "dash")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["definite_absent_pairs"], 1)
        self.assertEqual(corpus["undetermined_pairs"], 0)

    def test_missing_id_channel_outside_metrics_is_not_a_corpus_mismatch(self) -> None:
        # eid-metrics omits records with no EventID. A channel displayed only
        # by such a record therefore need not occur in its pair corpus.
        tl = self.make_timeline("missing_id_channel.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
            "Rare", "", "", "Count:1",
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
            ["7", "70.0%", "Sec", "4688", "process creation"],
            ["2", "20.0%", "Sec", "4624", "different Sec identity"],
            ["1", "10.0%", "Sys", "1", "other event"],
        ])
        r, state = self.measure(tl, m, "mixed_missing_id")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 1)
        self.assertEqual(corpus["undetermined_pairs"], 0)
        self.assertEqual(corpus["definite_absent_pairs"], 2)
        self.assertEqual(corpus["definite_absent_events"], 3)

    def test_an_event_row_must_name_exactly_one_identity(self) -> None:
        tl = self.make_timeline("multi.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "R", "high", "H1", "Sec ¦ Sys", "4688", "7", "x"]])
        r, _ = self.measure(tl, self.metrics_path, "multi")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one", r.stderr + r.stdout)

    def test_blank_direct_identity_maps_to_dash_channel_and_null_id(self) -> None:
        # With a RecordID, blank display values are the concrete corpus identity
        # used by the exporters: missing channel '-' plus EventID 'null'.
        tl = self.make_timeline("blank.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "R", "high", "H1", "", "", "1", "x"]])
        m = self.write_metrics("blank_m.csv", [["7", "70.0%", "-", "null", "blank identity"],
                                                ["3", "30.0%", "Sys", "1", "other"]])
        r, state = self.measure(tl, m, "blank")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["recordid_pairs"], 1)
        self.assertEqual(corpus["represented_events"], 7)
        self.assertEqual(corpus["definite_absent_events"], 3)
        self.assertEqual(corpus["undetermined_pairs"], 0)

    def test_a_blank_event_id_does_not_abort_the_measurement(self) -> None:
        # Direct timeline output renders null/missing EventID as blank while
        # eid-metrics uses the concrete key "null". It cannot be an unrelated
        # concrete ID on the same channel.
        tl = self.make_timeline("openid.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1", "Sec", "", "1", "x"],
            ["2024-01-01 00:01:00.000 +00:00", "Beta", "high", "H1", "Other", "1", "2", "y"]])
        m = self.write_metrics("openid_m.csv", [["10", "10.0%", "Sec", "null", "null id"],
                                                ["80", "80.0%", "Sec", "4688", "process"],
                                                ["10", "10.0%", "Other", "1", "other"]])
        r, state = self.measure(tl, m, "openid")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 2)
        self.assertEqual(corpus["represented_events"], 20)
        self.assertEqual(corpus["undetermined_pairs"], 0)
        self.assertEqual(
            sorted((e["channel"], e["event_id"]) for e in corpus["definite_absent"]),
            [("Sec", "4688")])
        self.assertEqual(corpus["definite_absent_events"], 80)
        # The row carries a RecordID, so it is not counted as a correlation row.
        self.assertEqual(corpus["correlation_rows"], 0)

    def test_literal_dash_event_id_is_concrete(self) -> None:
        tl = self.make_timeline("dash_direct.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1",
            "Sec", "-", "1", "x",
        ]])
        m = self.write_metrics("dash_direct_m.csv", [
            ["7", "70.0%", "Sec", "-", "literal dash"],
            ["3", "30.0%", "Sys", "1", "other"],
        ])
        r, state = self.measure(tl, m, "dash_direct")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["recordid_pairs"], 1)
        self.assertEqual(corpus["represented_events"], 7)
        self.assertEqual(corpus["definite_absent_events"], 3)

    def test_literal_dash_event_id_is_concrete_on_an_aggregate(self) -> None:
        tl = self.make_timeline("dash_aggregate.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Corr", "high", "H1",
            "Sec", "-", "", "Count:1",
        ]])
        m = self.write_metrics("dash_aggregate_m.csv", [
            ["7", "70.0%", "Sec", "-", "literal dash"],
            ["3", "30.0%", "Sys", "1", "other"],
        ])
        r, state = self.measure(tl, m, "dash_aggregate")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["correlation_rows"], 1)
        self.assertEqual(corpus["correlation_forced_pairs"], 1)
        self.assertEqual(corpus["represented_events"], 7)
        self.assertEqual(corpus["definite_absent_events"], 3)

    def test_empty_metrics_channel_is_compared_as_missing(self) -> None:
        # metrics.rs writes "-" only when the Channel KEY is absent; a present
        # but empty value reaches the CSV as an empty cell. The timeline side
        # already normalises its blank channel to "-", so the two must meet.
        tl = self.make_timeline("nochan.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1", "", "4688", "1", "x"]])
        m = self.write_metrics("nochan_m.csv", [["7", "70.0%", "", "4688", "a"],
                                                ["3", "30.0%", "Sys", "1014", "b"]])
        r, state = self.measure(tl, m, "nochan")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 1)
        self.assertEqual(corpus["definite_absent_events"], 3)

    def test_event_id_case_is_folded_like_the_channel(self) -> None:
        # metrics.rs lowercases BOTH halves of its key; the timeline prints the
        # value as recorded. A non-numeric id must not read as two identities.
        tl = self.make_timeline("hexid.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1", "Sec", "0xC0FE", "1", "x"]])
        m = self.write_metrics("hexid_m.csv", [["8", "80.0%", "Sec", "0xc0fe", "a"],
                                               ["2", "20.0%", "Sys", "1014", "b"]])
        r, state = self.measure(tl, m, "hexid")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 1)
        self.assertEqual(corpus["definite_absent_events"], 2)
        # The corpus spelling is what gets displayed, not the folded key.
        self.assertEqual([(e["channel"], e["event_id"]) for e in corpus["definite_absent"]],
                         [("Sys", "1014")])

    def test_normalization_matches_rust_lowercase_not_unicode_casefold(self) -> None:
        # Rust to_lowercase keeps these exporter keys distinct; Python casefold
        # would merge both into "ss" and erase the 90-event gap.
        tl = self.make_timeline("unicode_lower.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1",
            "SS", "1", "1", "x",
        ]])
        m = self.write_metrics("unicode_lower_m.csv", [
            ["90", "90.0%", "ß", "1", "eszett channel"],
            ["10", "10.0%", "ss", "1", "ascii channel"],
        ])
        r, state = self.measure(tl, m, "unicode_lower")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["corpus_pairs"], 2)
        self.assertEqual(corpus["represented_events"], 10)
        self.assertEqual(corpus["definite_absent_events"], 90)
        self.assertEqual([(e["channel"], e["event_id"])
                          for e in corpus["definite_absent"]], [("ß", "1")])

    def test_a_tiny_gap_does_not_round_away_to_zero(self) -> None:
        # 1 absent event in 10,500,000 is 0.0000095%, which round(,2) renders as
        # "0.0% definitely absent" -- indistinguishable from full coverage.
        m = self.write_metrics("tiny.csv", [["10499998", "100.0%", "Sec", "4688", "a"],
                                            ["1", "0.0%", "Sec", "4624", "b"],
                                            ["1", "0.0%", "Sys", "1014", "c"]])
        r = self.reach("--eid-metrics", str(m))
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["definite_absent_events"], 1)
        self.assertEqual((corpus["absent_pct_lower"], corpus["absent_pct_upper"]),
                         (0.0, 0.01))
        self.assertIn("<0.01%", r.stdout)
        listed = self.reach("--list")
        self.assertIn("<0.01%", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertIn("<0.01%", appendix.stdout)

    def test_a_tiny_remnant_does_not_round_up_to_everything(self) -> None:
        # The mirror image: 1 represented event in 10,500,000 ceils to "100.0%
        # definitely absent", asserting the timeline represents nothing.
        m = self.write_metrics("huge_gap.csv", [["1", "0.0%", "Sec", "4688", "a"],
                                                ["1", "0.0%", "Sec", "4624", "b"],
                                                ["10499998", "100.0%", "Sys", "1014", "c"]])
        r = self.reach("--eid-metrics", str(m))
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["represented_pairs"], 2)
        self.assertEqual((corpus["absent_pct_lower"], corpus["absent_pct_upper"]),
                         (99.99, 100.0))
        self.assertIn(">99.99%", r.stdout)
        self.assertIn(">99.99%", self.reach("--list").stdout)
        self.assertIn(">99.99%", run_state(
            "appendix", "--dir", str(self.state_dir)).stdout)

    def test_percentage_bounds_use_integer_arithmetic_and_enclose_truth(self) -> None:
        # This rational is just below 87.18%. A float-first floor rounded it up
        # to 87.18, turning the purported lower bound into an overstatement.
        absent = 6_022_948_197_440_399
        total = 6_908_635_234_503_785
        represented = total - absent
        tl = self.make_timeline("rational.csv", [[
            "2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1",
            "Sec", "1", "1", "x",
        ]])
        m = self.write_metrics("rational_m.csv", [
            [str(represented), "12.8%", "Sec", "1", "represented"],
            [str(absent), "87.2%", "Sys", "2", "absent"],
        ])
        r, state = self.measure(tl, m, "rational")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        exact = Fraction(100 * absent, total)
        lower = Fraction(str(corpus["absent_pct_lower"]))
        upper = Fraction(str(corpus["absent_pct_upper"]))
        self.assertLessEqual(lower, exact)
        self.assertLessEqual(exact, upper)
        self.assertEqual((lower, upper), (Fraction("87.17"), Fraction("87.18")))

    def test_appendix_distinguishes_point_precision_from_ambiguity_bounds(self) -> None:
        absent = 6_022_948_197_440_399
        total = 6_908_635_234_503_785
        represented = total - absent - 4
        tl = self.make_timeline("rational_ambiguous.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1",
             "Sec", "0", "1", "x"],
            ["2024-01-01 00:01:00.000 +00:00", "Corr", "high", "H1",
             "A ¦ B", "1 ¦ 2", "", "Count:4"],
        ])
        m = self.write_metrics("rational_ambiguous_m.csv", [
            [str(represented), "12.8%", "Sec", "0", "represented"],
            [str(absent), "87.2%", "Sys", "9", "definitely absent"],
            ["1", "0.0%", "A", "1", "candidate"],
            ["1", "0.0%", "A", "2", "candidate"],
            ["1", "0.0%", "B", "1", "candidate"],
            ["1", "0.0%", "B", "2", "candidate"],
        ])
        r, state = self.measure(tl, m, "rational_ambiguous")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual((corpus["absent_pct_lower"], corpus["absent_pct_upper"]),
                         (87.17, 87.19))
        appendix = run_state("appendix", "--dir", str(state))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertIn(f"{absent:,} of {total:,}", appendix.stdout)
        self.assertIn("87.18% at display precision", appendix.stdout)
        self.assertIn("between 87.17% and 87.19%", appendix.stdout)

    def test_a_total_gap_still_reads_as_a_total_gap(self) -> None:
        # The endpoint guard must not fire when the endpoint is the truth.
        tl = self.make_timeline("none.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1", "Sec", "4688", "1", "x"]])
        m = self.write_metrics("none_m.csv", [["10", "100.0%", "Sec", "4688", "a"]])
        r, state = self.measure(tl, m, "nogap")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["absent_pct_lower"], 0.0)
        self.assertEqual(corpus["absent_pct_upper"], 0.0)

    def test_init_clears_a_previous_datasets_measurement(self) -> None:
        # Re-pointing a state directory at another timeline must not inherit the
        # old figure: it would be published in the appendix as this dataset's.
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        self.assertIsNotNone(
            json.loads((self.state_dir / "reachability.json").read_text())["corpus"])
        (self.state_dir / "manifest.json").unlink()
        other = self.make_timeline("other.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H9", "Sec", "4688", "1", "x"]])
        again = run_state("init", "--csv", str(other), "--dir", str(self.state_dir))
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertNoCorpus(self.state_dir)

    def test_a_measurement_of_another_timeline_is_not_published(self) -> None:
        # Defence in depth for the same hazard: a corpus whose recorded timeline
        # hash is not the loaded dataset's describes some other investigation.
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        path = self.state_dir / "reachability.json"
        stored = json.loads(path.read_text())
        stored["corpus"]["timeline_sha256"] = "0" * 64
        path.write_text(json.dumps(stored), encoding="utf-8")
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("cannot be verified", listed.stdout)
        self.assertNotIn("evtx corpus  :", listed.stdout)
        # The appendix is what a reader sees, so it must withhold the figure too.
        for lang, marker in (("en", "cannot be verified"), ("ja", "検証できない")):
            appendix = run_state("appendix", "--dir", str(self.state_dir), "--lang", lang)
            self.assertEqual(appendix.returncode, 0, appendix.stderr)
            self.assertIn(marker, appendix.stdout)
            self.assertNotIn("59,884,494", appendix.stdout)
            self.assertNotIn("definitely absent from the supplied timeline",
                             appendix.stdout)

    def test_a_timeline_changed_after_measurement_is_not_published(self) -> None:
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        with self.csv_path.open("a", encoding="utf-8") as f:
            f.write("\n")
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("cannot be verified", listed.stdout)
        self.assertNotIn("evtx corpus  :", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertIn("cannot be verified", appendix.stdout)
        self.assertNotIn("70.0%", appendix.stdout)

    def test_missing_manifest_hash_withholds_the_measurement(self) -> None:
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        manifest_path = self.state_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        del manifest["dataset"]["sha256"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("cannot be verified", listed.stdout)
        self.assertNotIn("evtx corpus  :", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertIn("cannot be verified", appendix.stdout)

    def test_missing_timeline_withholds_the_measurement_cleanly(self) -> None:
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        self.csv_path.unlink()
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertNotIn("Traceback", listed.stderr)
        self.assertIn("cannot be verified", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertNotIn("Traceback", appendix.stderr)
        self.assertIn("cannot be verified", appendix.stdout)

    def test_malformed_timeline_path_withholds_without_a_traceback(self) -> None:
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        manifest_path = self.state_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["dataset"]["path"] = "bad\x00path"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertNotIn("Traceback", listed.stderr)
        self.assertIn("cannot be verified", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertNotIn("Traceback", appendix.stderr)
        self.assertIn("cannot be verified", appendix.stdout)

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
        self.assertNoCorpus(state)

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
        self.assertNoCorpus(state)

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
        self.assertNoCorpus(state)

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

    def test_fully_omitted_correlation_identity_does_not_change_coverage(self) -> None:
        tl = self.make_timeline("nada.csv", [
            ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "H1",
             "Sec", "4688", "1", "x"],
            ["2024-01-01 00:01:00.000 +00:00", "Corr", "high", "H1",
             "", "", "", "Count:3"],
        ])
        m = self.write_metrics("nada_m.csv", [["1", "100.0%", "Sec", "4688", "x"]])
        r, state = self.measure(tl, m, "nada")
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((state / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["correlation_rows"], 1)
        self.assertEqual(corpus["resolved_correlation_rows"], 1)
        self.assertEqual(corpus["ambiguous_correlation_rows"], 0)
        self.assertEqual(corpus["represented_pairs"], 1)
        self.assertEqual(corpus["definite_absent_pairs"], 0)

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
                self.assertNoCorpus(state)

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

    def test_schema_one_measurement_is_not_reused_with_new_bound_semantics(self) -> None:
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        path = self.state_dir / "reachability.json"
        stored = json.loads(path.read_text())
        stored["schema_version"] = 1
        path.write_text(json.dumps(stored), encoding="utf-8")
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("obsolete", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertIn("obsolete", appendix.stdout)

    def test_inconsistent_current_schema_measurement_is_not_published(self) -> None:
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        path = self.state_dir / "reachability.json"
        stored = json.loads(path.read_text())
        stored["corpus"]["correlation_forced_pairs"] = 2
        path.write_text(json.dumps(stored), encoding="utf-8")
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("obsolete", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertIn("obsolete", appendix.stdout)

    def test_impossible_timeline_counts_are_not_published(self) -> None:
        self.assertEqual(self.reach("--eid-metrics", str(self.metrics_path)).returncode, 0)
        path = self.state_dir / "reachability.json"
        stored = json.loads(path.read_text())
        stored["corpus"]["timeline_rows"] = 0
        path.write_text(json.dumps(stored), encoding="utf-8")
        listed = self.reach("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("obsolete", listed.stdout)
        appendix = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(appendix.returncode, 0, appendix.stderr)
        self.assertIn("obsolete", appendix.stdout)


if __name__ == "__main__":
    unittest.main()
