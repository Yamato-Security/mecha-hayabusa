"""Raw-evtx reachability: corpus coverage, IOC search-backs, and gate G12.

A Hayabusa timeline contains only events that matched a rule, so "absent from
the timeline" is a weaker claim than "absent from the logs". These tests pin the
behaviour that keeps the two apart: absence claims must be backed by a search-back
against the original evtx, and a search-back that finds more in the raw corpus
than the timeline holds must be reconciled before the report can render.
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

# `hayabusa eid-metrics` output over the ORIGINAL evtx. Sec/4688 and Sec/4624
# also appear in the timeline; Sys/1014 and Shell-Core/9707 never matched a rule.
EID_METRICS = [
    ["Total", "%", "Channel", "ID", "Event"],
    ["9000", "60.0", "Sys", "1014", "DNS resolution timeout"],
    ["4000", "26.7", "Sec", "4688", "Process creation"],
    ["1500", "10.0", "MS-Win-Shell-Core/Op", "9707", "Shell command"],
    ["500", "3.3", "Sec", "4624", "Logon"],
]


def run_state(*argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STATE_PY), *argv],
        input=stdin_data, capture_output=True, text=True,
    )


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

    # -- helpers ---------------------------------------------------------

    def reach(self, *argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
        return run_state("reach", "--dir", str(self.state_dir), *argv, stdin_data=stdin_data)

    def gate(self, gate_id: str) -> dict:
        result = run_state("check", "--dir", str(self.state_dir), "--json", "--no-hash")
        payload = json.loads(result.stdout)
        for g in payload["gates"]:
            if g["id"] == gate_id:
                return g
        self.fail(f"gate {gate_id} not present in check output")

    def declare(self, artifacts, rationale: str = "Checked the raw evtx.") -> None:
        """Record a triage verdict that DECLARES which artifacts it asserts absent."""
        entry = [{
            "rule_title": "Beta", "verdict": "false_positive", "rationale": rationale,
            "absence": artifacts,
            "refs": [{"record_id": "2", "computer": "HOST-A", "channel": "Sec"}],
            "excerpt": "TgtUser: svc",
        }]
        r = run_state("triage", "--dir", str(self.state_dir), "--batch",
                      stdin_data=json.dumps(entry))
        self.assertEqual(r.returncode, 0, r.stderr)

    # -- corpus coverage -------------------------------------------------

    def test_eid_metrics_import_computes_unreachable_pairs(self) -> None:
        result = self.reach("--eid-metrics", str(self.metrics_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads((self.state_dir / "reachability.json").read_text())
        corpus = state["corpus"]
        self.assertEqual(corpus["corpus_events"], 15000)
        self.assertEqual(corpus["corpus_pairs"], 4)
        self.assertEqual(corpus["timeline_rows"], 2)
        self.assertEqual(corpus["timeline_pairs"], 2)
        self.assertEqual(corpus["uncovered_pairs"], 2)
        self.assertEqual(corpus["uncovered_events"], 10500)
        self.assertEqual(corpus["unreachable_pct"], 70.0)
        self.assertLessEqual(corpus["unreachable_pct"], 100.0)
        self.assertEqual(corpus["uncovered"][0]["channel"], "Sys")

    def test_eid_metrics_rejects_a_csv_that_is_not_eid_metrics(self) -> None:
        result = self.reach("--eid-metrics", str(self.csv_path))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("eid-metrics", result.stderr + result.stdout)

    def test_channel_case_differences_do_not_count_as_unreachable(self) -> None:
        # hayabusa spells the same channel differently across subcommands
        # (MS-Win-appxDeploySvr vs MS-Win-AppXDeploySvr); that is not a gap.
        metrics = self.state_dir.parent / "cased.csv"
        with metrics.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows([["Total", "%", "Channel", "ID", "Event"],
                                     ["100", "50.0", "SEC", "4688", "Process creation"],
                                     ["100", "50.0", "sec", "4624", "Logon"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertEqual(r.returncode, 0, r.stderr)
        corpus = json.loads((self.state_dir / "reachability.json").read_text())["corpus"]
        self.assertEqual(corpus["uncovered_pairs"], 0)

    def test_timeline_pair_absent_from_corpus_is_refused(self) -> None:
        # A partial overlap must not be accepted: it means the two files do not
        # describe the same evtx, or spell channels differently.
        metrics = self.state_dir.parent / "partial.csv"
        with metrics.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows([["Total", "%", "Channel", "ID", "Event"],
                                     ["100", "50.0", "Sec", "4688", "Process creation"],
                                     ["100", "50.0", "Other", "1", "x"]])
        r = self.reach("--eid-metrics", str(metrics))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("absent from", r.stderr + r.stdout)

    # -- declared absence ------------------------------------------------

    def test_declared_absence_without_a_searchback_fails(self) -> None:
        self.declare(["evil.example.com"])
        g12 = self.gate("G12")
        self.assertEqual(g12["status"], "FAIL")
        self.assertTrue(any("no evtx search-back" in gap for gap in g12["gaps"]))

    def test_declared_absence_with_a_zero_hit_searchback_passes(self) -> None:
        self.declare(["evil.example.com"])
        self.reach("--ioc", "evil.example.com", "--raw-hits", "0")
        self.assertEqual(self.gate("G12")["status"], "PASS")

    def test_every_declared_artifact_needs_its_own_searchback(self) -> None:
        self.declare(["evil.example.com", "10.0.0.1"])
        self.reach("--ioc", "evil.example.com", "--raw-hits", "0")
        self.assertEqual(self.gate("G12")["status"], "FAIL")
        self.reach("--ioc", "10.0.0.1", "--raw-hits", "0")
        self.assertEqual(self.gate("G12")["status"], "PASS")

    def test_a_searchback_that_found_hits_refutes_the_declaration(self) -> None:
        self.declare(["evil.example.com"])
        self.reach("--ioc", "evil.example.com", "--raw-hits", "9", "--timeline-hits", "9")
        g12 = self.gate("G12")
        self.assertEqual(g12["status"], "FAIL")
        self.assertTrue(any("refuted" in gap for gap in g12["gaps"]))

    def test_unavailable_corpus_excuses_a_missing_search_but_not_a_contradiction(self) -> None:
        self.declare(["evil.example.com"])
        self.reach("--none", "--reason", "only the CSV was provided")
        self.assertEqual(self.gate("G12")["status"], "PASS")
        # A recorded positive hit refutes the claim regardless of availability.
        self.reach("--ioc", "evil.example.com", "--raw-hits", "1", "--timeline-hits", "1")
        self.reach("--none", "--reason", "corpus unmounted again")
        self.assertEqual(self.gate("G12")["status"], "FAIL")

    def test_undeclared_prose_warns_but_never_gates(self) -> None:
        # The matcher cannot soundly decide this, so it advises rather than fails.
        self.declare([], rationale="There is no evidence of data exfiltration.")
        g12 = self.gate("G12")
        self.assertEqual(g12["status"], "PASS")
        self.assertIn("undeclared absence claim", g12["detail"])

    def test_declaration_accepts_objects_and_deduplicates(self) -> None:
        self.declare([{"artifact": "evil.example.com", "note": "checked"},
                      "EVIL.EXAMPLE.COM"])
        triage = json.loads((self.state_dir / "rule_triage.json").read_text())
        rule = [r for r in triage["rules"] if r["rule_title"] == "Beta"][0]
        self.assertEqual(len(rule["absence"]), 1)
        self.assertEqual(rule["absence"][0]["note"], "checked")

    def test_declaration_rejects_an_empty_artifact(self) -> None:
        entry = [{"rule_title": "Beta", "verdict": "indeterminate",
                  "rationale": "Reviewed the cited 4624 rows; TgtUser svc is the"
                                " backup service account and the logon type matches.",
                  "absence": [{"note": "no artifact"}],
                  "refs": [{"record_id": "2", "computer": "HOST-A", "channel": "Sec"}]}]
        r = run_state("triage", "--dir", str(self.state_dir), "--batch",
                      stdin_data=json.dumps(entry))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("artifact", r.stderr + r.stdout)

    # -- search-back reconciliation --------------------------------------

    def test_raw_hits_exceeding_timeline_must_be_reconciled(self) -> None:
        r = self.reach("--ioc", "d3azl80n0qqn6q.cloudfront.net", "--raw-hits", "504",
                       "--timeline-hits", "1", "--raw-hosts", "HOST-A,HOST-B,HOST-C")
        self.assertEqual(r.returncode, 0, r.stderr)
        g12 = self.gate("G12")
        self.assertEqual(g12["status"], "FAIL")
        self.assertTrue(any("cloudfront" in gap and "only in the raw evtx" in gap
                            for gap in g12["gaps"]))

    def make_finding(self, hosts: list[str]) -> None:
        finding = [{
            "id": "f1", "title": "C2 beacon", "summary": "Implant beaconing out.",
            "hosts": hosts, "rule_titles": ["Alpha"],
            "refs": [{"record_id": "1", "computer": "HOST-A", "channel": "Sec"}],
        }]
        r = run_state("finding", "--dir", str(self.state_dir), "--batch",
                      stdin_data=json.dumps(finding))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_reconciled_search_back_passes(self) -> None:
        self.make_finding(["HOST-A", "HOST-B", "HOST-C"])
        self.reach("--ioc", "d3azl80n0qqn6q.cloudfront.net", "--raw-hits", "504",
                   "--timeline-hits", "1", "--raw-hosts", "HOST-A,HOST-B,HOST-C",
                   "--timeline-hosts", "HOST-A", "--finding", "f1")
        self.assertEqual(self.gate("G12")["status"], "FAIL")
        # The finding now carries every raw-only host, so the gap can be closed.
        r = self.reach("--ioc", "d3azl80n0qqn6q.cloudfront.net", "--reconciled",
                       "--note", "added HOST-B and HOST-C to the C2 finding")
        self.assertEqual(r.returncode, 0, r.stderr)
        state = json.loads((self.state_dir / "reachability.json").read_text())
        self.assertEqual(len(state["searchbacks"]), 1)
        self.assertEqual(self.gate("G12")["status"], "PASS")

    def test_re_recording_preserves_omitted_fields(self) -> None:
        # The documented workflow re-records with only --reconciled --note; it
        # must not silently drop raw_hosts / finding / tool.
        self.make_finding(["HOST-A", "HOST-B", "HOST-C"])
        self.reach("--ioc", "c2.example", "--raw-hits", "504", "--timeline-hits", "1",
                   "--raw-hosts", "HOST-A,HOST-B,HOST-C", "--timeline-hosts", "HOST-A",
                   "--finding", "f1", "--tool", "hayabusa search -k c2.example")
        self.reach("--ioc", "c2.example", "--reconciled", "--note", "hosts added to f1")
        b = json.loads((self.state_dir / "reachability.json").read_text())["searchbacks"][0]
        self.assertEqual(b["raw_hosts"], ["HOST-A", "HOST-B", "HOST-C"])
        self.assertEqual(b["finding"], "f1")
        self.assertEqual(b["tool"], "hayabusa search -k c2.example")
        self.assertEqual(b["raw_hits"], 504)

    def test_cannot_reconcile_while_a_raw_only_host_is_unaccounted(self) -> None:
        # The motivating case: HOST-Z was found only in the raw evtx and the
        # finding never picked it up. A note must not be able to close that.
        self.make_finding(["HOST-A"])
        self.reach("--ioc", "c2.example", "--raw-hits", "40", "--timeline-hits", "1",
                   "--raw-hosts", "HOST-A,HOST-Z", "--timeline-hosts", "HOST-A",
                   "--finding", "f1")
        r = self.reach("--ioc", "c2.example", "--reconciled", "--note", "looked at it")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not list HOST-Z", r.stderr + r.stdout)
        self.assertEqual(self.gate("G12")["status"], "FAIL")

    def test_cannot_reconcile_raw_only_hosts_without_linking_a_finding(self) -> None:
        self.reach("--ioc", "c2.example", "--raw-hits", "40", "--timeline-hits", "0",
                   "--raw-hosts", "HOST-A,HOST-Z")
        r = self.reach("--ioc", "c2.example", "--reconciled", "--note", "done")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--finding", r.stderr + r.stdout)

    def test_hosts_without_hits_are_rejected(self) -> None:
        r = self.reach("--ioc", "c2.example", "--raw-hits", "0", "--raw-hosts", "HOST-Z")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("attributes no host", r.stderr + r.stdout)

    def test_non_integer_and_negative_counts_are_rejected(self) -> None:
        for bad in (True, -1, 3.9, "7"):
            r = self.reach("--batch", stdin_data=json.dumps(
                [{"ioc": "c2.example", "raw_hits": bad}]))
            self.assertNotEqual(r.returncode, 0, f"accepted raw_hits={bad!r}")

    def test_linking_a_nonexistent_finding_is_rejected(self) -> None:
        r = self.reach("--ioc", "c2.example", "--raw-hits", "3", "--finding", "f99")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not exist", r.stderr + r.stdout)

    def test_batch_search_backs(self) -> None:
        batch = [
            {"ioc": "a.example", "raw_hits": 3, "timeline_hits": 3, "reconciled": False},
            {"ioc": "b.example", "raw_hits": 9, "timeline_hits": 9},
        ]
        r = self.reach("--batch", stdin_data=json.dumps(batch))
        self.assertEqual(r.returncode, 0, r.stderr)
        # raw == timeline needs no reconciliation; the other is already reconciled.
        self.assertEqual(self.gate("G12")["status"], "PASS")

    def test_search_back_requires_raw_hits(self) -> None:
        r = self.reach("--batch", stdin_data=json.dumps([{"ioc": "a.example"}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("raw_hits", r.stderr + r.stdout)

    def test_timeline_hits_may_not_exceed_raw_hits(self) -> None:
        # timeline_hits is a DEDUPLICATED event count; a timeline event is always
        # also a raw event, so exceeding raw_hits means rows were counted.
        r = self.reach("--ioc", "c2.example", "--raw-hits", "1", "--timeline-hits", "5")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("distinct underlying EVENTS", r.stderr + r.stdout)

    def test_more_hosts_than_hits_is_rejected(self) -> None:
        r = self.reach("--ioc", "c2.example", "--raw-hits", "1",
                       "--raw-hosts", "HOST-A,HOST-B")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("each host needs at least one hit", r.stderr + r.stdout)

    def test_timeline_host_absent_from_raw_hosts_is_rejected(self) -> None:
        # Otherwise an impossible timeline host cancels the raw-only set and
        # lets a gap close with no finding at all.
        r = self.reach("--ioc", "c2.example", "--raw-hits", "1", "--raw-hosts", "HOST-A",
                       "--timeline-hits", "1", "--timeline-hosts", "HOST-Z")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("timeline cannot hold a host", r.stderr + r.stdout)

    def test_count_only_gap_still_requires_a_linked_finding(self) -> None:
        # A gap with no raw-only host must not be closeable on a note alone.
        r = self.reach("--ioc", "c2.example", "--raw-hits", "40", "--timeline-hits", "1",
                       "--reconciled", "--note", "looked at it")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--finding", r.stderr + r.stdout)

    def test_re_recording_preserves_reconciled(self) -> None:
        self.make_finding(["HOST-A"])
        self.reach("--ioc", "c2.example", "--raw-hits", "40", "--timeline-hits", "1",
                   "--finding", "f1")
        self.reach("--ioc", "c2.example", "--reconciled", "--note", "f1 now covers it")
        self.assertEqual(self.gate("G12")["status"], "PASS")
        # Re-recording an unrelated field must not silently re-open the gap.
        self.reach("--ioc", "c2.example", "--tool", "hayabusa search -k c2.example")
        b = json.loads((self.state_dir / "reachability.json").read_text())["searchbacks"][0]
        self.assertTrue(b["reconciled"])
        self.assertEqual(self.gate("G12")["status"], "PASS")

    # -- reporting -------------------------------------------------------

    def test_string_false_is_rejected_as_reconciled(self) -> None:
        # bool("false") is True -- a batch entry must not close a gap that way.
        r = self.reach("--batch", stdin_data=json.dumps(
            [{"ioc": "a.example", "raw_hits": 9, "timeline_hits": 1, "reconciled": "false"}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must be a JSON boolean", r.stderr + r.stdout)

    def test_reconciling_a_positive_gap_requires_a_note(self) -> None:
        r = self.reach("--ioc", "a.example", "--raw-hits", "9", "--timeline-hits", "1",
                       "--reconciled")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("requires a note", r.stderr + r.stdout)

    def test_equal_hit_counts_are_not_labelled_a_gap(self) -> None:
        self.reach("--ioc", "a.example", "--raw-hits", "3", "--timeline-hits", "3")
        out = self.reach("--list")
        self.assertIn("[OK ]", out.stdout)
        self.assertNotIn("[GAP]", out.stdout)

    def test_recording_evidence_clears_a_prior_unavailable_declaration(self) -> None:
        self.reach("--none", "--reason", "corpus not shipped yet")
        self.reach("--eid-metrics", str(self.metrics_path))
        state = json.loads((self.state_dir / "reachability.json").read_text())
        self.assertFalse(state["declared_unavailable"])
        # The measured coverage must now reach the appendix.
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertIn("no rule ever matched", out.stdout)

    def test_searchback_hosts_can_back_a_finding_host(self) -> None:
        # A host found only in the RAW evtx cannot have a timeline ref by
        # definition; linking the search-back to the finding must satisfy G9.
        finding = [{
            "id": "f1", "title": "C2 beacon", "summary": "Implant beaconing out.",
            "hosts": ["HOST-A", "HOST-Z"], "rule_titles": ["Alpha"],
            "refs": [{"record_id": "1", "computer": "HOST-A", "channel": "Sec"}],
        }]
        r = run_state("finding", "--dir", str(self.state_dir), "--batch",
                      stdin_data=json.dumps(finding))
        self.assertEqual(r.returncode, 0, r.stderr)
        # HOST-Z appears in no timeline row -> G9 FAILs.
        self.assertEqual(self.gate("G9")["status"], "FAIL")
        self.reach("--ioc", "c2.example", "--raw-hits", "40", "--timeline-hits", "0",
                   "--raw-hosts", "HOST-A,HOST-Z", "--finding", "f1")
        self.assertEqual(self.gate("G9")["status"], "PASS")

    def test_appendix_states_reachability_was_not_measured(self) -> None:
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("not measured", out.stdout)

    def test_appendix_reports_measured_coverage(self) -> None:
        self.reach("--eid-metrics", str(self.metrics_path))
        out = run_state("appendix", "--dir", str(self.state_dir))
        self.assertIn("no rule ever matched", out.stdout)

    def test_g12_present_and_passing_on_a_clean_investigation(self) -> None:
        g12 = self.gate("G12")
        self.assertEqual(g12["status"], "PASS")
        self.assertIn("no corpus coverage recorded", g12["detail"])


if __name__ == "__main__":
    unittest.main()
