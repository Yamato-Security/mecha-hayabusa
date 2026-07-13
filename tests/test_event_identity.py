"""get_event_detail must not silently return an arbitrary row when the cited
RecordID is ambiguous (RecordIDs are unique per host+channel, not globally)."""

from __future__ import annotations

import csv
import pathlib
import tempfile
import unittest

import server


CSV_HEADER = [
    "Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
    "MitreTactics", "MitreTags", "OtherTags", "RecordID", "Details",
    "ExtraFieldInfo", "RuleFile", "EvtxFile", "RecoveredRecord",
]

# RecordID 100 denotes two DIFFERENT events (HOST-A/Sec and HOST-B/Sysmon).
# RecordID 3 denotes ONE event detected by TWO rules (Gamma and Delta).
# RecordID 2 is globally unique.
CSV_ROWS = [
    ["2024-01-01 00:00:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688",
     "Exec", "T1001", "", "100", "Cmdline: evil.exe -x ¦ User: bob", "", "alpha.yml", "a.evtx", ""],
    ["2024-01-01 00:01:00.000 +00:00", "Beta", "high", "HOST-B", "Sysmon", "1",
     "Exec", "T1002", "", "100", "Image: C:\\Windows\\legit.exe", "", "beta.yml", "b.evtx", ""],
    ["2024-01-01 00:02:00.000 +00:00", "Alpha", "high", "HOST-A", "Sec", "4688",
     "Exec", "T1001", "", "2", "Cmdline: benign.exe ¦ User: alice", "", "alpha.yml", "a.evtx", ""],
    ["2024-01-01 00:03:00.000 +00:00", "Gamma", "low", "HOST-A", "Sec", "4624",
     "", "", "", "3", "TgtUser: svc", "", "gamma.yml", "a.evtx", ""],
    ["2024-01-01 00:03:00.000 +00:00", "Delta", "med", "HOST-A", "Sec", "4624",
     "", "", "", "3", "TgtUser: svc ¦ LogonType: 3", "", "delta.yml", "a.evtx", ""],
]


class EventIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "dup.csv"
        self.db_path = tmpdir / "dup.duckdb"

        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(CSV_ROWS)

        self.orig_db_path = server.DB_PATH
        self.orig_repo = server.repo
        self.orig_cache = server._LOG_COLUMNS_CACHE
        self.orig_roots = server.DATASET_ROOTS

        server.DB_PATH = self.db_path
        server.repo = server.DuckDBRepository(self.db_path)
        server._LOG_COLUMNS_CACHE = None
        server.DATASET_ROOTS = [pathlib.Path(self.tmp.name).resolve()]
        server.switch_dataset(target=str(self.csv_path))

    def tearDown(self) -> None:
        server.DB_PATH = self.orig_db_path
        server.repo = self.orig_repo
        server._LOG_COLUMNS_CACHE = self.orig_cache
        server.DATASET_ROOTS = self.orig_roots
        self.tmp.cleanup()

    def test_duplicated_record_id_is_reported_ambiguous(self) -> None:
        df = server.get_event_detail(record_id="100")
        self.assertEqual(df.iloc[0]["status"], "ambiguous")
        self.assertEqual(len(df), 2)
        self.assertIn("computer", str(df.iloc[0]["message"]))
        computers = set(df["Computer"].tolist())
        self.assertEqual(computers, {"HOST-A", "HOST-B"})

    def test_computer_qualifier_resolves_ambiguity(self) -> None:
        df = server.get_event_detail(record_id="100", computer="HOST-B")
        self.assertEqual(df.iloc[0]["status"], "ok")
        values = dict(zip(df["Field"], df["Value"]))
        self.assertEqual(values.get("Computer"), "HOST-B")
        self.assertEqual(values.get("RuleTitle"), "Beta")
        self.assertNotIn("_MatchedRows", values)

    def test_channel_qualifier_also_narrows(self) -> None:
        df = server.get_event_detail(record_id="100", computer="HOST-A", channel="Sec")
        self.assertEqual(df.iloc[0]["status"], "ok")
        values = dict(zip(df["Field"], df["Value"]))
        self.assertEqual(values.get("RuleTitle"), "Alpha")

    def test_unique_record_id_still_works_bare(self) -> None:
        df = server.get_event_detail(record_id="2")
        self.assertEqual(df.iloc[0]["status"], "ok")
        values = dict(zip(df["Field"], df["Value"]))
        self.assertEqual(values.get("Computer"), "HOST-A")

    def test_multi_rule_event_surfaces_alternatives(self) -> None:
        df = server.get_event_detail(record_id="3")
        self.assertEqual(df.iloc[0]["status"], "ok")
        values = dict(zip(df["Field"], df["Value"]))
        self.assertEqual(values.get("_MatchedRows"), "2")
        self.assertIn("Gamma", values.get("_MatchedRuleTitles", ""))
        self.assertIn("Delta", values.get("_MatchedRuleTitles", ""))
        # Deterministic first row: ordered by RuleTitle -> Delta
        self.assertEqual(values.get("RuleTitle"), "Delta")

    def test_rule_title_filter_selects_specific_row(self) -> None:
        df = server.get_event_detail(record_id="3", rule_title="Gamma")
        self.assertEqual(df.iloc[0]["status"], "ok")
        values = dict(zip(df["Field"], df["Value"]))
        self.assertEqual(values.get("RuleTitle"), "Gamma")
        self.assertNotIn("_MatchedRows", values)

    def test_wrong_qualifier_returns_no_data(self) -> None:
        df = server.get_event_detail(record_id="100", computer="HOST-Z")
        self.assertEqual(df.iloc[0]["status"], "no_data")

    def test_qualifiers_rejected_with_sql_filter(self) -> None:
        with self.assertRaises(ValueError):
            server.get_event_detail(sql_filter="\"Level\" = 'high'", computer="HOST-A")


if __name__ == "__main__":
    unittest.main()
