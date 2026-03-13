from __future__ import annotations

import csv
import pathlib
import tempfile
import unittest

import pandas as pd
import server


CSV_HEADER = [
    "Timestamp",
    "RuleTitle",
    "Level",
    "Computer",
    "Channel",
    "EventID",
    "MitreTactics",
    "MitreTags",
    "OtherTags",
    "RecordID",
    "Details",
    "ExtraFieldInfo",
    "RuleFile",
    "EvtxFile",
    "RecoveredRecord",
]

CSV_ROWS = [
    [
        "2024-01-01 00:00:00.000 +00:00",
        "Beta",
        "low",
        "HOST-B",
        "Sec",
        "4688",
        "Exec",
        "T1001",
        "",
        "10",
        "wmic launched by beta",
        "",
        "beta.yml",
        "a.evtx",
        "",
    ],
    [
        "2024-01-01 00:00:00.000 +00:00",
        "Alpha",
        "low",
        "HOST-A",
        "Sec",
        "4688",
        "Exec",
        "T1002",
        "",
        "2",
        "wmic launched by alpha",
        "",
        "alpha.yml",
        "a.evtx",
        "",
    ],
    [
        "2024-01-01 00:01:00.000 +00:00",
        "Alpha",
        "high",
        "HOST-A",
        "Sysmon",
        "1",
        "PrivEsc",
        "T1003",
        "",
        "3",
        "wmic follow-up",
        "",
        "alpha.yml",
        "b.evtx",
        "",
    ],
    [
        "2024-01-01 00:01:00.000 +00:00",
        "Beta",
        "high",
        "HOST-C",
        "Sysmon",
        "1",
        "PrivEsc",
        "T1004",
        "",
        "4",
        "beta follow-up",
        "",
        "beta.yml",
        "b.evtx",
        "",
    ],
    [
        "2024-01-01 00:02:00.000 +00:00",
        "Delta",
        "info",
        "HOST-D",
        "Sec",
        "4624",
        "",
        "",
        "",
        "5",
        "logon event",
        "",
        "delta.yml",
        "c.evtx",
        "",
    ],
    [
        "2024-01-01 00:03:00.000 +00:00",
        "Gamma",
        "med",
        "HOST-E",
        "Sec",
        "4625",
        "",
        "",
        "",
        "6",
        "failed logon",
        "",
        "gamma.yml",
        "d.evtx",
        "",
    ],
    [
        "2024-01-01 00:01:30.000 +00:00",
        "EncodedPS",
        "high",
        "HOST-B",
        "Sec",
        "4688",
        "Exec \u00a6 LatMov",
        "T1059",
        "",
        "7",
        "Cmdline: powershell.exe -enc dABlAHMAdAA= \u00a6 User: admin",
        "",
        "encps.yml",
        "e.evtx",
        "",
    ],
]


class DeterminismTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.db_path = tmpdir / "sample.duckdb"

        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(CSV_ROWS)

        self.orig_db_path = server.DB_PATH
        self.orig_repo = server.repo
        self.orig_cache = server._LOG_COLUMNS_CACHE

        server.DB_PATH = self.db_path
        server.repo = server.DuckDBRepository(self.db_path)
        server._LOG_COLUMNS_CACHE = None
        server.switch_dataset(target=str(self.csv_path))

    def tearDown(self) -> None:
        server.DB_PATH = self.orig_db_path
        server.repo = self.orig_repo
        server._LOG_COLUMNS_CACHE = self.orig_cache
        self.tmp.cleanup()

    def test_run_sql_requires_order_by_for_offset(self) -> None:
        with self.assertRaises(ValueError):
            server.run_sql(sql='SELECT "RuleTitle" FROM logs', page_size=2, page_offset=1)

        ok_df = server.run_sql(
            sql='SELECT "RuleTitle" FROM logs ORDER BY "RuleTitle" ASC',
            page_size=2,
            page_offset=1,
        )
        self.assertEqual(ok_df.iloc[0]["status"], "ok")

    def test_summarize_events_tie_breaker_is_stable(self) -> None:
        df = server.summarize_events(groupby_field="RuleTitle", page_size=10, page_offset=0)
        records = df.to_dict(orient="records")
        top_titles = [row["RuleTitle"] for row in records[:2]]
        self.assertEqual(top_titles, ["Alpha", "Beta"])
        self.assertEqual(records[0]["status"], "ok")

    def test_analyze_rule_titles_tie_breaker_is_stable(self) -> None:
        df = server.analyze_rule_titles(page_size=10, page_offset=0)
        records = df.to_dict(orient="records")
        top_titles = [row["RuleTitle"] for row in records[:2]]
        self.assertEqual(top_titles, ["Alpha", "Beta"])
        self.assertEqual(records[0]["status"], "ok")

    def test_search_all_fields_is_deterministic(self) -> None:
        df1 = server.search_all_fields(query="wmic", page_size=10, page_offset=0)
        df2 = server.search_all_fields(query="wmic", page_size=10, page_offset=0)
        rec1 = df1.to_dict(orient="records")
        rec2 = df2.to_dict(orient="records")

        self.assertEqual(rec1, rec2)
        first = rec1[0]
        self.assertEqual(first["Computer"], "HOST-A")
        self.assertEqual(first["RuleTitle"], "Alpha")
        self.assertEqual(first["status"], "ok")

    def test_uniform_schema_contains_status_message_meta(self) -> None:
        ok_df = server.list_datasets(search_root=self.tmp.name, recursive=False, page_size=2, page_offset=0)
        for col in ("status", "message", "total_count", "has_more", "next_offset", "page_size", "page_offset"):
            self.assertIn(col, ok_df.columns)
        self.assertEqual(ok_df.iloc[0]["status"], "ok")

        no_data_df = server.search_all_fields(query="__not_found__", page_size=2, page_offset=0)
        for col in ("status", "message", "total_count", "has_more", "next_offset", "page_size", "page_offset"):
            self.assertIn(col, no_data_df.columns)
        self.assertEqual(no_data_df.iloc[0]["status"], "no_data")
        self.assertEqual(no_data_df.iloc[0]["total_count"], 0)

    def test_run_sql_include_total_false_without_hint(self) -> None:
        sql = 'SELECT "Timestamp", "RuleTitle" FROM logs ORDER BY "Timestamp" ASC, "RuleTitle" ASC'
        df = server.run_sql(sql=sql, page_size=2, page_offset=0, include_total=False)
        row = df.iloc[0]

        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["count_source"], "none")
        self.assertTrue(pd.isna(row["total_count"]))
        self.assertTrue(bool(row["has_more"]))

    def test_run_sql_with_hint(self) -> None:
        sql = 'SELECT "Timestamp", "RuleTitle" FROM logs ORDER BY "Timestamp" ASC, "RuleTitle" ASC'
        # Use run_sql with include_total=True to get count info
        full_df = server.run_sql(sql=sql, page_size=500, page_offset=0, include_total=True)
        total = int(full_df.iloc[0]["total_count"])
        qhash = str(full_df.iloc[0]["query_hash"])
        dver = str(full_df.iloc[0]["dataset_version"])

        hinted = server.run_sql(
            sql=sql,
            page_size=2,
            page_offset=0,
            include_total=False,
            total_count_hint=total,
            query_hash_hint=qhash,
            dataset_version_hint=dver,
        )
        row = hinted.iloc[0]
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["count_source"], "hint")
        self.assertEqual(int(row["total_count"]), total)

    # P1: run_sql wide_display
    def test_run_sql_wide_display_returns_wide_dataframe(self) -> None:
        sql = 'SELECT * FROM logs ORDER BY "Timestamp" ASC'
        df = server.run_sql(sql=sql, page_size=2, page_offset=0, wide_display=True)
        self.assertIsInstance(df, server._WideDisplayDataFrame)

    def test_run_sql_wide_display_false_returns_plain_dataframe(self) -> None:
        sql = 'SELECT * FROM logs ORDER BY "Timestamp" ASC'
        df = server.run_sql(sql=sql, page_size=2, page_offset=0, wide_display=False)
        self.assertNotIsInstance(df, server._WideDisplayDataFrame)
        self.assertIsInstance(df, pd.DataFrame)

    # P2: dataset_profile section
    def test_dataset_profile_section_levels(self) -> None:
        df = server.dataset_profile(section="levels")
        self.assertIn("Level", df.columns)
        self.assertIn("Count", df.columns)
        self.assertEqual(df.iloc[0]["status"], "ok")

    def test_dataset_profile_section_overview(self) -> None:
        df = server.dataset_profile(section="overview")
        self.assertIn("metric", df.columns)
        self.assertIn("value", df.columns)
        self.assertEqual(df.iloc[0]["status"], "ok")

    def test_dataset_profile_section_computers(self) -> None:
        df = server.dataset_profile(section="computers")
        self.assertIn("Computer", df.columns)
        self.assertIn("Count", df.columns)

    def test_dataset_profile_section_rules(self) -> None:
        df = server.dataset_profile(section="rules")
        self.assertIn("RuleTitle", df.columns)
        self.assertIn("Count", df.columns)

    # P3: get_event_detail
    def test_get_event_detail_by_record_id(self) -> None:
        df = server.get_event_detail(record_id="2")
        self.assertIn("Field", df.columns)
        self.assertIn("Value", df.columns)
        self.assertEqual(df.iloc[0]["status"], "ok")
        fields = df["Field"].tolist()
        self.assertIn("Timestamp", fields)
        self.assertIn("RuleTitle", fields)

    def test_get_event_detail_not_found(self) -> None:
        df = server.get_event_detail(record_id="99999")
        self.assertEqual(df.iloc[0]["status"], "no_data")

    def test_get_event_detail_by_sql_filter(self) -> None:
        df = server.get_event_detail(sql_filter="\"Level\" = 'high'")
        self.assertIn("Field", df.columns)
        self.assertIn("Value", df.columns)
        self.assertEqual(df.iloc[0]["status"], "ok")

    def test_get_event_detail_exclusive_params(self) -> None:
        with self.assertRaises(ValueError):
            server.get_event_detail(record_id="2", sql_filter="\"Level\" = 'high'")

    # P4: summarize_by_time_window
    def test_summarize_by_time_window_1h(self) -> None:
        df = server.summarize_by_time_window(interval="1h")
        self.assertIn("TimeWindow", df.columns)
        self.assertIn("EventCount", df.columns)
        self.assertEqual(df.iloc[0]["status"], "ok")

    def test_summarize_by_time_window_invalid_interval(self) -> None:
        with self.assertRaises(ValueError):
            server.summarize_by_time_window(interval="2h")

    # P5: decode_powershell_commands
    def test_decode_powershell_commands(self) -> None:
        df = server.decode_powershell_commands()
        self.assertIn("DecodedCommand", df.columns)
        self.assertIn("EncodedCommand", df.columns)
        self.assertEqual(df.iloc[0]["status"], "ok")
        # dABlAHMAdAA= decodes to "test" in UTF-16-LE
        decoded_values = df["DecodedCommand"].tolist()
        self.assertTrue(any("test" in str(v) for v in decoded_values))

    # P6: correlate_lateral_movement
    def test_correlate_lateral_movement(self) -> None:
        df = server.correlate_lateral_movement(time_window_minutes=5)
        self.assertIn("SourceHost", df.columns)
        self.assertIn("TargetHost", df.columns)
        self.assertIn("DeltaMinutes", df.columns)
        # Should find correlations between HOST-A and HOST-C (both high level, within 5 min)
        self.assertEqual(df.iloc[0]["status"], "ok")

    def test_correlate_lateral_movement_invalid_window(self) -> None:
        with self.assertRaises(ValueError):
            server.correlate_lateral_movement(time_window_minutes=0)
        with self.assertRaises(ValueError):
            server.correlate_lateral_movement(time_window_minutes=1441)


if __name__ == "__main__":
    unittest.main()
