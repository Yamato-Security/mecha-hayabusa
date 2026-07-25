"""correlate_lateral_movement must refuse a search space it cannot serve.

total_count is COUNT(*) over the joined pairs, so the cost of returning one
page is driven by the number of candidate pairs, not by page_size. Left
unguarded, an ordinary unfiltered call on a dense dataset turns into a very
long-running query with no feedback. These tests pin the guard: it refuses
loudly with the real numbers, it says how to narrow, and narrowing works.
"""

from __future__ import annotations

import csv
import pathlib
import tempfile
import unittest

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
    "RecordID",
    "Details",
    "ExtraFieldInfo",
]

HOSTS = ["DC01", "WS01", "WS02", "FS01"]
# 3,000 correlatable events in one hour: 3,000 x 3,000 = 9,000,000 candidate
# pairs, above the guard, while staying small enough for a fast test.
DENSE_ROWS = [
    [
        f"2024-06-01 00:{(i // 60) % 60:02d}:{i % 60:02d}.000 +00:00",
        "Remote Logon",
        "high",
        HOSTS[i % len(HOSTS)],
        "Sec",
        "4624",
        "LatMov",
        "T1021",
        str(i),
        f"TgtUser: user{i % 20}",
        "",
    ]
    for i in range(3000)
]

# A handful of events on a distinct rule and host pair, used to prove that a
# narrowed call still correlates normally.
SPARSE_ROWS = [
    [
        f"2024-06-02 12:0{i}:00.000 +00:00",
        "PsExec Service Install",
        "high",
        "JUMPBOX" if i % 2 == 0 else "TARGET",
        "Sec",
        "7045",
        "LatMov",
        "T1021.002",
        str(90000 + i),
        "Svc: PSEXESVC",
        "",
    ]
    for i in range(4)
]


class CorrelationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.db_path = tmpdir / "sample.duckdb"

        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(DENSE_ROWS + SPARSE_ROWS)

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

    @staticmethod
    def _first(df) -> dict:
        return df.to_dict("records")[0]

    def test_oversized_search_space_is_refused(self) -> None:
        result = self._first(server.correlate_lateral_movement(page_size=10))
        self.assertEqual(result["status"], "too_broad")

    def test_refusal_reports_the_real_numbers(self) -> None:
        # An analyst has to be able to see how far over the limit they are to
        # judge how much narrowing is needed.
        result = self._first(server.correlate_lateral_movement(page_size=10))
        self.assertEqual(result["source_event_count"], len(DENSE_ROWS) + len(SPARSE_ROWS))
        self.assertEqual(result["target_event_count"], len(DENSE_ROWS) + len(SPARSE_ROWS))
        self.assertEqual(
            result["candidate_pairs"],
            result["source_event_count"] * result["target_event_count"],
        )
        self.assertEqual(result["max_candidate_pairs"], server.MAX_CORRELATION_SEARCH_SPACE)

    def test_refusal_names_the_ways_to_narrow(self) -> None:
        message = self._first(server.correlate_lateral_movement(page_size=10))["message"]
        for hint in ("time_window_minutes", "source_host", "target_host", "level"):
            self.assertIn(hint, message)

    def test_refusal_returns_no_rows(self) -> None:
        # A refusal must not look like "no lateral movement found".
        records = server.correlate_lateral_movement(page_size=10).to_dict("records")
        self.assertFalse([r for r in records if r.get("SourceHost")])
        self.assertNotEqual(self._first(server.correlate_lateral_movement(page_size=10))["status"], "no_data")

    def test_narrowing_by_host_correlates_normally(self) -> None:
        result = server.correlate_lateral_movement(
            source_host="JUMPBOX", target_host="TARGET", time_window_minutes=10, page_size=10
        )
        records = [r for r in result.to_dict("records") if r.get("SourceHost")]
        self.assertTrue(records, "a narrowed correlation should still return pairs")
        self.assertEqual(records[0]["status"], "ok")
        for record in records:
            self.assertEqual(record["SourceHost"], "JUMPBOX")
            self.assertEqual(record["TargetHost"], "TARGET")

    def test_guard_runs_before_the_join(self) -> None:
        # The point of the guard is that it costs two counts, not a join, so
        # the refusal must come back quickly even though the join would be huge.
        import time

        start = time.monotonic()
        server.correlate_lateral_movement(page_size=10)
        self.assertLess(time.monotonic() - start, 5.0, "refusal path should not run the join")


if __name__ == "__main__":
    unittest.main()
