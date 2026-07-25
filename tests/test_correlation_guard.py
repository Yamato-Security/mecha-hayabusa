"""correlate_lateral_movement must refuse only what it cannot serve.

total_count is COUNT(*) over the joined pairs, so the cost of returning one
page is driven by the number of candidate pairs, not by page_size. Left
unguarded, an ordinary unfiltered call on a dense dataset turns into a very
long-running query with no feedback.

The guard therefore has to be *time-aware*. A Cartesian count_a * count_b
bound is identical for every window width, which both refuses queries that
would run in a fraction of a second and makes the "use a shorter
time_window_minutes" advice in the refusal impossible to act on. These tests
pin the behaviour that matters: expensive runs are refused with the real
numbers, cheap ones are served, and narrowing the window changes the verdict.
"""

from __future__ import annotations

import csv
import pathlib
import tempfile
import time
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
# 4,000 correlatable events spread over 30 minutes. Inside a 60-minute window
# they all fall in one bucket (~12M candidate pairs, above the limit); inside a
# 1-minute window they spread over 30 buckets (~0.4M, comfortably below it).
# That gap is what makes the window-sensitivity test meaningful.
DENSE_ROWS = [
    [
        f"2024-06-01 00:{(i * 30) // 4000:02d}:{i % 60:02d}.000 +00:00",
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
    for i in range(4000)
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

    def _call(self, **kwargs) -> dict:
        kwargs.setdefault("page_size", 10)
        return self._first(server.correlate_lateral_movement(**kwargs))

    def _estimate(self, **kwargs) -> int:
        """The guard's estimate, read by forcing every call to report it."""
        original = server.MAX_CORRELATION_CANDIDATE_PAIRS
        server.MAX_CORRELATION_CANDIDATE_PAIRS = 0
        try:
            return self._call(**kwargs)["candidate_pairs"]
        finally:
            server.MAX_CORRELATION_CANDIDATE_PAIRS = original

    # ── refusal ────────────────────────────────────────────────────────────
    def test_oversized_search_space_is_refused(self) -> None:
        self.assertEqual(self._call(time_window_minutes=60)["status"], "too_broad")

    def test_refusal_reports_the_real_numbers(self) -> None:
        # An analyst has to see how far over the limit they are to judge how
        # much narrowing is needed.
        result = self._call(time_window_minutes=60)
        total_rows = len(DENSE_ROWS) + len(SPARSE_ROWS)
        self.assertEqual(result["source_event_count"], total_rows)
        self.assertEqual(result["target_event_count"], total_rows)
        self.assertGreater(result["candidate_pairs"], result["max_candidate_pairs"])
        self.assertEqual(result["max_candidate_pairs"], server.MAX_CORRELATION_CANDIDATE_PAIRS)
        self.assertEqual(result["time_window_minutes"], 60)

    def test_refusal_names_the_ways_to_narrow(self) -> None:
        message = self._call(time_window_minutes=60)["message"]
        for hint in ("time_window_minutes", "source_host", "target_host", "level"):
            self.assertIn(hint, message)

    def test_refusal_returns_no_rows(self) -> None:
        # A refusal must not look like "no lateral movement found".
        records = server.correlate_lateral_movement(
            time_window_minutes=60, page_size=10
        ).to_dict("records")
        self.assertFalse([r for r in records if r.get("SourceHost")])
        self.assertNotEqual(self._call(time_window_minutes=60)["status"], "no_data")

    def test_guard_runs_before_the_join(self) -> None:
        # The guard costs two aggregates, not a join, so the refusal must come
        # back quickly even though the join it declined would be huge.
        start = time.monotonic()
        self._call(time_window_minutes=60)
        self.assertLess(time.monotonic() - start, 5.0, "refusal path should not run the join")

    # ── the bound must track the window ────────────────────────────────────
    def test_shorter_window_takes_the_same_data_below_the_limit(self) -> None:
        """The remediation the refusal advertises has to actually work.

        A Cartesian bound is invariant to the window, so this is the test that
        fails if the guard ever regresses to one: the same rows and the same
        filters, only a shorter window, must go from refused to served.
        """
        self.assertEqual(self._call(time_window_minutes=60)["status"], "too_broad")
        narrowed = self._call(time_window_minutes=1)
        self.assertEqual(narrowed["status"], "ok")
        self.assertGreater(narrowed["total_count"], 0)

    def test_estimate_shrinks_with_the_window(self) -> None:
        estimates = [self._estimate(time_window_minutes=w) for w in (60, 30, 10, 1)]
        self.assertEqual(estimates, sorted(estimates, reverse=True))
        self.assertLess(estimates[-1], estimates[0])

    def test_estimate_is_an_upper_bound_on_the_real_pair_count(self) -> None:
        """The guard may over-estimate; it must never under-estimate.

        An under-estimate would let through exactly the runs it exists to stop.
        """
        estimate = self._estimate(time_window_minutes=5)
        actual = self._call(time_window_minutes=5)["total_count"]
        self.assertGreaterEqual(estimate, actual)

    # ── serving ────────────────────────────────────────────────────────────
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

    # ── parameter binding ──────────────────────────────────────────────────
    def test_level_filter_combines_with_host_filters(self) -> None:
        """A level filter alongside a host filter must not silently return nothing.

        The two WHERE clauses interleave their placeholders in the statement
        (level_a, source_host, level_b, target_host); collecting the values in
        the order the conditions were built instead bound the host predicate to
        a level string. It matched no Computer, so the tool reported "no
        lateral movement patterns detected" — a false negative, not an error,
        because the placeholder count still happened to line up.
        """
        host_only = server.correlate_lateral_movement(
            source_host="JUMPBOX", target_host="TARGET", time_window_minutes=10, page_size=10
        ).to_dict("records")
        with_level = server.correlate_lateral_movement(
            source_host="JUMPBOX",
            target_host="TARGET",
            level="high",
            time_window_minutes=10,
            page_size=10,
        ).to_dict("records")

        host_rows = [r for r in host_only if r.get("SourceHost")]
        level_rows = [r for r in with_level if r.get("SourceHost")]
        self.assertTrue(host_rows)
        self.assertEqual(
            len(level_rows),
            len(host_rows),
            "every fixture row is level=high, so adding level='high' must not change the result",
        )

    def test_level_filter_alone_still_applies(self) -> None:
        # Guard against "fixing" the ordering by dropping the level predicate.
        result = server.correlate_lateral_movement(
            level="low", time_window_minutes=1, page_size=10
        ).to_dict("records")
        self.assertFalse([r for r in result if r.get("SourceHost")])


if __name__ == "__main__":
    unittest.main()
