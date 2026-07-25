"""Paginated tool results must be reproducible.

Every paginated tool orders its rows and then serves them with LIMIT/OFFSET.
If that ordering is not total, the engine may interleave tied rows differently
on each execution, and paging then returns some rows twice and others never —
silently, with a correct-looking total_count. These tests pin the ordering of
each paginated tool by checking the property that actually matters: the union
of the pages equals the single-page result, exactly once each.
"""

from __future__ import annotations

import csv
import pathlib
import tempfile
import unittest
from collections import Counter

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

# 40 process IOCs that all occur exactly once, so every row ties on Count —
# the ordinary case for IOC extraction, and the one that exposes an ordering
# that is not total.
CSV_ROWS = [
    [
        f"2024-03-01 0{i // 30}:{(i // 2) % 60:02d}:00.000 +00:00",
        "Suspicious Process",
        "high",
        f"HOST-{i % 4}",
        "Sysmon",
        "1",
        "Exec",
        "T1059",
        str(1000 + i),
        f"Proc: C:\\tmp\\tool{i:02d}.exe ¦ TgtUser: user{i % 5}",
        "",
    ]
    for i in range(40)
]

# One event detected by TWO rules, repeated. Hayabusa writes a row per
# (event x matching rule), so these pairs share Timestamp, Computer, Channel
# AND RecordID and differ only in RuleTitle/Level/Details — the case an
# event-identity tie-breaker cannot separate. See tests/test_event_identity.py.
CSV_ROWS += [
    [
        f"2024-03-02 00:{i:02d}:00.000 +00:00",
        rule,
        level,
        "HOST-DUP",
        "Sec",
        "4624",
        "",
        "",
        str(5000 + i),
        f"TgtUser: svc ¦ Extra: {rule.lower()}",
        "",
    ]
    for i in range(8)
    for rule, level in (("Gamma", "low"), ("Delta", "med"))
]

# 100 rows sharing Timestamp, RecordID, Computer, RuleTitle and EventID and
# differing only in Details — the shape that ties every identity-ish ordering
# column while the projection still distinguishes the rows.
CSV_ROWS += [
    [
        "2024-03-03 00:00:00.000 +00:00",
        "SameRule",
        "high",
        "HOST-TIE",
        "Sec",
        "4688",
        "Exec",
        "T1059",
        "777",
        f"Cmdline: tie-{i:03d}.exe",
        "",
    ]
    for i in range(100)
]

# A second rule whose events share one timestamp per host pair, so the
# lateral-movement join produces ties on (a.ts, b.ts).
CSV_ROWS += [
    [
        "2024-03-01 02:00:00.000 +00:00",
        "Remote Logon",
        "high",
        f"HOST-{host}",
        "Sec",
        "4624",
        "LatMov",
        "T1021",
        str(2000 + host * 10 + n),
        f"TgtUser: svc{n}",
        "",
    ]
    for host in range(4)
    for n in range(3)
]


class PaginationStabilityTests(unittest.TestCase):
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

    # ── helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _rows(df, *key_columns: str) -> list[tuple]:
        """Data rows of a tool result as tuples of the given key columns.

        Metadata-only responses (status/message rows with no data) carry no key
        columns, so they drop out.
        """
        records = df.to_dict("records")
        return [
            tuple(str(record.get(column)) for column in key_columns)
            for record in records
            if record.get(key_columns[0]) is not None
        ]

    def _assert_pages_reconstruct_whole(self, call, *key_columns: str, page_size: int = 7) -> None:
        """Paging through a tool must reproduce the unpaginated result exactly.

        Compared as a sequence, which catches both failure modes of an unstable
        ordering at once: a row served on two pages, and a row served on none.
        (A multiset comparison alone would miss reordering, and a set
        comparison would wrongly collapse rows that legitimately share the
        compared columns.)
        """
        whole = self._rows(call(page_size=1000, page_offset=0), *key_columns)
        self.assertTrue(whole, "fixture produced no rows to paginate")

        paged: list[tuple] = []
        offset = 0
        while offset < len(whole) + page_size:
            page = self._rows(call(page_size=page_size, page_offset=offset), *key_columns)
            if not page:
                break
            paged.extend(page)
            offset += page_size

        missing = Counter(whole) - Counter(paged)
        extra = Counter(paged) - Counter(whole)
        self.assertFalse(
            missing, f"{sum(missing.values())} row(s) never returned by any page: {list(missing)[:5]}"
        )
        self.assertFalse(
            extra, f"{sum(extra.values())} row(s) returned on more than one page: {list(extra)[:5]}"
        )
        self.assertEqual(whole, paged, "page order does not match the single-fetch order")

    def _assert_repeatable(self, call, *key_columns: str, runs: int = 5) -> None:
        """The same query must return the same row order every time."""
        orders = {tuple(self._rows(call(page_size=1000, page_offset=0), *key_columns)) for _ in range(runs)}
        self.assertEqual(len(orders), 1, f"query returned {len(orders)} different row orders over {runs} runs")

    # ── extract_iocs ───────────────────────────────────────────────────────
    def test_extract_iocs_pages_reconstruct_whole(self) -> None:
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.extract_iocs(ioc_type="process", **kw), "Value"
        )

    def test_extract_iocs_order_is_repeatable(self) -> None:
        self._assert_repeatable(lambda **kw: server.extract_iocs(ioc_type="process", **kw), "Value")

    def test_extract_iocs_hosts_are_sorted(self) -> None:
        # STRING_AGG without ORDER BY leaves the aggregated host list in an
        # engine-defined order, so the same query_hash could stamp different
        # Hosts strings between runs.
        for record in server.extract_iocs(ioc_type="user", page_size=1000).to_dict("records"):
            hosts = record.get("Hosts")
            if not hosts:
                continue
            parts = [part.strip() for part in str(hosts).split(",")]
            self.assertEqual(parts, sorted(parts), f"Hosts not deterministically ordered: {hosts}")

    # ── parse_details_field ────────────────────────────────────────────────
    def test_parse_details_field_list_mode_pages_reconstruct_whole(self) -> None:
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.parse_details_field(**kw), "FieldName", page_size=1
        )

    def test_parse_details_field_unique_mode_pages_reconstruct_whole(self) -> None:
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.parse_details_field(field_name="Proc", unique=True, **kw), "Value"
        )

    def test_parse_details_field_event_mode_pages_reconstruct_whole(self) -> None:
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.parse_details_field(field_name="TgtUser", unique=False, **kw),
            "Timestamp",
            "Computer",
            # RuleTitle is required in the key: without it, one duplicated
            # Gamma row and one lost Delta row cancel out and the assertion
            # passes over a broken ordering.
            "RuleTitle",
            "Value",
            page_size=3,
        )

    def test_parse_details_field_event_mode_keeps_its_columns(self) -> None:
        # The identity columns added for ordering must not leak into the
        # projection and change the tool's output shape.
        columns = set(
            server.parse_details_field(field_name="TgtUser", unique=False, page_size=5).columns
        )
        self.assertNotIn("RecordID", columns)
        self.assertNotIn("Channel", columns)
        self.assertIn("Value", columns)

    # ── analyze_host_timeline ──────────────────────────────────────────────
    def test_analyze_host_timeline_pages_reconstruct_whole(self) -> None:
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.analyze_host_timeline(host_contains="HOST-", **kw),
            "Timestamp",
            "RuleTitle",
            "Computer",
        )

    # ── correlate_lateral_movement ─────────────────────────────────────────
    def test_correlate_lateral_movement_pages_reconstruct_whole(self) -> None:
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.correlate_lateral_movement(time_window_minutes=60, **kw),
            "SourceTime",
            "SourceHost",
            "TargetHost",
            "TargetEvent",
        )

    # ── analyze_rule_titles ────────────────────────────────────────────────
    def test_analyze_rule_titles_aggregates_are_sorted(self) -> None:
        for record in server.analyze_rule_titles(page_size=1000).to_dict("records"):
            for column in ("severity", "detected_hosts"):
                value = record.get(column)
                if not value:
                    continue
                parts = [part.strip() for part in str(value).split(",")]
                self.assertEqual(parts, sorted(parts), f"{column} not deterministically ordered: {value}")

    # ── duplicate-rule rows (the event-vs-row identity trap) ───────────────
    def test_host_timeline_pages_survive_duplicate_rule_rows(self) -> None:
        """Two detections of ONE event must not swap places between pages.

        They share Timestamp, Computer, Channel and RecordID, so an ordering
        built from the event identity ties for them. page_size=1 makes every
        page boundary land between two tied rows.
        """
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.analyze_host_timeline(host_contains="HOST-DUP", **kw),
            "Timestamp",
            "RuleTitle",
            "Level",
            page_size=1,
        )

    def test_parse_details_pages_survive_duplicate_rule_rows(self) -> None:
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.parse_details_field(field_name="TgtUser", unique=False, **kw),
            "Timestamp",
            "RuleTitle",
            "Value",
            page_size=1,
        )

    # ── search_all_fields ──────────────────────────────────────────────────
    def test_search_all_fields_pages_reconstruct_whole(self) -> None:
        """Rows tied on every identity column must still page deterministically.

        search_all_fields ordered only by Timestamp/RecordID/Computer/
        RuleTitle/EventID while projecting the detail columns as well, so rows
        differing solely in Details were free to swap between pages.
        """
        self._assert_pages_reconstruct_whole(
            lambda **kw: server.search_all_fields(query="tie-", **kw),
            "Details",
            page_size=10,
        )

    def test_search_all_fields_order_is_repeatable(self) -> None:
        self._assert_repeatable(lambda **kw: server.search_all_fields(query="tie-", **kw), "Details")

    # ── the helper itself ──────────────────────────────────────────────────
    def test_total_order_terms_covers_projection_and_dedups(self) -> None:
        self.assertEqual(
            server._total_order_terms(["Timestamp", "RuleTitle"]),
            ['"Timestamp" ASC', '"RuleTitle" ASC'],
        )
        # A column repeated in the projection must not be ordered by twice.
        self.assertEqual(
            server._total_order_terms(["Level", "Level"], leading=["parsed ASC"]),
            ["parsed ASC", '"Level" ASC'],
        )
        self.assertEqual(server._total_order_terms([]), [])


if __name__ == "__main__":
    unittest.main()
