"""Behavioral tests for the investigate skill's chart generator scripts.

The chart scripts read a JSON object on stdin and write an HTML file. These
tests exercise the input-validation contract (clean error + non-zero exit on
bad input, instead of an uncaught traceback) and a valid end-to-end generation.
Both skill trees (investigate and investigate_jp) are covered so the JP copies
cannot drift or regress unnoticed.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_DIRS = [
    REPO_ROOT / "skill" / "investigate" / "scripts",
    REPO_ROOT / "skill" / "investigate_jp" / "scripts",
]

# script -> a minimal valid payload (without the "output" key, added per test).
VALID_PAYLOADS = {
    "mitre_flow.py": {
        "tactics": [
            {"id": "TA0001", "name": "Initial Access", "techniques": ["T1566"], "hosts": ["HOST-A"], "event_count": 1}
        ]
    },
    "timeline_chart.py": {
        "events": [
            {"timestamp": "2024-01-01T00:00:00", "host": "HOST-A", "rule": "R", "level": "high"}
        ]
    },
    "lateral_movement_chart.py": {
        "movements": [
            {
                "source_time": "2024-01-01T00:00:00Z", "source_host": "HOST-A",
                "source_event": "e", "source_level": "high",
                "target_time": "2024-01-01T00:05:00Z", "target_host": "HOST-B",
                "target_event": "e", "target_level": "high", "delta_minutes": 5.0,
            }
        ]
    },
}


def _run(scripts_dir: pathlib.Path, script: str, stdin_text: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(scripts_dir / script)],
        input=stdin_text,
        capture_output=True,
        text=True,
    )


# script -> payloads whose *items* are malformed. The top-level object and its
# keys are present, so these only fail if each collection and each item is
# validated too. Every one of them was an uncaught traceback before.
MALFORMED_ITEM_PAYLOADS = {
    "timeline_chart.py": [
        ("collection is not a list", {"events": "nope"}),
        ("event is not an object", {"events": [None]}),
        ("event missing timestamp", {"events": [{"host": "HOST-A"}]}),
        ("event missing host", {"events": [{"timestamp": "2024-01-01T00:00:00"}]}),
        ("unparseable timestamp", {"events": [{"timestamp": "not-a-date", "host": "HOST-A"}]}),
        ("non-string host", {"events": [{"timestamp": "2024-01-01T00:00:00", "host": 7}]}),
    ],
    "mitre_flow.py": [
        ("collection is not a list", {"tactics": {"id": "TA0001"}}),
        ("tactic is not an object", {"tactics": [None]}),
        ("techniques is not a list", {"tactics": [{"id": "TA0001", "techniques": "T1566"}]}),
        ("technique is not a string", {"tactics": [{"id": "TA0001", "techniques": [None]}]}),
        ("hosts entry is not a string", {"tactics": [{"id": "TA0001", "hosts": [None]}]}),
        ("event_count is not a number", {"tactics": [{"id": "TA0001", "event_count": "many"}]}),
    ],
    "lateral_movement_chart.py": [
        ("collection is not a list", {"movements": 5}),
        ("movement is not an object", {"movements": ["A -> B"]}),
        ("movement missing source_host", {"movements": [{"target_host": "HOST-B"}]}),
        ("movement missing target_host", {"movements": [{"source_host": "HOST-A"}]}),
        ("non-string target_host", {"movements": [{"source_host": "HOST-A", "target_host": 2}]}),
    ],
}

# Optional fields explicitly set to null must be tolerated, not rejected: a
# generator that emits every key with an empty value is well-formed input.
NULL_OPTIONAL_PAYLOADS = {
    "timeline_chart.py": {
        "events": [{"timestamp": "2024-01-01T00:00:00", "host": "HOST-A",
                    "rule": None, "level": None, "mitre": None}]
    },
    "mitre_flow.py": {
        "tactics": [{"id": "TA0001", "name": None, "techniques": None,
                     "hosts": None, "time_range": None}]
    },
    "lateral_movement_chart.py": {
        "movements": [{"source_host": "HOST-A", "target_host": "HOST-B",
                       "source_time": None, "target_time": None,
                       "source_level": None, "target_level": None}]
    },
}


class ChartScriptTests(unittest.TestCase):
    def test_missing_required_key_exits_cleanly(self) -> None:
        for scripts_dir in SCRIPT_DIRS:
            for script in VALID_PAYLOADS:
                with self.subTest(tree=scripts_dir.parent.name, script=script):
                    res = _run(scripts_dir, script, json.dumps({"output": "/tmp/unused.html"}))
                    self.assertEqual(res.returncode, 2)
                    self.assertIn("missing required key", res.stderr)
                    self.assertEqual(res.stdout.strip(), "")

    def test_invalid_json_exits_cleanly(self) -> None:
        for scripts_dir in SCRIPT_DIRS:
            for script in VALID_PAYLOADS:
                with self.subTest(tree=scripts_dir.parent.name, script=script):
                    res = _run(scripts_dir, script, "this is not json {")
                    self.assertEqual(res.returncode, 2)
                    self.assertIn("not valid JSON", res.stderr)

    def test_non_object_input_exits_cleanly(self) -> None:
        for scripts_dir in SCRIPT_DIRS:
            for script in VALID_PAYLOADS:
                with self.subTest(tree=scripts_dir.parent.name, script=script):
                    res = _run(scripts_dir, script, json.dumps([1, 2, 3]))
                    self.assertEqual(res.returncode, 2)
                    self.assertIn("must be a JSON object", res.stderr)

    def test_valid_input_generates_html(self) -> None:
        for scripts_dir in SCRIPT_DIRS:
            for script, payload in VALID_PAYLOADS.items():
                with self.subTest(tree=scripts_dir.parent.name, script=script):
                    with tempfile.TemporaryDirectory() as d:
                        out = pathlib.Path(d) / "chart.html"
                        body = dict(payload)
                        body["output"] = str(out)
                        res = _run(scripts_dir, script, json.dumps(body))
                        self.assertEqual(res.returncode, 0, res.stderr)
                        self.assertTrue(out.exists())
                        self.assertGreater(out.stat().st_size, 0)


    def test_malformed_items_exit_cleanly(self) -> None:
        """Bad values inside a collection must not surface as a traceback.

        The top-level object and its keys are present in every case here, so
        these only pass if each collection and each item is validated too.
        """
        for scripts_dir in SCRIPT_DIRS:
            for script, cases in MALFORMED_ITEM_PAYLOADS.items():
                for label, payload in cases:
                    with self.subTest(tree=scripts_dir.parent.name, script=script, case=label):
                        with tempfile.TemporaryDirectory() as tmp:
                            payload = {**payload, "output": str(pathlib.Path(tmp) / "chart.html")}
                            result = _run(scripts_dir, script, json.dumps(payload))
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("Traceback", result.stderr)
                        self.assertTrue(
                            result.stderr.strip().startswith("error:"),
                            f"expected a clean error line, got: {result.stderr!r}",
                        )

    def test_malformed_item_error_names_the_index(self) -> None:
        # "events[3] is missing required key" is actionable; "KeyError" is not.
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "events": [
                    {"timestamp": "2024-01-01T00:00:00", "host": "HOST-A"},
                    {"timestamp": "2024-01-01T00:01:00", "host": "HOST-B"},
                    {"timestamp": "2024-01-01T00:02:00"},
                ],
                "output": str(pathlib.Path(tmp) / "chart.html"),
            }
            result = _run(SCRIPT_DIRS[0], "timeline_chart.py", json.dumps(payload))
        self.assertIn("events[2]", result.stderr)
        self.assertIn("host", result.stderr)

    def test_null_optional_fields_are_tolerated(self) -> None:
        """Explicit nulls on optional fields are well-formed input.

        Validation must not turn a generator that emits every key with an
        empty value into an error.
        """
        for scripts_dir in SCRIPT_DIRS:
            for script, payload in NULL_OPTIONAL_PAYLOADS.items():
                with self.subTest(tree=scripts_dir.parent.name, script=script):
                    with tempfile.TemporaryDirectory() as tmp:
                        output = pathlib.Path(tmp) / "chart.html"
                        result = _run(
                            scripts_dir, script, json.dumps({**payload, "output": str(output)})
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
