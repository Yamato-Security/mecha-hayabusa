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


if __name__ == "__main__":
    unittest.main()
