"""Variant-coverage evidence (gate G10), the mixed verdict, and the
environment profile: a false_positive over a high-volume rule must enumerate
and judge every behavior variant, recounted deterministically from the CSV."""

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


def build_rows() -> list[list[str]]:
    rows = []
    # "Noisy" (24 events, above the variant threshold of 20):
    # 20x veeam->lsass (benign backup) + 4x evil->lsass (the attack hiding inside).
    for i in range(20):
        rows.append(["2024-01-01 00:00:00.000 +00:00", "Noisy", "high", "HOST-A", "Sysmon",
                     "10", str(1000 + i), "SrcProc: veeam.exe ¦ TgtProc: lsass.exe"])
    for i in range(4):
        rows.append(["2024-01-01 01:00:00.000 +00:00", "Noisy", "high", "HOST-A", "Sysmon",
                     "10", str(1020 + i), "SrcProc: evil.exe ¦ TgtProc: lsass.exe"])
    # "Empty" (21 events with an empty detail field).
    for i in range(21):
        rows.append(["2024-01-01 02:00:00.000 +00:00", "Empty", "high", "HOST-B", "Sec",
                     "4624", str(2000 + i), ""])
    # "HostKeyed" (24 events, ONE host, SIX distinct command lines): a
    # Computer-only variant key hides the diversity entirely.
    for i in range(24):
        rows.append(["2024-01-01 03:00:00.000 +00:00", "HostKeyed", "high", "HOST-D", "Sysmon",
                     "1", str(3000 + i), f"Cmdline: cmd{i % 6}.exe /install ¦ Proc: host.exe"])
    # "Uniform" (24 events, one host, a single identical command line).
    for i in range(24):
        rows.append(["2024-01-01 04:00:00.000 +00:00", "Uniform", "high", "HOST-E", "Sysmon",
                     "1", str(4000 + i), "Cmdline: saltcall.exe remove ¦ Proc: python.exe"])
    return rows


def run_state(*argv: str, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STATE_PY), *argv],
        input=stdin_data,
        capture_output=True,
        text=True,
    )


NOISY_VARIANTS = {
    "fields": ["SrcProc", "TgtProc"],
    "groups": [
        {"key": {"SrcProc": "veeam.exe", "TgtProc": "lsass.exe"}, "count": 20,
         "verdict": "benign", "note": "backup agent"},
        {"key": {"SrcProc": "evil.exe", "TgtProc": "lsass.exe"}, "count": 4,
         "verdict": "attack", "note": "credential access"},
    ],
}


class BehaviorVariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "noisy.csv"
        self.state_dir = tmpdir / "state"
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(build_rows())
        result = run_state("init", "--csv", str(self.csv_path), "--dir", str(self.state_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def triage(self, entry: dict) -> subprocess.CompletedProcess:
        return run_state("triage", "--dir", str(self.state_dir), "--batch",
                         stdin_data=json.dumps([entry], ensure_ascii=False))

    def gates(self) -> dict[str, dict]:
        result = run_state("check", "--dir", str(self.state_dir), "--json")
        payload = json.loads(result.stdout)
        return {g["id"]: g for g in payload["gates"]}

    def noisy_entry(self, **overrides) -> dict:
        entry = {
            "rule_title": "Noisy", "verdict": "mixed",
            "rationale": "veeam backup traffic plus evil.exe accessing lsass",
            "refs": [{"record_id": "1020", "computer": "HOST-A"}],
            "excerpt": "SrcProc: evil.exe ¦ TgtProc: lsass.exe",
            "variants": NOISY_VARIANTS,
        }
        entry.update(overrides)
        return entry

    # -- entry-time validation --------------------------------------------

    def test_high_volume_fp_without_variants_rejected(self) -> None:
        result = self.triage(self.noisy_entry(
            verdict="false_positive",
            refs=[{"record_id": "1000", "computer": "HOST-A"}],
            excerpt="SrcProc: veeam.exe ¦ TgtProc: lsass.exe",
            variants=None,
        ))
        self.assertEqual(result.returncode, 2)
        self.assertIn("variant", result.stderr.lower())

    def test_fp_with_attack_group_rejected(self) -> None:
        result = self.triage(self.noisy_entry(verdict="false_positive"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("mixed", result.stderr)

    def test_mixed_without_attack_group_rejected(self) -> None:
        variants = {
            "fields": ["SrcProc", "TgtProc"],
            "groups": [
                {"key": {"SrcProc": "veeam.exe", "TgtProc": "lsass.exe"}, "count": 20, "verdict": "benign"},
                {"key": {"SrcProc": "evil.exe", "TgtProc": "lsass.exe"}, "count": 4, "verdict": "benign"},
            ],
        }
        result = self.triage(self.noisy_entry(variants=variants))
        self.assertEqual(result.returncode, 2)
        self.assertIn("attack", result.stderr)

    def test_variant_sum_mismatch_rejected(self) -> None:
        variants = json.loads(json.dumps(NOISY_VARIANTS))
        variants["groups"][1]["count"] = 3  # 20 + 3 != 24
        result = self.triage(self.noisy_entry(variants=variants))
        self.assertEqual(result.returncode, 2)
        self.assertIn("23", result.stderr)

    def test_empty_detail_variant_cannot_be_benign(self) -> None:
        result = self.triage({
            "rule_title": "Empty", "verdict": "false_positive",
            "rationale": "no detail content recorded for these logons",
            "refs": [{"record_id": "2000", "computer": "HOST-B"}],
            "excerpt": "placeholder",
            "variants": {
                "fields": ["SrcProc", "TgtProc"],
                "groups": [{"key": {"SrcProc": "", "TgtProc": ""}, "count": 21, "verdict": "benign"}],
            },
        })
        self.assertEqual(result.returncode, 2)
        self.assertIn("indeterminate", result.stderr)

    # -- G10 recount against the CSV ---------------------------------------

    def test_valid_mixed_passes_g10(self) -> None:
        result = self.triage(self.noisy_entry())
        self.assertEqual(result.returncode, 0, result.stderr)
        gates = self.gates()
        self.assertEqual(gates["G10"]["status"], "PASS", gates["G10"])
        self.assertEqual(gates["G6"]["status"], "PASS", gates["G6"])

    def test_mixed_rule_requires_finding_via_g4(self) -> None:
        self.triage(self.noisy_entry())
        g4 = self.gates()["G4"]
        self.assertEqual(g4["status"], "FAIL")
        self.assertIn("Noisy", g4["gaps"])

    def test_recount_catches_wrong_distribution(self) -> None:
        # 19 + 5 = 24 passes the entry-time sum check, but the dataset says 20 + 4.
        self.triage(self.noisy_entry())
        triage_path = self.state_dir / "rule_triage.json"
        data = json.loads(triage_path.read_text(encoding="utf-8"))
        for rule in data["rules"]:
            if rule["rule_title"] == "Noisy":
                rule["variants"]["groups"][0]["count"] = 19
                rule["variants"]["groups"][1]["count"] = 5
        triage_path.write_text(json.dumps(data), encoding="utf-8")
        g10 = self.gates()["G10"]
        self.assertEqual(g10["status"], "FAIL")
        self.assertTrue(any("declared 19" in gap and "20" in gap for gap in g10["gaps"]), g10["gaps"])

    def test_recount_catches_unjudged_dataset_variant(self) -> None:
        # Declaring the benign variant as covering everything hides the evil one.
        self.triage(self.noisy_entry())
        triage_path = self.state_dir / "rule_triage.json"
        data = json.loads(triage_path.read_text(encoding="utf-8"))
        for rule in data["rules"]:
            if rule["rule_title"] == "Noisy":
                rule["verdict"] = "false_positive"
                rule["variants"]["groups"] = [
                    {"key": {"SrcProc": "veeam.exe", "TgtProc": "lsass.exe"},
                     "count": 24, "verdict": "benign", "note": ""},
                ]
        triage_path.write_text(json.dumps(data), encoding="utf-8")
        g10 = self.gates()["G10"]
        self.assertEqual(g10["status"], "FAIL")
        self.assertTrue(any("evil.exe" in gap and "not" in gap for gap in g10["gaps"]), g10["gaps"])

    # -- G10 probe: non-content grouping keys --------------------------------

    def test_non_content_key_hiding_diversity_fails_g10(self) -> None:
        result = self.triage({
            "rule_title": "HostKeyed", "verdict": "false_positive",
            "rationale": "bulk software rollout across the fleet",
            "refs": [{"record_id": "3000", "computer": "HOST-D"}],
            "excerpt": "Proc: host.exe",
            "variants": {
                "fields": ["Computer"],
                "groups": [{"key": {"Computer": "HOST-D"}, "count": 24, "verdict": "benign"}],
            },
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("non-content", result.stderr)  # entry-time warning
        g10 = self.gates()["G10"]
        self.assertEqual(g10["status"], "FAIL")
        self.assertTrue(
            any("content-bearing" in gap and "Cmdline" in gap for gap in g10["gaps"]),
            g10["gaps"],
        )

    def test_non_content_key_over_homogeneous_content_passes_with_warning(self) -> None:
        result = self.triage({
            "rule_title": "Uniform", "verdict": "false_positive",
            "rationale": "saltstack agent cleanup, identical on every event",
            "refs": [{"record_id": "4000", "computer": "HOST-E"}],
            "excerpt": "Cmdline: saltcall.exe remove",
            "variants": {
                "fields": ["Computer"],
                "groups": [{"key": {"Computer": "HOST-E"}, "count": 24, "verdict": "benign"}],
            },
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        g10 = self.gates()["G10"]
        self.assertEqual(g10["status"], "PASS", g10)
        self.assertIn("non-content", g10["detail"])

    def test_content_keyed_grouping_with_arg_diversity_passes(self) -> None:
        # Grouping by Proc while Cmdline varies is a deliberate, content-based
        # choice (e.g. same binary with random per-event arguments) — no probe.
        result = self.triage({
            "rule_title": "HostKeyed", "verdict": "false_positive",
            "rationale": "single installer binary invoked with varying arguments",
            "refs": [{"record_id": "3000", "computer": "HOST-D"}],
            "excerpt": "Proc: host.exe",
            "variants": {
                "fields": ["Proc"],
                "groups": [{"key": {"Proc": "host.exe"}, "count": 24, "verdict": "benign"}],
            },
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("non-content", result.stderr)
        g10 = self.gates()["G10"]
        self.assertEqual(g10["status"], "PASS", g10)
        self.assertNotIn("non-content", g10["detail"])

    # -- environment profile ------------------------------------------------

    def test_env_entry_recorded_and_in_appendix(self) -> None:
        result = run_state("env", "--dir", str(self.state_dir),
                           "--value", "Veeam Backup on all servers",
                           "--category", "backup", "--status", "operator_confirmed",
                           "--source", "user statement")
        self.assertEqual(result.returncode, 0, result.stderr)
        appendix = run_state("appendix", "--dir", str(self.state_dir), "--lang", "en")
        self.assertIn("Veeam Backup on all servers (operator_confirmed)", appendix.stdout)

    def test_env_none_declaration(self) -> None:
        result = run_state("env", "--dir", str(self.state_dir), "--none")
        self.assertEqual(result.returncode, 0, result.stderr)
        appendix = run_state("appendix", "--dir", str(self.state_dir), "--lang", "en")
        self.assertIn("explicitly declared", appendix.stdout)

    def test_env_requires_valid_status(self) -> None:
        result = run_state("env", "--dir", str(self.state_dir),
                           "--value", "something", "--status", "guessed")
        self.assertEqual(result.returncode, 2)
        self.assertIn("operator_confirmed", result.stderr)


if __name__ == "__main__":
    unittest.main()
