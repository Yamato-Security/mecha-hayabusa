"""decode_powershell_commands must recognise every spelling that executes.

PowerShell accepts more than `-EncodedCommand`, `-enc` and `-e`:
about_PowerShell_exe documents `-e` and `-ec` as its abbreviations, and the
native argument parser also takes ordinary prefixes (`-en`, `-enco`,
`-encod`, ...). Windows PowerShell takes `/` in place of `-` as well. A
spelling the tool does not recognise is a payload it never decodes, so these
tests pin the accepted set from both ends: the variants that must decode, and
the neighbouring switches that must not.
"""

from __future__ import annotations

import base64
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

PAYLOAD = base64.b64encode("Get-Process".encode("utf-16-le")).decode()

# Spellings that really do run an encoded command.
ACCEPTED = [
    ("HOST-ENC", f"Cmdline: powershell.exe -enc {PAYLOAD}"),
    ("HOST-EC", f"Cmdline: powershell.exe -ec {PAYLOAD}"),
    ("HOST-E", f"Cmdline: powershell.exe -e {PAYLOAD}"),
    ("HOST-FULL", f"Cmdline: powershell.exe -EncodedCommand {PAYLOAD}"),
    ("HOST-ENCOD", f"Cmdline: powershell.exe -encod {PAYLOAD}"),
    ("HOST-ENCODEDC", f"Cmdline: powershell.exe -encodedc {PAYLOAD}"),
    ("HOST-SLASH", f"Cmdline: powershell.exe /enc {PAYLOAD}"),
    ("HOST-MIXEDCASE", f"Cmdline: powershell.exe -EnCoDeDcOmMaNd {PAYLOAD}"),
    # PowerShell's parser tests the switch prefix with CharExtensions.IsDash,
    # which accepts three Unicode dashes as well as the ASCII hyphen. These are
    # what a command line becomes after a round trip through a word processor
    # or a chat client, and they still execute.
    ("HOST-ENDASH", f"Cmdline: powershell.exe \u2013ec {PAYLOAD}"),
    ("HOST-EMDASH", f"Cmdline: powershell.exe \u2014enc {PAYLOAD}"),
    ("HOST-HORIZBAR", f"Cmdline: powershell.exe \u2015EncodedCommand {PAYLOAD}"),
]

# Switches that start the same way but mean something else. Decoding these
# would put fabricated "commands" in front of an analyst.
REJECTED = [
    ("HOST-EXECPOL", "Cmdline: powershell.exe -ExecutionPolicy Bypass -File run.ps1"),
    ("HOST-ENCODING", "Cmdline: powershell.exe -Encoding UTF8 -Path C:\\tmp"),
    ("HOST-NOPROFILE", "Cmdline: powershell.exe -NoProfile -Command Get-Date"),
    ("HOST-NETUSE", "Cmdline: net use \\\\server\\share /user:admin Passw0rd"),
]


def _row(index: int, computer: str, details: str) -> list[str]:
    return [
        f"2024-05-01 00:{index:02d}:00.000 +00:00",
        "PowerShell Execution",
        "high",
        computer,
        "PowerShell",
        "4104",
        "Exec",
        "T1059.001",
        str(500 + index),
        details,
        "",
    ]


class EncodedPowerShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        tmpdir = pathlib.Path(self.tmp.name)
        self.csv_path = tmpdir / "sample.csv"
        self.db_path = tmpdir / "sample.duckdb"

        rows = [
            _row(index, computer, details)
            for index, (computer, details) in enumerate(ACCEPTED + REJECTED)
        ]
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(rows)

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

    def _decoded_hosts(self) -> set[str]:
        records = server.decode_powershell_commands(page_size=100).to_dict("records")
        return {r["Computer"] for r in records if r.get("Computer")}

    def test_every_accepted_spelling_is_decoded(self) -> None:
        decoded = self._decoded_hosts()
        missing = {computer for computer, _ in ACCEPTED} - decoded
        self.assertFalse(missing, f"encoded commands not decoded: {sorted(missing)}")

    def test_unrelated_switches_are_not_decoded(self) -> None:
        decoded = self._decoded_hosts()
        false_positives = decoded & {computer for computer, _ in REJECTED}
        self.assertFalse(
            false_positives,
            f"non-encoded command lines decoded as payloads: {sorted(false_positives)}",
        )

    def test_payload_decodes_to_the_original_text(self) -> None:
        records = server.decode_powershell_commands(page_size=100).to_dict("records")
        by_host = {r["Computer"]: r for r in records if r.get("Computer")}
        for computer, _ in ACCEPTED:
            self.assertIn("Get-Process", str(by_host[computer]["DecodedCommand"]))

    def test_sql_prefilter_and_python_matcher_agree(self) -> None:
        # The pre-filter decides which rows are ever fetched, so a spelling it
        # misses can never be decoded no matter how good the regex is. Both are
        # generated from one alternation; assert they really do agree.
        for _, details in ACCEPTED:
            self.assertTrue(
                server._ENCODED_PS_PATTERN.search(details),
                f"python matcher missed: {details}",
            )
            self.assertTrue(
                server.repo.query_dataframe(
                    "SELECT regexp_matches(lower(?), ?) AS hit", [details, server._ENCODED_PS_SQL_REGEX]
                ).iloc[0]["hit"],
                f"SQL pre-filter missed: {details}",
            )
        for _, details in REJECTED:
            self.assertIsNone(
                server._ENCODED_PS_PATTERN.search(details),
                f"python matcher false positive: {details}",
            )
            self.assertFalse(
                server.repo.query_dataframe(
                    "SELECT regexp_matches(lower(?), ?) AS hit", [details, server._ENCODED_PS_SQL_REGEX]
                ).iloc[0]["hit"],
                f"SQL pre-filter false positive: {details}",
            )

    def test_switch_prefix_covers_the_unicode_dashes(self) -> None:
        # A narrower class than PowerShell's own IsDash is a detection bypass,
        # not a style question.
        for char in ("-", "/", "\u2013", "\u2014", "\u2015"):
            self.assertIn(char, server._SWITCH_PREFIX_CHARS)

    def test_flag_set_covers_prefixes_and_documented_abbreviations(self) -> None:
        flags = set(server._ENCODED_PS_FLAGS)
        self.assertIn("ec", flags, "-ec is documented in about_PowerShell_exe")
        for length in range(1, len("encodedcommand") + 1):
            self.assertIn("encodedcommand"[:length], flags)


if __name__ == "__main__":
    unittest.main()
