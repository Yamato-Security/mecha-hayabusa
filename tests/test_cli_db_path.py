"""--db-path must be resolved and validated at startup, always.

Two things go wrong when the option is only handled once it is supplied: the
startup banner prints the CWD-relative default it exists to disambiguate, and
an unusable path is accepted at startup and only fails later, from DuckDB, on
the first dataset load — far from the argument that caused it.

These exercise the real CLI, since that is where the behaviour lives.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SERVER = str(pathlib.Path(__file__).resolve().parent.parent / "server.py")
BANNER_TIMEOUT = 30.0


def _run_until_banner(args: list[str], cwd: str) -> tuple[int | None, str]:
    """Start the server, collect output up to the Database: line, stop it.

    The stdio transport blocks once started, so the process is terminated as
    soon as the banner has been seen.
    """
    process = subprocess.Popen(
        [sys.executable, "-u", SERVER, *args],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines: list[str] = []
    try:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line)
            if line.startswith("Database:"):
                break
    finally:
        process.terminate()
        try:
            remaining = process.communicate(timeout=BANNER_TIMEOUT)[0]
        except subprocess.TimeoutExpired:
            process.kill()
            remaining = process.communicate()[0]
        if remaining:
            lines.append(remaining)
    return process.returncode, "".join(lines)


class CliDbPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name).resolve()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_default_path_is_reported_resolved(self) -> None:
        # Without this, the banner prints the bare "hayabusa.duckdb" the option
        # was added to disambiguate — it looks like an answer but is not one.
        _, output = _run_until_banner(["--transport", "stdio"], cwd=str(self.dir))
        self.assertIn(f"Database: {self.dir / 'hayabusa.duckdb'}", output)

    def test_explicit_relative_path_is_reported_resolved(self) -> None:
        _, output = _run_until_banner(
            ["--transport", "stdio", "--db-path", "./custom.duckdb"], cwd=str(self.dir)
        )
        self.assertIn(f"Database: {self.dir / 'custom.duckdb'}", output)

    def test_missing_parent_directory_fails_at_startup(self) -> None:
        # Previously the server started and this surfaced later as a DuckDB
        # "No such file or directory" from the first switch_dataset call.
        result = subprocess.run(
            [sys.executable, "-u", SERVER, "--db-path", str(self.dir / "nope" / "x.duckdb")],
            cwd=str(self.dir),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=BANNER_TIMEOUT,
        )
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertIn("--db-path directory does not exist", combined)
        self.assertIn(str(self.dir / "nope"), combined)

    def test_startup_does_not_create_the_database(self) -> None:
        """The writability probe must not bring the database into existence.

        DuckDBRepository.is_initialised() is `db_path.exists()`, so creating an
        empty file here would make an unloaded server report itself as
        initialised — trading a clear "no dataset loaded" for a confusing
        failure on the first query.
        """
        target = self.dir / "created.duckdb"
        _run_until_banner(
            ["--transport", "stdio", "--db-path", str(target)], cwd=str(self.dir)
        )
        self.assertFalse(target.exists(), "startup must not create the database file")
        leftovers = [p.name for p in self.dir.iterdir() if p.name.startswith(".hayabusa-mcp-")]
        self.assertFalse(leftovers, f"probe file was left behind: {leftovers}")

    @unittest.skipUnless(os.name == "posix", "permission bits are POSIX-specific")
    def test_unwritable_parent_fails_at_startup(self) -> None:
        # Probing by writing answers for the user the process actually runs as,
        # so root legitimately passes here — mode-bit inspection would not.
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permissions, so there is nothing to catch")
        readonly = self.dir / "readonly"
        readonly.mkdir(mode=0o500)
        try:
            result = subprocess.run(
                [sys.executable, "-u", SERVER, "--db-path", str(readonly / "x.duckdb")],
                cwd=str(self.dir), stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=BANNER_TIMEOUT,
            )
        finally:
            readonly.chmod(0o700)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("directory is not writable", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "posix", "permission bits are POSIX-specific")
    def test_unwritable_existing_database_fails_at_startup(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root bypasses file permissions, so there is nothing to catch")
        existing = self.dir / "readonly.duckdb"
        existing.touch(mode=0o400)
        try:
            result = subprocess.run(
                [sys.executable, "-u", SERVER, "--db-path", str(existing)],
                cwd=str(self.dir), stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=BANNER_TIMEOUT,
            )
        finally:
            existing.chmod(0o600)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not writable", result.stdout + result.stderr)

    def test_directory_given_as_db_path_fails_at_startup(self) -> None:
        result = subprocess.run(
            [sys.executable, "-u", SERVER, "--db-path", str(self.dir)],
            cwd=str(self.dir),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=BANNER_TIMEOUT,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--db-path is not a file", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
