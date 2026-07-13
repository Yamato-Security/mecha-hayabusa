"""EN/JP skill script parity.

The investigate (EN) and investigate_jp (JP) skills ship separate copies of the
same scripts. Security and correctness fixes must land in both, so this test
fails whenever the copies drift apart beyond an explicit allowlist of
language-specific tokens (report appendix language, default chart titles).

To fix a failure: apply the same change to both copies, or — if the difference
is genuinely language-specific — add the token pair to the allowlist below.
"""

from __future__ import annotations

import difflib
import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
JP_SCRIPTS = REPO_ROOT / "skill" / "investigate_jp" / "scripts"
EN_SCRIPTS = REPO_ROOT / "skill" / "investigate" / "scripts"

# script name -> {JP-only token: EN counterpart}. After substituting the JP
# tokens with their EN counterparts, the two files must be byte-identical.
PAIRED_SCRIPTS: dict[str, dict[str, str]] = {
    "state.py": {},
    "report.py": {'APPENDIX_LANG = "ja"': 'APPENDIX_LANG = "en"'},
    "timeline_chart.py": {},
    "mitre_flow.py": {},
    "lateral_movement_chart.py": {
        "横展開分析 (Lateral Movement)": "Lateral Movement Analysis",
    },
}


class SkillScriptParityTests(unittest.TestCase):
    def test_every_shared_script_is_paired(self) -> None:
        """A script added to one skill must be added to the other (and listed here)."""
        jp_names = {p.name for p in JP_SCRIPTS.glob("*.py")}
        en_names = {p.name for p in EN_SCRIPTS.glob("*.py")}
        self.assertEqual(
            jp_names, en_names,
            "investigate/scripts and investigate_jp/scripts contain different files",
        )
        unlisted = sorted(jp_names - set(PAIRED_SCRIPTS))
        self.assertFalse(
            unlisted,
            f"new shared script(s) {unlisted} must be added to PAIRED_SCRIPTS in {__file__}",
        )

    def test_scripts_match_modulo_language_tokens(self) -> None:
        for name, substitutions in PAIRED_SCRIPTS.items():
            with self.subTest(script=name):
                jp_text = (JP_SCRIPTS / name).read_text(encoding="utf-8")
                en_text = (EN_SCRIPTS / name).read_text(encoding="utf-8")
                normalized = jp_text
                for jp_token, en_token in substitutions.items():
                    self.assertIn(
                        jp_token, jp_text,
                        f"{name}: expected JP token {jp_token!r} not found — "
                        "update PAIRED_SCRIPTS if the language-specific token changed",
                    )
                    normalized = normalized.replace(jp_token, en_token)
                if normalized != en_text:
                    diff = "\n".join(
                        difflib.unified_diff(
                            normalized.splitlines(),
                            en_text.splitlines(),
                            fromfile=f"investigate_jp/scripts/{name} (normalized)",
                            tofile=f"investigate/scripts/{name}",
                            lineterm="",
                        )
                    )
                    self.fail(
                        f"{name} drifted between the EN and JP skills — apply the fix to "
                        f"both copies:\n{diff[:4000]}"
                    )


if __name__ == "__main__":
    unittest.main()
