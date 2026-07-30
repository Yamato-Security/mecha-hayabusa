# Changes

## 1.0.0 [2026/07/31] - Black Hat Arsenal USA 2026 Release

First public release. Mecha Hayabusa is an MCP server plus an `investigate` skill that let an AI
assistant query [Hayabusa](https://github.com/Yamato-Security/hayabusa) results in natural
language, build a DFIR timeline, and write up the findings — with the log data staying in a local
DuckDB file.

**New Features:**

- Added the MCP server and the `investigate` skill in English and Japanese variants, so an assistant can be pointed at a Hayabusa result set and asked questions in either language. (#2) (@pinksawtooth)
- Added coverage-gated investigation state tracking, so a run reports what it has and has not examined instead of leaving the analyst to infer it. (#7) (@pinksawtooth)
- Added a lateral movement (propagation path) chart visualization. (#3) (@nishikawaakira)
- Added a `detail_source` option so the tools can read Hayabusa's `AllFieldInfo` profile output as well as the default profile. (#6) (@pinksawtooth)
- Added a multilingual Material for MkDocs documentation site published to GitHub Pages, and replaced the README with a landing page pointing at it. (#4 #5) (@YamatoSecurity)
- Added `--db-path`, and documented the single-client model that follows from DuckDB allowing one writer. (#10 #19) (@YamatoSecurity)
- `correlate_lateral_movement` now refuses runs whose input is too broad to serve rather than attempting a lateral join that cannot complete, and says what to narrow. (#27 #31) (@YamatoSecurity)

**Enhancements:**

- Chart-script input is validated before use, with behavioral tests covering the generated scripts. (#13 #24) (@YamatoSecurity)
- Documented skill installation and `--dataset-root`, and fixed the language switcher in the Japanese README. (#14 #21) (@YamatoSecurity)
- Extracted the pagination response coda that was repeated across the paginated tools. (#12 #25) (@YamatoSecurity)

**Bug Fixes:**

- Chart tooltips interpolated untrusted log data without escaping, so a crafted field value in a Hayabusa result could inject markup into a generated chart opened in a browser. Tooltip data is now escaped. (#8 #17) (@YamatoSecurity)
- `decode_powershell_commands` silently truncated its scan, so encoded commands past the cut-off were never reported — an absence that read as "nothing found". It now scans the full input. (#9 #18) (@YamatoSecurity)
- `-EncodedCommand` was matched too narrowly, missing spellings PowerShell itself accepts, so encoded payloads using an abbreviated or differently-cased form went undecoded. Every executable spelling is now recognised. (#28 #32) (@YamatoSecurity)
- Paginated tools ordered rows by a non-total key, so two pages of the same query could repeat or omit a row. The orderings are now total and the pages reproducible. (#26 #30) (@YamatoSecurity)
- Corrected localization drift between the English and Japanese skills, where the two had diverged on chart labels. (#11 #20) (@YamatoSecurity)

**Other:**

- Documentation builds run with `--strict` on pull requests, and the checkout action version is unified across workflows. (#16 #23) (@YamatoSecurity)
- Filled in the placeholder project description in `pyproject.toml`. (#15 #22) (@YamatoSecurity)
- Added the skill's `work/` scratch directory to `.gitignore`, so generated datasets and draft reports are not committed by accident. (#29 #33) (@YamatoSecurity)
