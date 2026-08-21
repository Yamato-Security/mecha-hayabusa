# Changes

## 1.1.0 [2026/08/21]

**New Features:**

- Added evtx reachability tracking (`state.py reach`) and gate G12, so an investigation can tell "absent from the timeline" apart from "absent from the logs". A Hayabusa CSV holds only events that matched a rule, so everything no rule matched is missing from it while still present in the evtx; on a 7,928-file / 36.7 GiB corpus, 1,968 of 2,072 `(channel, event id)` pairs never matched any rule — 44,010,488 of 59,884,494 events (73.5%) are of a type the timeline can never surface. `reach --eid-metrics` imports `hayabusa eid-metrics` output taken over the original evtx and records exactly which pairs are unreachable, and `reach --ioc` records a `hayabusa search` search-back so a known IOC can be reconciled against the raw corpus. (#45) (@YamatoSecurity)
- Added gate G12, which fails when a triage rationale or finding summary asserts absence ("no evidence of", "left no trace", and the Japanese equivalents) without a recorded evtx search-back, and when a recorded search-back still finds more in the raw corpus than the timeline holds. That difference is where missed hosts hide: on the corpus above, a C2 domain present 505 times across three hosts in the raw evtx appeared exactly once in the timeline, and two of the three hosts were consequently left out of the finding. `reach --none --reason ...` records the limitation explicitly when the original evtx is unavailable. (#45) (@YamatoSecurity)
- Added the measured coverage figure to the report appendix, so a reader sees how much of the evtx corpus the timeline could ever surface instead of assuming it is complete. The figure is computed from corpus events on both sides rather than from rule-match rows, which double-count events matched by several rules. (#45) (@YamatoSecurity)

## 1.0.1 [2026/08/20]

**Bug Fixes:**

- Fixed count-based Hayabusa correlation rules being impossible to triage, which blocked report generation entirely. Those rules emit one aggregated row per correlation window with an empty `RecordID`, but `state.py` demanded evidence refs whenever the dataset merely had a `RecordID` *column*, so no verdict — not even `indeterminate` — could be recorded for them, gate G1 never reached zero pending, and `report.py` refused to generate. A triage entry, or a finding resting entirely on such rules, may now declare `"refs_unavailable": true`; the gates verify that claim against the dataset and reject it when the rule does have rows carrying RecordIDs, so the row-level audit guarantee is preserved rather than waived. (#38 #39) (@YamatoSecurity)
- Fixed detail parsing dropping every field of a count-based correlation rule. Those rules render fields as `Key:Value` with no space after the colon, so nothing was extracted, which made variant evidence — and therefore a `false_positive` verdict over 20 events — unreachable for them. The new form is a fallback that only applies to a pair the normal rule rejected and only for field-name-shaped keys of at least two characters, so a drive letter is never mistaken for a field and `C:\Windows\foo.exe` still parses to nothing. Verified against a 3,254,344-row timeline: 1,950 rows gain fields and no existing field changes. (#38 #39) (@YamatoSecurity)
- Fixed host coverage asking for pseudo-hosts. A correlation row can aggregate several machines into one `Computer` value joined by the detail separator, which reached gate G2 as a single unusable host name; the constituent hosts are now counted individually. (#38 #39) (@YamatoSecurity)

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
