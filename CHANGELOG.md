# Changes

## 1.1.0 [2026/08/21]

**New Features:**

- Added evtx identity-representation measurement (`state.py reach --eid-metrics`), so an investigation can quantify which `(channel, event id)` values from the collected evtx are not unambiguously represented in the supplied timeline instead of assuming the CSV is a complete copy. RecordID-bearing event rows and correlation pairs forced by the same-corpus candidate graph count as represented; remaining optional mappings produce a lower/upper range and a persisted list of undetermined pairs. On a 7,928-file / 36.7 GiB corpus, 1,959 of 2,072 pairs — 43,981,154 of 59,884,494 events (73.4%) — were absent from the timeline's identity fields, with no undetermined pairs. Both identity components use the same Unicode lowercase normalization as `eid-metrics`, rather than broader case folding, so distinct exporter keys such as `ß` and `ss` remain distinct; rows that channel abbreviation collapses onto one displayed name — the four AppLocker sub-channels, the two Security-Mitigations ones — are summed rather than read as a tampered file. Incompatible event pairs and concrete correlation projections are refused rather than recorded as a false figure. A blank EventID on a direct RecordID-bearing row maps to the concrete corpus identity `null`, a literal `-` remains literal, and an empty aggregate component never makes unrelated concrete IDs on its channel candidates. Percentage envelopes are derived from integer event counts and rounded outward; renderers use `<0.01%` / `>99.99%` notation for nonzero values below display precision instead of moving a bound inward. (#45) (@YamatoSecurity)
- Added the measured figure and any ambiguity range to the report appendix, together with the caveat that filtering by time, host, level or rule can inflate the representation gap, and `reach --none --reason ...` to record explicitly that the original evtx was unavailable. The comparison establishes only identity representation in the supplied timeline; it does not establish that an event matched no rule, could never be surfaced, or is absent from the logs. `init` clears any recorded measurement along with the rest of the state. Before `reach --list` or the appendix publishes a result, the current timeline bytes are re-hashed and compared with the manifest's dataset hash and the measurement's recorded timeline hash; missing, unreadable, or mismatched provenance is withheld rather than reported as this investigation's coverage. (#45) (@YamatoSecurity)

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
