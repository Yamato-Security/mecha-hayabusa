<div align="center">
 <p>
    <img alt="Mecha Hayabusa Logo" src="mecha_hayabusa_logo.png" width="50%">
 </p>
 [ <b>English</b> ] | [<a href="README-Japanese.md">日本語</a>]
</div>

# Mecha Hayabusa

AI analyzer and DFIR timeline and report generation tool for Hayabusa results.

# About

**Mecha Hayabusa** connects the Windows event log analysis tool **Hayabusa** to large language models (LLMs) through the **Model Context Protocol (MCP)**, enabling natural-language driven digital forensics and threat hunting. Analysts can investigate CSV-based Windows event log datasets using capabilities such as MITRE ATT&CK tactic analysis, IOC extraction, lateral movement correlation, PowerShell decoding, and host-centric timeline analysis.

Hayabusa CSV timelines are automatically converted into a local **DuckDB** database, allowing LLMs to perform fast, structured analysis over large log datasets. The system provides capabilities including dataset switching and profiling, read-only SQL execution, cross-field search, rule title aggregation, time-window summarization, host timeline analysis, `Details` field parsing, IOC extraction, Base64-encoded PowerShell decoding, and lateral movement correlation.

Mecha Hayabusa also includes a dedicated **investigation skill** that standardizes the DFIR workflow and supports structured incident report generation in **Japanese or English**.

The key innovation of Mecha Hayabusa is enabling an LLM to execute a **structured DFIR investigation workflow through MCP**, rather than acting as a simple search interface. This approach supports the full investigation lifecycle—from dataset triage and hypothesis development to attack-phase analysis, host-level investigation, lateral movement correlation, and final report generation—while improving consistency and efficiency for incident responders.

# Preparing the Hayabusa CSV

Run Hayabusa with the **`verbose`** profile to create the CSV timeline (recommended):

```bash
hayabusa csv-timeline -d <EVTX_DIR> -o hayabusa-results.csv -p verbose -w
```

When you need the full, unabbreviated field information of each event, use the **`all-field-info-verbose`** profile instead:

```bash
hayabusa csv-timeline -d <EVTX_DIR> -o hayabusa-results.csv -p all-field-info-verbose -w
```

Profile differences that matter to Mecha Hayabusa (verified against Hayabusa 3.8.0 output):

| Profile | Detail columns | Field names in detail columns |
|---|---|---|
| `verbose` (recommended) | `Details` + `ExtraFieldInfo` | Abbreviated (e.g. `Cmdline`, `Proc`, `SrcIP`) |
| `all-field-info-verbose` | `AllFieldInfo` | Original event field names (e.g. `CommandLine`, `NewProcessName`, `SourceIp`) |

Notes:

- The detail-parsing tools (`parse_details_field`, `extract_iocs`, `decode_powershell_commands`, `analyze_mitre_tactics`) parse the `Details` column by default. When analyzing an `all-field-info-verbose` CSV, pass **`detail_source="AllFieldInfo"`**.
- Both profiles include the `MitreTactics` / `MitreTags` columns required by `analyze_mitre_tactics` and `correlate_lateral_movement`.

## How to execute（HTTP）

```bash
uv sync
uv run server.py --transport http --port 9999
```

Endpoint:

```text
http://127.0.0.1:9999/mcp
```

## How to add to Claude

```bash
claude mcp add --transport http hayabusa http://127.0.0.1:9999/mcp
```

Confirmation:

```bash
claude mcp list
```

## Prompt example:

### Use investigate Skill
```
Use Mecha Hayabusa to read hayabusa-results.csv and build an intrusion timeline and report.
```

<img width="1073" height="895" alt="Image" src="https://github.com/user-attachments/assets/8c972743-9f22-4278-a468-bd97376f1329" />

Results

<img width="1073" height="795" alt="Image" src="https://github.com/user-attachments/assets/4077c74f-fc85-4d07-9597-370a1e20582e" />

An HTML report will be generated. See the "samples" folder for an example.

<img width="1073" height="743" alt="Image" src="https://github.com/user-attachments/assets/2c5414f7-fc02-4db7-b85b-b62f4a03b9a4" />

<img width="1073" height="992" alt="Image" src="https://github.com/user-attachments/assets/4ba38a9b-1618-4c2c-86a2-7b621d205774" />

<img width="1073" height="682" alt="Image" src="https://github.com/user-attachments/assets/47919ec4-67e9-40bc-a503-26bef27cddcf" />

### Ask additional investigation and explanation

```
What happened in ACC-09?
```

<img width="1073" height="892" alt="Image" src="https://github.com/user-attachments/assets/bac54fd4-9e7c-401a-8fda-e6160dec0409" />

# Features

## Dataset Operations

Manage datasets used for analysis.

- **get_dataset_status**  
  Retrieve the status of the currently loaded dataset.

- **list_datasets**  
  List available CSV datasets for analysis.  
  Supports pagination.

- **switch_dataset**  
  Switch the active analysis dataset to a specified CSV file.

- **unload_dataset**  
  Unload the current `logs` table.

- **dataset_profile**  
  Retrieve a summary of the dataset, including:
  - total event count
  - time range
  - top trends

  Supports pagination.

---

## Query & Search

Search and query log data.

- **run_sql**  
  Execute a read-only `SELECT` query against the `logs` table.  
  Includes built-in safety constraints.

- **search_all_fields**  
  Perform keyword searches across all columns or specified columns.  
  Supports pagination.

- **get_event_detail**  
  Retrieve a single event in expanded `Field / Value` format.  
  Supports lookup by `RecordID` or query conditions.

---

## Timeline & Analytics

Analyze attack activity and event timelines.

- **analyze_mitre_tactics**  
  Perform chronological analysis of attack phases grouped by **MITRE ATT&CK tactics**.

- **analyze_host_timeline**  
  Extract chronological events for a specific host.  
  Useful for **compromise chain tracking**.

- **correlate_lateral_movement**  
  Correlate lateral movement activity between hosts within a specified time window.

- **summarize_events**  
  Aggregate log events by a specified field.

- **summarize_by_time_window**  
  Count events by time window:
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  Aggregate the frequency of `RuleTitle` occurrences with optional filtering conditions.

---

## Detail & IOC Analysis

Extract and analyze indicators from log details.

- **parse_details_field**  
  Extract key/value pairs from the `Details` field (default) or the `AllFieldInfo` field (`detail_source="AllFieldInfo"`).  
  Supports listing and unique aggregation.

- **extract_iocs**  
  Extract **Indicators of Compromise (IOCs)** from `Details` and `ExtraFieldInfo` (default) or `AllFieldInfo` (`detail_source="AllFieldInfo"`), categorized by type.

- **decode_powershell_commands**  
  Decode Base64-encoded PowerShell commands found in events.  
  Scans `Details`/`ExtraFieldInfo` by default, or `AllFieldInfo` with `detail_source="AllFieldInfo"`.

# Contributors

- Akira Nishikawa (https://github.com/nishikawaakira)
- Pinksawtooth (https://github.com/pinksawtooth | https://x.com/PINKSAWTOOTH)
- Zach Mathis / Tanaka Zakku (https://github.com/Yamato-Security/ | https://x.com/yamatosecurity)
