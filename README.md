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

Prompt example:
```
Use Mecha Hayabusa to read hayabusa-results.csv and build an intrusion timeline and report.
```

<img width="1190" height="211" alt="image" src="https://github.com/user-attachments/assets/7116517e-ce36-4f80-a474-931021875953" />

Results
<img width="2486" height="1488" alt="image" src="https://github.com/user-attachments/assets/78fe5337-768a-4ef5-9e44-6f9ac57e25ab" />


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
  Extract key/value pairs from the `Details` field.  
  Supports listing and unique aggregation.

- **extract_iocs**  
  Extract **Indicators of Compromise (IOCs)** from `Details` and `ExtraFieldInfo`, categorized by type.

- **decode_powershell_commands**  
  Decode Base64-encoded PowerShell commands found in events.

# Contributors

- Akira Nishikawa (https://github.com/nishikawaakira)
- Pinksawtooth (https://github.com/pinksawtooth | https://x.com/PINKSAWTOOTH)
- Zach Mathis / Tanaka Zakku (https://github.com/Yamato-Security/ | https://x.com/yamatosecurity)