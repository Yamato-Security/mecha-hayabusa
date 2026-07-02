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
