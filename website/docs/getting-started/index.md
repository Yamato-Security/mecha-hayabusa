# Usage

## Preparing the Hayabusa CSV

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
