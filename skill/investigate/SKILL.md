---
name: investigate
description: "Incident investigation and timeline generation skill using Hayabusa MCP. Use when the user types /investigate, or asks to 'investigate logs', 'analyze security events', 'create an incident timeline', 'forensic analysis', 'analyze this CSV' in the context of security log analysis. Requires Hayabusa MCP tools to be available."
---

# Investigate - Hayabusa Incident Timeline Investigation

Systematically analyze CSV logs using Hayabusa MCP tools to generate an incident forensic report in English. A universal investigation framework that handles all types of cyber attacks (APT, ransomware, insider threats, web compromises, supply chain attacks, etc.).

## Arguments

- Optional: CSV file path
- Example: `/investigate /path/to/results.csv`

## Workflow

Execute the following steps in order. Independent tool calls within each step should be run **in parallel** to minimize latency.

### Step 1: Identify Target CSV and Load Dataset

1. **Record investigation start time**: Run `date '+%Y-%m-%d %H:%M:%S'` via Bash tool and note the start time (used for report metadata in Step 7)
2. If a CSV path is specified as an argument → use that path
3. If no argument is given → use `mcp__hayabusa__list_datasets` to list CSV files under the current directory, then use `AskUserQuestion` tool to have the user select the target file. Confirm with the user even if there is only one candidate
4. Load the user's selected CSV via `mcp__hayabusa__switch_dataset`

### Step 2: Profile Dataset and Determine Investigation Strategy

Use `mcp__hayabusa__dataset_profile` to get an overview of the dataset. Information obtained:
- Event time range (timestamp_min / timestamp_max)
- Counts by severity (info / low / med / high / crit)
- Counts by host
- Top rule titles

Based on these results, **form a hypothesis about the nature of the incident** and adaptively adjust subsequent investigation parameters:
- crit/high concentrated on a few hosts → possible targeted attack (APT). Prioritize deep-diving those hosts
- crit/high occurring across all hosts in a short time → possible ransomware/worm. Set short time windows (1h)
- Massive activity from specific accounts → possible credential theft/insider threat. Emphasize account-based analysis
- Only med or below with no clear crit/high → possible slow reconnaissance. Expand analysis to include med

### Step 3: Establish Attack Overview (Parallel Execution)

Call the following 3 **simultaneously**:

1. **`mcp__hayabusa__analyze_rule_titles`** — with `level: ["high", "crit"]` to aggregate high/crit rule titles. Get the overall picture of attack techniques and affected hosts. Fall back to `level: "med"` if no crit/high exist
2. **`mcp__hayabusa__analyze_mitre_tactics`** — MITRE ATT&CK tactics analysis. Understand the coverage and timeline of attack phases
3. **`mcp__hayabusa__summarize_by_time_window`** — Understand temporal concentration of activity. Adjust interval based on incident duration:
   - Within 24 hours: `"1h"`
   - 1-7 days: `"3h"`
   - Over 7 days: `"12h"` or `"1d"`

### Step 3.5: Verify Details of All Rule Titles (False Positive Elimination) - CRITICAL

**This step must not be skipped.** For all rule titles obtained from `analyze_rule_titles` in Step 3, retrieve the Details field from 1-2 sample events per rule and **verify the actual content before determining whether it's an attack or false positive**.

#### Method

For **all distinct rule titles** detected in Step 3, retrieve representative event Details using the following SQL:

```sql
SELECT Timestamp, Computer, RuleTitle, Level, Details
FROM logs WHERE RuleTitle = '[rule title]'
ORDER BY Timestamp LIMIT 2
```

When there are many rule titles (>10), parallelize/optimize using:
- Combine multiple rule titles with `WHERE RuleTitle IN (...)`
- Limit to 5 rules per query with LIMIT 10 to ensure at least 1 event per rule

#### Verification Criteria

Check the following from each rule's Details. **Rules determined to be false positives should be excluded from the report (or listed in Section 9's false positive section)**:

1. **Process path legitimacy**: Is it a legitimate Windows service like `C:\Windows\system32\svchost.exe -k print`?
2. **Service name/description**: Is the service name in Details a legitimate Windows feature?
3. **Binary provenance**: Do Description/Product/Company fields indicate a legitimate vendor product? (e.g., "Winlogbeat ships Windows event logs" → legitimate Elastic tool)
4. **File path suspiciousness**: Is it in attacker-favored staging directories like `C:\Users\Public\`, `C:\Windows\Temp\<random>`, `C:\ProgramData\`?
5. **Parent process check**: Is ParentCmdline a legitimate service manager (services.exe, svchost.exe) or a suspicious process (cmd.exe, powershell.exe, wsmprovhost.exe)?
6. **User context**: Is it a legitimate scheduled task under SYSTEM, or suspicious execution under a regular user account?

#### Common False Positive Patterns (Exclusion Candidates)

The following are frequently occurring false positive patterns. If Details content matches, exclude from the attack timeline and list in Section 9:

- **Suspicious Service Path**: Legitimate service paths like `svchost.exe -k print` (print service), `svchost.exe -k netsvcs` (general Windows service)
- **LOLBAS Renamed**: Renamed binaries of legitimate tools (Elastic Winlogbeat, Velociraptor, etc.) where Description/Product indicates a legitimate vendor. However, **attackers may also spoof tool attributes, so make a comprehensive judgment including deployment path and execution context**
- **Proc Access (Sysmon Alert)**: Legitimate inter-process access between Veeam Backup, Defender ATP, sppsvc.exe, etc.
- **Proc Exec (Sysmon Alert)**: Windows scheduled tasks (makecab, rundll32 Windows.Storage.*), Windows Update related

#### Attack Infrastructure Discovery

During Details verification, if the following attack infrastructure patterns are found, **record them and add to Step 5 deep-dive targets**:

- **Staging directories**: Executables or DLLs placed in `C:\Users\Public\`, `C:\ProgramData\`, `C:\Windows\Temp\<random>`, `C:\Perflogs\`, etc.
- **Same PID detected by multiple rules**: When the same PID/PGUID is detected by different rules, it indicates multifaceted malicious activity from the same process
- **Suspicious DLL loading**: rundll32.exe loading DLLs from paths other than System32 (e.g., `rundll32 C:\Users\Public\Music\*.dll`)

### Step 4: Detailed Investigation (Parallel Execution)

Call the following 4 **simultaneously**:

1. **`mcp__hayabusa__run_sql`** — `SELECT Timestamp, RuleTitle, Level, Computer, Details FROM logs WHERE Level = 'crit' ORDER BY Timestamp` to get full details of all crit events. Expand to high if no crit events exist
2. **`mcp__hayabusa__extract_iocs`** — with `level: ["high", "crit"]` to extract IOCs (processes, command lines, IPs, users, hashes, etc.)
3. **`mcp__hayabusa__correlate_lateral_movement`** — with `time_window_minutes: 60`, `level: ["high", "crit"]` to detect inter-host lateral movement patterns. Empty results for single-host incidents are themselves evidence of no lateral movement
4. **`mcp__hayabusa__parse_details_field`** — with `field_name: "User"`, `level: ["high", "crit"]`, `unique: true` to aggregate accounts involved in the attack. Identifying the attack principal is required for virtually all incidents

### Step 5: Adaptive Deep Dive (Parallel Execution)

Based on Step 3-4 results, **select and simultaneously call** the necessary tools from below according to threats present in the data:

#### Always execute:
- **`mcp__hayabusa__analyze_host_timeline`** — Get the timeline of the most suspicious host

#### Conditional execution:
- **`mcp__hayabusa__decode_powershell_commands`** — Execute when PowerShell-related rules (Encoded PowerShell, PowerShell ScriptBlock, etc.) are detected in Step 3
- **`mcp__hayabusa__parse_details_field`** — When specific field deep-dives are needed (e.g., `field_name: "Cmdline"` for command list, `field_name: "User"` for account analysis)
- **`mcp__hayabusa__search_all_fields`** — When specific IOCs (filenames, IPs, hashes, etc.) are found in Steps 3-4, cross-search all fields to identify related events
- **`mcp__hayabusa__run_sql`** — When additional custom queries are needed (e.g., event list for a specific host during a specific time window)

Criteria for "most suspicious host" (priority order):
1. Host with the most crit events
2. Host identified as the lateral movement origin
3. Host where high/crit was first detected (Patient Zero candidate)
4. Host appearing across multiple MITRE tactic phases

#### Attack infrastructure cross-search (required if discovered in Step 3.5):

If attacker staging directories (e.g., `C:\Users\Public\Music\`) or suspicious process paths were found in Step 3.5, use `search_all_fields` to cross-search those paths across all fields to **comprehensively identify other tools and related activity in the same directory**.

#### Full activity period coverage (required if multiple clusters found in Step 3 time window):

If `summarize_by_time_window` in Step 3 detects multiple discontinuous activity clusters (e.g., 2023-03, 2023-04, 2023-11, 2024-09), **verify representative events for all clusters**. Specifically, execute the following SQL for each cluster's time range:

```sql
SELECT Timestamp, Computer, RuleTitle, Level, Details
FROM logs WHERE Timestamp >= '[cluster start]' AND Timestamp <= '[cluster end]'
AND Level IN ('high','crit')
ORDER BY Timestamp LIMIT 20
```

This helps identify cases where what was assumed to be a "wave N attack" is actually normal activity (Windows scheduled tasks, etc.). Clusters without clear attack activity should not be reported as "attack campaigns."

### Step 5.5: Process Correlation & Network Mapping (Parallel Execution)

After key events are identified from Steps 4-5, perform the following correlation analysis:

#### PID/PGUID Correlation:
When the same PID/PGUID is detected by multiple different rules, they represent **different malicious behaviors of the same process**. Cross-reference PID/PGUIDs in Details fields. For example:
- rundll32.exe (PID X) that loaded a Qakbot DLL also made RDP connections with the same PID → the DLL has built-in RDP capability
- PsExec.exe (PID Y) making network connections (port 135/445) while simultaneously creating remote services → full picture of lateral movement

#### IP → Hostname Mapping:
For internal IP addresses detected in IOC extraction or Details, check which Computer name is associated with the same IP in other events:
```sql
SELECT DISTINCT Computer, Details FROM logs
WHERE Details LIKE '%10.65.45.XXX%' LIMIT 5
```

#### SID → Account Name Resolution:
When events like "User Added To Local Admin Grp" only record SIDs, search whether the same SID appears with an account name in other events:
```sql
SELECT Details FROM logs WHERE Details LIKE '%S-1-5-21-XXXX%' LIMIT 5
```

#### Hash IOC Collection:
Record Hashes values (SHA256, SHA1, MD5) from Details fields confirmed in Steps 3.5-5 for attack-related processes/DLLs. The following hashes in particular should be included in the report's IOC section:
- Hashes of files placed in attacker staging directories
- Hashes of attack tools (PsExec, Mimikatz, BloodHound, etc.)
- Hashes of suspicious DLLs

### Step 6: Visualization Chart Generation

Generate timeline charts and MITRE ATT&CK flow diagrams from investigation data and embed them in the report.

**Important**: Scripts are located in this skill's `scripts/` subdirectory. The script base directory is:
```
SCRIPT_DIR="$HOME/.claude/skills/investigate/scripts"
```

**Note**: `~` or Glob tool may not resolve paths correctly. Always use the **Bash tool** for script existence checks and execution, referencing with absolute paths using `$HOME`. Do not use the Glob tool to search for scripts.

#### 6-0. Create Output Directory

Before generating any output files, create a directory named after the CSV file (without extension) with a timestamp suffix in the same directory as the CSV. All output files (charts and report) will be saved inside this directory.

```bash
mkdir -p "[CSV directory]/[CSV filename without extension]_[YYYY-MM-DDTHHMI]"
```

- `[YYYY-MM-DDTHHMI]`: Local timestamp at the time of directory creation (to the minute)

For example, if the CSV is `/data/hayabusa-results.csv`, create `/data/hayabusa-results_2026-02-20T0723/` and save all outputs there. Use this same directory path for all subsequent output files in Steps 6-1, 6-2, and 7.

#### 6-1. Timeline Chart Generation

Execute the following via Bash tool, piping JSON input:

```bash
echo '<JSON>' | python3 "$HOME/.claude/skills/investigate/scripts/timeline_chart.py"
```

JSON input structure:
```json
{
  "events": [
    {"timestamp": "YYYY-MM-DDTHH:MM:SS", "host": "hostname", "rule": "RuleTitle", "level": "crit/high/med/low/info", "mitre": "TXXXX"}
  ],
  "phases": [
    {"name": "Phase N: Phase Name", "start": "YYYY-MM-DDTHH:MM:SS", "end": "YYYY-MM-DDTHH:MM:SS"}
  ],
  "title": "Incident Timeline - [environment name]",
  "output": "[CSV directory]/[CSV name]_[YYYY-MM-DDTHHMI]/[CSV name]_timeline.html"
}
```

- `events`: Select representative events (up to ~50) from high/crit events collected in Steps 3-5. Deduplicate repetitions of the same rule on the same host to 1 representative
- `phases`: Time ranges of attack phases defined in Section 3. Optional
- `level`: Marker color/shape varies by severity (crit=red diamond, high=orange circle, med=yellow square, low=blue triangle)

#### 6-2. MITRE ATT&CK Flow Diagram Generation

```bash
echo '<JSON>' | python3 "$HOME/.claude/skills/investigate/scripts/mitre_flow.py"
```

JSON input structure:
```json
{
  "tactics": [
    {
      "id": "TA0001",
      "name": "Initial Access",
      "techniques": ["T1566 Phishing", "T1078 Valid Accounts"],
      "hosts": ["HOST-A"],
      "event_count": 5,
      "time_range": "YYYY-MM-DD HH:MM ~ HH:MM"
    }
  ],
  "title": "Attack Flow (MITRE ATT&CK) - [environment name]",
  "output": "[CSV directory]/[CSV name]_[YYYY-MM-DDTHHMI]/[CSV name]_mitre_flow.html"
}
```

- `tactics`: Attack flow information from Section 4. List tactics in detection order
- Each tactic's `techniques` should include technique IDs and names inferred from Step 3 rule titles
- `hosts` should list host names associated with each tactic

#### 6-3. Lateral Movement (Propagation Path) Chart Generation

```bash
echo '<JSON>' | python3 "$HOME/.claude/skills/investigate/scripts/lateral_movement_chart.py"
```

JSON input structure:
```json
{
  "movements": [
    {
      "source_time": "YYYY-MM-DDTHH:MM:SSZ",
      "source_host": "HOST-A",
      "source_event": "Event description on source host",
      "source_level": "crit/high/med/low/info",
      "target_time": "YYYY-MM-DDTHH:MM:SSZ",
      "target_host": "HOST-B",
      "target_event": "Event description on target host",
      "target_level": "crit/high/med/low/info",
      "delta_minutes": 5.0
    }
  ],
  "title": "Propagation Path - [environment name]",
  "output": "[CSV directory]/[CSV name]_[YYYY-MM-DDTHHMI]/[CSV name]_lateral_movement.html"
}
```

- `movements`: Inter-host attack propagation events from `correlate_lateral_movement` results and manual correlation in Steps 3-5. Each entry represents a source→target propagation step
- `source_event` / `target_event`: Representative detection rule name or technique description
- `delta_minutes`: Time difference between source and target events in minutes
- If no lateral movement is detected (single-host incident or no inter-host correlation), skip this chart generation

#### 6-4. Embedding Charts in the Report

Embed generated HTML files as markdown links in the appropriate report sections:
- Timeline chart → Insert at the beginning of Section 3 "Compromise Timeline" as `[Interactive Timeline Chart](filename_timeline.html)`
- MITRE flow diagram → Insert at the beginning of Section 4 "Attack Flow" as `[Interactive Attack Flow Diagram](filename_mitre_flow.html)`
- Lateral movement chart → Insert at the beginning of Section 8 "Propagation Path" as `[Interactive Propagation Path Chart](filename_lateral_movement.html)`

#### 6-5. Collect Time and Version Metadata for the Report

After visualization files have been generated, use the Bash tool to obtain the following values for report metadata:
- `date '+%Y-%m-%d %H:%M:%S'` → use as the report metadata timestamp reference
- `claude --version` → use for the "Generated by" field

**Ordering requirement**: Run these commands **only after visualization chart generation is complete**. Do not run them earlier.

> **Note**: Step 6-0 description references "Steps 6-1, 6-2, and 7" — this now includes 6-3 as well.

### Step 7: Report Generation

Analyze all collected data and generate an **English** incident forensic report following the output format below.

#### File Output

The report should be generated as an **HTML file only**. Do not create an intermediate Markdown file.

##### Step 7-1: HTML Report Output

File naming convention:

```
{CSV filename (without extension)}_{YYYY-MM-DDTHHMI}.html
```

- `{CSV filename}`: The stem of the target CSV filename (without `.csv` extension)
- `{YYYY-MM-DDTHHMI}`: Local timestamp at report generation time (to the minute)
- Save location: Inside the output directory created in Step 6-0 (`[CSV directory]/[CSV filename without extension]_[YYYY-MM-DDTHHMI]/`)

First, assemble the full report body as a string. Do not save it as a `.md` file at any point.

Then execute the following via Bash tool to convert the report body directly to HTML and save it:

```bash
echo '<JSON>' | python3 "$HOME/.claude/skills/investigate/scripts/report.py"
```

JSON input structure:
```json
{
  "content": "# Incident Forensic Report\n...",
  "output": "/path/to/report.html",
  "title": "Incident Forensic Report",
  "charts": {
    "timeline": "/path/to/timeline.html",
    "mitre_flow": "/path/to/mitre_flow.html",
    "lateral_movement": "/path/to/lateral_movement.html"
  }
}
```

- `content`: The complete report body as a markdown-style string
- `output`: Final HTML output file path
- `charts`: Paths to chart HTML files generated in Step 6. Chart links `[...](xxx.html)` in the report body are automatically converted to iframe embeds. Omit `lateral_movement` if no chart was generated (single-host incident)

After conversion, notify the user of the final `.html` file path.

Example:
- `hayabusa-results.csv` → `hayabusa-results_2026-02-20T0723/hayabusa-results_2026-02-20T0723.html` (final report)
- The output directory `hayabusa-results_2026-02-20T0723/` will also contain `hayabusa-results_timeline.html` and `hayabusa-results_mitre_flow.html`

---

## Output Format Specification

The report consists of the following 9 sections. Follow the content, table columns, and formatting rules for each section. Sections with no applicable data should still remain as "None identified" to make clear that they were investigated.

### Section 1: Executive Summary

A summary for executives and non-technical readers. Convey the following in 3-5 sentences:
- What happened (nature of compromise: APT, ransomware, unauthorized access, etc.)
- When it occurred (time period)
- Scale of impact (number of affected hosts/accounts)
- Severity of the attack (highest severity and confirmed threats)

```markdown
# Incident Forensic Report

## 1. Executive Summary

From YYYY-MM-DD to YYYY-MM-DD, a [type of compromise] was confirmed in [environment name].
The attacker... (3-5 sentence summary)
```

### Section 2: Incident Overview

Present a quantitative fact sheet in table format.

```markdown
## 2. Incident Overview

| Item | Value |
|---|---|
| Incident Period | YYYY-MM-DD HH:MM UTC ~ YYYY-MM-DD HH:MM UTC |
| Total Events Analyzed | N events |
| Counts by Severity | crit: N / high: N / med: N / low: N / info: N |
| Affected Host Count | N hosts |
| Affected Hosts | HOST-A, HOST-B, ... |
| Compromised Account Count | N accounts |
| Detected Attack Tools/Malware | (identified from rule names, or "No specific tool names detected") |
| Initial Access Vector (Estimated) | (with evidence. If unidentifiable: "Unknown - further investigation required") |
| Highest Severity Event | Rule Name (hostname, timestamp) |
```

"Detected Attack Tools/Malware" should be based on tool names found in rule names. Even if no specific tool name is identifiable, describe the attack technique (e.g., "Remote execution via PowerShell", "Defense evasion via registry modification").

Initial access vector estimation evidence examples:
- Initial Access tactic events exist → estimate from event content
- Double-extension file execution → phishing email attachment
- Logon from external IP → remote access
- Vulnerability-related rule → vulnerability exploitation
- None of the above → explicitly state "Unknown"

### Section 3: Compromise Timeline (Main Section)

The core of the report. Group the timeline by attack phase, with events listed chronologically in table format within each phase.

#### Phase Classification Guidelines

Divide phases based on MITRE ATT&CK tactics and temporal clustering. The following are reference categories; set phases flexibly according to the actual data:

| Phase Candidate | Corresponding MITRE Tactic | Typical Activities |
|---|---|---|
| Initial Access | Initial Access (TA0001) | Phishing, vulnerability exploitation, valid account abuse, supply chain |
| Execution | Execution (TA0002) | Script execution, command line, WMI/PowerShell/Task Scheduler |
| Persistence | Persistence (TA0003) | Service registration, scheduled tasks, registry Run keys, Bootkit |
| Privilege Escalation | Privilege Escalation (TA0004) | Admin group addition, token manipulation, vulnerability exploitation |
| Defense Evasion | Defense Evasion (TA0005) | AV disabling, log clearing, obfuscation, process injection, signature spoofing |
| Credential Access | Credential Access (TA0006) | LSASS, SAM dump, Kerberoasting, password spraying |
| Discovery | Discovery (TA0007) | System info, network enumeration, AD enumeration, file exploration |
| Lateral Movement | Lateral Movement (TA0008) | RDP, SMB, WinRM, PsExec, Pass-the-Hash/Ticket |
| Collection | Collection (TA0009) | File collection, clipboard, screen capture, email collection |
| Command and Control | Command and Control (TA0011) | HTTP/HTTPS, DNS, encrypted channels, proxies |
| Exfiltration | Exfiltration (TA0010) | External transfer, cloud storage, alternative protocols |
| Impact | Impact (TA0040) | Encryption (ransomware), destruction, service disruption, defacement |

Omit phases where no activity was confirmed. Multiple tactics may be combined into one phase, or the same tactic may be split across time periods as appropriate.

#### Per-Phase Format

```markdown
## 3. Compromise Timeline

### Phase 1: [Phase Name] (YYYY-MM-DD HH:MM ~ HH:MM UTC)

| Time (UTC) | Host | Event (RuleTitle) | Severity | MITRE | Details |
|---|---|---|---|---|---|
| HH:MM:SS | HOST-A | Rule Name | crit/high | TID | Key information extracted from Details for understanding the attack |

**Analysis**: In this phase...
```

Each phase's "Analysis" should include:
- What the attacker was trying to achieve (estimated objective)
- Description of techniques used (understandable to general readers)
- Detection basis (which Sigma rule fired and why)
- Causal relationship with preceding/following phases

Event selection criteria for tables:
- All crit/high events should be listed in principle
- Repetitions of the same rule on the same host → 1 representative + count note
- When multiple rules fire at the same timestamp → use the highest severity rule and note others

### Section 4: Attack Flow Diagram

Visualization of attack progression based on detected MITRE ATT&CK tactics.

```markdown
## 4. Attack Flow (MITRE ATT&CK)

[Detected Tactic 1] → [Detected Tactic 2] → ... → [Detected Tactic N]
     (TID)              (TID)                        (TID)
   [Related Hosts]     [Related Hosts]              [Related Hosts]
```

- List only actually detected tactics
- Below each tactic, note the most representative technique ID and related hosts
- When gaps exist between detections (e.g., unknown between Initial Access and C2), note "(Not detected/Estimated)" to indicate gaps in the attack chain

### Section 5: Affected Assets and Accounts

#### 5-1. Per-Host Impact Summary

```markdown
## 5. Affected Assets and Accounts

### 5-1. Per-Host Impact Summary

| Hostname | Role (Estimated) | High/Crit Count | Primary Detection Rules | First Anomaly Detected | Last Anomaly Detected | Compromise Level |
|---|---|---|---|---|---|---|
| HOST-A | Workstation/Server/DC/DB etc. | N events | Rule1, Rule2 | YYYY-MM-DD HH:MM | YYYY-MM-DD HH:MM | Confirmed/Suspected/Under Investigation |
```

Host role estimation methods:
- Infer from hostname naming conventions (DC-, SRV-, WS-, DB-, etc.)
- Infer from detected event types (AD-related events → Domain Controller, DB-related → DB server, etc.)
- If unable to estimate → "Unknown"

Compromise level criteria:
- **Confirmed**: Host with crit events detected, malware/attack tool execution, or C2 communication confirmed
- **Suspected**: High events detected, lateral movement target candidate but lacking definitive evidence
- **Under Investigation**: Related but only medium or below. Additional logs needed

#### 5-2. Per-Account Impact

```markdown
### 5-2. Compromised Accounts

| Account Name | Type | Related Hosts | Primary Related Events | Detection Count | Compromise Evidence |
|---|---|---|---|---|---|
| Account name | Type | HOST-A, HOST-B | Event summary | N events | Reason for compromise determination |
```

Account types: Domain User / Domain Admin / Local Admin / Service Account / SYSTEM / Machine Account

Compromise determination criteria:
- Activity on hosts not normally used
- Activity during abnormal hours (outside business hours)
- Activity involving privilege escalation
- Actor executing attack tools
- Short-duration authentication across multiple hosts (lateral movement indicator)

### Section 6: IOC List (Indicators of Compromise)

Organize IOCs by category. Present in a format usable for forensic investigation and containment response.

```markdown
## 6. IOC List (Indicators of Compromise)

### 6-1. Malicious Processes/Files

| IOC Type | Value | Detected Host | Detection Count | Context |
|---|---|---|---|---|
| File Path/Process/Hash | value | hostname | N | Role in the attack |

### 6-2. Network IOCs

| IOC Type | Value | Direction | Detected Host | Context |
|---|---|---|---|---|
| IP/Domain/URL/Port | value | In/Out | hostname | Purpose of communication |

### 6-3. Persistence Mechanisms

| Type | Name/Path | Host | Context |
|---|---|---|---|
| Service/Task/Registry/Startup etc. | value | hostname | Purpose |

### 6-4. Account IOCs

| Account | Type | Suspicious Activity | Host |
|---|---|---|---|
| Account name | Type | Activity description | hostname |
```

For categories with no findings, explicitly state "None identified - [reason]". It is important to distinguish between "investigated but not detected" and "not investigated."

### Section 7: Decoded Payloads

Analysis results of encoded/obfuscated scripts. Covers all payloads requiring decoding, not just PowerShell — VBScript, JScript, Base64-encoded binaries, etc.

```markdown
## 7. Decoded Payloads

### Payload 1: [Brief description of purpose]
- **Detection Time**: YYYY-MM-DD HH:MM UTC
- **Detection Host**: HOST-A
- **Detection Rule**: Rule Name
- **Encoding Method**: Base64 / XOR / Gzip+Base64 etc.
- **Decoded Result**:
  ```
  Decoded command/script
  ```
- **Analysis**: Purpose of this script and impact if executed (intent and impact description)
- **Maliciousness Assessment**: Attack payload / Legitimate tool origin (non-malicious) / Indeterminate
```

If no decode targets exist, state "No encoded payloads were detected."

Maliciousness assessment criteria:
- Contains external communications → likely attack payload
- Traces of known configuration management tools (Ansible, Puppet, Chef, Packer, etc.) → legitimate tool origin
- Contains memory manipulation, process injection, credential access → attack payload
- If difficult to determine → "Indeterminate - further investigation required"

### Section 8: Lateral Movement Analysis

Organize inter-host attack propagation patterns.

```markdown
## 8. Lateral Movement Analysis

### Propagation Path

[Interactive Propagation Path Chart](filename_lateral_movement.html)

### Lateral Movement Event Details

| Time (UTC) | Source Host | Destination Host | Technique | Detection Rule | Account Used |
|---|---|---|---|---|---|
| HH:MM:SS | HOST-A | HOST-B | Technique name | Rule Name | Account name |
```

When no lateral movement is detected:
- Single-host incident → "No lateral movement was detected. The attack may have been confined to [HOST-A]"
- Possible log insufficiency → "No evidence of lateral movement was detected, but this is not conclusive due to [reason]"

### Section 9: Investigation Notes and Recommendations

```markdown
## 9. Investigation Notes and Recommendations

### Analysis Constraints
- **Scope**: This report is based on events detected by Hayabusa Sigma rules. Activity not matching any rule is outside detection scope
- **Timestamps**: All in UTC
- **Log Sources**: Log sources used for analysis / missing log sources

### Events Determined to be False Positives
List events determined to be false positives (or highly likely false positives) in Step 3.5 verification that were **excluded from the attack timeline**. Include determination rationale and a Details summary so readers can independently re-evaluate.

| Rule Title | Count | Determination Rationale (Details Summary) |
|---|---|---|
| Rule name | N events | Specific reason for false positive determination (e.g., "Legitimate Windows print service svchost.exe -k print") |

### Indeterminate Events
List events where it was not possible to definitively determine attack vs. legitimate activity. Include conditions under which a determination could be made with additional information.

### Recommended Additional Investigation
(Areas not covered in this analysis, additional logs to collect, items to verify)

### Containment and Recovery Recommendations
(Immediate response suggestions based on detected threats: account resets, host isolation, IOC blocking, etc.)
```

### Report Metadata (Footer)

Add the following metadata section at the end of the report, after Section 9, separated by a horizontal rule.

```markdown
---

> **Report Metadata**
> - Generated by: Claude Code (`claude --version` output)
> - Model: [model ID from system prompt (e.g., claude-opus-4-6)]
> - Analysis duration: [elapsed time from Step 1 start to report output (min:sec)]
> - Report generated at: YYYY-MM-DD HH:MM:SS (Local)
```

Metadata collection procedure:
1. **Start time**: Record `date '+%Y-%m-%d %H:%M:%S'` in Step 1
2. **Claude Code version**: Run `claude --version` via Bash tool in Step 6-4
3. **Model ID**: Obtain from the system prompt's "You are powered by the model named ..." statement. If unknown, state "Claude (model ID unknown)"
4. **Analysis duration**: Calculate the difference between the start time recorded in Step 1 and either the post-visualization timestamp captured in Step 6-4 or the final report generation time in Step 7
5. **Report generated at**: Record the Step 7 report completion time

---

## Analysis Guidelines

Observe the following throughout the entire report:

- **Identifying attacker tools**: Hayabusa rule names often contain attack tool names (e.g., "HackTool - [tool name]", "[tool name] Execution"). Identify attack tools/frameworks from rule name patterns and reflect in Section 2
- **Distinguishing from legitimate activity**: Activity from configuration management tools (Packer, Ansible, SCCM, etc.) and IT management tools can be mistaken for attacks. Judge based on context (execution path, executing user, timing) and document rationale in Section 9
- **Handling duplicate detections**: Multiple rules firing at the same timestamp is likely multiple rule matches on the same event. Use the highest severity rule as representative in the timeline
- **Account analysis**: Focus on single accounts active across multiple hosts, service accounts with interactive logons, and abnormal admin account usage patterns
- **Temporal correlation**: Events occurring across different hosts within a short time are indicators of lateral movement. Correlate event groups within time windows (typically minutes to tens of minutes)
- **Pagination handling**: When MCP tool results show `has_more: True`, follow these criteria for additional retrieval:
  - **Must retrieve all**: Crit events (`run_sql` WHERE Level = 'crit'), compromised account list (`parse_details_field` User)
  - **Retrieve up to 200**: IOCs (`extract_iocs`), lateral movement correlation (`correlate_lateral_movement`)
  - **First page is sufficient**: Time window summaries (`summarize_by_time_window`), rule title aggregation (`analyze_rule_titles`)
  - **Retrieve all for the 2-3 most suspicious hosts**: Host timeline (`analyze_host_timeline`)
  - For others, judge by situation. Prioritize reaching needed data through filter refinement (level, rule_title, time_range, etc.) over pagination
- **Handling large tool outputs**: Results from `decode_powershell_commands` or `run_sql` may exceed token limits and be saved to files. In such cases, delegate file reading and summarization to a Task tool (background agent) to avoid blocking the main investigation flow. Instructions to background agents should include "summarize decode results", "extract hosts/timestamps", and "classify attack objectives"
- **Handling absence of data**: The absence of events in a specific category is also important information. "Not detected" means "nothing matched detection rules," not "did not occur." Reflect this distinction in the report
- **Proactive false positive elimination (most critical)**: **Never determine an attack based on rule title alone. Always verify the actual Details field content before making a judgment.** "Suspicious Service Path" may be a legitimate print service, "LOLBAS Renamed" may be a legitimate Elastic Winlogbeat rename, "Proc Access" may be legitimate Veeam Backup operation. At first encounter of each rule, always check 1-2 event Details and do not skip the determination step (Step 3.5)
- **Attacker staging directory search**: Attackers frequently place tools in `C:\Users\Public\`, `C:\ProgramData\`, `C:\Windows\Temp\<random>\`, `C:\Perflogs\`, etc. When process paths in Details fields contain these directories, use `search_all_fields` to cross-search the same directory path to comprehensively discover other deployed tools
- **Process correlation via PID/PGUID**: When the same PID/PGUID is detected by different rules, it means detection of different aspects of the same process. For example, if a rundll32.exe (PID X) loaded a Qakbot DLL and the same PID X made RDP connections, conclude that the DLL has built-in RDP capability. Reflect this correlation in the report's timeline and lateral movement analysis
- **IP → hostname mapping**: For internal IP addresses detected in IOCs and lateral movement analysis, resolve to corresponding hostnames where possible. Check if the same IP appears with a Computer name in other events, or correlate SrcIP/TgtIP with Computer names via SQL
- **SID → account name resolution**: When events like "User Added To Local Admin Grp" only record SIDs, search whether the same SID appears with an account name in other events and identify the account name where possible
- **Reliable hash IOC collection**: Hashes values (SHA256, SHA1, MD5, IMPHASH) in Details fields must be included in the report's IOC section for attack-related processes/DLLs. Hashes of files in staging directories, attack tools, and suspicious DLLs are particularly important
- **Full activity period coverage**: When time window analysis detects multiple discontinuous activity clusters, verify representative events for all clusters, not just the primary ones. Clusters with confirmed activity but no clear attack activity should not be reported as "attack campaigns" — treat as normal activity or details unknown
