---
name: investigate
description: "Incident investigation and timeline generation using Hayabusa MCP. Triggered by /investigate, or requests like 'compromise investigation', 'incident analysis', 'forensic analysis', 'analyze logs', 'create timeline', '侵害調査', 'タイムライン作成', 'インシデント分析', 'フォレンジック分析', 'ログ分析して'. Operates in environments where Hayabusa MCP tools are available."
---

# Investigate — Hayabusa Incident Timeline Investigation

Systematically analyze CSV logs using Hayabusa MCP tools and generate a compromise timeline report. A general-purpose investigation framework that handles all types of cyberattacks (APT, ransomware, insider threats, web compromises, supply chain attacks, etc.).

## Language Handling

Detect the user's language from their input message and set `REPORT_LANG` accordingly:

- If the user writes in **Japanese** → `REPORT_LANG=JA`. Generate the report using section headers, table columns, and prose templates from **§Output Format (JA)**.
- If the user writes in **English** → `REPORT_LANG=EN`. Generate the report using section headers, table columns, and prose templates from **§Output Format (EN)**.
- If the language is **ambiguous** (e.g., the user typed only `/investigate`) → ask the user which language they prefer for the report.

All workflow steps, tool calls, SQL queries, and analysis logic below are **language-independent**. Only the final report output (Step 7) adapts based on `REPORT_LANG`.

## Arguments

- Optional: CSV file path
- Example: `/investigate /path/to/results.csv`

## Workflow

Execute the following steps in order. Independent tool calls within each step should be **executed in parallel** to minimize latency.

### Step 1: Identify Target CSV and Load Dataset

1. If a CSV path is specified as an argument → use that path
2. If no argument is provided → use `mcp__hayabusa__list_datasets` to list CSV files under the current directory, then use the `AskUserQuestion` tool to have the user select the target file. Confirm with the user even if there is only one candidate
3. Load the user-selected CSV with `mcp__hayabusa__switch_dataset`

### Step 2: Obtain Profile and Determine Investigation Strategy

Use `mcp__hayabusa__dataset_profile` to get a dataset overview. Information obtained here includes:
- Event time range (timestamp_min / timestamp_max)
- Counts by severity (info / low / med / high / crit)
- Counts by host
- Top rule titles

Based on these results, **form hypotheses about the nature of the incident** and adaptively adjust subsequent investigation parameters:
- crit/high concentrated on a small number of hosts → possible targeted attack (APT). Prioritize deep-dive into those hosts
- crit/high occurring across all hosts in a short time window → possible ransomware/worm. Set a shorter time window (1h)
- Massive activity from a specific account → possible credential theft/insider threat. Emphasize account-based analysis
- Only med or below with no clear crit/high → possible slow reconnaissance. Expand analysis to include med

### Step 3: Obtain Big-Picture View of the Attack (Parallel Execution)

Call the following 3 tools **simultaneously**:

1. **`mcp__hayabusa__analyze_rule_titles`** — Aggregate rule titles with `level: ["high", "crit"]`. Understand the overall picture of attack techniques and detection hosts. If no crit/high exists, fall back to `level: "med"`
2. **`mcp__hayabusa__analyze_mitre_tactics`** — MITRE ATT&CK tactics analysis. Understand the coverage and timeline of attack phases
3. **`mcp__hayabusa__summarize_by_time_window`** — Understand the temporal concentration of activity. Adjust interval based on incident duration:
   - Within 24 hours: `"1h"`
   - 1–7 days: `"3h"`
   - Over 7 days: `"12h"` or `"1d"`

### Step 3.5: Verify Details for All Rule Titles (False Positive Elimination) ★ CRITICAL

**This step must not be skipped.** For all rule titles obtained from `analyze_rule_titles` in Step 3, retrieve the Details field from 1–2 sample events for each rule and **verify the actual content before determining whether it is an attack or false positive**.

#### How to Execute

For **all distinct rule titles** detected in Step 3, retrieve representative event Details using the following SQL:

```sql
SELECT Timestamp, Computer, RuleTitle, Level, Details
FROM logs WHERE RuleTitle = '[rule title]'
ORDER BY Timestamp LIMIT 2
```

If there are many rule titles (10+), parallelize and optimize using:
- Combine multiple rule titles with `WHERE RuleTitle IN (...)`
- Limit to 5 rules per query with `LIMIT 10` to ensure at least 1 result per rule

#### Verification Criteria

Confirm the following from each rule's Details and **exclude rules determined to be false positives from the report (or include them in Section 9's false positive section)**:

1. **Process path legitimacy**: Is it a legitimate Windows service such as `C:\Windows\system32\svchost.exe -k print`?
2. **Service name/description check**: Is the service name in Details a legitimate Windows feature?
3. **Executable provenance**: Do the Description/Product/Company fields indicate a legitimate vendor product? (e.g., "Winlogbeat ships Windows event logs" → legitimate Elastic tool)
4. **File path suspicion level**: Is it in a staging directory commonly used by attackers such as `C:\Users\Public\`, `C:\Windows\Temp\<random>`, `C:\ProgramData\`?
5. **Parent process check**: Is the ParentCmdline a legitimate service manager (services.exe, svchost.exe) or a suspicious process (cmd.exe, powershell.exe, wsmprovhost.exe)?
6. **User context**: Is it a legitimate scheduled task under the SYSTEM account, or suspicious execution under a regular user account?

#### Common False Positive Patterns (Exclusion Candidates)

The following are frequently occurring false positive patterns. When Details content matches, exclude from the attack timeline and list in Section 9:

- **Suspicious Service Path**: Legitimate service paths such as `svchost.exe -k print` (print service), `svchost.exe -k netsvcs` (general Windows service)
- **LOLBAS Renamed**: Renamed binaries of legitimate tools (Elastic Winlogbeat, Velociraptor, etc.) where Description/Product indicates a legitimate vendor. However, **attackers may also spoof tool attributes, so make a comprehensive judgment including deployment path and execution context**
- **Proc Access (Sysmon Alert)**: Legitimate inter-process access by Veeam Backup, Defender ATP, sppsvc.exe, etc.
- **Proc Exec (Sysmon Alert)**: Windows scheduled tasks (makecab, rundll32 Windows.Storage.*), Windows Update-related

#### Discovering Attack Infrastructure

If the following attack infrastructure patterns are found during Details verification, **always record them and add them as deep-dive targets in Step 5**:

- **Staging directories**: Executables or DLLs placed in `C:\Users\Public\`, `C:\ProgramData\`, `C:\Windows\Temp\<random>`, `C:\Perflogs\`, etc.
- **Same PID detected by multiple rules**: When the same PID/PGUID is detected by different rules, it indicates multi-faceted malicious activity by the same process
- **Suspicious DLL loads**: When rundll32.exe loads a DLL from a non-standard System32 path (e.g., `rundll32 C:\Users\Public\Music\*.dll`)

### Step 4: Detailed Investigation (Parallel Execution)

Call the following 4 tools **simultaneously**:

1. **`mcp__hayabusa__run_sql`** — `SELECT Timestamp, RuleTitle, Level, Computer, Details FROM logs WHERE Level = 'crit' ORDER BY Timestamp` to get full details of all crit events. If no crit events exist, expand to high
2. **`mcp__hayabusa__extract_iocs`** — Extract IOCs (processes, command lines, IPs, users, hashes, etc.) with `level: ["high", "crit"]`
3. **`mcp__hayabusa__correlate_lateral_movement`** — Detect inter-host lateral movement patterns with `time_window_minutes: 60`, `level: ["high", "crit"]`. For single-host incidents, results may be empty, but that itself serves as evidence of no lateral movement
4. **`mcp__hayabusa__parse_details_field`** — `field_name: "User"`, `level: ["high", "crit"]`, `unique: true` to aggregate accounts involved in the attack. Identifying the attack principal is necessary for virtually all incidents, so always execute this

### Step 5: Adaptive Deep Dive (Parallel Execution)

Based on results from Steps 3–4, select the necessary tools from the following **based on threats present in the data** and call them simultaneously:

#### Always Execute:
- **`mcp__hayabusa__analyze_host_timeline`** — Get the timeline for the most suspicious host

#### Conditional Execution:
- **`mcp__hayabusa__decode_powershell_commands`** — Execute if PowerShell-related rules (Encoded PowerShell, PowerShell ScriptBlock, etc.) were detected in Step 3
- **`mcp__hayabusa__parse_details_field`** — When deeper analysis of specific fields is needed (e.g., `field_name: "Cmdline"` for command listing, `field_name: "User"` for account analysis)
- **`mcp__hayabusa__search_all_fields`** — If specific IOCs (filenames, IPs, hashes, etc.) were found in Steps 3–4, perform a cross-field search to identify related events
- **`mcp__hayabusa__run_sql`** — When additional custom queries are needed (e.g., event listing for a specific host during a specific time window)

Criteria for determining "most suspicious host" (by priority):
1. Host with the most crit events
2. Host identified as the lateral movement origin
3. Host where high/crit was detected earliest (Patient Zero candidate)
4. Host appearing across multiple MITRE tactic phases

#### Attack Infrastructure Cross-Search (Required if discovered in Step 3.5):

If attacker staging directories (e.g., `C:\Users\Public\Music\`) or suspicious process paths were discovered in Step 3.5, use `search_all_fields` to cross-search that path across all fields to **comprehensively identify other tools placed in the same directory and related activity**.

#### Full Activity Period Coverage (Required if multiple clusters found in Step 3 time-window summary):

If `summarize_by_time_window` in Step 3 detected multiple discontinuous activity clusters, **verify representative events for all clusters**. Execute the following SQL for each cluster's time range:

```sql
SELECT Timestamp, Computer, RuleTitle, Level, Details
FROM logs WHERE Timestamp >= '[cluster_start]' AND Timestamp <= '[cluster_end]'
AND Level IN ('high','crit')
ORDER BY Timestamp LIMIT 20
```

This allows identification of cases where what was assumed to be a "Wave N attack" is actually normal activity (Windows scheduled tasks, etc.). Clusters with no clear attack activity should not be described as "attack campaigns" in the report.

### Step 5.5: Process Correlation and Network Mapping (Parallel Execution)

After important events have been identified from Steps 4–5, perform the following correlation analysis:

#### PID/PGUID Correlation:
When the same PID/PGUID is detected by multiple different rules, they indicate **different malicious behaviors of the same process**. Cross-check PID/PGUID values in the Details field. For example:
- rundll32.exe that loaded a Qakbot DLL (PID X) also performed RDP connections with the same PID → DLL has built-in RDP capability
- PsExec.exe (PID Y) makes network connections (port 135/445) and simultaneously creates remote services → full picture of lateral movement

#### IP-to-Hostname Mapping:
For internal IP addresses detected in IOC extraction or within Details, verify which Computer names the same IP is associated with in other events:
```sql
SELECT DISTINCT Computer, Details FROM logs
WHERE Details LIKE '%10.65.45.XXX%' LIMIT 5
```

#### SID-to-Account Name Resolution:
When events like "User Added To Local Admin Grp" only record a SID, search whether the same SID appears with an account name in other events:
```sql
SELECT Details FROM logs WHERE Details LIKE '%S-1-5-21-XXXX%' LIMIT 5
```

#### Hash IOC Collection:
Record Hashes values (SHA256, SHA1, MD5) from Details fields confirmed in Steps 3.5–5 for attack-related processes and DLLs. The following hashes in particular should be included in the report's IOC section:
- Hashes of files placed in attacker staging directories
- Hashes of attack tools (PsExec, Mimikatz, BloodHound, etc.)
- Hashes of suspicious DLLs

### Step 6: Visualization Chart Generation

Generate a timeline chart and MITRE ATT&CK flow diagram from the data collected during investigation and embed them in the report.

**Important**: Scripts are located in the `scripts/` subdirectory of this skill. The script base directory is:
```
SCRIPT_DIR="$HOME/.claude/skills/investigate/scripts"
```

**Note**: `~` or Glob tools may not resolve paths correctly. Always use **Bash tool** for checking script existence and execution, referencing them with absolute paths using `$HOME`. Do not use Glob tools to find scripts.

#### 6-1. Timeline Chart Generation

Execute with Bash tool, piping JSON input:

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
    {"name": "Phase N: Phase name", "start": "YYYY-MM-DDTHH:MM:SS", "end": "YYYY-MM-DDTHH:MM:SS"}
  ],
  "title": "Incident Timeline - [Environment Name]",
  "output": "[same directory as CSV]/[CSV name]_timeline.html"
}
```

- `events`: Select representative events (up to ~50) from high/crit events collected in Steps 3–5. Consolidate repeated same-rule/same-host occurrences to one representative entry
- `phases`: Time ranges for attack phases defined in Section 3. Optional
- `level`: Marker color/shape varies by severity (crit = red diamond, high = orange circle, med = yellow square, low = blue triangle)

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
  "title": "Attack Flow (MITRE ATT&CK) - [Environment Name]",
  "output": "[same directory as CSV]/[CSV name]_mitre_flow.html"
}
```

#### 6-3. Embedding Charts in the Report

Embed generated HTML files as links in the corresponding report sections:
- Timeline chart → Insert at the beginning of Section 3 as a link
- MITRE flow diagram → Insert at the beginning of Section 4 as a link

### Step 7: Report Generation

Analyze all collected data and generate an incident forensic report. **Select the output format section matching `REPORT_LANG`** (determined in §Language Handling):

- `REPORT_LANG=EN` → Use **§Output Format (EN)** below
- `REPORT_LANG=JA` → Use **§Output Format (JA)** below

#### File Output

Save the report as a **Markdown file (.md)**. File naming convention:

```
{CSV filename (without extension)}_{YYYY-MM-DDTHHMI}.md
```

- `{CSV filename}`: Stem of the analyzed CSV filename (excluding `.csv`)
- `{YYYY-MM-DDTHHMI}`: Local timestamp at report generation (hours and minutes)
- Save location: Same directory as the analyzed CSV

Examples:
- `hayabusa-results.csv` → `hayabusa-results_2026-02-20T0723.md`
- `/path/to/incident-log.csv` → `/path/to/incident-log_2026-02-20T1530.md`

Write the entire report to a file using the Write tool and notify the user of the file path after saving is complete.

---

## Output Format (EN)

The report consists of 9 sections. Follow the content, table columns, and documentation rules for each section. Sections with no applicable data should still be retained with "N/A" to indicate they were investigated.

### Section 1: Executive Summary

A summary for executives and non-technical audiences. Convey the following in 3–5 sentences:
- What happened (nature of the compromise: APT, ransomware, unauthorized access, etc.)
- When it happened (time period)
- Scale (number of affected hosts and accounts)
- Severity (highest severity level and confirmed threats)

```markdown
# Incident Forensic Report

## 1. Executive Summary

During the period from YYYY-MM-DD to YYYY-MM-DD, [type of compromise]
was confirmed in [environment name]. The attacker... (3–5 sentence summary)
```

### Section 2: Incident Overview

Present a quantitative fact sheet in table format.

```markdown
## 2. Incident Overview

| Item | Value |
|---|---|
| Incident Period | YYYY-MM-DD HH:MM UTC – YYYY-MM-DD HH:MM UTC |
| Total Events Analyzed | N events |
| Counts by Severity | crit: N / high: N / med: N / low: N / info: N |
| Affected Host Count | N hosts |
| Affected Host List | HOST-A, HOST-B, ... |
| Compromised Account Count | N accounts |
| Detected Attack Tools/Malware | (Identified from rule names; if none, "No specific tool names detected") |
| Initial Access Vector (Estimated) | (State with evidence. If unknown, "Unknown — additional investigation required") |
| Highest Severity Event | Rule name (hostname, time) |
```

"Detected Attack Tools/Malware": Based on tool names in rule names. If none identifiable, describe attack techniques instead (e.g., "Remote execution via PowerShell", "Defense evasion through registry modification").

"Initial Access Vector" estimation basis:
- Initial Access tactic events exist → estimate from event content
- Double-extension file execution → phishing email attachment
- Logon from external IP → remote access
- Vulnerability-related rules → vulnerability exploitation
- None of the above → explicitly state "Unknown"

### Section 3: Compromise Timeline (Main Section)

The core of the report. Group chronology by attack phase; within each phase, list events in time order.

#### Phase Classification Guidelines

Classify based on MITRE ATT&CK tactics and temporal clustering. Reference categories:

| Phase Candidate | MITRE Tactic | Typical Activities |
|---|---|---|
| Initial Access | TA0001 | Phishing, vulnerability exploitation, valid account abuse, supply chain |
| Execution | TA0002 | Script execution, command line, WMI/PowerShell/Task Scheduler |
| Persistence | TA0003 | Service registration, scheduled tasks, registry Run keys, Bootkits |
| Privilege Escalation | TA0004 | Admin group addition, token manipulation, vulnerability exploitation |
| Defense Evasion | TA0005 | AV disabling, log clearing, obfuscation, process injection |
| Credential Access | TA0006 | LSASS, SAM dump, Kerberoasting, password spray |
| Discovery | TA0007 | System info, network enumeration, AD enumeration |
| Lateral Movement | TA0008 | RDP, SMB, WinRM, PsExec, Pass-the-Hash/Ticket |
| Collection | TA0009 | File collection, clipboard, screen capture, email collection |
| Command and Control | TA0011 | HTTP/HTTPS, DNS, encrypted channels, proxy |
| Exfiltration | TA0010 | External transfer, cloud storage, alternative protocols |
| Impact | TA0040 | Encryption (ransomware), destruction, service disruption |

Omit phases with no confirmed activity. Combine or split freely based on data.

#### Per-Phase Format

```markdown
## 3. Compromise Timeline

### Phase 1: [Phase Name] (YYYY-MM-DD HH:MM – HH:MM UTC)

| Time (UTC) | Host | Event (RuleTitle) | Severity | MITRE | Details |
|---|---|---|---|---|---|
| HH:MM:SS | HOST-A | Rule Name | crit/high | TID | Excerpt from Details |

**Analysis Notes**: In this phase...
```

Each phase's "Analysis Notes" should include:
- Estimated attacker objective
- Technique explanation (accessible to general readers)
- Detection basis (which Sigma rules fired and why)
- Causal links to preceding/subsequent phases

Event selection criteria:
- All crit/high events in principle
- Same-rule/same-host repeats → one representative + count annotation
- Same-timestamp multi-rule → highest severity as representative, annotate others

### Section 4: Attack Flow (MITRE ATT&CK)

```markdown
## 4. Attack Flow (MITRE ATT&CK)

[Tactic 1] → [Tactic 2] → ... → [Tactic N]
   (TID)        (TID)              (TID)
 [Hosts]      [Hosts]            [Hosts]
```

- Only detected tactics
- Annotate representative technique ID and hosts below each tactic
- Mark gaps as "(Not detected / Estimated)"

### Section 5: Affected Assets and Accounts

```markdown
## 5. Affected Assets and Accounts

### 5-1. Per-Host Impact Summary

| Hostname | Role (Est.) | High/Crit Count | Key Rules | First Anomaly | Last Anomaly | Compromise Level |
|---|---|---|---|---|---|---|
| HOST-A | Workstation/Server/DC/DB | N | Rule1, Rule2 | YYYY-MM-DD HH:MM | YYYY-MM-DD HH:MM | Confirmed/Suspected/Under Investigation |
```

Host role estimation: from naming conventions (DC-, SRV-, WS-, DB-), event types, or "Unknown".

Compromise levels:
- **Confirmed**: Crit events, malware/tool execution, C2 confirmed
- **Suspected**: High events, lateral movement candidate, insufficient definitive evidence
- **Under Investigation**: Related but medium or below only; additional logs needed

```markdown
### 5-2. Compromised Accounts

| Account Name | Type | Related Hosts | Key Events | Count | Basis for Compromise |
|---|---|---|---|---|---|
| name | Domain User/Admin/Local Admin/Service/SYSTEM/Machine | HOST-A, HOST-B | summary | N | reason |
```

### Section 6: IOC List (Indicators of Compromise)

```markdown
## 6. IOC List (Indicators of Compromise)

### 6-1. Malicious Processes/Files

| IOC Type | Value | Detection Host | Count | Context |
|---|---|---|---|---|
| File path/Process/Hash | value | hostname | N | role in attack |

### 6-2. Network IOCs

| IOC Type | Value | Direction | Detection Host | Context |
|---|---|---|---|---|
| IP/Domain/URL/Port | value | In/Out | hostname | purpose |

### 6-3. Persistence Mechanisms

| Type | Name/Path | Host | Context |
|---|---|---|---|
| Service/Task/Registry/Startup | value | hostname | purpose |

### 6-4. Account IOCs

| Account | Type | Suspicious Activity | Host |
|---|---|---|---|
| name | type | activity | hostname |
```

State "N/A — [reason]" for empty categories. Distinguish "investigated but not detected" from "not investigated."

### Section 7: Decoded Payloads

```markdown
## 7. Decoded Payloads

### Payload 1: [Brief description]
- **Detection Time**: YYYY-MM-DD HH:MM UTC
- **Detection Host**: HOST-A
- **Detection Rule**: Rule Name
- **Encoding Method**: Base64 / XOR / Gzip+Base64 etc.
- **Decoded Result**:
  ```
  decoded command/script
  ```
- **Analysis**: Purpose and impact
- **Maliciousness**: Attack payload / Legitimate tool origin / Indeterminate
```

If none: "No encoded payloads were detected."

### Section 8: Lateral Movement Analysis

```markdown
## 8. Lateral Movement Analysis

### Propagation Path

HOST-A (HH:MM) --[method]--> HOST-B (HH:MM) --[method]--> HOST-C (HH:MM)

### Event Details

| Time (UTC) | Source Host | Dest Host | Method | Rule | Account |
|---|---|---|---|---|---|
| HH:MM:SS | HOST-A | HOST-B | method | Rule Name | account |
```

If none detected:
- Single host → "No lateral movement detected. Attack may have been confined to [HOST-A]"
- Possible log gap → "No evidence found, but not conclusive due to [reason]"

### Section 9: Investigation Notes and Recommendations

```markdown
## 9. Investigation Notes and Recommendations

### Analysis Constraints
- **Scope**: Based on Hayabusa Sigma rule detections. Unmatched activity is out of scope
- **Timestamps**: All UTC
- **Log Sources**: Sources used / sources missing

### False Positives Excluded

| Rule Title | Count | Rationale (Details Summary) |
|---|---|---|
| name | N | specific reason |

### Indeterminate Events
(Events that could not be classified as attack or legitimate. Conditions for resolution.)

### Recommended Additional Investigation
(Gaps, additional logs needed, items to verify)

### Containment and Recovery Recommendations
(Immediate actions: account reset, host isolation, IOC blocking, etc.)
```

---

## Output Format (JA)

レポートは以下の9セクションで構成する。各セクションの内容・テーブル列・記載ルールに従うこと。データに該当がないセクションも「該当なし」として残し、調査済みであることを明示する。

### セクション 1: エグゼクティブサマリー

経営層・非技術者向けの要約。3〜5文で以下を伝える:
- 何が起きたか（侵害の性質: APT、ランサムウェア、不正アクセス等）
- いつ起きたか（期間）
- どの程度の規模か（影響ホスト数・アカウント数）
- 攻撃の深刻度（最高重要度と確認された脅威）

```markdown
# インシデント・フォレンジックレポート

## 1. エグゼクティブサマリー

YYYY-MM-DD から YYYY-MM-DD の期間にかけて、[環境名] において
[侵害の種類] が確認された。攻撃者は...（3〜5文の要約）
```

### セクション 2: インシデント概要

定量的なファクトシートを表形式で示す。

```markdown
## 2. インシデント概要

| 項目 | 値 |
|---|---|
| インシデント期間 | YYYY-MM-DD HH:MM UTC ~ YYYY-MM-DD HH:MM UTC |
| 分析対象イベント総数 | N 件 |
| 重要度別件数 | crit: N / high: N / med: N / low: N / info: N |
| 影響ホスト数 | N 台 |
| 影響ホスト一覧 | HOST-A, HOST-B, ... |
| 侵害確認アカウント数 | N アカウント |
| 検出された攻撃ツール/マルウェア | （ルール名から識別されたもの、なければ「特定のツール名は未検出」） |
| 初期侵入ベクター（推定） | （根拠とともに記載。特定できない場合は「不明 - 追加調査が必要」） |
| 最高重要度イベント | ルール名 (ホスト名, 時刻) |
```

「検出された攻撃ツール/マルウェア」はルール名に含まれるツール名を根拠に記載する。ルール名からツール名が特定できない場合でも、攻撃手法（例: "PowerShellによるリモート実行", "レジストリ改ざんによる防御回避"）を記載する。

「初期侵入ベクター」の推定根拠例:
- Initial Access戦術のイベントが存在する場合 → そのイベント内容から推定
- 二重拡張子ファイルの実行 → フィッシングメール添付ファイル
- 外部IPからのログオン → リモートアクセス経由
- 脆弱性関連ルール → 脆弱性悪用
- 上記いずれにも該当しない → 「不明」と明記

### セクション 3: 侵害タイムライン（メインセクション）

レポートの核心部分。時系列を攻撃フェーズごとにグループ化し、各フェーズ内はイベントを時刻順に表形式で記載する。

#### フェーズ分類のガイドライン

MITRE ATT&CKタクティクスと時間的クラスタリングに基づいてフェーズを分ける。以下は参考区分であり、データの実態に合わせて柔軟にフェーズを設定する:

| フェーズ候補 | 対応MITRE戦術 | 典型的な活動内容 |
|---|---|---|
| 初期アクセス | Initial Access (TA0001) | フィッシング、脆弱性悪用、有効アカウントの不正使用、サプライチェーン |
| 実行 | Execution (TA0002) | スクリプト実行、コマンドライン、WMI/PowerShell/タスクスケジューラ |
| 永続化 | Persistence (TA0003) | サービス登録、スケジュールタスク、レジストリRun key、Bootkit |
| 権限昇格 | Privilege Escalation (TA0004) | 管理者グループ追加、トークン操作、脆弱性悪用 |
| 防御回避 | Defense Evasion (TA0005) | AV無効化、ログ消去、難読化、プロセスインジェクション、署名偽装 |
| 認証情報窃取 | Credential Access (TA0006) | LSASS、SAMダンプ、Kerberoasting、パスワードスプレー |
| 偵察 | Discovery (TA0007) | システム情報、ネットワーク列挙、AD列挙、ファイル探索 |
| 横展開 | Lateral Movement (TA0008) | RDP、SMB、WinRM、PsExec、Pass-the-Hash/Ticket |
| 収集 | Collection (TA0009) | ファイル収集、クリップボード、スクリーンキャプチャ、メール収集 |
| C2通信 | Command and Control (TA0011) | HTTP/HTTPS、DNS、暗号化チャネル、プロキシ |
| 持ち出し | Exfiltration (TA0010) | 外部転送、クラウドストレージ、代替プロトコル |
| 影響 | Impact (TA0040) | 暗号化（ランサムウェア）、破壊、サービス停止、改ざん |

活動が確認されないフェーズは省略する。データに応じて複数のタクティクスを1フェーズにまとめたり、同一タクティクスを時間帯で分割してもよい。

#### 各フェーズの記載フォーマット

```markdown
## 3. 侵害タイムライン

### Phase 1: [フェーズ名] (YYYY-MM-DD HH:MM ~ HH:MM UTC)

| 時刻 (UTC) | ホスト | イベント (RuleTitle) | 重要度 | MITRE | 詳細 |
|---|---|---|---|---|---|
| HH:MM:SS | HOST-A | Rule Name | crit/high | TID | Detailsから攻撃理解に必要な情報を抜粋 |

**分析所見**: このフェーズでは...
```

各フェーズの「分析所見」には以下を含める:
- 攻撃者が何を達成しようとしたか（目的の推定）
- 使用された手法の説明（一般読者にもわかるように）
- 検出根拠（どのSigmaルールがなぜ発火したか）
- 前後のフェーズとの因果関係

テーブルに載せるイベントの選別基準:
- crit/highイベントは原則すべて記載
- 同一ルール・同一ホストの繰り返しは代表的な1件+件数注記
- 同一タイムスタンプで複数ルールが発火した場合は最も重要度の高いルールを採用し、他を注記

### セクション 4: 攻撃フロー図

検出されたMITRE ATT&CKタクティクスに基づく攻撃進行の可視化。

```markdown
## 4. 攻撃フロー (MITRE ATT&CK)

[検出タクティクス1] → [検出タクティクス2] → ... → [検出タクティクスN]
     (TID)              (TID)                        (TID)
   [関連ホスト]        [関連ホスト]                  [関連ホスト]
```

- 実際に検出されたタクティクスのみ記載する
- 各タクティクスの下に、最も代表的なテクニックIDと関連ホストを付記
- 検出間にギャップがある場合（例: 初期アクセス→C2の間が不明）、「(未検出/推定)」と注記して攻撃チェーンの欠落を明示

### セクション 5: 影響を受けた資産とアカウント

#### 5-1. ホスト別影響サマリー

```markdown
## 5. 影響を受けた資産とアカウント

### 5-1. ホスト別影響サマリー

| ホスト名 | 役割（推定） | high/crit件数 | 主な検出ルール | 最初の異常検出 | 最後の異常検出 | 侵害レベル |
|---|---|---|---|---|---|---|
| HOST-A | 端末/サーバ/DC/DB等 | N件 | Rule1, Rule2 | YYYY-MM-DD HH:MM | YYYY-MM-DD HH:MM | 確定/疑い/調査中 |
```

ホスト役割の推定方法:
- ホスト名の命名規則から推定（DC-, SRV-, WS-, DB- 等）
- 検出イベントの種類から推定（AD関連イベント→ドメインコントローラ、DB関連→DBサーバ等）
- 推定できない場合は「不明」

侵害レベルの判定基準:
- **確定**: critイベント検出、マルウェア/攻撃ツール実行、C2通信が確認されたホスト
- **疑い**: highイベント検出、横展開先候補だが決定的証拠が不足
- **調査中**: 関連はあるがmedium以下のみ。追加ログが必要

#### 5-2. アカウント別影響

```markdown
### 5-2. 侵害されたアカウント

| アカウント名 | 種別 | 関連ホスト | 主な関連イベント | 検出件数 | 侵害の根拠 |
|---|---|---|---|---|---|
| アカウント名 | 種別 | HOST-A, HOST-B | イベント概要 | N件 | 侵害と判断した理由 |
```

アカウント種別: ドメインユーザー / ドメイン管理者 / ローカル管理者 / サービスアカウント / SYSTEM / マシンアカウント

### セクション 6: IOC一覧 (Indicators of Compromise)

```markdown
## 6. IOC一覧 (Indicators of Compromise)

### 6-1. 悪性プロセス/ファイル

| IOC種別 | 値 | 検出ホスト | 検出件数 | コンテキスト |
|---|---|---|---|---|
| ファイルパス/プロセス/ハッシュ | 値 | ホスト名 | N | 攻撃における役割 |

### 6-2. ネットワークIOC

| IOC種別 | 値 | 方向 | 検出ホスト | コンテキスト |
|---|---|---|---|---|
| IP/ドメイン/URL/ポート | 値 | In/Out | ホスト名 | 通信の目的 |

### 6-3. 永続化メカニズム

| 種別 | 名前/パス | ホスト | コンテキスト |
|---|---|---|---|
| サービス/タスク/レジストリ/スタートアップ等 | 値 | ホスト名 | 目的 |

### 6-4. アカウントIOC

| アカウント | 種別 | 不審な活動 | ホスト |
|---|---|---|---|
| アカウント名 | 種別 | 活動内容 | ホスト名 |
```

各カテゴリで該当がない場合は「該当なし - [理由]」と明記する。「調査したが検出されなかった」と「調査していない」を区別することが重要。

### セクション 7: デコード済みペイロード

```markdown
## 7. デコード済みペイロード

### ペイロード 1: [目的の簡潔な説明]
- **検出時刻**: YYYY-MM-DD HH:MM UTC
- **検出ホスト**: HOST-A
- **検出ルール**: Rule Name
- **エンコード方式**: Base64 / XOR / Gzip+Base64 等
- **デコード結果**:
  ```
  デコードされたコマンド/スクリプト
  ```
- **分析**: このスクリプトの目的と実行された場合の影響
- **攻撃性判定**: 攻撃ペイロード / 正規ツール由来（非攻撃性） / 判定不能
```

デコード対象が存在しない場合は「エンコードされたペイロードは検出されなかった」と記載。

### セクション 8: 横展開分析

```markdown
## 8. 横展開 (Lateral Movement) 分析

### 伝播経路

HOST-A (HH:MM) --[手法]--> HOST-B (HH:MM) --[手法]--> HOST-C (HH:MM)

### 横展開イベント詳細

| 時刻 (UTC) | 起点ホスト | 宛先ホスト | 手法 | 検出ルール | 使用アカウント |
|---|---|---|---|---|---|
| HH:MM:SS | HOST-A | HOST-B | 手法名 | Rule Name | アカウント名 |
```

横展開が検出されなかった場合:
- 単一ホストのインシデント → 「横展開は検出されなかった。攻撃は [HOST-A] に限定されていた可能性がある」
- ログ不足の可能性 → 「横展開の証拠は検出されなかったが、[理由] により確定的ではない」

### セクション 9: 調査上の留意事項と推奨事項

```markdown
## 9. 調査上の留意事項と推奨事項

### 分析の制約
- **分析範囲**: 本レポートは Hayabusa Sigmaルールにより検出されたイベントに基づく。ルールに合致しない活動は検出対象外
- **タイムスタンプ**: すべてUTC表記
- **ログソース**: 分析に使用したログソース / 不足しているログソース

### 偽陽性と判定したイベント

| ルールタイトル | 件数 | 判定根拠（Detailsの要約） |
|---|---|---|
| ルール名 | N件 | 偽陽性と判断した具体的理由 |

### 判断が困難なイベント
（攻撃活動か正規活動か確定できなかったイベント。追加情報による判定可能条件も記載。）

### 追加調査の推奨
（本分析では確認できなかった領域、追加で取得すべきログ、確認すべき事項）

### 封じ込め・復旧の推奨事項
（検出された脅威に基づく即時対応の提案: アカウントリセット、ホスト隔離、IOCブロック等）
```

---

## Analysis Notes (Shared)

These notes apply regardless of `REPORT_LANG`:

- **Attack tool identification**: Hayabusa rule names often contain attack tool names (e.g., "HackTool - [ToolName]", "[ToolName] Execution"). Identify attack tools/frameworks from rule name patterns and reflect in Section 2
- **Distinguishing from legitimate activity**: Activity from configuration management tools (Packer, Ansible, SCCM, etc.) and IT management tools is easily mistaken for attacks. Judge based on context (execution path, executing user, timing) and document the rationale in Section 9
- **Handling duplicate detections**: Multiple rules firing at the same timestamp likely indicates multiple rule matches on the same event. Use the highest-severity rule as the representative in the timeline
- **Account analysis**: Focus on single-account activity across multiple hosts, interactive logons by service accounts, and abnormal usage patterns of admin accounts
- **Temporal correlation**: Events occurring across different hosts in a short time are indicators of lateral movement. Correlate event groups within a time window (typically minutes to tens of minutes)
- **Pagination handling**: When MCP tool results contain `has_more: True`, follow these criteria:
  - **Must fetch all**: Crit events (`run_sql` WHERE Level = 'crit'), compromised account list (`parse_details_field` User)
  - **Fetch up to top 200**: IOCs (`extract_iocs`), lateral movement correlation (`correlate_lateral_movement`)
  - **First page sufficient**: Time window summary (`summarize_by_time_window`), rule title aggregation (`analyze_rule_titles`)
  - **Fetch all for 2–3 most suspicious hosts**: Host timeline (`analyze_host_timeline`)
  - Otherwise judge by situation. Prioritize filter refinement (level, rule_title, time_range) over pagination
- **Handling large tool outputs**: When `decode_powershell_commands` or `run_sql` results exceed token limits and are saved to files, delegate file reading and summarization to the Task tool (background agent). Instructions should include "summarize decoded results", "extract hosts and timestamps", "classify attack objectives"
- **Handling data absence**: Absence of events in a category is important information. "Not detected" means "nothing matched detection rules," not "did not occur." Reflect this distinction in the report
- **Active false positive elimination (Most Important)**: **Never determine something is an attack based on rule title alone. Always verify actual Details field content before making a determination.** Do not skip Step 3.5
- **Searching attacker staging directories**: When process paths in Details contain `C:\Users\Public\`, `C:\ProgramData\`, `C:\Windows\Temp\<random>\`, `C:\Perflogs\`, etc., cross-search the same directory path with `search_all_fields` to discover other tools placed there
- **Process correlation via PID/PGUID**: Same PID/PGUID detected by different rules = different aspects of the same process. Reflect this correlation in the timeline and lateral movement analysis
- **IP-to-hostname mapping**: Resolve internal IPs to hostnames wherever possible via SQL correlation
- **SID-to-account name resolution**: When only SIDs are recorded, search for the same SID with an associated account name in other events
- **Reliable hash IOC collection**: Include Hashes values (SHA256, SHA1, MD5, IMPHASH) from Details for attack-related processes/DLLs in the IOC section
- **Full activity period coverage**: When multiple discontinuous activity clusters exist, check representative events for all clusters. Clusters without clear attack activity should not be labeled "attack campaigns"
