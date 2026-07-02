# 功能特色

## Dataset Operations

管理用於分析的資料集。

- **get_dataset_status**  
  取得目前載入資料集的狀態。

- **list_datasets**  
  列出可供分析的 CSV 資料集。  
  支援分頁。

- **switch_dataset**  
  將作用中的分析資料集切換為指定的 CSV 檔案。

- **unload_dataset**  
  卸載目前的 `logs` 資料表。

- **dataset_profile**  
  取得資料集的摘要，包括：
  - 事件總數
  - 時間範圍
  - 主要趨勢

  支援分頁。

---

## Query & Search

搜尋並查詢記錄資料。

- **run_sql**  
  對 `logs` 資料表執行唯讀的 `SELECT` 查詢。  
  內建安全限制。

- **search_all_fields**  
  在所有欄位或指定欄位中執行關鍵字搜尋。  
  支援分頁。

- **get_event_detail**  
  以展開的 `Field / Value` 格式取得單一事件。  
  支援透過 `RecordID` 或查詢條件查找。

---

## Timeline & Analytics

分析攻擊活動與事件時間軸。

- **analyze_mitre_tactics**  
  依 **MITRE ATT&CK tactics** 分組，對攻擊階段進行時序分析。

- **analyze_host_timeline**  
  擷取特定主機的時序事件。  
  適用於**入侵鏈追蹤**。

- **correlate_lateral_movement**  
  在指定時間窗口內關聯主機之間的橫向移動活動。

- **summarize_events**  
  依指定欄位彙整記錄事件。

- **summarize_by_time_window**  
  依時間窗口計算事件數量：
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  彙整 `RuleTitle` 出現的頻率，並可套用選用的篩選條件。

---

## Detail & IOC Analysis

從記錄細節中擷取並分析指標。

- **parse_details_field**  
  從 `Details` 欄位擷取鍵/值配對。  
  支援列出與唯一值彙整。

- **extract_iocs**  
  從 `Details` 與 `ExtraFieldInfo` 擷取 **Indicators of Compromise (IOCs)**，並依類型分類。

- **decode_powershell_commands**  
  解碼事件中發現的 Base64 編碼 PowerShell 指令。
