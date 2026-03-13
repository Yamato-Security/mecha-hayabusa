# hayabusa-mcp
MCP Server for Hayabusa

## 実行方法（HTTP）

```bash
uv sync
uv run server.py --transport http --port 9999
```

起動後のエンドポイント:

```text
http://127.0.0.1:9999/mcp
```

## Claude に追加する方法

```bash
claude mcp add --transport http hayabusa http://127.0.0.1:9999/mcp
```

確認:

```bash
claude mcp list
```

プロンプト例
```
hayabus mcpを使ってhayabusa-results.csvを読み込んで侵害のタイムラインを作って
```

<img width="1190" height="211" alt="image" src="https://github.com/user-attachments/assets/7116517e-ce36-4f80-a474-931021875953" />

結果
<img width="2486" height="1488" alt="image" src="https://github.com/user-attachments/assets/78fe5337-768a-4ef5-9e44-6f9ac57e25ab" />


## ツール一覧

### Dataset Operations

- get_dataset_status - 現在ロードされているデータセット状態を取得
- list_datasets - 解析候補のCSV一覧を取得（ページング対応）
- switch_dataset - 解析対象データセットをCSVへ切り替え
- unload_dataset - 現在の `logs` テーブルをアンロード
- dataset_profile - データセット概要（件数/期間/上位傾向）を取得（ページング対応）

### Query & Search

- run_sql - `logs` テーブルに対して読み取り専用 `SELECT` を実行（安全制約付き）
- search_all_fields - 全カラム/指定カラムを横断してキーワード検索（ページング対応）
- get_event_detail - 単一イベントを `Field/Value` 形式で展開取得（`RecordID` または条件）

### Timeline & Analytics

- analyze_mitre_tactics - MITRE ATT&CK タクティクス別に攻撃フェーズを時系列分析
- analyze_host_timeline - 特定ホストの時系列イベントを抽出（侵害チェーン追跡向け）
- correlate_lateral_movement - ホスト間の横展開イベントを時間窓で相関分析
- summarize_events - 指定フィールドでログイベントを集計
- summarize_by_time_window - 時間窓（`1h/3h/6h/12h/1d`）ごとのイベント数を集計
- analyze_rule_titles - `RuleTitle` の出現頻度を条件付きで集計

### Detail & IOC Analysis

- parse_details_field - `Details` のキー/値を抽出・一覧化・一意集計
- extract_iocs - `Details/ExtraFieldInfo` から IOC をカテゴリ別抽出
- decode_powershell_commands - Base64 エンコードされた PowerShell コマンドをデコード
