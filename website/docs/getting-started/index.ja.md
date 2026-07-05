# 使い方

## Hayabusa CSV の作成方法

Hayabusa は **`verbose`** プロファイルで実行して CSV タイムラインを作成してください（推奨）:

``` bash
hayabusa csv-timeline -d <EVTXフォルダ> -o hayabusa-results.csv -p verbose -w
```

省略されていない全フィールド情報など、より詳細な情報が欲しい場合は **`all-field-info-verbose`** プロファイルを使用してください:

``` bash
hayabusa csv-timeline -d <EVTXフォルダ> -o hayabusa-results.csv -p all-field-info-verbose -w
```

Mecha Hayabusa に関係するプロファイルの違い（Hayabusa 3.8.0 の実出力で確認済み）:

| プロファイル | 詳細カラム | 詳細カラム内のフィールド名 |
|---|---|---|
| `verbose`（推奨） | `Details` + `ExtraFieldInfo` | 略称（例: `Cmdline`, `Proc`, `SrcIP`） |
| `all-field-info-verbose` | `AllFieldInfo` | 元のイベントフィールド名（例: `CommandLine`, `NewProcessName`, `SourceIp`） |

注意:

- 詳細フィールドを解析するツール（`parse_details_field`, `extract_iocs`, `decode_powershell_commands`, `analyze_mitre_tactics`）はデフォルトで `Details` カラムを解析します。`all-field-info-verbose` の CSV を解析する場合は **`detail_source="AllFieldInfo"`** を指定してください。
- どちらのプロファイルにも、`analyze_mitre_tactics` と `correlate_lateral_movement` が必要とする `MitreTactics` / `MitreTags` カラムが含まれます。

------------------------------------------------------------------------

## 実行方法（HTTP）

``` bash
uv sync
uv run server.py --transport http --port 9999
```

エンドポイント:

    http://127.0.0.1:9999/mcp

------------------------------------------------------------------------

### Claude への追加方法

``` bash
claude mcp add --transport http hayabusa http://127.0.0.1:9999/mcp
```

確認:

``` bash
claude mcp list
```

プロンプト例:

    Mecha Hayabusa を使って hayabusa-results.csv を読み込み、侵害タイムラインとレポートを作成してください。

------------------------------------------------------------------------
