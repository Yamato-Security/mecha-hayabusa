<div align="center">
 <p>
    <img alt="Mecha Hayabusa Logo" src="mecha_hayabusa_logo.png" width="50%">
 </p>
 [ <b>English</b> ] | [<a href="OLD-README.md">English</a>]
</div>

# Mecha Hayabusa

Hayabusa の解析結果を対象に、DFIRタイムライン分析とインシデントレポート生成を行う AI アナライザー。

# 概要

**Mecha Hayabusa** は、Windows イベントログ解析ツール **Hayabusa** を**Model Context Protocol (MCP)**を通じて大規模言語モデル（LLM）と接続し、自然言語によるデジタルフォレンジック調査および脅威ハンティングを可能にします。
アナリストは CSV 形式の Windows イベントログデータセットを対象に、MITRE ATT&CK タクティクス分析、IOC抽出、ラテラルムーブメント相関分析、PowerShellコマンドのデコード、ホスト単位のタイムライン分析などをインタラクティブに実行できます。

Hayabusa の CSV タイムラインは自動的にローカルの **DuckDB**データベースへ変換され、大規模なログデータに対して LLM が高速かつ構造化された分析を行えるようになります。
主な機能として、データセットの切り替えとプロファイリング、読み取り専用SQL 実行、クロスフィールド検索、RuleTitle集計、時間ウィンドウ集計、ホストタイムライン分析、`Details`フィールド解析、IOC 抽出、Base64 エンコードされた PowerShellのデコード、ラテラルムーブメント相関分析などを提供します。

さらに Mecha Hayabusa には、DFIR 調査プロセスを標準化する**解析SKILL**が含まれており、日本語または英語での構造化インシデントレポート生成をサポートします。

Mecha Hayabusa の最大の特徴は、LLMを単なる検索インターフェースとして利用するのではなく、**MCPを通じて構造化された DFIR 調査ワークフローを実行できる点**にあります。
この仕組みにより、データセットの初期トリアージ、仮説構築、IOC抽出、攻撃フェーズ分析、ホスト単位の詳細調査、ラテラルムーブメント分析、最終レポート生成まで、インシデント調査のライフサイクル全体をサポートします。

これにより、経験豊富なフォレンジックアナリストの調査手順を再現しつつ、ジュニアおよびミッドレベルのインシデントレスポンダーにとっても一貫性と再現性の高い調査を可能にします。

------------------------------------------------------------------------

# 実行方法（HTTP）

``` bash
uv sync
uv run server.py --transport http --port 9999
```

エンドポイント:

    http://127.0.0.1:9999/mcp

------------------------------------------------------------------------

## Claude への追加方法

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

# 機能

## Dataset Operations

解析対象データセットを管理します。

-   **get_dataset_status**
    現在ロードされているデータセットの状態を取得します。

-   **list_datasets**
    解析可能な CSV データセットの一覧を取得します。
    ページングに対応しています。

-   **switch_dataset**
    解析対象データセットを指定した CSV に切り替えます。

-   **unload_dataset**
    現在の `logs` テーブルをアンロードします。

-   **dataset_profile**
    データセットの概要を取得します。
    内容:

    -   イベント総数
    -   期間
    -   上位傾向

    ページングに対応しています。

------------------------------------------------------------------------

## Query & Search

ログデータの検索およびクエリ実行を行います。

-   **run_sql**
    `logs` テーブルに対して読み取り専用 `SELECT` クエリを実行します。
    安全制約が組み込まれています。

-   **search_all_fields**
    全カラムまたは指定カラムを対象にキーワード検索を行います。
    ページング対応。

-   **get_event_detail**
    単一イベントを `Field / Value` 形式で展開取得します。
    `RecordID` または条件指定で取得できます。

------------------------------------------------------------------------

## Timeline & Analytics

攻撃活動およびイベントの時系列分析を行います。

-   **analyze_mitre_tactics**
    **MITRE ATT&CK タクティクス**別に攻撃フェーズを時系列分析します。

-   **analyze_host_timeline**
    特定ホストの時系列イベントを抽出します。
    **侵害チェーン追跡**に有用です。

-   **correlate_lateral_movement**
    指定時間ウィンドウ内でホスト間のラテラルムーブメントを相関分析します。

-   **summarize_events**
    指定フィールドでログイベントを集計します。

-   **summarize_by_time_window**
    時間ウィンドウごとのイベント数を集計します。

    -   `1h`
    -   `3h`
    -   `6h`
    -   `12h`
    -   `1d`

-   **analyze_rule_titles**
    `RuleTitle` の出現頻度を条件付きで集計します。

------------------------------------------------------------------------

## Detail & IOC Analysis

ログ詳細から IOC や重要情報を抽出します。

-   **parse_details_field**
    `Details` フィールドからキー / 値を抽出します。
    一覧表示およびユニーク集計に対応。

-   **extract_iocs**
    `Details` および `ExtraFieldInfo` から **IOC (Indicators of Compromise)** をカテゴリ別に抽出します。

-   **decode_powershell_commands**
    イベント内の Base64 エンコードされた PowerShell
    コマンドをデコードします。

# コントリビュータ

- Akira Nishikawa (https://github.com/nishikawaakira)
- Pinksawtooth (https://github.com/pinksawtooth | https://x.com/PINKSAWTOOTH)
- Zach Mathis / Tanaka Zakku (https://github.com/Yamato-Security/ | https://x.com/yamatosecurity)