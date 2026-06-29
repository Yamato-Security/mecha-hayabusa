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
