# 使い方

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
