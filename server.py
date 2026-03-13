from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
from typing import Sequence

import duckdb
import pandas as pd
from mcp.server.fastmcp import FastMCP

DB_PATH = pathlib.Path("hayabusa.duckdb")
app = FastMCP("Hayabusa MCP")

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
RUN_SQL_MAX_ROWS = 500
DATASET_LIST_MAX_ROWS = 500
SUMMARY_FIELD_CANDIDATES = ("RuleTitle", "Computer", "Level", "EventID", "Channel", "Provider")
SEARCH_RESULT_COLUMNS = ("Timestamp", "Computer", "RuleTitle", "Level", "Channel", "EventID", "MitreTactics", "MitreTags", "Details")
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f %z"

class _WideDisplayDataFrame(pd.DataFrame):
    """parse_details_field 専用 DataFrame。str/repr 時のみ全カラム・全幅で表示する。"""

    @property
    def _constructor(self):
        return _WideDisplayDataFrame

    def __repr__(self) -> str:
        with pd.option_context(
            "display.max_colwidth", None,
            "display.max_columns", None,
            "display.width", None,
        ):
            return super().__repr__()

    def __str__(self) -> str:
        with pd.option_context(
            "display.max_colwidth", None,
            "display.max_columns", None,
            "display.width", None,
        ):
            return super().__str__()


DETAILS_SEPARATOR_CHAR = "\u00a6"  # Hayabusa broken bar (U+00A6)
DETAILS_SEPARATOR = f" {DETAILS_SEPARATOR_CHAR} "

IOC_FIELD_CATEGORIES = {
    "process": ["Proc", "Image", "ParentImage"],
    "cmdline": ["Cmdline"],
    "filepath": ["Path", "TgtFile"],
    "ip": ["SrcIP", "DstIP", "SrcAddr", "DstAddr", "IpAddress", "DestAddress", "SourceAddress"],
    "user": ["User", "TgtUser", "SrcUser"],
    "hash": ["Hash", "Hashes"],
    "service": ["Svc"],
}

TACTICS_MAP = {
    "InitAccess": "初期アクセス",
    "Exec": "実行",
    "Persis": "永続化",
    "PrivEsc": "特権昇格",
    "Evas": "防御回避",
    "CredAccess": "認証情報窃取",
    "Disc": "偵察",
    "LatMov": "横方向移動",
    "Collect": "収集",
    "C2": "C2通信",
    "Exfil": "データ持ち出し",
    "Impact": "影響",
    "Recon": "偵察",
    "ResDev": "リソース開発",
}


class DuckDBRepository:
    """DuckDB操作をまとめたユーティリティラッパー。"""

    def __init__(self, db_path: pathlib.Path) -> None:
        self.db_path = db_path

    def is_initialised(self) -> bool:
        return self.db_path.exists()

    @staticmethod
    def _table_exists(con: duckdb.DuckDBPyConnection, table_name: str) -> bool:
        exists = con.execute(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE LOWER(table_name) = LOWER(?)
            """,
            [table_name],
        ).fetchone()[0]
        return bool(exists)

    def _ensure_state_table(self, con: duckdb.DuckDBPyConnection) -> None:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_state (
                key VARCHAR PRIMARY KEY,
                value VARCHAR
            )
            """
        )

    def load_csv_dataset(self, dataset: pathlib.Path) -> int:
        dataset_literal = str(dataset).replace("'", "''")
        with duckdb.connect(str(self.db_path)) as con:
            self._ensure_state_table(con)
            con.execute("DROP TABLE IF EXISTS logs")
            con.execute(
                f"""
                CREATE TABLE logs AS
                SELECT *
                FROM read_csv_auto(
                    '{dataset_literal}',
                    SAMPLE_SIZE=-1,
                    ALL_VARCHAR=True
                )
                """
            )
            row_count = int(con.execute("SELECT COUNT(*) FROM logs").fetchone()[0])
            con.execute("DELETE FROM mcp_state WHERE key IN ('dataset_path', 'loaded_at')")
            con.execute("INSERT INTO mcp_state (key, value) VALUES ('dataset_path', ?)", [str(dataset)])
            con.execute(
                """
                INSERT INTO mcp_state (key, value)
                VALUES ('loaded_at', CAST(CURRENT_TIMESTAMP AS VARCHAR))
                """
            )
        return row_count

    def unload_dataset(self) -> None:
        if not self.db_path.exists():
            return
        with duckdb.connect(str(self.db_path)) as con:
            self._ensure_state_table(con)
            con.execute("DROP TABLE IF EXISTS logs")
            con.execute("DELETE FROM mcp_state WHERE key IN ('dataset_path', 'loaded_at')")

    def query_dataframe(self, sql: str, params: Sequence[object] | None = None) -> pd.DataFrame:
        """read_only接続でSELECT結果をDataFrameに変換する。"""
        with duckdb.connect(str(self.db_path), read_only=True) as con:
            if params:
                return con.execute(sql, params).df()
            return con.execute(sql).df()

    def get_logs_columns(self) -> set[str]:
        if not self.db_path.exists():
            return set()
        with duckdb.connect(str(self.db_path), read_only=True) as con:
            if not self._table_exists(con, "logs"):
                return set()
            rows = con.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'logs'
                ORDER BY ordinal_position
                """
            ).fetchall()
        return {row[0] for row in rows}

    def explain_json(self, sql: str) -> list[dict[str, object]]:
        with duckdb.connect(str(self.db_path), read_only=True) as con:
            con.execute("PRAGMA disable_optimizer")
            row = con.execute(f"EXPLAIN (FORMAT JSON) {sql}").fetchone()
        if not row or len(row) < 2:
            return []
        return json.loads(row[1])

    def get_dataset_status(self) -> dict[str, object]:
        if not self.db_path.exists():
            return {
                "loaded": False,
                "dataset_path": "",
                "loaded_at": "",
                "row_count": 0,
                "column_count": 0,
                "columns": [],
            }

        with duckdb.connect(str(self.db_path), read_only=True) as con:
            has_logs = self._table_exists(con, "logs")
            has_state = self._table_exists(con, "mcp_state")

            dataset_path = ""
            loaded_at = ""
            if has_state:
                state_rows = con.execute(
                    """
                    SELECT key, value
                    FROM mcp_state
                    WHERE key IN ('dataset_path', 'loaded_at')
                    """
                ).fetchall()
                state = {row[0]: row[1] for row in state_rows}
                dataset_path = str(state.get("dataset_path", ""))
                loaded_at = str(state.get("loaded_at", ""))

            if not has_logs:
                return {
                    "loaded": False,
                    "dataset_path": dataset_path,
                    "loaded_at": loaded_at,
                    "row_count": 0,
                    "column_count": 0,
                    "columns": [],
                }

            row_count = int(con.execute("SELECT COUNT(*) FROM logs").fetchone()[0])
            columns = [
                row[0]
                for row in con.execute(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'logs'
                    ORDER BY ordinal_position
                    """
                ).fetchall()
            ]
            return {
                "loaded": True,
                "dataset_path": dataset_path,
                "loaded_at": loaded_at,
                "row_count": row_count,
                "column_count": len(columns),
                "columns": columns,
            }


repo = DuckDBRepository(DB_PATH)
_LOG_COLUMNS_CACHE: set[str] | None = None


def init_db(dataset: pathlib.Path) -> None:
    """
    指定されたCSVデータセットを読み込み、DuckDBデータベースを初期化します。
    既存のlogsテーブルがある場合は置き換えます。

    Parameters:
        dataset: 読み込むCSVファイルのパス
    """
    global _LOG_COLUMNS_CACHE
    row_count = repo.load_csv_dataset(dataset)
    _LOG_COLUMNS_CACHE = repo.get_logs_columns()
    print(f"✓ {dataset.name} loaded ({row_count} rows) → {DB_PATH}")


def _status_to_dataframe(status: dict[str, object]) -> pd.DataFrame:
    columns_value = status.get("columns", [])
    columns_text = ", ".join(columns_value) if isinstance(columns_value, list) else str(columns_value)
    return pd.DataFrame(
        [
            {
                "message": str(status.get("message", "")),
                "loaded": bool(status.get("loaded", False)),
                "dataset_path": str(status.get("dataset_path", "")),
                "loaded_at": str(status.get("loaded_at", "")),
                "row_count": int(status.get("row_count", 0)),
                "column_count": int(status.get("column_count", 0)),
                "columns": columns_text,
            }
        ]
    )


def _quote_identifier(name: str) -> str:
    stripped = name.strip()
    if not stripped or '"' in stripped:
        raise ValueError(f"不正なカラム名です: {name}")
    return f'"{stripped}"'


def _get_logs_columns() -> set[str]:
    global _LOG_COLUMNS_CACHE
    if _LOG_COLUMNS_CACHE is None:
        _LOG_COLUMNS_CACHE = repo.get_logs_columns()
    return set(_LOG_COLUMNS_CACHE)


def _ensure_database_ready() -> None:
    if not repo.is_initialised():
        raise RuntimeError("Hayabusa DB が初期化されていません。switch_dataset ツールでCSVをロードしてください。")
    columns = _get_logs_columns()
    if not columns:
        raise RuntimeError("logs テーブルが見つかりません。switch_dataset ツールでCSVをロードしてください。")


def _ensure_columns_exist(columns: Sequence[str], context: str) -> None:
    existing = _get_logs_columns()
    missing = [col for col in columns if col not in existing]
    if not missing:
        return

    missing_label = ", ".join(sorted(set(missing)))
    available_label = ", ".join(sorted(existing))
    raise ValueError(
        f"{context}: 必要なカラムが存在しません ({missing_label})。"
        f" 利用可能カラム: {available_label}"
    )


def _resolve_pagination(
    page_size: int,
    page_offset: int,
    *,
    default_page_size: int = DEFAULT_PAGE_SIZE,
    max_page_size: int = MAX_PAGE_SIZE,
    legacy_size: int | None = None,
    legacy_name: str = "limit",
) -> tuple[int, int]:
    if legacy_size is not None:
        resolved_size = legacy_size
    elif page_size == 0:
        resolved_size = default_page_size
    else:
        resolved_size = page_size

    if resolved_size <= 0 or resolved_size > max_page_size:
        raise ValueError(
            f"page_size は 1 〜 {max_page_size} の範囲で指定してください。"
            f"（互換引数 {legacy_name} も同範囲）"
        )
    if page_offset < 0:
        raise ValueError("page_offset は 0 以上で指定してください。")
    return resolved_size, page_offset


def _query_with_pagination(
    sql: str,
    params: Sequence[object] | None,
    *,
    page_size: int,
    page_offset: int,
    include_total: bool = True,
) -> tuple[pd.DataFrame, int | None]:
    normalized_sql = sql.strip().rstrip(";").strip()
    if not normalized_sql:
        raise ValueError("SQLが空です。")

    total_count: int | None = None
    if include_total:
        count_sql = f"""
            SELECT COUNT(*) AS total_count
            FROM ({normalized_sql}) AS _hayabusa_mcp_count
        """
        count_df = repo.query_dataframe(count_sql, params)
        total_count = int(count_df.iloc[0]["total_count"]) if not count_df.empty else 0

    paging_sql = f"""
        SELECT *
        FROM ({normalized_sql}) AS _hayabusa_mcp_paged
        LIMIT ?
        OFFSET ?
    """
    paging_params: list[object] = list(params or [])
    paging_params.extend([page_size, page_offset])
    return repo.query_dataframe(paging_sql, paging_params), total_count


def _attach_pagination_metadata(
    df: pd.DataFrame,
    *,
    total_count: int | None,
    page_size: int,
    page_offset: int,
    status: str = "ok",
    message: str = "",
    extra_meta: dict[str, object] | None = None,
) -> pd.DataFrame:
    returned_count = len(df)
    if total_count is None:
        has_more = returned_count == page_size
        next_offset = (page_offset + returned_count) if has_more else None
    else:
        has_more = (page_offset + returned_count) < total_count
        next_offset = (page_offset + returned_count) if has_more else None

    if df.empty:
        row: dict[str, object] = {
            "status": status,
            "message": message,
            "total_count": total_count,
            "has_more": has_more,
            "next_offset": next_offset,
            "page_size": page_size,
            "page_offset": page_offset,
        }
        if extra_meta:
            row.update(extra_meta)
        return pd.DataFrame([row])

    out = df.copy()
    out["status"] = status
    out["message"] = message
    out["total_count"] = total_count
    out["has_more"] = has_more
    out["next_offset"] = next_offset
    out["page_size"] = page_size
    out["page_offset"] = page_offset
    if extra_meta:
        for key, value in extra_meta.items():
            out[key] = value
    return out


def _has_order_by_clause(sql: str) -> bool:
    normalized = re.sub(r"\s+", " ", sql).strip().lower()
    return " order by " in f" {normalized} "


def _query_hash(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _dataset_version() -> str:
    status = repo.get_dataset_status()
    dataset_path = str(status.get("dataset_path", ""))
    loaded_at = str(status.get("loaded_at", ""))
    return f"{dataset_path}|{loaded_at}"


def _normalise_levels(level: str | Sequence[str] | None) -> list[str]:
    if level is None:
        return []
    if isinstance(level, str):
        return [level]
    return [str(item) for item in level]


def _collect_plan_sources(plan_nodes: Sequence[dict[str, object]]) -> tuple[set[str], set[str]]:
    tables: set[str] = set()
    functions: set[str] = set()

    stack = list(plan_nodes)
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue

        extra_info = node.get("extra_info")
        if isinstance(extra_info, dict):
            table_name = extra_info.get("Table")
            if isinstance(table_name, str) and table_name:
                tables.add(table_name.lower())

            function_name = extra_info.get("Function")
            if isinstance(function_name, str) and function_name:
                functions.add(function_name.upper())

        children = node.get("children")
        if isinstance(children, list):
            stack.extend(children)

    return tables, functions


def _validate_select_on_logs_only(sql: str) -> str:
    if not sql or not sql.strip():
        raise ValueError("SQLを入力してください。")

    try:
        statements = duckdb.extract_statements(sql)
    except duckdb.Error as exc:
        raise ValueError(f"SQLの構文が不正です: {exc}") from exc

    if len(statements) != 1:
        raise ValueError("run_sql は単一の SELECT 文のみ実行できます。")

    statement = statements[0]
    if statement.type != duckdb.StatementType.SELECT:
        raise ValueError("run_sql は SELECT 文のみ実行できます。")

    normalized_sql = statement.query.strip().rstrip(";").strip()
    if not normalized_sql:
        raise ValueError("SQLを入力してください。")

    try:
        plan_nodes = repo.explain_json(normalized_sql)
    except duckdb.Error as exc:
        raise ValueError("run_sql は logs テーブルを参照する SELECT 文のみ実行できます。") from exc

    scanned_tables, scanned_functions = _collect_plan_sources(plan_nodes)

    if scanned_functions:
        refs = ", ".join(sorted(scanned_functions))
        raise ValueError(f"run_sql ではテーブル関数/システム関数は使用できません: {refs}")

    if not scanned_tables:
        raise ValueError("run_sql は logs テーブルを参照する SELECT 文のみ実行できます。")

    if scanned_tables != {"logs"}:
        refs = ", ".join(sorted(scanned_tables))
        raise ValueError(f"run_sql は logs テーブルのみ参照できます。検出参照: {refs}")

    return normalized_sql


def _available_summary_fields() -> list[str]:
    existing = _get_logs_columns()
    return [field for field in SUMMARY_FIELD_CANDIDATES if field in existing]


def _format_path_for_display(path: pathlib.Path) -> str:
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _search_csv_files(base_dir: pathlib.Path, recursive: bool, name_filter: str = "") -> list[pathlib.Path]:
    iterator = base_dir.rglob("*.csv") if recursive else base_dir.glob("*.csv")
    files: list[pathlib.Path] = []
    name_filter_lower = name_filter.lower().strip()

    for path in iterator:
        if not path.is_file():
            continue
        if name_filter_lower and name_filter_lower not in path.name.lower():
            continue
        files.append(path.resolve())

    return sorted(files, key=lambda p: str(p).lower())


def _resolve_dataset_target(target: str, search_root: str = ".", recursive: bool = True, search_limit: int = DATASET_LIST_MAX_ROWS) -> pathlib.Path:
    target_text = target.strip()
    if not target_text:
        raise ValueError("target を指定してください。")

    explicit = pathlib.Path(target_text).expanduser()
    if explicit.exists() and explicit.is_file():
        resolved = explicit.resolve()
        if resolved.suffix.lower() != ".csv":
            raise ValueError(f"CSVファイルを指定してください: {resolved}")
        return resolved

    root = pathlib.Path(search_root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"search_root が不正です: {root}")

    target_lower = target_text.lower()
    matches: list[pathlib.Path] = []
    iterator = root.rglob("*.csv") if recursive else root.glob("*.csv")
    for path in iterator:
        if not path.is_file():
            continue
        resolved = path.resolve()
        path_text_lower = str(resolved).lower()
        name_lower = resolved.name.lower()
        stem_lower = resolved.stem.lower()
        if (
            target_lower == name_lower
            or target_lower == stem_lower
            or path_text_lower.endswith(target_lower)
        ):
            matches.append(resolved)
            if len(matches) >= search_limit:
                break

    if not matches:
        raise ValueError(
            f"CSV候補が見つかりません: {target_text}. "
            "list_datasets で候補を確認してください。"
        )

    if len(matches) > 1:
        candidates = ", ".join(_format_path_for_display(path) for path in matches[:5])
        raise ValueError(
            f"候補が複数あります: {target_text}. "
            f"より具体的なパスを指定してください。候補例: {candidates}"
        )

    return matches[0]


# ──────────────────────────────────────────
# ツール定義
# ──────────────────────────────────────────
@app.tool()
def get_dataset_status():
    """
    現在ロードされているデータセット状態を返します。
    """
    status = repo.get_dataset_status()
    return _status_to_dataframe(status)


@app.tool()
def list_datasets(
    search_root: str = ".",
    recursive: bool = True,
    name_filter: str = "",
    page_size: int = 100,
    page_offset: int = 0,
    limit: int | None = None,
):
    """
    解析候補のCSVファイル一覧を返します。

    Parameters:
        search_root (str): 探索開始ディレクトリ
        recursive (bool): サブディレクトリを再帰探索するか
        name_filter (str): ファイル名部分一致フィルタ
        page_size (int): 1ページあたりの件数（1〜500）
        page_offset (int): 取得開始オフセット（0以上）
        limit (int | None): 後方互換用。指定時は page_size として扱う
    """
    page_size, page_offset = _resolve_pagination(
        page_size,
        page_offset,
        default_page_size=100,
        max_page_size=DATASET_LIST_MAX_ROWS,
        legacy_size=limit,
        legacy_name="limit",
    )

    root = pathlib.Path(search_root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"search_root が不正です: {root}")

    files = _search_csv_files(root, recursive=recursive, name_filter=name_filter)
    paged_files = files[page_offset : page_offset + page_size]
    rows: list[dict[str, object]] = []
    for path in paged_files:
        stat = path.stat()
        rows.append(
            {
                "alias": path.stem,
                "name": path.name,
                "path": _format_path_for_display(path),
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "modified_at": pd.Timestamp(stat.st_mtime, unit="s").strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    if not rows:
        if files and page_offset >= len(files):
            return _attach_pagination_metadata(
                pd.DataFrame(),
                total_count=len(files),
                page_size=page_size,
                page_offset=page_offset,
                status="no_data",
                message="指定ページにCSV候補はありません",
            )
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=len(files),
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="CSVが見つかりませんでした",
        )

    return _attach_pagination_metadata(
        pd.DataFrame(rows),
        total_count=len(files),
        page_size=page_size,
        page_offset=page_offset,
    )


@app.tool()
def switch_dataset(target: str = "", search_root: str = ".", recursive: bool = True):
    """
    指定したCSVに解析対象を切り替えます。

    Parameters:
        target (str): CSVのパス / ファイル名 / エイリアス（stem）
        search_root (str): targetがパスでない場合の探索起点
        recursive (bool): サブディレクトリ探索を行うか
    """
    global _LOG_COLUMNS_CACHE

    dataset = _resolve_dataset_target(target, search_root=search_root, recursive=recursive)
    row_count = repo.load_csv_dataset(dataset)
    _LOG_COLUMNS_CACHE = repo.get_logs_columns()
    status = repo.get_dataset_status()
    status["message"] = f"switched dataset -> {dataset} ({row_count} rows)"
    return _status_to_dataframe(status)


@app.tool()
def unload_dataset():
    """
    現在の `logs` テーブルをアンロードします。
    """
    global _LOG_COLUMNS_CACHE
    repo.unload_dataset()
    _LOG_COLUMNS_CACHE = None
    status = repo.get_dataset_status()
    status["message"] = "unloaded logs table"
    return _status_to_dataframe(status)


PROFILE_SECTIONS = {"all", "overview", "levels", "computers", "rules"}

@app.tool()
def dataset_profile(
    top_n: int = 10,
    section: str = "all",
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    現在の解析対象データセットの概要を返します。

    Parameters:
        top_n (int): 上位表示件数（Level/Computer/RuleTitle）
        section (str): 取得セクション。'all', 'overview', 'levels', 'computers', 'rules' から選択
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE)
    if top_n <= 0 or top_n > 100:
        raise ValueError("top_n は 1 〜 100 の範囲で指定してください。")

    section = section.strip().lower()
    if section not in PROFILE_SECTIONS:
        allowed = ", ".join(sorted(PROFILE_SECTIONS))
        raise ValueError(f"section は {allowed} から選択してください。")

    columns = _get_logs_columns()
    status = repo.get_dataset_status()

    # Section-specific returns
    if section == "overview":
        overview_rows: list[dict[str, object]] = [
            {"metric": "dataset_path", "value": str(status.get("dataset_path", ""))},
            {"metric": "row_count", "value": str(status.get("row_count", 0))},
            {"metric": "column_count", "value": str(status.get("column_count", 0))},
        ]
        if "Timestamp" in columns:
            time_df = repo.query_dataframe(
                f"""
                SELECT
                    MIN("Timestamp") AS min_ts,
                    MAX("Timestamp") AS max_ts,
                    COUNT(TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}')) AS parsed_count
                FROM logs
                """
            )
            overview_rows.append({"metric": "timestamp_min", "value": str(time_df.iloc[0]["min_ts"] or "")})
            overview_rows.append({"metric": "timestamp_max", "value": str(time_df.iloc[0]["max_ts"] or "")})
            overview_rows.append({"metric": "parsed_timestamp_rows", "value": str(int(time_df.iloc[0]["parsed_count"]))})
        df = pd.DataFrame(overview_rows)
        paged = df.iloc[page_offset : page_offset + page_size].reset_index(drop=True)
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            paged if not paged.empty else pd.DataFrame(),
            total_count=len(df),
            page_size=page_size,
            page_offset=page_offset,
            status="no_data" if paged.empty else "ok",
            message="指定ページにデータはありません" if paged.empty else "",
        ))

    if section == "levels":
        if "Level" not in columns:
            return _WideDisplayDataFrame(_attach_pagination_metadata(
                pd.DataFrame(), total_count=0, page_size=page_size, page_offset=page_offset,
                status="no_data", message="Level カラムが存在しません",
            ))
        level_df = repo.query_dataframe(
            """
            SELECT COALESCE(NULLIF("Level", ''), '(empty)') AS "Level", COUNT(*) AS "Count"
            FROM logs GROUP BY "Level" ORDER BY "Count" DESC, "Level" ASC LIMIT ?
            """, [top_n],
        )
        paged = level_df.iloc[page_offset : page_offset + page_size].reset_index(drop=True)
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            paged if not paged.empty else pd.DataFrame(),
            total_count=len(level_df),
            page_size=page_size,
            page_offset=page_offset,
            status="no_data" if paged.empty else "ok",
            message="指定ページにデータはありません" if paged.empty else "",
        ))

    if section == "computers":
        if "Computer" not in columns:
            return _WideDisplayDataFrame(_attach_pagination_metadata(
                pd.DataFrame(), total_count=0, page_size=page_size, page_offset=page_offset,
                status="no_data", message="Computer カラムが存在しません",
            ))
        host_df = repo.query_dataframe(
            """
            SELECT COALESCE(NULLIF("Computer", ''), '(empty)') AS "Computer", COUNT(*) AS "Count"
            FROM logs GROUP BY "Computer" ORDER BY "Count" DESC, "Computer" ASC LIMIT ?
            """, [top_n],
        )
        paged = host_df.iloc[page_offset : page_offset + page_size].reset_index(drop=True)
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            paged if not paged.empty else pd.DataFrame(),
            total_count=len(host_df),
            page_size=page_size,
            page_offset=page_offset,
            status="no_data" if paged.empty else "ok",
            message="指定ページにデータはありません" if paged.empty else "",
        ))

    if section == "rules":
        if "RuleTitle" not in columns:
            return _WideDisplayDataFrame(_attach_pagination_metadata(
                pd.DataFrame(), total_count=0, page_size=page_size, page_offset=page_offset,
                status="no_data", message="RuleTitle カラムが存在しません",
            ))
        rule_df = repo.query_dataframe(
            """
            SELECT COALESCE(NULLIF("RuleTitle", ''), '(empty)') AS "RuleTitle", COUNT(*) AS "Count"
            FROM logs GROUP BY "RuleTitle" ORDER BY "Count" DESC, "RuleTitle" ASC LIMIT ?
            """, [top_n],
        )
        paged = rule_df.iloc[page_offset : page_offset + page_size].reset_index(drop=True)
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            paged if not paged.empty else pd.DataFrame(),
            total_count=len(rule_df),
            page_size=page_size,
            page_offset=page_offset,
            status="no_data" if paged.empty else "ok",
            message="指定ページにデータはありません" if paged.empty else "",
        ))

    # section == "all": original behavior
    rows: list[dict[str, object]] = []

    rows.append({"section": "overview", "metric": "dataset_path", "key": "", "value": str(status.get("dataset_path", ""))})
    rows.append({"section": "overview", "metric": "row_count", "key": "", "value": str(status.get("row_count", 0))})
    rows.append({"section": "overview", "metric": "column_count", "key": "", "value": str(status.get("column_count", 0))})

    if "Timestamp" in columns:
        time_df = repo.query_dataframe(
            f"""
            SELECT
                MIN("Timestamp") AS min_ts,
                MAX("Timestamp") AS max_ts,
                COUNT(TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}')) AS parsed_count
            FROM logs
            """
        )
        min_ts = str(time_df.iloc[0]["min_ts"] or "")
        max_ts = str(time_df.iloc[0]["max_ts"] or "")
        parsed_count = int(time_df.iloc[0]["parsed_count"])
        rows.append({"section": "overview", "metric": "timestamp_min", "key": "", "value": min_ts})
        rows.append({"section": "overview", "metric": "timestamp_max", "key": "", "value": max_ts})
        rows.append({"section": "overview", "metric": "parsed_timestamp_rows", "key": "", "value": str(parsed_count)})

    if "Level" in columns:
        level_df = repo.query_dataframe(
            """
            SELECT COALESCE(NULLIF("Level", ''), '(empty)') AS label, COUNT(*) AS cnt
            FROM logs GROUP BY label ORDER BY cnt DESC, label ASC LIMIT ?
            """, [top_n],
        )
        for _, rec in level_df.iterrows():
            rows.append({"section": "level", "metric": "count", "key": str(rec["label"]), "value": str(int(rec["cnt"]))})

    if "Computer" in columns:
        host_df = repo.query_dataframe(
            """
            SELECT COALESCE(NULLIF("Computer", ''), '(empty)') AS label, COUNT(*) AS cnt
            FROM logs GROUP BY label ORDER BY cnt DESC, label ASC LIMIT ?
            """, [top_n],
        )
        for _, rec in host_df.iterrows():
            rows.append({"section": "computer", "metric": "count", "key": str(rec["label"]), "value": str(int(rec["cnt"]))})

    if "RuleTitle" in columns:
        rule_df = repo.query_dataframe(
            """
            SELECT COALESCE(NULLIF("RuleTitle", ''), '(empty)') AS label, COUNT(*) AS cnt
            FROM logs GROUP BY label ORDER BY cnt DESC, label ASC LIMIT ?
            """, [top_n],
        )
        for _, rec in rule_df.iterrows():
            rows.append({"section": "rule_title", "metric": "count", "key": str(rec["label"]), "value": str(int(rec["cnt"]))})

    profile_df = pd.DataFrame(rows)
    paged = profile_df.iloc[page_offset : page_offset + page_size].reset_index(drop=True)
    if paged.empty:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(),
            total_count=len(profile_df),
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="指定ページにデータはありません",
        ))
    return _WideDisplayDataFrame(_attach_pagination_metadata(
        paged,
        total_count=len(profile_df),
        page_size=page_size,
        page_offset=page_offset,
    ))



@app.tool()
def run_sql(
    sql: str = "",
    page_size: int = RUN_SQL_MAX_ROWS,
    page_offset: int = 0,
    include_total: bool = True,
    total_count_hint: int | None = None,
    query_hash_hint: str = "",
    dataset_version_hint: str = "",
    max_rows: int | None = None,
    wide_display: bool = True,
):
    """
    📊 テーブル `logs` に対して **読み取り専用 SELECT** を実行し、DataFrame で返します。

    制限:
        - SQLはAST検証され、SELECTかつlogsテーブル参照のみ許可
        - テーブル関数/システム関数参照は不可
        - 返却件数は page_size で指定（最大500行）
        - max_rows は後方互換用（指定時は page_size として扱う）
        - page_offset > 0 の場合は ORDER BY 必須（ページ再現性のため）
        - include_total=False で毎ページの COUNT(*) を省略可能
        - total_count_hint/query_hash_hint/dataset_version_hint を渡すと
          include_total=False でも has_more 判定を正確化できる
        - wide_display=True（デフォルト）で全カラム・全幅表示の _WideDisplayDataFrame を返す
    """
    _ensure_database_ready()
    wrap = _WideDisplayDataFrame if wide_display else lambda df: df
    page_size, page_offset = _resolve_pagination(
        page_size,
        page_offset,
        default_page_size=RUN_SQL_MAX_ROWS,
        max_page_size=RUN_SQL_MAX_ROWS,
        legacy_size=max_rows,
        legacy_name="max_rows",
    )

    validated_sql = _validate_select_on_logs_only(sql)
    if page_offset > 0 and not _has_order_by_clause(validated_sql):
        raise ValueError("run_sql で page_offset を使う場合は、再現性のため ORDER BY を必ず指定してください。")

    query_hash = _query_hash(validated_sql)
    dataset_version = _dataset_version()

    total_count: int | None = None
    count_source = "count_query" if include_total else "none"
    if include_total:
        result_df, total_count = _query_with_pagination(
            validated_sql,
            [],
            page_size=page_size,
            page_offset=page_offset,
            include_total=True,
        )
    else:
        if total_count_hint is not None:
            if total_count_hint < 0:
                raise ValueError("total_count_hint は 0 以上で指定してください。")
            if not query_hash_hint or not dataset_version_hint:
                raise ValueError(
                    "total_count_hint を使う場合は query_hash_hint と dataset_version_hint も指定してください。"
                )
            if query_hash_hint != query_hash:
                raise ValueError("query_hash_hint が現在のSQLと一致しません。count_sql を再実行してください。")
            if dataset_version_hint != dataset_version:
                raise ValueError(
                    "dataset_version_hint が現在のデータセットと一致しません。count_sql を再実行してください。"
                )
            total_count = int(total_count_hint)
            count_source = "hint"

        result_df, _ = _query_with_pagination(
            validated_sql,
            [],
            page_size=page_size,
            page_offset=page_offset,
            include_total=False,
        )

    extra_meta = {
        "query_hash": query_hash,
        "dataset_version": dataset_version,
        "count_source": count_source,
    }

    if include_total and total_count == 0:
        return wrap(_attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="クエリ結果は0件でした",
            extra_meta=extra_meta,
        ))
    if result_df.empty:
        return wrap(_attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="指定ページにデータはありません",
            extra_meta=extra_meta,
        ))
    return wrap(_attach_pagination_metadata(
        result_df,
        total_count=total_count,
        page_size=page_size,
        page_offset=page_offset,
        extra_meta=extra_meta,
    ))


@app.tool()
def get_event_detail(
    record_id: str = "",
    sql_filter: str = "",
):
    """
    単一イベントの全フィールドを Field/Value 形式で展開して返します。

    Parameters:
        record_id (str): RecordID で指定（排他）
        sql_filter (str): WHERE句相当のSQL条件で指定（排他）。
                          例: "Level = 'crit'" → SELECT * FROM logs WHERE Level = 'crit' LIMIT 1
    """
    _ensure_database_ready()

    if record_id.strip() and sql_filter.strip():
        raise ValueError("record_id と sql_filter は同時に指定できません。どちらか一方を指定してください。")
    if not record_id.strip() and not sql_filter.strip():
        raise ValueError("record_id または sql_filter のいずれかを指定してください。")

    if record_id.strip():
        _ensure_columns_exist(["RecordID"], context="get_event_detail")
        fetch_sql = f'SELECT * FROM logs WHERE "RecordID" = ? LIMIT 1'
        row_df = repo.query_dataframe(fetch_sql, [record_id.strip()])
    else:
        full_sql = f"SELECT * FROM logs WHERE {sql_filter.strip()} LIMIT 1"
        _validate_select_on_logs_only(full_sql)
        row_df = repo.query_dataframe(full_sql)

    if row_df.empty:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=1,
            page_offset=0,
            status="no_data",
            message="条件に一致するイベントはありませんでした",
        ))

    row = row_df.iloc[0]
    result_rows: list[dict[str, str]] = []

    for col in row_df.columns:
        val = row[col]
        str_val = "" if pd.isna(val) else str(val)

        if col in ("Details", "ExtraFieldInfo") and str_val:
            prefix = "Details" if col == "Details" else "Extra"
            pairs = str_val.split(DETAILS_SEPARATOR)
            for pair in pairs:
                pair = pair.strip()
                if ": " in pair:
                    k, v = pair.split(": ", 1)
                    result_rows.append({"Field": f"{prefix}.{k.strip()}", "Value": v.strip()})
                elif pair:
                    result_rows.append({"Field": f"{prefix}._raw", "Value": pair})
        else:
            result_rows.append({"Field": col, "Value": str_val})

    detail_df = pd.DataFrame(result_rows)
    return _WideDisplayDataFrame(_attach_pagination_metadata(
        detail_df,
        total_count=len(detail_df),
        page_size=len(detail_df),
        page_offset=0,
    ))


@app.tool()
def search_all_fields(
    query: str = "",
    columns: Sequence[str] | None = None,
    match_mode: str = "contains",
    case_sensitive: bool = False,
    page_size: int = 100,
    page_offset: int = 0,
    include_hit_columns: bool = True,
):
    """
    logsテーブルの全カラム（または指定カラム）を横断してキーワード検索します。

    Parameters:
        query (str): 検索文字列
        columns (Sequence[str] | None): 検索対象カラム。Noneなら全カラム
        match_mode (str): `contains` / `exact` / `prefix` / `regex`
        case_sensitive (bool): 大文字小文字を区別するか
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット
        include_hit_columns (bool): どのカラムでヒットしたかを返却するか
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE)

    keyword = query.strip()
    if not keyword:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="query を指定してください",
        )

    existing_columns = sorted(_get_logs_columns())
    if not existing_columns:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="検索対象カラムが見つかりません",
        )

    if columns is None:
        target_columns = existing_columns
    elif isinstance(columns, str):
        target_columns = [columns.strip()]
    else:
        target_columns = [str(col).strip() for col in columns if str(col).strip()]

    if not target_columns:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="columns が空です",
        )

    _ensure_columns_exist(target_columns, context="search_all_fields")

    normalized_mode = match_mode.strip().lower()
    allowed_modes = {"contains", "exact", "prefix", "regex"}
    if normalized_mode not in allowed_modes:
        allowed_label = ", ".join(sorted(allowed_modes))
        raise ValueError(f"match_mode は {allowed_label} から選択してください。")

    if case_sensitive:
        needle_value = keyword
        needle_ref = "_needle"
    else:
        needle_value = keyword.lower()
        needle_ref = "_needle"

    def build_match_condition(column_name: str) -> str:
        quoted = _quote_identifier(column_name)
        column_expr = f"COALESCE(CAST({quoted} AS VARCHAR), '')"
        if not case_sensitive:
            column_expr = f"LOWER({column_expr})"

        if normalized_mode == "contains":
            return f"POSITION({needle_ref} IN {column_expr}) > 0"
        if normalized_mode == "exact":
            return f"{column_expr} = {needle_ref}"
        if normalized_mode == "prefix":
            return f"{column_expr} LIKE {needle_ref} || '%'"
        return f"REGEXP_MATCHES({column_expr}, {needle_ref})"

    match_conditions = [build_match_condition(col) for col in target_columns]
    where_clause = " OR ".join(match_conditions)

    select_columns = [col for col in SEARCH_RESULT_COLUMNS if col in existing_columns]
    if not select_columns:
        select_columns = target_columns[:8]
    select_expr = ", ".join(_quote_identifier(col) for col in select_columns)

    hit_columns_expr = ""
    if include_hit_columns:
        hit_labels = []
        for col, cond in zip(target_columns, match_conditions):
            label = col.replace("'", "''")
            hit_labels.append(f"CASE WHEN {cond} THEN '{label}' ELSE NULL END")
        hit_columns_expr = f', CONCAT_WS(\', \', {", ".join(hit_labels)}) AS "HitColumns"'

    order_parts: list[str] = []
    if "Timestamp" in existing_columns:
        order_parts.append(f'TRY_STRPTIME("Timestamp", \'{TIMESTAMP_FORMAT}\') ASC NULLS LAST')
        order_parts.append('"Timestamp" ASC')
    if "RecordID" in existing_columns:
        order_parts.append('TRY_CAST("RecordID" AS BIGINT) ASC NULLS LAST')
        order_parts.append('"RecordID" ASC')
    if "Computer" in existing_columns:
        order_parts.append('"Computer" ASC')
    if "RuleTitle" in existing_columns:
        order_parts.append('"RuleTitle" ASC')
    if "EventID" in existing_columns:
        order_parts.append('TRY_CAST("EventID" AS BIGINT) ASC NULLS LAST')
        order_parts.append('"EventID" ASC')
    if not order_parts:
        order_parts.extend(f'{_quote_identifier(col)} ASC' for col in target_columns[:3])
    order_expr = f"ORDER BY {', '.join(order_parts)}"

    query_sql = f"""
        WITH source AS (
            SELECT *, ? AS _needle
            FROM logs
        )
        SELECT
            {select_expr}
            {hit_columns_expr}
        FROM source
        WHERE {where_clause}
        {order_expr}
    """

    result_df, total_count = _query_with_pagination(
        query_sql,
        [needle_value],
        page_size=page_size,
        page_offset=page_offset,
    )

    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="一致するデータはありませんでした",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="指定ページにデータはありません",
        )
    return _attach_pagination_metadata(
        result_df,
        total_count=total_count,
        page_size=page_size,
        page_offset=page_offset,
    )


@app.tool()
def analyze_mitre_tactics(
    filter_tactics: Sequence[str] | None = None,
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    MITRE ATT&CKタクティクスに基づいた攻撃フェーズの分析を行います。

    Parameters:
        filter_tactics (Sequence[str], optional): 分析対象の戦術リスト
                                                 例: ['InitAccess', 'PrivEsc']
                                                 Noneの場合は全戦術を分析
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット

    Returns:
        pandas.DataFrame: 攻撃フェーズの分析結果（時系列順）
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE)
    _ensure_columns_exist(
        ["Timestamp", "Computer", "RuleTitle", "Details", "MitreTactics"],
        context="analyze_mitre_tactics",
    )

    target_tactics = [str(tactic).strip() for tactic in (filter_tactics or TACTICS_MAP.keys()) if str(tactic).strip()]
    if not target_tactics:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="対象のタクティクスが指定されていません",
        )

    values_clause = ", ".join("(?, ?)" for _ in target_tactics)
    params: list[object] = []
    for tactic in target_tactics:
        params.extend([tactic, TACTICS_MAP.get(tactic, tactic)])

    query = f"""
        WITH tactic_map("RawTactic", "Phase") AS (
            VALUES {values_clause}
        ),
        ranked AS (
            SELECT
                tm."RawTactic",
                tm."Phase",
                l."Timestamp" AS "First Seen",
                l."Computer" AS "Computer",
                l."RuleTitle" AS "Event",
                l."Details" AS "Details",
                ROW_NUMBER() OVER (
                    PARTITION BY tm."RawTactic"
                    ORDER BY
                        TRY_STRPTIME(l."Timestamp", '{TIMESTAMP_FORMAT}') ASC NULLS LAST,
                        l."Timestamp" ASC,
                        l."Computer" ASC,
                        l."RuleTitle" ASC,
                        l."Details" ASC
                ) AS rn
            FROM logs AS l
            JOIN tactic_map AS tm
              ON POSITION(tm."RawTactic" IN COALESCE(l."MitreTactics", '')) > 0
        )
        SELECT "Phase", "First Seen", "Computer", "Event", "Details"
        FROM ranked
        WHERE rn = 1
        ORDER BY
            TRY_STRPTIME("First Seen", '{TIMESTAMP_FORMAT}') ASC NULLS LAST,
            "First Seen" ASC,
            "Phase" ASC,
            "Computer" ASC,
            "Event" ASC
    """

    result_df, total_count = _query_with_pagination(query, params, page_size=page_size, page_offset=page_offset)
    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="対象のタクティクスは見つかりませんでした",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="指定ページにデータはありません",
        )
    return _attach_pagination_metadata(
        result_df,
        total_count=total_count,
        page_size=page_size,
        page_offset=page_offset,
    )


@app.tool()
def summarize_events(
    groupby_field: str = "RuleTitle",
    filter_level: str | None = None,
    top_n: int | None = None,
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    ログイベントの集計を行います。

    Parameters:
        groupby_field (str): グループ化するフィールド名 (デフォルト: 'RuleTitle')
                           例: 'Computer', 'RuleTitle', 'Level', 'EventID' など
        filter_level (str, optional): フィルタする重要度レベル ('info', 'low', 'med', 'high', 'crit')
        top_n (int | None): 後方互換用の上位件数制限。Noneなら全件対象
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット

    Returns:
        pandas.DataFrame: イベント集計結果
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE)

    available_fields = _available_summary_fields()
    if not available_fields:
        raise ValueError("summarize_events: 集計対象フィールドが見つかりません。")

    column_name = groupby_field.strip()
    if column_name not in available_fields:
        allowed = ", ".join(available_fields)
        raise ValueError(f"groupby_field={groupby_field} は使用できません。利用可能: {allowed}")

    if top_n is not None and top_n <= 0:
        raise ValueError("top_n は正の整数で指定してください。")

    required_columns = [column_name]
    if filter_level:
        required_columns.append("Level")
    _ensure_columns_exist(required_columns, context="summarize_events")

    params: list[object] = []
    where_clause = ""
    if filter_level:
        where_clause = 'WHERE "Level" = ?'
        params.append(filter_level)

    quoted = _quote_identifier(column_name)
    base_query = f"""
        SELECT {quoted}, COUNT(*) AS "Count"
        FROM logs
        {where_clause}
        GROUP BY {quoted}
        ORDER BY "Count" DESC, {quoted} ASC
    """

    query = base_query
    paged_params = list(params)
    if top_n is not None:
        query = f"""
            SELECT *
            FROM ({base_query}) AS _hayabusa_summary_top
            LIMIT ?
        """
        paged_params.append(top_n)

    result_df, total_count = _query_with_pagination(query, paged_params, page_size=page_size, page_offset=page_offset)
    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="条件に一致するイベントはありませんでした",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="指定ページにデータはありません",
        )
    return _attach_pagination_metadata(
        result_df,
        total_count=total_count,
        page_size=page_size,
        page_offset=page_offset,
    )


ALLOWED_TIME_INTERVALS = {"1h", "3h", "6h", "12h", "1d"}

@app.tool()
def summarize_by_time_window(
    interval: str = "1h",
    filter_level: str | None = None,
    filter_rule: str | None = None,
    page_size: int = 500,
    page_offset: int = 0,
):
    """
    時間窓別のアクティビティ集計を行います。

    Parameters:
        interval (str): 集約間隔。'1h', '3h', '6h', '12h', '1d' から選択
        filter_level (str, optional): フィルタする重要度レベル ('info', 'low', 'med', 'high', 'crit')
        filter_rule (str, optional): フィルタするルールタイトル（部分一致）
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット

    Returns:
        pandas.DataFrame: 時間窓別アクティビティ集計結果
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=500, max_page_size=MAX_PAGE_SIZE)

    if interval not in ALLOWED_TIME_INTERVALS:
        allowed = ", ".join(sorted(ALLOWED_TIME_INTERVALS))
        raise ValueError(f"interval は {allowed} から選択してください。")

    required_columns = ["Timestamp"]
    if filter_level:
        required_columns.append("Level")
    if filter_rule:
        required_columns.append("RuleTitle")
    _ensure_columns_exist(required_columns, context="summarize_by_time_window")

    params: list[object] = []
    conditions: list[str] = []

    if filter_level:
        conditions.append('"Level" = ?')
        params.append(filter_level)

    if filter_rule:
        conditions.append('POSITION(? IN COALESCE("RuleTitle", \'\')) > 0')
        params.append(filter_rule)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    query = f"""
        WITH filtered AS (
            SELECT TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}') AS ts
            FROM logs
            {where_clause}
        )
        SELECT
            CAST(time_bucket(INTERVAL '{interval}', ts) AS VARCHAR) AS "TimeWindow",
            COUNT(*) AS "EventCount"
        FROM filtered
        WHERE ts IS NOT NULL
        GROUP BY "TimeWindow"
        ORDER BY "TimeWindow" ASC
    """

    result_df, total_count = _query_with_pagination(query, params, page_size=page_size, page_offset=page_offset)
    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="条件に一致するイベントはありませんでした",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="指定ページにデータはありません",
        )
    return _attach_pagination_metadata(
        result_df,
        total_count=total_count,
        page_size=page_size,
        page_offset=page_offset,
    )


@app.tool()
def analyze_rule_titles(
    level: str | Sequence[str] | None = None,
    min_count: int = 1,
    top_n: int | None = None,
    contains: str | None = None,
    time_range: Sequence[str | None] | None = None,
    page_size: int = 50,
    page_offset: int = 0,
):
    """
    ルールタイトル（RuleTitle）の集計分析を行います。

    Parameters:
        level (str/Sequence[str], optional): フィルタする重要度レベル
                                            単一の値（例: 'high'）または複数の値（例: ['high', 'crit']）
        min_count (int): 表示する最小出現回数 (デフォルト: 1)
        top_n (int | None): 後方互換用の上位件数制限。Noneなら全件対象
        contains (str, optional): RuleTitleに含まれる文字列でフィルタ
        time_range (Sequence[str], optional): 時間範囲でフィルタ（例: ('2023-01-01', '2023-01-02')）
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット

    Returns:
        pandas.DataFrame: RuleTitle集計結果
    """
    _ensure_database_ready()
    _ensure_columns_exist(["RuleTitle", "Timestamp", "Level", "Computer"], context="analyze_rule_titles")
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=50, max_page_size=MAX_PAGE_SIZE)

    if min_count <= 0:
        raise ValueError("min_count は正の整数で指定してください。")
    if top_n is not None and top_n <= 0:
        raise ValueError("top_n は正の整数で指定してください。")

    if time_range is not None and len(time_range) != 2:
        raise ValueError("time_range は (start, end) の2要素で指定してください。")

    params: list[object] = []
    conditions: list[str] = []

    level_values = _normalise_levels(level)
    if level_values:
        placeholders = ", ".join("?" for _ in level_values)
        conditions.append(f'"Level" IN ({placeholders})')
        params.extend(level_values)

    if contains:
        conditions.append('POSITION(? IN COALESCE("RuleTitle", \'\')) > 0')
        params.append(contains)

    if time_range and len(time_range) == 2:
        start_time, end_time = time_range
        if start_time:
            conditions.append('"Timestamp" >= ?')
            params.append(start_time)
        if end_time:
            conditions.append('"Timestamp" <= ?')
            params.append(end_time)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    base_query = f"""
        SELECT
            "RuleTitle",
            COUNT(*) AS "イベント数",
            MIN("Timestamp") AS "初回検出",
            MAX("Timestamp") AS "最終検出",
            STRING_AGG(DISTINCT "Level", ', ') AS "重要度",
            STRING_AGG(DISTINCT "Computer", ', ') AS "検出ホスト"
        FROM logs
        {where_clause}
        GROUP BY "RuleTitle"
        HAVING COUNT(*) >= ?
        ORDER BY "イベント数" DESC, "RuleTitle" ASC
    """

    params.append(min_count)
    query = base_query
    if top_n is not None:
        query = f"""
            SELECT *
            FROM ({base_query}) AS _hayabusa_rule_titles_top
            LIMIT ?
        """
        params.append(top_n)

    result, total_count = _query_with_pagination(query, params, page_size=page_size, page_offset=page_offset)

    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="条件に一致するルールタイトルはありませんでした",
        )
    if result.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="指定ページにデータはありません",
        )

    return _attach_pagination_metadata(
        result,
        total_count=total_count,
        page_size=page_size,
        page_offset=page_offset,
    )


def _validate_detail_field_name(name: str) -> str:
    """Details フィールド名を検証し、SQL安全な文字列を返す。"""
    stripped = name.strip()
    if not stripped:
        raise ValueError("field_name を指定してください。")
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', stripped):
        raise ValueError(
            f"不正なフィールド名です: {stripped}. "
            "英数字とアンダースコアのみ使用可能です。"
        )
    return stripped


def _build_details_conditions(
    rule_title: str | None,
    level: str | Sequence[str] | None,
) -> tuple[str, list[object]]:
    """Details系ツール共通のフィルタ条件を構築する。"""
    conditions: list[str] = []
    params: list[object] = []

    level_values = _normalise_levels(level)
    if level_values:
        placeholders = ", ".join("?" for _ in level_values)
        conditions.append(f'"Level" IN ({placeholders})')
        params.extend(level_values)

    if rule_title:
        conditions.append('POSITION(? IN COALESCE("RuleTitle", \'\')) > 0')
        params.append(rule_title)

    where_fragment = " AND ".join(conditions) if conditions else ""
    return where_fragment, params


@app.tool()
def analyze_host_timeline(
    host_contains: str = "",
    level: str | Sequence[str] | None = None,
    time_range: Sequence[str | None] | None = None,
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    特定ホストに絞った時系列イベント一覧を返します。
    侵害チェーン（例: HostA → HostB → HostC）の追跡に最適です。

    Parameters:
        host_contains (str): ホスト名の部分一致フィルタ（必須）
        level (str/Sequence[str], optional): 重要度フィルタ（例: 'high', ['high', 'crit']）
        time_range (Sequence[str], optional): 時間範囲フィルタ (start, end)
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE
    )

    host = host_contains.strip()
    if not host:
        raise ValueError("host_contains を指定してください。")

    if time_range is not None and len(time_range) != 2:
        raise ValueError("time_range は (start, end) の2要素で指定してください。")

    required = ["Timestamp", "Computer", "RuleTitle", "Level"]
    _ensure_columns_exist(required, context="analyze_host_timeline")

    params: list[object] = []
    conditions: list[str] = []

    conditions.append('POSITION(? IN COALESCE("Computer", \'\')) > 0')
    params.append(host)

    level_values = _normalise_levels(level)
    if level_values:
        placeholders = ", ".join("?" for _ in level_values)
        conditions.append(f'"Level" IN ({placeholders})')
        params.extend(level_values)

    if time_range and len(time_range) == 2:
        start_time, end_time = time_range
        if start_time:
            conditions.append('"Timestamp" >= ?')
            params.append(start_time)
        if end_time:
            conditions.append('"Timestamp" <= ?')
            params.append(end_time)

    where_clause = f"WHERE {' AND '.join(conditions)}"

    columns = _get_logs_columns()
    select_cols = [
        col for col in
        ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
         "MitreTactics", "MitreTags", "Details"]
        if col in columns
    ]
    select_expr = ", ".join(_quote_identifier(c) for c in select_cols)

    query = f"""
        SELECT {select_expr}
        FROM logs
        {where_clause}
        ORDER BY
            TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}') ASC NULLS LAST,
            "Timestamp" ASC
    """

    result_df, total_count = _query_with_pagination(
        query, params, page_size=page_size, page_offset=page_offset
    )

    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data",
            message=f"ホスト '{host}' に一致するイベントはありませんでした",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="指定ページにデータはありません",
        )
    return _attach_pagination_metadata(
        result_df, total_count=total_count,
        page_size=page_size, page_offset=page_offset,
    )


@app.tool()
def parse_details_field(
    field_name: str = "",
    rule_title: str | None = None,
    level: str | Sequence[str] | None = None,
    unique: bool = False,
    page_size: int = 50,
    page_offset: int = 0,
):
    """
    Details カラムのキーバリュー構造（Key: Value ¦ Key: Value）を解析します。

    field_name が空の場合、利用可能なフィールド名一覧をカウント付きで返します。
    field_name を指定すると、そのフィールドの値を抽出します。

    Parameters:
        field_name (str): 抽出するフィールド名（例: 'Cmdline', 'Proc', 'User'）
                         空の場合はフィールド名一覧を返す
        rule_title (str, optional): RuleTitleフィルタ（部分一致）
        level (str/Sequence[str], optional): 重要度フィルタ
        unique (bool): Trueの場合、一意な値のカウント集計を返す
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット
    """
    _ensure_database_ready()
    _ensure_columns_exist(["Details"], context="parse_details_field")
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=50, max_page_size=MAX_PAGE_SIZE
    )

    extra_filter, params = _build_details_conditions(rule_title, level)
    and_clause = f"AND {extra_filter}" if extra_filter else ""

    sep_literal = f"' {DETAILS_SEPARATOR_CHAR} '"

    if not field_name.strip():
        # Mode 1: List available field names with counts
        query = f"""
            WITH split AS (
                SELECT unnest(string_split(
                    COALESCE("Details", ''), {sep_literal}
                )) AS kv_pair
                FROM logs
                WHERE "Details" IS NOT NULL AND "Details" != ''
                {and_clause}
            )
            SELECT
                trim(split_part(trim(kv_pair), ': ', 1)) AS "FieldName",
                COUNT(*) AS "Count"
            FROM split
            WHERE position(': ' IN trim(kv_pair)) > 0
            AND length(trim(split_part(trim(kv_pair), ': ', 1))) > 0
            GROUP BY "FieldName"
            ORDER BY "Count" DESC
        """
    else:
        validated_name = _validate_detail_field_name(field_name)
        fn_len = len(validated_name)

        if unique:
            # Mode 2: Aggregate unique values with counts
            query = f"""
                WITH split AS (
                    SELECT
                        unnest(string_split(
                            COALESCE("Details", ''), {sep_literal}
                        )) AS kv_pair,
                        "Computer"
                    FROM logs
                    WHERE position('{validated_name}: ' IN COALESCE("Details", '')) > 0
                    {and_clause}
                )
                SELECT
                    trim(substr(trim(kv_pair), {fn_len + 3})) AS "Value",
                    STRING_AGG(DISTINCT "Computer", ', ') AS "Hosts",
                    COUNT(*) AS "Count"
                FROM split
                WHERE starts_with(trim(kv_pair), '{validated_name}: ')
                AND length(trim(substr(trim(kv_pair), {fn_len + 3}))) > 0
                GROUP BY "Value"
                ORDER BY "Count" DESC
            """
        else:
            # Mode 3: Extract values with event context
            columns = _get_logs_columns()
            context_cols = [
                _quote_identifier(c) for c in
                ["Timestamp", "Computer", "RuleTitle", "Level"]
                if c in columns
            ]
            context_select = (", ".join(context_cols) + ",") if context_cols else ""

            order_clause = ""
            if "Timestamp" in columns:
                order_clause = f"""
                    ORDER BY
                        TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}') ASC NULLS LAST,
                        "Timestamp" ASC
                """

            query = f"""
                WITH split AS (
                    SELECT
                        {context_select}
                        unnest(string_split(
                            COALESCE("Details", ''), {sep_literal}
                        )) AS kv_pair
                    FROM logs
                    WHERE position('{validated_name}: ' IN COALESCE("Details", '')) > 0
                    {and_clause}
                )
                SELECT
                    {context_select}
                    trim(substr(trim(kv_pair), {fn_len + 3})) AS "Value"
                FROM split
                WHERE starts_with(trim(kv_pair), '{validated_name}: ')
                {order_clause}
            """

    result_df, total_count = _query_with_pagination(
        query, params, page_size=page_size, page_offset=page_offset
    )

    if total_count == 0:
        msg = "一致するデータはありませんでした"
        if field_name.strip():
            msg = f"フィールド '{field_name.strip()}' のデータは見つかりませんでした"
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message=msg,
        ))
    if result_df.empty:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="指定ページにデータはありません",
        ))
    return _WideDisplayDataFrame(_attach_pagination_metadata(
        result_df, total_count=total_count,
        page_size=page_size, page_offset=page_offset,
    ))


@app.tool()
def extract_iocs(
    ioc_type: str | None = None,
    level: str | Sequence[str] | None = None,
    rule_title: str | None = None,
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    Details/ExtraFieldInfo カラムからIOC（Indicator of Compromise）を自動抽出します。

    プロセスパス、コマンドライン、IPアドレス、ファイルパス、ユーザー、ハッシュ、
    サービス名をカテゴリ別に集計して返します。

    Parameters:
        ioc_type (str, optional): 抽出するIOCタイプで絞り込み
                                  'process', 'cmdline', 'filepath', 'ip', 'user', 'hash', 'service'
                                  Noneの場合は全タイプを抽出
        level (str/Sequence[str], optional): 重要度フィルタ
        rule_title (str, optional): RuleTitleフィルタ（部分一致）
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット
    """
    _ensure_database_ready()
    _ensure_columns_exist(["Details"], context="extract_iocs")
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE
    )

    valid_types = set(IOC_FIELD_CATEGORIES.keys())
    if ioc_type is not None:
        ioc_type_normalized = ioc_type.strip().lower()
        if ioc_type_normalized not in valid_types:
            allowed = ", ".join(sorted(valid_types))
            raise ValueError(f"ioc_type は {allowed} から選択してください。")
        target_categories = {ioc_type_normalized: IOC_FIELD_CATEGORIES[ioc_type_normalized]}
    else:
        target_categories = IOC_FIELD_CATEGORIES

    # Build CASE expression for field categorization
    case_parts: list[str] = []
    target_field_names: list[str] = []
    for category, fields in target_categories.items():
        for field in fields:
            case_parts.append(f"WHEN fkey = '{field}' THEN '{category}'")
            target_field_names.append(field)

    if not target_field_names:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="対象のIOCタイプが指定されていません",
        )

    case_expr = "CASE " + " ".join(case_parts) + " END"
    field_in_list = ", ".join(f"'{f}'" for f in target_field_names)

    extra_filter, params = _build_details_conditions(rule_title, level)
    and_clause = f"AND {extra_filter}" if extra_filter else ""

    columns = _get_logs_columns()
    has_extra = "ExtraFieldInfo" in columns
    sep_literal = f"' {DETAILS_SEPARATOR_CHAR} '"

    if has_extra:
        combined_expr = f"""COALESCE("Details", '') || {sep_literal} || COALESCE("ExtraFieldInfo", '')"""
    else:
        combined_expr = 'COALESCE("Details", \'\')'

    query = f"""
        WITH split AS (
            SELECT
                unnest(string_split({combined_expr}, {sep_literal})) AS kv_pair,
                "Computer"
            FROM logs
            WHERE ("Details" IS NOT NULL AND "Details" != '')
            {and_clause}
        ),
        parsed AS (
            SELECT
                trim(split_part(trim(kv_pair), ': ', 1)) AS fkey,
                trim(substr(
                    trim(kv_pair),
                    length(trim(split_part(trim(kv_pair), ': ', 1))) + 3
                )) AS fvalue,
                "Computer"
            FROM split
            WHERE position(': ' IN trim(kv_pair)) > 0
        )
        SELECT
            {case_expr} AS "Type",
            fkey AS "FieldName",
            fvalue AS "Value",
            STRING_AGG(DISTINCT "Computer", ', ') AS "Hosts",
            COUNT(*) AS "Count"
        FROM parsed
        WHERE fkey IN ({field_in_list})
        AND fvalue NOT IN ('', '-', 'N/A')
        AND length(fvalue) > 0
        GROUP BY "Type", fkey, fvalue
        ORDER BY "Count" DESC
    """

    result_df, total_count = _query_with_pagination(
        query, params, page_size=page_size, page_offset=page_offset
    )

    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="IOCが見つかりませんでした",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="指定ページにデータはありません",
        )
    return _attach_pagination_metadata(
        result_df, total_count=total_count,
        page_size=page_size, page_offset=page_offset,
    )


_ENCODED_PS_PATTERN = re.compile(
    r"-(encodedcommand|enc|e)\s+([A-Za-z0-9+/=]{4,})",
    re.IGNORECASE,
)


@app.tool()
def decode_powershell_commands(
    level: str | Sequence[str] | None = None,
    rule_title: str | None = None,
    page_size: int = 50,
    page_offset: int = 0,
):
    """
    Base64エンコードされたPowerShellコマンドをデコードして返します。

    Details/ExtraFieldInfo に含まれる -enc/-encodedcommand/-e パラメータの
    Base64値を検出し、UTF-16-LEとしてデコードします。

    Parameters:
        level (str/Sequence[str], optional): 重要度フィルタ
        rule_title (str, optional): RuleTitleフィルタ（部分一致）
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット
    """
    _ensure_database_ready()
    _ensure_columns_exist(["Timestamp", "Computer", "RuleTitle", "Level", "Details"], context="decode_powershell_commands")
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=50, max_page_size=MAX_PAGE_SIZE
    )

    extra_filter, params = _build_details_conditions(rule_title, level)
    and_clause = f"AND {extra_filter}" if extra_filter else ""

    columns = _get_logs_columns()
    has_extra = "ExtraFieldInfo" in columns
    sep_literal = f"' {DETAILS_SEPARATOR_CHAR} '"

    if has_extra:
        combined_expr = f"""COALESCE("Details", '') || {sep_literal} || COALESCE("ExtraFieldInfo", '')"""
    else:
        combined_expr = 'COALESCE("Details", \'\')'

    query = f"""
        SELECT
            "Timestamp", "Computer", "RuleTitle", "Level",
            {combined_expr} AS _combined
        FROM logs
        WHERE (
            LOWER({combined_expr}) LIKE '%%-enc %%'
            OR LOWER({combined_expr}) LIKE '%%-encodedcommand %%'
            OR LOWER({combined_expr}) LIKE '%%-e %%'
        )
        {and_clause}
        ORDER BY
            TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}') ASC NULLS LAST,
            "Timestamp" ASC
    """

    raw_df, total_count = _query_with_pagination(
        query, params, page_size=page_size * 2, page_offset=0, include_total=True
    )

    if total_count == 0 or raw_df.empty:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="Base64エンコードされたPowerShellコマンドは見つかりませんでした",
        ))

    decoded_rows: list[dict[str, str]] = []
    for _, row in raw_df.iterrows():
        combined = str(row.get("_combined", ""))
        matches = _ENCODED_PS_PATTERN.findall(combined)
        for _, b64_value in matches:
            try:
                decoded = base64.b64decode(b64_value).decode("utf-16-le", errors="replace")
            except Exception:
                decoded = "(decode error)"
            encoded_short = b64_value[:80] + ("..." if len(b64_value) > 80 else "")
            decoded_rows.append({
                "Timestamp": str(row.get("Timestamp", "")),
                "Computer": str(row.get("Computer", "")),
                "RuleTitle": str(row.get("RuleTitle", "")),
                "Level": str(row.get("Level", "")),
                "EncodedCommand": encoded_short,
                "DecodedCommand": decoded,
            })

    if not decoded_rows:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="Base64パターンにマッチするコマンドは見つかりませんでした",
        ))

    all_df = pd.DataFrame(decoded_rows)
    total = len(all_df)
    paged = all_df.iloc[page_offset : page_offset + page_size].reset_index(drop=True)

    if paged.empty:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=total,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="指定ページにデータはありません",
        ))

    return _WideDisplayDataFrame(_attach_pagination_metadata(
        paged, total_count=total,
        page_size=page_size, page_offset=page_offset,
    ))


@app.tool()
def correlate_lateral_movement(
    time_window_minutes: int = 15,
    level: str | Sequence[str] | None = None,
    source_host: str | None = None,
    target_host: str | None = None,
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    ホスト間の横展開（Lateral Movement）相関分析を行います。

    時間窓内で異なるホスト間に発生したイベントを self-join で検出し、
    攻撃の横展開パターンを特定します。

    Parameters:
        time_window_minutes (int): 相関を検出する時間窓（分）。1〜1440
        level (str/Sequence[str], optional): 重要度フィルタ
        source_host (str, optional): ソースホスト名フィルタ（部分一致）
        target_host (str, optional): ターゲットホスト名フィルタ（部分一致）
        page_size (int): 1ページあたりの件数
        page_offset (int): 取得開始オフセット
    """
    _ensure_database_ready()
    _ensure_columns_exist(
        ["Timestamp", "Computer", "RuleTitle", "Level", "MitreTactics"],
        context="correlate_lateral_movement",
    )
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE
    )

    if time_window_minutes < 1 or time_window_minutes > 1440:
        raise ValueError("time_window_minutes は 1〜1440 の範囲で指定してください。")

    params: list[object] = []
    conditions_a: list[str] = []
    conditions_b: list[str] = []

    level_values = _normalise_levels(level)
    if level_values:
        placeholders = ", ".join("?" for _ in level_values)
        conditions_a.append(f'"Level" IN ({placeholders})')
        params.extend(level_values)
        conditions_b.append(f'"Level" IN ({placeholders})')
        params.extend(level_values)
    else:
        conditions_a.append("""("Level" IN ('high', 'crit') OR POSITION('LatMov' IN COALESCE("MitreTactics", '')) > 0)""")
        conditions_b.append("""("Level" IN ('high', 'crit') OR POSITION('LatMov' IN COALESCE("MitreTactics", '')) > 0)""")

    if source_host:
        conditions_a.append('POSITION(? IN COALESCE("Computer", \'\')) > 0')
        params.append(source_host)
    if target_host:
        conditions_b.append('POSITION(? IN COALESCE("Computer", \'\')) > 0')
        params.append(target_host)

    where_a = f"WHERE {' AND '.join(conditions_a)}" if conditions_a else ""
    where_b = f"WHERE {' AND '.join(conditions_b)}" if conditions_b else ""

    query = f"""
        WITH parsed_a AS (
            SELECT
                TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}') AS ts,
                "Computer", "RuleTitle", "Level"
            FROM logs
            {where_a}
        ),
        parsed_b AS (
            SELECT
                TRY_STRPTIME("Timestamp", '{TIMESTAMP_FORMAT}') AS ts,
                "Computer", "RuleTitle", "Level"
            FROM logs
            {where_b}
        )
        SELECT
            CAST(a.ts AS VARCHAR) AS "SourceTime",
            a."Computer" AS "SourceHost",
            a."RuleTitle" AS "SourceEvent",
            a."Level" AS "SourceLevel",
            CAST(b.ts AS VARCHAR) AS "TargetTime",
            b."Computer" AS "TargetHost",
            b."RuleTitle" AS "TargetEvent",
            b."Level" AS "TargetLevel",
            ROUND(EXTRACT(EPOCH FROM (b.ts - a.ts)) / 60.0, 1) AS "DeltaMinutes"
        FROM parsed_a a
        JOIN parsed_b b
          ON a."Computer" != b."Computer"
          AND a.ts IS NOT NULL
          AND b.ts IS NOT NULL
          AND b.ts BETWEEN a.ts AND a.ts + INTERVAL '{time_window_minutes} minutes'
        ORDER BY a.ts ASC, b.ts ASC
    """

    result_df, total_count = _query_with_pagination(
        query, params, page_size=page_size, page_offset=page_offset
    )

    if total_count == 0:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data",
            message="横展開パターンは検出されませんでした",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="指定ページにデータはありません",
        )
    return _attach_pagination_metadata(
        result_df, total_count=total_count,
        page_size=page_size, page_offset=page_offset,
    )


# ──────────────────────────────────────────
# エントリポイント
# ──────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hayabusa MCP")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "http"],
        default="stdio",
        help="MCPトランスポート (default: stdio, httpはstreamable-httpの別名)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP待受ホスト (streamable-http用)")
    parser.add_argument("--port", type=int, default=8763, help="HTTP待受ポート (streamable-http用)")
    parser.add_argument(
        "--streamable-http-path",
        default="/mcp",
        help="Streamable HTTPエンドポイントパス (default: /mcp)",
    )
    parser.add_argument(
        "--stateless-http",
        action="store_true",
        help="stateless HTTPモードを有効化",
    )
    parser.add_argument(
        "--json-response",
        action="store_true",
        help="JSONレスポンスモードを有効化",
    )
    args = parser.parse_args()
    transport = "streamable-http" if args.transport == "http" else args.transport
    status = repo.get_dataset_status()

    app.settings.host = args.host
    app.settings.port = args.port
    app.settings.streamable_http_path = args.streamable_http_path
    app.settings.stateless_http = args.stateless_http
    app.settings.json_response = args.json_response

    if transport == "streamable-http":
        path = args.streamable_http_path if args.streamable_http_path.startswith("/") else f"/{args.streamable_http_path}"
        print("⚡ Hayabusa MCP サーバーを起動します（streamable-http モード）")
        print(f"endpoint: http://{args.host}:{args.port}{path}")
    else:
        print("⚡ Hayabusa MCP サーバーを起動します（stdio モード）")

    if status.get("loaded"):
        print(f"現在のデータセット: {status.get('dataset_path', '')}")
    else:
        print("データセット未ロードです。switch_dataset ツールでCSVをロードしてください。")

    try:
        app.run(transport=transport)
    except KeyboardInterrupt:
        print("🛑 Hayabusa MCP サーバーを停止しました。")
