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
SEARCH_RESULT_COLUMNS = ("Timestamp", "Computer", "RuleTitle", "Level", "Channel", "EventID", "MitreTactics", "MitreTags", "Details", "AllFieldInfo")
# Detail columns that hold "Key: Value ¦ Key: Value" data.
# "Details" comes from the standard/verbose profiles (with abbreviated field names),
# "AllFieldInfo" comes from the all-field-info-verbose profile
# (with original event field names). A CSV contains one or the other, never both.
DETAIL_SOURCE_COLUMNS = ("Details", "AllFieldInfo")
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f %z"

class _WideDisplayDataFrame(pd.DataFrame):
    """DataFrame dedicated to parse_details_field. Displays all columns at full width only during str/repr."""

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

# Abbreviated field names used in the Details column (standard/verbose profiles).
IOC_FIELD_CATEGORIES = {
    "process": ["Proc", "Image", "ParentImage"],
    "cmdline": ["Cmdline"],
    "filepath": ["Path", "TgtFile"],
    "ip": ["SrcIP", "DstIP", "SrcAddr", "DstAddr", "IpAddress", "DestAddress", "SourceAddress"],
    "user": ["User", "TgtUser", "SrcUser"],
    "hash": ["Hash", "Hashes"],
    "service": ["Svc"],
}

# Original event field names as they appear in the AllFieldInfo column
# (all-field-info-verbose profile). Verified against Hayabusa 3.8.0
# CSV output for Security, Sysmon and PowerShell channels.
IOC_FIELD_CATEGORIES_ALL_FIELD_INFO = {
    "process": ["Image", "ParentImage", "ImageLoaded", "NewProcessName", "ParentProcessName", "ProcessName"],
    "cmdline": ["CommandLine", "ParentCommandLine"],
    "filepath": ["TargetFilename", "RelativeTargetName", "ObjectName", "Path"],
    "ip": ["SourceIp", "DestinationIp", "IpAddress"],
    "user": ["User", "ParentUser", "SubjectUserName", "TargetUserName", "TargetOutboundUserName"],
    "hash": ["Hashes", "Hash"],
    "service": ["ServiceName", "ServiceFileName", "ImagePath"],
}

TACTICS_MAP = {
    "InitAccess": "Initial Access",
    "Exec": "Execution",
    "Persis": "Persistence",
    "PrivEsc": "Privilege Escalation",
    "Evas": "Defense Evasion",
    "CredAccess": "Credential Access",
    "Disc": "Discovery",
    "LatMov": "Lateral Movement",
    "Collect": "Collection",
    "C2": "Command and Control",
    "Exfil": "Exfiltration",
    "Impact": "Impact",
    "Recon": "Reconnaissance",
    "ResDev": "Resource Development",
}


class DuckDBRepository:
    """Utility wrapper consolidating DuckDB operations."""

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
        """Execute a SELECT query via read-only connection and return the result as a DataFrame."""
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
    Load the specified CSV dataset and initialize the DuckDB database.
    Replaces the existing logs table if one exists.

    Parameters:
        dataset: Path to the CSV file to load
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
        raise ValueError(f"Invalid column name: {name}")
    return f'"{stripped}"'


def _get_logs_columns() -> set[str]:
    global _LOG_COLUMNS_CACHE
    if _LOG_COLUMNS_CACHE is None:
        _LOG_COLUMNS_CACHE = repo.get_logs_columns()
    return set(_LOG_COLUMNS_CACHE)


def _ensure_database_ready() -> None:
    if not repo.is_initialised():
        raise RuntimeError("Hayabusa DB is not initialized. Please load a CSV using the switch_dataset tool.")
    columns = _get_logs_columns()
    if not columns:
        raise RuntimeError("logs table not found. Please load a CSV using the switch_dataset tool.")


def _ensure_columns_exist(columns: Sequence[str], context: str) -> None:
    existing = _get_logs_columns()
    missing = [col for col in columns if col not in existing]
    if not missing:
        return

    missing_label = ", ".join(sorted(set(missing)))
    available_label = ", ".join(sorted(existing))
    raise ValueError(
        f"{context}: Required columns are missing ({missing_label})."
        f" Available columns: {available_label}"
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
            f"page_size must be between 1 and {max_page_size}."
            f" (legacy argument {legacy_name} has the same range)"
        )
    if page_offset < 0:
        raise ValueError("page_offset must be 0 or greater.")
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
        raise ValueError("SQL is empty.")

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
        raise ValueError("Please enter a SQL statement.")

    try:
        statements = duckdb.extract_statements(sql)
    except duckdb.Error as exc:
        raise ValueError(f"Invalid SQL syntax: {exc}") from exc

    if len(statements) != 1:
        raise ValueError("run_sql can only execute a single SELECT statement.")

    statement = statements[0]
    if statement.type != duckdb.StatementType.SELECT:
        raise ValueError("run_sql can only execute SELECT statements.")

    normalized_sql = statement.query.strip().rstrip(";").strip()
    if not normalized_sql:
        raise ValueError("Please enter a SQL statement.")

    try:
        plan_nodes = repo.explain_json(normalized_sql)
    except duckdb.Error as exc:
        raise ValueError("run_sql can only execute SELECT statements that reference the logs table.") from exc

    scanned_tables, scanned_functions = _collect_plan_sources(plan_nodes)

    if scanned_functions:
        refs = ", ".join(sorted(scanned_functions))
        raise ValueError(f"run_sql does not allow table functions or system functions: {refs}")

    if not scanned_tables:
        raise ValueError("run_sql can only execute SELECT statements that reference the logs table.")

    if scanned_tables != {"logs"}:
        refs = ", ".join(sorted(scanned_tables))
        raise ValueError(f"run_sql can only reference the logs table. Detected references: {refs}")

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
        raise ValueError("Please specify a target.")

    explicit = pathlib.Path(target_text).expanduser()
    if explicit.exists() and explicit.is_file():
        resolved = explicit.resolve()
        if resolved.suffix.lower() != ".csv":
            raise ValueError(f"Please specify a CSV file: {resolved}")
        return resolved

    root = pathlib.Path(search_root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Invalid search_root: {root}")

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
            f"No CSV candidates found: {target_text}. "
            "Please check candidates using list_datasets."
        )

    if len(matches) > 1:
        candidates = ", ".join(_format_path_for_display(path) for path in matches[:5])
        raise ValueError(
            f"Multiple candidates found: {target_text}. "
            f"Please specify a more specific path. Candidates: {candidates}"
        )

    return matches[0]


# ──────────────────────────────────────────
# Tool definitions
# ──────────────────────────────────────────
@app.tool()
def get_dataset_status():
    """
    Returns the status of the currently loaded dataset.
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
    Returns a list of CSV files available for analysis.

    Parameters:
        search_root (str): Starting directory for search
        recursive (bool): Whether to recursively search subdirectories
        name_filter (str): Partial match filter for file names
        page_size (int): Number of items per page (1-500)
        page_offset (int): Starting offset for retrieval (0 or greater)
        limit (int | None): Legacy parameter. When specified, treated as page_size
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
        raise ValueError(f"Invalid search_root: {root}")

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
                message="No CSV candidates on the specified page",
            )
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=len(files),
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No CSV files found",
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
    Switch the analysis target to the specified CSV.

    Parameters:
        target (str): CSV path / filename / alias (stem)
        search_root (str): Search starting point when target is not a path
        recursive (bool): Whether to search subdirectories
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
    Unload the current `logs` table.
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
    Returns an overview of the current analysis target dataset.

    Parameters:
        top_n (int): Number of top items to display (Level/Computer/RuleTitle)
        section (str): Section to retrieve. Choose from 'all', 'overview', 'levels', 'computers', 'rules'
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE)
    if top_n <= 0 or top_n > 100:
        raise ValueError("top_n must be between 1 and 100.")

    section = section.strip().lower()
    if section not in PROFILE_SECTIONS:
        allowed = ", ".join(sorted(PROFILE_SECTIONS))
        raise ValueError(f"section must be one of: {allowed}")

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
            message="No data on the specified page" if paged.empty else "",
        ))

    if section == "levels":
        if "Level" not in columns:
            return _WideDisplayDataFrame(_attach_pagination_metadata(
                pd.DataFrame(), total_count=0, page_size=page_size, page_offset=page_offset,
                status="no_data", message="Level column does not exist",
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
            message="No data on the specified page" if paged.empty else "",
        ))

    if section == "computers":
        if "Computer" not in columns:
            return _WideDisplayDataFrame(_attach_pagination_metadata(
                pd.DataFrame(), total_count=0, page_size=page_size, page_offset=page_offset,
                status="no_data", message="Computer column does not exist",
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
            message="No data on the specified page" if paged.empty else "",
        ))

    if section == "rules":
        if "RuleTitle" not in columns:
            return _WideDisplayDataFrame(_attach_pagination_metadata(
                pd.DataFrame(), total_count=0, page_size=page_size, page_offset=page_offset,
                status="no_data", message="RuleTitle column does not exist",
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
            message="No data on the specified page" if paged.empty else "",
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
            message="No data on the specified page",
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
    Execute a **read-only SELECT** against the `logs` table and return the result as a DataFrame.

    Restrictions:
        - SQL is AST-validated; only SELECT referencing the logs table is allowed
        - Table functions/system function references are not permitted
        - Number of returned rows is specified by page_size (max 500 rows)
        - max_rows is for backward compatibility (treated as page_size when specified)
        - ORDER BY is required when page_offset > 0 (for page reproducibility)
        - include_total=False can skip the per-page COUNT(*)
        - Passing total_count_hint/query_hash_hint/dataset_version_hint enables
          accurate has_more determination even with include_total=False
        - wide_display=True (default) returns a _WideDisplayDataFrame with full column/width display
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
        raise ValueError("When using page_offset with run_sql, ORDER BY must be specified for reproducibility.")

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
                raise ValueError("total_count_hint must be 0 or greater.")
            if not query_hash_hint or not dataset_version_hint:
                raise ValueError(
                    "When using total_count_hint, query_hash_hint and dataset_version_hint must also be specified."
                )
            if query_hash_hint != query_hash:
                raise ValueError("query_hash_hint does not match the current SQL. Please re-execute count_sql.")
            if dataset_version_hint != dataset_version:
                raise ValueError(
                    "dataset_version_hint does not match the current dataset. Please re-execute count_sql."
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
            message="Query returned 0 results",
            extra_meta=extra_meta,
        ))
    if result_df.empty:
        return wrap(_attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No data on the specified page",
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
    Expands all fields of a single event in Field/Value format and returns them.

    Parameters:
        record_id (str): Specify by RecordID (mutually exclusive)
        sql_filter (str): Specify by SQL condition equivalent to WHERE clause (mutually exclusive).
                          Example: "Level = 'crit'" -> SELECT * FROM logs WHERE Level = 'crit' LIMIT 1
    """
    _ensure_database_ready()

    if record_id.strip() and sql_filter.strip():
        raise ValueError("record_id and sql_filter cannot be specified at the same time. Please specify one or the other.")
    if not record_id.strip() and not sql_filter.strip():
        raise ValueError("Please specify either record_id or sql_filter.")

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
            message="No events matched the specified condition",
        ))

    row = row_df.iloc[0]
    result_rows: list[dict[str, str]] = []

    for col in row_df.columns:
        val = row[col]
        str_val = "" if pd.isna(val) else str(val)

        if col in ("Details", "ExtraFieldInfo", "AllFieldInfo") and str_val:
            prefix = {"Details": "Details", "ExtraFieldInfo": "Extra", "AllFieldInfo": "AllField"}[col]
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
    Search across all columns (or specified columns) in the logs table by keyword.

    Parameters:
        query (str): Search string
        columns (Sequence[str] | None): Columns to search. None searches all columns
        match_mode (str): `contains` / `exact` / `prefix` / `regex`
        case_sensitive (bool): Whether to distinguish between upper and lower case
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval
        include_hit_columns (bool): Whether to return which columns matched
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
            message="Please specify a query",
        )

    existing_columns = sorted(_get_logs_columns())
    if not existing_columns:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No searchable columns found",
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
            message="columns is empty",
        )

    _ensure_columns_exist(target_columns, context="search_all_fields")

    normalized_mode = match_mode.strip().lower()
    allowed_modes = {"contains", "exact", "prefix", "regex"}
    if normalized_mode not in allowed_modes:
        allowed_label = ", ".join(sorted(allowed_modes))
        raise ValueError(f"match_mode must be one of: {allowed_label}")

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
            message="No matching data found",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No data on the specified page",
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
    detail_source: str = "Details",
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    Perform attack phase analysis based on MITRE ATT&CK tactics.

    Parameters:
        filter_tactics (Sequence[str], optional): List of tactics to analyze
                                                 Example: ['InitAccess', 'PrivEsc']
                                                 Analyzes all tactics when None
        detail_source (str): Detail column shown in the results. 'Details' (default,
                             standard/verbose profiles) or 'AllFieldInfo'
                             (all-field-info-verbose profile)
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval

    Returns:
        pandas.DataFrame: Attack phase analysis results (in chronological order)
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE)
    detail_column = _resolve_detail_source(detail_source, context="analyze_mitre_tactics")
    _ensure_columns_exist(
        ["Timestamp", "Computer", "RuleTitle", detail_column, "MitreTactics"],
        context="analyze_mitre_tactics",
    )
    detail_quoted = _quote_identifier(detail_column)

    target_tactics = [str(tactic).strip() for tactic in (filter_tactics or TACTICS_MAP.keys()) if str(tactic).strip()]
    if not target_tactics:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=0,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No target tactics specified",
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
                l.{detail_quoted} AS "Details",
                ROW_NUMBER() OVER (
                    PARTITION BY tm."RawTactic"
                    ORDER BY
                        TRY_STRPTIME(l."Timestamp", '{TIMESTAMP_FORMAT}') ASC NULLS LAST,
                        l."Timestamp" ASC,
                        l."Computer" ASC,
                        l."RuleTitle" ASC,
                        l.{detail_quoted} ASC
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
            message="No matching tactics found",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No data on the specified page",
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
    Aggregate log events.

    Parameters:
        groupby_field (str): Field name to group by (default: 'RuleTitle')
                           Example: 'Computer', 'RuleTitle', 'Level', 'EventID', etc.
        filter_level (str, optional): Severity level to filter by ('info', 'low', 'med', 'high', 'crit')
        top_n (int | None): Legacy top-N limit. None targets all records
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval

    Returns:
        pandas.DataFrame: Event aggregation results
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE)

    available_fields = _available_summary_fields()
    if not available_fields:
        raise ValueError("summarize_events: No aggregation target fields found.")

    column_name = groupby_field.strip()
    if column_name not in available_fields:
        allowed = ", ".join(available_fields)
        raise ValueError(f"groupby_field={groupby_field} is not available. Available: {allowed}")

    if top_n is not None and top_n <= 0:
        raise ValueError("top_n must be a positive integer.")

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
            message="No events matched the specified condition",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No data on the specified page",
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
    Aggregate activity by time window.

    Parameters:
        interval (str): Aggregation interval. Choose from '1h', '3h', '6h', '12h', '1d'
        filter_level (str, optional): Severity level to filter by ('info', 'low', 'med', 'high', 'crit')
        filter_rule (str, optional): Rule title to filter by (partial match)
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval

    Returns:
        pandas.DataFrame: Activity aggregation results by time window
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=500, max_page_size=MAX_PAGE_SIZE)

    if interval not in ALLOWED_TIME_INTERVALS:
        allowed = ", ".join(sorted(ALLOWED_TIME_INTERVALS))
        raise ValueError(f"interval must be one of: {allowed}")

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
            message="No events matched the specified condition",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No data on the specified page",
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
    Perform aggregation analysis on rule titles (RuleTitle).

    Parameters:
        level (str/Sequence[str], optional): Severity level to filter by
                                            Single value (e.g., 'high') or multiple values (e.g., ['high', 'crit'])
        min_count (int): Minimum occurrence count to display (default: 1)
        top_n (int | None): Legacy top-N limit. None targets all records
        contains (str, optional): Filter by string contained in RuleTitle
        time_range (Sequence[str], optional): Filter by time range (e.g., ('2023-01-01', '2023-01-02'))
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval

    Returns:
        pandas.DataFrame: RuleTitle aggregation results
    """
    _ensure_database_ready()
    _ensure_columns_exist(["RuleTitle", "Timestamp", "Level", "Computer"], context="analyze_rule_titles")
    page_size, page_offset = _resolve_pagination(page_size, page_offset, default_page_size=50, max_page_size=MAX_PAGE_SIZE)

    if min_count <= 0:
        raise ValueError("min_count must be a positive integer.")
    if top_n is not None and top_n <= 0:
        raise ValueError("top_n must be a positive integer.")

    if time_range is not None and len(time_range) != 2:
        raise ValueError("time_range must be specified as a 2-element tuple (start, end).")

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
            COUNT(*) AS "event_count",
            MIN("Timestamp") AS "first_seen",
            MAX("Timestamp") AS "last_seen",
            STRING_AGG(DISTINCT "Level", ', ') AS "severity",
            STRING_AGG(DISTINCT "Computer", ', ') AS "detected_hosts"
        FROM logs
        {where_clause}
        GROUP BY "RuleTitle"
        HAVING COUNT(*) >= ?
        ORDER BY "event_count" DESC, "RuleTitle" ASC
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
            message="No rule titles matched the specified condition",
        )
    if result.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(),
            total_count=total_count,
            page_size=page_size,
            page_offset=page_offset,
            status="no_data",
            message="No data on the specified page",
        )

    return _attach_pagination_metadata(
        result,
        total_count=total_count,
        page_size=page_size,
        page_offset=page_offset,
    )


def _validate_detail_field_name(name: str) -> str:
    """Validate a Details field name and return a SQL-safe string."""
    stripped = name.strip()
    if not stripped:
        raise ValueError("Please specify a field_name.")
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', stripped):
        raise ValueError(
            f"Invalid field name: {stripped}. "
            "Only alphanumeric characters and underscores are allowed."
        )
    return stripped


def _resolve_detail_source(detail_source: str, context: str) -> str:
    """
    Resolve which detail column to parse: 'Details' (default) or 'AllFieldInfo'.

    Raises ValueError when the value is invalid or the column does not exist in
    the current dataset. When the requested column is missing but the other
    detail column exists (e.g. an all-field-info-verbose profile CSV was loaded), the
    error message suggests the correct detail_source value to retry with.
    """
    requested = (detail_source or "Details").strip()
    matched = next(
        (column for column in DETAIL_SOURCE_COLUMNS if column.lower() == requested.lower()),
        None,
    )
    if matched is None:
        allowed = ", ".join(DETAIL_SOURCE_COLUMNS)
        raise ValueError(f"{context}: detail_source must be one of: {allowed}")

    existing = _get_logs_columns()
    if matched not in existing:
        fallback = next(
            (column for column in DETAIL_SOURCE_COLUMNS if column != matched and column in existing),
            None,
        )
        if fallback is not None:
            raise ValueError(
                f"{context}: Column '{matched}' does not exist in the current dataset."
                f" This dataset contains '{fallback}' instead."
                f" Please call again with detail_source='{fallback}'."
            )
        available_label = ", ".join(sorted(existing))
        raise ValueError(
            f"{context}: Column '{matched}' does not exist in the current dataset."
            f" Available columns: {available_label}"
        )
    return matched


def _build_details_conditions(
    rule_title: str | None,
    level: str | Sequence[str] | None,
) -> tuple[str, list[object]]:
    """Build filter conditions common to Details-related tools."""
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
    Returns a chronological event list filtered to a specific host.
    Ideal for tracking compromise chains (e.g., HostA -> HostB -> HostC).

    Parameters:
        host_contains (str): Partial match filter for host name (required)
        level (str/Sequence[str], optional): Severity filter (e.g., 'high', ['high', 'crit'])
        time_range (Sequence[str], optional): Time range filter (start, end)
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval
    """
    _ensure_database_ready()
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE
    )

    host = host_contains.strip()
    if not host:
        raise ValueError("Please specify host_contains.")

    if time_range is not None and len(time_range) != 2:
        raise ValueError("time_range must be specified as a 2-element tuple (start, end).")

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
         "MitreTactics", "MitreTags", "Details", "AllFieldInfo"]
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
            message=f"No events found matching host '{host}'",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="No data on the specified page",
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
    detail_source: str = "Details",
    page_size: int = 50,
    page_offset: int = 0,
):
    """
    Parse the key-value structure of the Details or AllFieldInfo column (Key: Value | Key: Value).

    When field_name is empty, returns a list of available field names with counts.
    When field_name is specified, extracts values for that field.

    Parameters:
        field_name (str): Field name to extract.
                         Details uses abbreviated names (e.g., 'Cmdline', 'Proc', 'User');
                         AllFieldInfo uses original event field names (e.g., 'CommandLine',
                         'NewProcessName', 'Image'). Returns field name list when empty
        rule_title (str, optional): RuleTitle filter (partial match)
        level (str/Sequence[str], optional): Severity filter
        unique (bool): When True, returns count aggregation of unique values
        detail_source (str): Column to parse. 'Details' (default, standard/verbose profiles)
                             or 'AllFieldInfo' (all-field-info-verbose profile)
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval
    """
    _ensure_database_ready()
    detail_column = _resolve_detail_source(detail_source, context="parse_details_field")
    detail_quoted = _quote_identifier(detail_column)
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
                    COALESCE({detail_quoted}, ''), {sep_literal}
                )) AS kv_pair
                FROM logs
                WHERE {detail_quoted} IS NOT NULL AND {detail_quoted} != ''
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
                            COALESCE({detail_quoted}, ''), {sep_literal}
                        )) AS kv_pair,
                        "Computer"
                    FROM logs
                    WHERE position('{validated_name}: ' IN COALESCE({detail_quoted}, '')) > 0
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
                            COALESCE({detail_quoted}, ''), {sep_literal}
                        )) AS kv_pair
                    FROM logs
                    WHERE position('{validated_name}: ' IN COALESCE({detail_quoted}, '')) > 0
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
        msg = "No matching data found"
        if field_name.strip():
            msg = f"No data found for field '{field_name.strip()}'"
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=0,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message=msg,
        ))
    if result_df.empty:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="No data on the specified page",
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
    detail_source: str = "Details",
    page_size: int = 100,
    page_offset: int = 0,
):
    """
    Automatically extract IOCs (Indicators of Compromise) from Details/ExtraFieldInfo
    columns (standard/verbose profiles) or the AllFieldInfo column (all-field-info-verbose profile).

    Aggregates process paths, command lines, IP addresses, file paths, users, hashes,
    and service names by category and returns the results.

    Parameters:
        ioc_type (str, optional): Filter by IOC type to extract
                                  'process', 'cmdline', 'filepath', 'ip', 'user', 'hash', 'service'
                                  Extracts all types when None
        level (str/Sequence[str], optional): Severity filter
        rule_title (str, optional): RuleTitle filter (partial match)
        detail_source (str): Column to parse. 'Details' (default, also scans ExtraFieldInfo)
                             or 'AllFieldInfo' (all-field-info-verbose profile)
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval
    """
    _ensure_database_ready()
    detail_column = _resolve_detail_source(detail_source, context="extract_iocs")
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=100, max_page_size=MAX_PAGE_SIZE
    )

    field_categories = (
        IOC_FIELD_CATEGORIES if detail_column == "Details" else IOC_FIELD_CATEGORIES_ALL_FIELD_INFO
    )
    valid_types = set(field_categories.keys())
    if ioc_type is not None:
        ioc_type_normalized = ioc_type.strip().lower()
        if ioc_type_normalized not in valid_types:
            allowed = ", ".join(sorted(valid_types))
            raise ValueError(f"ioc_type must be one of: {allowed}")
        target_categories = {ioc_type_normalized: field_categories[ioc_type_normalized]}
    else:
        target_categories = field_categories

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
            status="no_data", message="No target IOC types specified",
        )

    case_expr = "CASE " + " ".join(case_parts) + " END"
    field_in_list = ", ".join(f"'{f}'" for f in target_field_names)

    extra_filter, params = _build_details_conditions(rule_title, level)
    and_clause = f"AND {extra_filter}" if extra_filter else ""

    columns = _get_logs_columns()
    has_extra = detail_column == "Details" and "ExtraFieldInfo" in columns
    sep_literal = f"' {DETAILS_SEPARATOR_CHAR} '"
    detail_quoted = _quote_identifier(detail_column)

    if has_extra:
        combined_expr = f"""COALESCE("Details", '') || {sep_literal} || COALESCE("ExtraFieldInfo", '')"""
    else:
        combined_expr = f"COALESCE({detail_quoted}, '')"

    query = f"""
        WITH split AS (
            SELECT
                unnest(string_split({combined_expr}, {sep_literal})) AS kv_pair,
                "Computer"
            FROM logs
            WHERE ({detail_quoted} IS NOT NULL AND {detail_quoted} != '')
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
            status="no_data", message="No IOCs found",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="No data on the specified page",
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
    detail_source: str = "Details",
    page_size: int = 50,
    page_offset: int = 0,
):
    """
    Decode and return Base64-encoded PowerShell commands.

    Detects Base64 values from -enc/-encodedcommand/-e parameters found in
    Details/ExtraFieldInfo (or AllFieldInfo) and decodes them as UTF-16-LE.

    Parameters:
        level (str/Sequence[str], optional): Severity filter
        rule_title (str, optional): RuleTitle filter (partial match)
        detail_source (str): Column to scan. 'Details' (default, also scans ExtraFieldInfo)
                             or 'AllFieldInfo' (all-field-info-verbose profile)
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval
    """
    _ensure_database_ready()
    detail_column = _resolve_detail_source(detail_source, context="decode_powershell_commands")
    _ensure_columns_exist(["Timestamp", "Computer", "RuleTitle", "Level", detail_column], context="decode_powershell_commands")
    page_size, page_offset = _resolve_pagination(
        page_size, page_offset, default_page_size=50, max_page_size=MAX_PAGE_SIZE
    )

    extra_filter, params = _build_details_conditions(rule_title, level)
    and_clause = f"AND {extra_filter}" if extra_filter else ""

    columns = _get_logs_columns()
    has_extra = detail_column == "Details" and "ExtraFieldInfo" in columns
    sep_literal = f"' {DETAILS_SEPARATOR_CHAR} '"
    detail_quoted = _quote_identifier(detail_column)

    if has_extra:
        combined_expr = f"""COALESCE("Details", '') || {sep_literal} || COALESCE("ExtraFieldInfo", '')"""
    else:
        combined_expr = f"COALESCE({detail_quoted}, '')"

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
            status="no_data", message="No Base64-encoded PowerShell commands found",
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
            status="no_data", message="No commands matching the Base64 pattern were found",
        ))

    all_df = pd.DataFrame(decoded_rows)
    total = len(all_df)
    paged = all_df.iloc[page_offset : page_offset + page_size].reset_index(drop=True)

    if paged.empty:
        return _WideDisplayDataFrame(_attach_pagination_metadata(
            pd.DataFrame(), total_count=total,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="No data on the specified page",
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
    Perform lateral movement correlation analysis between hosts.

    Detects events occurring between different hosts within a time window using self-join,
    identifying lateral movement attack patterns.

    Parameters:
        time_window_minutes (int): Time window for correlation detection (minutes). 1-1440
        level (str/Sequence[str], optional): Severity filter
        source_host (str, optional): Source host name filter (partial match)
        target_host (str, optional): Target host name filter (partial match)
        page_size (int): Number of items per page
        page_offset (int): Starting offset for retrieval
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
        raise ValueError("time_window_minutes must be between 1 and 1440.")

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
            message="No lateral movement patterns detected",
        )
    if result_df.empty:
        return _attach_pagination_metadata(
            pd.DataFrame(), total_count=total_count,
            page_size=page_size, page_offset=page_offset,
            status="no_data", message="No data on the specified page",
        )
    return _attach_pagination_metadata(
        result_df, total_count=total_count,
        page_size=page_size, page_offset=page_offset,
    )


# ──────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hayabusa MCP")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "http"],
        default="stdio",
        help="MCP transport (default: stdio, http is an alias for streamable-http)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP listen host (for streamable-http)")
    parser.add_argument("--port", type=int, default=8763, help="HTTP listen port (for streamable-http)")
    parser.add_argument(
        "--streamable-http-path",
        default="/mcp",
        help="Streamable HTTP endpoint path (default: /mcp)",
    )
    parser.add_argument(
        "--stateless-http",
        action="store_true",
        help="Enable stateless HTTP mode",
    )
    parser.add_argument(
        "--json-response",
        action="store_true",
        help="Enable JSON response mode",
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
        print("Starting Hayabusa MCP server (streamable-http mode)")
        print(f"endpoint: http://{args.host}:{args.port}{path}")
    else:
        print("Starting Hayabusa MCP server (stdio mode)")

    if status.get("loaded"):
        print(f"Current dataset: {status.get('dataset_path', '')}")
    else:
        print("No dataset loaded. Please load a CSV using the switch_dataset tool.")

    try:
        app.run(transport=transport)
    except KeyboardInterrupt:
        print("Hayabusa MCP server stopped.")
