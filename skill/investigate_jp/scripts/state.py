#!/usr/bin/env python3
"""
Investigation state manager for the Hayabusa investigate skill.

Maintains machine-readable investigation state as JSON files inside the
report output directory, so that coverage (every rule triaged, every host
reviewed, every activity cluster judged) is enforced by deterministic code
instead of relying on the LLM's memory, and so that an interrupted
investigation can be resumed.

State directory layout:
  manifest.json     dataset fingerprint (sha256, rows, columns) + strategy
  rule_triage.json  one entry per distinct RuleTitle, seeded from the CSV
  clusters.json     activity clusters derived from event timestamps
  findings.json     confirmed attack findings with evidence refs
  iocs.json         extracted IOCs with source refs
  hosts.json        per-host investigation coverage
  environment.json  known-good products/accounts with provenance
  queries.jsonl     audit log of executed queries (query_hash, has_more)

Evidence refs:
  Windows EventRecordIDs are NOT globally unique — the same RecordID can
  appear on several hosts/channels. Evidence is therefore cited as a
  qualified ref {record_id, computer, channel} ("RID@Computer@Channel" in
  compact string form; computer/channel may be omitted only while the
  RecordID is unambiguous in the dataset — gate G6 enforces this).

Commands (all stdlib, no external dependencies):
  init      create the state directory and seed it from the CSV
  strategy  record the investigation hypothesis / levels / interval
  triage    record a verdict for one rule (or --batch from stdin)
  finding   record an attack finding (or --batch from stdin)
  ioc       record an IOC (or --batch from stdin)
  host      record host investigation coverage (or --batch from stdin)
  cluster   record a verdict for an activity cluster
  env       record environment facts with provenance (or --none / --list)
  log-query append a query audit entry (tracks unresolved has_more)
  status    human-readable progress summary (for resuming)
  check     run coverage gates; exit 0 = PASS, 1 = FAIL
  appendix  print the report appendix markdown (used by report.py)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone

csv.field_size_limit(1 << 30)

STATE_VERSION = 1
LEVELS = ("crit", "high", "med", "low", "info")
# "mixed" = the same rule matched both benign and attack events; the split is
# recorded per behavior variant (see "variants" below) instead of forcing an
# all-or-nothing verdict over thousands of events.
TRIAGE_VERDICTS = ("attack", "false_positive", "indeterminate", "mixed")
VARIANT_VERDICTS = ("benign", "attack", "indeterminate")
CLUSTER_VERDICTS = ("attack", "benign", "indeterminate")
HOST_STATUSES = ("investigated", "reviewed", "not_applicable")
DEFAULT_CLUSTER_GAP_DAYS = 7

# A false_positive / mixed verdict on a rule with more events than this must
# enumerate the rule's behavior variants (GROUP BY over discriminating fields)
# and judge every variant — sampling 1-2 events and writing off the rest is
# exactly how real attacks hide inside noisy rules. Gate G10 recounts the
# declared variants against the CSV.
VARIANT_EVIDENCE_THRESHOLD = 20
# Distinct variant keys tracked per rule during the recount; beyond this the
# chosen fields are too unstable to be a meaningful grouping.
VARIANT_GROUPS_CAP = 2000

# Hayabusa detail-field separator (" ¦ ", broken bar U+00A6).
DETAILS_SEPARATOR = " ¦ "

# Rationales that carry no information get rejected at record time: an
# unauditable verdict ("reviewed") over thousands of events is exactly the
# failure mode the evidence gates exist to prevent.
STUB_RATIONALES = {
    "reviewed", "checked", "check", "ok", "done", "verified", "confirmed",
    "fp", "false positive", "benign", "normal",
    "確認済み", "確認済", "済", "レビュー済み", "レビュー済", "問題なし", "正常",
}
# Rows kept in memory per cited RecordID while verifying evidence against the
# CSV. The same event legitimately appears once per matching Sigma rule, and a
# duplicated RecordID spans a handful of events; 200 rows is far above both.
CITED_ROWS_CAP = 200

MANIFEST = "manifest.json"
RULE_TRIAGE = "rule_triage.json"
CLUSTERS = "clusters.json"
FINDINGS = "findings.json"
IOCS = "iocs.json"
HOSTS = "hosts.json"
QUERIES = "queries.jsonl"
ENVIRONMENT = "environment.json"

ENV_STATUSES = ("operator_confirmed", "observed", "inferred")

TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f %z",
    "%Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _parse_ts(value: str):
    value = (value or "").strip()
    if not value:
        return None
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    # Last resort: trim >6 fractional digits (Hayabusa -O emits 7; %f accepts at
    # most 6) and retry the known formats. This must NOT rely on fromisoformat:
    # before Python 3.11 it rejects the space between seconds and the UTC offset
    # that Hayabusa emits ('... 00:00:00.0000000 +00:00'), so on 3.9/3.10 the
    # strptime retry is what actually parses the trimmed value.
    trimmed = re.sub(r"(\.\d{6})\d+", r"\1", value)
    if trimmed != value:
        for fmt in TS_FORMATS:
            try:
                return datetime.strptime(trimmed, fmt)
            except ValueError:
                continue
    # Then ISO-8601 via fromisoformat, normalized for pre-3.11: 'Z' -> '+00:00'
    # and the offset joined onto the time (no space).
    normalized = trimmed.replace("Z", "+00:00")
    normalized = re.sub(r"(?<=\d) (?=[+-]\d{2}:\d{2}$)", "", normalized)
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _fail(message: str) -> "NoReturn":
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


# ---------- JSON file helpers ----------

def _path(state_dir: str, name: str) -> str:
    return os.path.join(state_dir, name)


def _load(state_dir: str, name: str):
    try:
        with open(_path(state_dir, name), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        _fail(f"{name} not found in {state_dir}. Run 'state.py init' first.")
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        _fail(f"{name} could not be read: {exc}")


def _load_optional(state_dir: str, name: str, default):
    """Like _load, but a missing file returns the default instead of failing —
    for files newer than the state dir (e.g. environment.json on v1 states)."""
    try:
        with open(_path(state_dir, name), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        _fail(f"{name} could not be read: {exc}")


def _require_initialized(state_dir: str) -> dict:
    """Guard for mutating commands: refuse (without mutating anything) unless the
    state directory has a complete manifest. Returns the loaded manifest."""
    manifest = _load(state_dir, MANIFEST)
    if not isinstance(manifest, dict) or "strategy" not in manifest or "dataset" not in manifest:
        _fail(
            f"{MANIFEST} in {state_dir} is missing required keys "
            "(state directory is not fully initialized). Re-run 'state.py init'."
        )
    return manifest


def _save(state_dir: str, name: str, data) -> None:
    target = _path(state_dir, name)
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _split_arg(value) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _read_batch_stdin() -> list[dict]:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        hint = ""
        msg = str(exc).lower()
        # "Invalid \escape" and "Invalid control character" are the two classic
        # symptoms of hand-building this JSON via a single-quoted `echo`: a
        # Windows path (C:\Users\..., \Device\...) yields bad \U \D \$ escapes,
        # and raw newlines/tabs in the pasted text yield control characters.
        # Both have the same fix: write the JSON to a file and redirect it in.
        if "escape" in msg or "control character" in msg:
            hint = (
                " — this usually means batch JSON built inline (e.g. via echo)"
                " with an unescaped backslash in a Windows path (C:\\Users\\...,"
                " \\Device\\...) or a raw newline/tab. Write the JSON to a file with"
                " the Write tool and pipe it with '--batch < file.json' (recommended),"
                " or double the backslashes (\\\\) / use forward slashes in the"
                " rationale and excerpt text."
            )
        _fail(f"--batch expects a JSON array on stdin: {exc}{hint}")
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        _fail("--batch expects a JSON array of objects on stdin")
    return data


# ---------- CSV scanning ----------

def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_detail_fields(detail: str) -> dict:
    """Split a Hayabusa detail string ('Key: Value ¦ Key: Value') into a dict."""
    fields: dict[str, str] = {}
    for pair in detail.split(DETAILS_SEPARATOR):
        if ": " in pair:
            key, value = pair.split(": ", 1)
            fields[key.strip()] = value.strip()
    return fields


def _variant_key(row: dict, detail_fields: dict, fields: list) -> tuple:
    """Value tuple for the declared grouping fields: top-level CSV columns
    (Computer, Channel, EventID, ...) are read from the row, anything else from
    the parsed detail string. Missing fields become ''."""
    values = []
    for field in fields:
        if field in row and row.get(field) is not None:
            values.append(str(row.get(field) or "").strip())
        else:
            values.append(detail_fields.get(field, ""))
    return tuple(values)


class DatasetFacts:
    """Single-pass summary of the CSV used to seed and verify state."""

    def __init__(self) -> None:
        self.row_count = 0
        self.columns: list[str] = []
        self.rules: dict[str, dict[str, int]] = {}        # title -> level -> count
        self.hosts: dict[str, dict[str, int]] = {}        # host -> level -> count
        self.record_ids: set[str] = set()
        self.ts_total = 0                                 # rows with a non-empty Timestamp
        self.ts_parsed = 0                                # rows whose Timestamp parsed
        self._dates_by_level: dict[str, set] = {}
        # RecordID -> rows sharing it (only for cited IDs, capped): lets the
        # gates resolve a ref to concrete rows and detect duplicated RecordIDs.
        self.cited_rows: dict[str, list[dict]] = {}
        self.cited_rows_truncated: set[str] = set()
        # rule title -> {variant key tuple: count} recomputed from the CSV for
        # the rules that declared variant evidence (gate G10).
        self.variant_counts: dict[str, dict[tuple, int]] = {}
        self.variant_overflow: set[str] = set()


def scan_csv(
    csv_path: str,
    cited_ids: "set[str] | None" = None,
    variant_specs: "dict[str, list] | None" = None,
) -> DatasetFacts:
    cited_ids = cited_ids or set()
    variant_specs = variant_specs or {}
    facts = DatasetFacts()
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        facts.columns = list(reader.fieldnames or [])
        for row in reader:
            facts.row_count += 1
            level = (row.get("Level") or "").strip().lower()
            title = (row.get("RuleTitle") or "").strip()
            host = (row.get("Computer") or "").strip()
            record_id = (row.get("RecordID") or "").strip()
            detail = (row.get("Details") or row.get("AllFieldInfo") or "").strip()
            if title:
                facts.rules.setdefault(title, {}).setdefault(level, 0)
                facts.rules[title][level] += 1
                spec = variant_specs.get(title)
                if spec is not None and title not in facts.variant_overflow:
                    counts = facts.variant_counts.setdefault(title, {})
                    key = _variant_key(row, _parse_detail_fields(detail), spec)
                    if key in counts or len(counts) < VARIANT_GROUPS_CAP:
                        counts[key] = counts.get(key, 0) + 1
                    else:
                        facts.variant_overflow.add(title)
            if host:
                facts.hosts.setdefault(host, {}).setdefault(level, 0)
                facts.hosts[host][level] += 1
            if record_id:
                facts.record_ids.add(record_id)
                if record_id in cited_ids:
                    rows = facts.cited_rows.setdefault(record_id, [])
                    if len(rows) < CITED_ROWS_CAP:
                        rows.append({
                            "computer": host,
                            "channel": (row.get("Channel") or "").strip(),
                            "rule_title": title,
                            "detail": detail,
                        })
                    else:
                        facts.cited_rows_truncated.add(record_id)
            ts_raw = (row.get("Timestamp") or "").strip()
            if ts_raw:
                facts.ts_total += 1
                ts = _parse_ts(ts_raw)
                if ts is not None:
                    facts.ts_parsed += 1
                    facts._dates_by_level.setdefault(level, set()).add(ts.date())
    return facts


def derive_clusters(facts: DatasetFacts, levels: list[str], gap_days: int) -> list[dict]:
    dates = set()
    for level in levels:
        dates.update(facts._dates_by_level.get(level, set()))
    if not dates:
        for level_dates in facts._dates_by_level.values():
            dates.update(level_dates)
    if not dates:
        return []
    ordered = sorted(dates)
    clusters = []
    start = prev = ordered[0]
    for day in ordered[1:]:
        if (day - prev) > timedelta(days=gap_days):
            clusters.append((start, prev))
            start = day
        prev = day
    clusters.append((start, prev))
    return [
        {
            "id": f"c{i + 1}",
            "start": str(cluster_start),
            "end": str(cluster_end),
            "verdict": None,
            "note": "",
        }
        for i, (cluster_start, cluster_end) in enumerate(clusters)
    ]


def default_levels(facts: DatasetFacts) -> list[str]:
    present = set()
    for per_level in facts.rules.values():
        present.update(per_level.keys())
    if present & {"high", "crit"}:
        return ["high", "crit"]
    if "med" in present:
        return ["med"]
    return [level for level in LEVELS if level in present] or list(LEVELS)


def _validate_levels(raw: str) -> list[str]:
    levels = [item.lower() for item in _split_arg(raw)]
    invalid = [level for level in levels if level not in LEVELS]
    if invalid:
        _fail(f"invalid levels: {', '.join(invalid)} (allowed: {', '.join(LEVELS)})")
    if not levels:
        _fail("--levels must contain at least one level")
    return levels


# ---------- commands ----------

def cmd_init(args) -> None:
    csv_path = os.path.abspath(args.csv)
    if not os.path.isfile(csv_path):
        _fail(f"CSV not found: {csv_path}")
    state_dir = os.path.abspath(args.dir)
    manifest_path = _path(state_dir, MANIFEST)
    if os.path.exists(manifest_path):
        _fail(
            f"State already exists in {state_dir}. "
            "Use 'state.py status' to resume, or choose another directory."
        )
    # No manifest sentinel: either a clean directory or an init that was
    # interrupted before the sentinel was written. Overwriting stale partial
    # files here is the intended recovery path; mutating commands refuse to run
    # against a manifest-less directory (see _require_initialized), so no
    # analyst-entered data can exist to be lost.
    os.makedirs(state_dir, exist_ok=True)

    facts = scan_csv(csv_path)
    levels = _validate_levels(args.levels) if args.levels else default_levels(facts)
    detail_source = "AllFieldInfo" if "AllFieldInfo" in facts.columns else "Details"

    manifest = {
        "version": STATE_VERSION,
        "dataset": {
            "path": csv_path,
            "sha256": _sha256(csv_path),
            "row_count": facts.row_count,
            "columns": facts.columns,
            "detail_source": detail_source,
            "timestamp_total": facts.ts_total,
            "timestamp_parsed": facts.ts_parsed,
        },
        "strategy": {
            "hypothesis": args.hypothesis or "",
            "time_interval": args.interval or "",
            "levels_investigated": levels,
        },
        "session": {
            "started_at": _now(),
            "model": args.model or "",
            "skill": args.skill,
        },
        "updated_at": _now(),
    }

    rules = []
    for title in sorted(facts.rules):
        per_level = facts.rules[title]
        rules.append({
            "rule_title": title,
            "levels": dict(sorted(per_level.items())),
            "count": sum(per_level.values()),
            "status": "pending",
            "verdict": None,
            "rationale": "",
            "evidence": {"refs": [], "record_ids": [], "detail_excerpt": ""},
            "variants": None,
            "verified_at": None,
        })

    clusters = derive_clusters(facts, levels, args.cluster_gap_days)
    # manifest.json is the "state exists" sentinel checked above, so it is
    # written last: an interrupted init leaves no manifest and can be re-run.
    _save(state_dir, RULE_TRIAGE, {"rules": rules})
    _save(state_dir, CLUSTERS, {"gap_days": args.cluster_gap_days, "clusters": clusters})
    _save(state_dir, FINDINGS, {"findings": []})
    _save(state_dir, IOCS, {"iocs": []})
    _save(state_dir, HOSTS, {"hosts": []})
    _save(state_dir, ENVIRONMENT, {"entries": [], "declared_no_info": False})
    # Truncate: a re-init after an interrupted run must not inherit stale
    # query-log entries (they would resurface as phantom G5 failures).
    open(_path(state_dir, QUERIES), "w", encoding="utf-8").close()
    _save(state_dir, MANIFEST, manifest)

    gate_rules = [r for r in rules if set(r["levels"]) & set(levels)]
    print(f"Initialized investigation state: {state_dir}")
    print(f"  dataset: {os.path.basename(csv_path)} ({facts.row_count} rows, detail_source={detail_source})")
    print(f"  rules seeded: {len(rules)} total, {len(gate_rules)} at investigated levels {levels}")
    print(f"  activity clusters: {len(clusters)}")
    unparsed = facts.ts_total - facts.ts_parsed
    if facts.ts_total > 0 and facts.ts_parsed == 0:
        print(
            "  warning: no Timestamp values could be parsed (unsupported format?) —"
            " no activity clusters were derived, so gate G3 will FAIL until the known"
            " activity window(s) are added manually with"
            " 'state.py cluster --add --dir <dir> --start ... --end ...'."
        )
    elif unparsed > 0:
        print(
            f"  warning: {unparsed}/{facts.ts_total} rows have Timestamps state.py could not"
            " parse; they are excluded from activity clusters and reported as a G3 warning."
            " If a wave is missing, add it with 'state.py cluster --add --start ... --end ...'."
        )


def cmd_strategy(args) -> None:
    manifest = _require_initialized(args.dir)
    strategy = manifest["strategy"]
    levels_changed = False
    new_levels = strategy["levels_investigated"]
    if args.levels is not None:
        new_levels = _validate_levels(args.levels)
        # Compare as sets: reordering the same levels is not a change.
        levels_changed = set(new_levels) != set(strategy["levels_investigated"])

    # If the investigated levels changed, recompute the auto-derived clusters
    # for the new scope FIRST (before persisting anything).
    #   - The scan happens up front so a read failure aborts with NO state
    #     written (the level change is not half-applied).
    #   - Re-derived auto clusters are ALL reset to unjudged: broadening scope
    #     brings newly-in-scope events into a window, so a prior verdict must not
    #     mask them — the analyst re-judges. Manually-added clusters are kept.
    #   - A level change requires the CSV: without it we cannot re-derive, so we
    #     refuse rather than persist a level change that leaves clusters stale.
    rederived_clusters = None
    if levels_changed:
        csv_path = manifest["dataset"]["path"]
        if not os.path.isfile(csv_path):
            _fail(
                f"cannot re-derive clusters for the new levels: CSV not found ({csv_path})."
                " The level change was NOT applied. Restore the CSV and retry."
            )
        try:
            facts = scan_csv(csv_path)
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            _fail(f"could not re-scan CSV to re-derive clusters: {exc} (no changes written)")
        clusters = _load(args.dir, CLUSTERS)
        manual = [c for c in clusters["clusters"] if c.get("manual")]
        judged_reset = sum(
            1 for c in clusters["clusters"]
            if not c.get("manual") and c.get("verdict") is not None
        )
        fresh = derive_clusters(facts, new_levels, clusters.get("gap_days", DEFAULT_CLUSTER_GAP_DAYS))
        clusters["clusters"] = fresh + manual
        rederived_clusters = (clusters, len(fresh), len(manual), judged_reset)

    if args.hypothesis is not None:
        strategy["hypothesis"] = args.hypothesis
    if args.interval is not None:
        strategy["time_interval"] = args.interval
    strategy["levels_investigated"] = new_levels
    manifest["updated_at"] = _now()
    # Save clusters BEFORE the manifest: the manifest's levels_investigated is
    # what gates re-derivation on the next run, so if the process dies between
    # the two saves the manifest still shows the OLD levels and a re-run will
    # re-derive (self-healing) rather than leaving stale clusters undetected.
    if rederived_clusters is not None:
        clusters, n_fresh, n_manual, n_judged_reset = rederived_clusters
        _save(args.dir, CLUSTERS, clusters)
    _save(args.dir, MANIFEST, manifest)
    if rederived_clusters is not None:
        msg = f"re-derived {n_fresh} activity clusters (unjudged) for levels {new_levels}"
        if n_manual:
            msg += f" (kept {n_manual} manual cluster(s))"
        print(msg)
        if n_judged_reset:
            print(
                f"warning: {n_judged_reset} previously judged cluster verdict(s) were reset"
                " by the level change — re-judge them with 'state.py cluster --id ...'"
                " (gate G3 fails until every cluster is judged)",
                file=sys.stderr,
            )
    print(f"strategy updated: {json.dumps(strategy, ensure_ascii=False)}")


def _apply_triage(state_dir: str, entries: list[dict]) -> None:
    # Validate the state dir BEFORE mutating: against a half-initialized dir
    # (no manifest) this refuses without writing, so re-running init can safely
    # recover instead of silently overwriting analyst-entered verdicts.
    manifest = _require_initialized(state_dir)
    gate_levels = set(manifest["strategy"]["levels_investigated"])
    columns = manifest["dataset"].get("columns", [])
    has_record_id_col = "RecordID" in columns
    has_detail_col = ("Details" in columns) or ("AllFieldInfo" in columns)
    triage = _load(state_dir, RULE_TRIAGE)
    by_title = {rule["rule_title"]: rule for rule in triage["rules"]}
    for entry in entries:
        title = (entry.get("rule_title") or "").strip()
        verdict = (entry.get("verdict") or "").strip()
        rationale = (entry.get("rationale") or "").strip()
        if title not in by_title:
            candidates = [t for t in by_title if title.lower() in t.lower()][:3]
            hint = f" Did you mean: {', '.join(candidates)}?" if candidates else ""
            _fail(f"unknown rule_title: {title!r}.{hint} (titles are seeded from the CSV; copy them exactly)")
        if verdict not in TRIAGE_VERDICTS:
            _fail(f"verdict for {title!r} must be one of: {', '.join(TRIAGE_VERDICTS)}")
        if not rationale:
            _fail(f"rationale is required for {title!r} (record why, so the report and reviewers can re-evaluate)")
        _require_substantive_rationale(rationale, f"rule {title!r}")
        refs = _normalize_refs(entry)
        if has_record_id_col and not refs:
            _fail(
                f"refs (or record_ids) is required for a {verdict!r} verdict on {title!r}:"
                " cite the event(s) you actually verified as"
                ' {"record_id": ..., "computer": ..., "channel": ...} (gates G6/G7).'
                " Every verdict — false_positive and indeterminate included — must be"
                " auditable down to the row; RecordIDs duplicated across hosts need the"
                " computer (and channel) qualifier."
            )
        excerpt = entry.get("excerpt")
        excerpt_text = ("" if excerpt is None else str(excerpt)).strip()[:2000]
        if verdict in ("false_positive", "mixed") and has_detail_col and not excerpt_text:
            _fail(
                f"excerpt is required for a {verdict!r} verdict on {title!r}: quote"
                " the cited event's detail field VERBATIM (contiguous substring, no"
                " ellipsis) showing why it is benign. Gate G6 verifies the quote against"
                " the actual row, so a paraphrase will fail."
            )
        rule = by_title[title]
        variants_raw = entry.get("variants")
        if verdict == "mixed" and variants_raw is None:
            _fail(
                f"verdict 'mixed' on {title!r} requires variants: enumerate the rule's"
                " behavior variants (GROUP BY over discriminating fields) and judge"
                " each one benign/attack/indeterminate, so the attack part is explicit"
            )
        if (verdict == "false_positive" and variants_raw is None
                and rule["count"] > VARIANT_EVIDENCE_THRESHOLD):
            _fail(
                f"a false_positive verdict on {title!r} covers {rule['count']} events:"
                " sampling is not sufficient evidence at this volume (gate G10)."
                " Enumerate ALL behavior variants with a GROUP BY over the"
                " discriminating fields (e.g. Computer + SrcProc + TgtProc), judge each"
                " variant, and record them in 'variants' — or use 'mixed'/'indeterminate'"
            )
        variants = None
        if variants_raw is not None:
            variants = _validate_variants(variants_raw, title, verdict, rule["count"])
        rule["status"] = "verified"
        rule["verdict"] = verdict
        rule["rationale"] = rationale
        rule["evidence"]["refs"] = refs
        rule["evidence"]["record_ids"] = [r["record_id"] for r in refs]
        rule["evidence"]["detail_excerpt"] = excerpt_text
        rule["variants"] = variants
        rule["verified_at"] = _now()
    _save(state_dir, RULE_TRIAGE, triage)
    pending_all = [rule for rule in triage["rules"] if rule["status"] == "pending"]
    pending_gate = sum(1 for rule in pending_all if set(rule["levels"]) & gate_levels)
    print(
        f"recorded {len(entries)} triage verdict(s);"
        f" {pending_gate} rule(s) at investigated levels still pending (gate G1),"
        f" {len(pending_all)} pending across all levels"
    )


def cmd_triage(args) -> None:
    if args.batch:
        _apply_triage(args.dir, _read_batch_stdin())
        return
    if not args.rule:
        _fail("--rule is required (or use --batch with a JSON array on stdin)")
    _apply_triage(args.dir, [{
        "rule_title": args.rule,
        "verdict": args.verdict,
        "rationale": args.rationale,
        "record_ids": args.record_ids,
        "excerpt": args.excerpt,
    }])


def _normalize_record_ids(value) -> list[str]:
    """Accept a comma string, a list, or a bare scalar; return string RecordIDs.
    Batch JSON often carries a single numeric ID ("record_ids": 4624) — treat it
    as a one-element list rather than crashing on iteration."""
    if value is None:
        return []
    if isinstance(value, str):
        return [str(item) for item in _split_arg(value)]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _normalize_refs(entry: dict) -> list[dict]:
    """
    Merge an entry's evidence references into qualified refs
    [{record_id, computer, channel}], deduplicated.

    Accepted inputs:
      - entry["refs"]: list of {"record_id": ..., "computer": ..., "channel": ...}
        dicts (computer/channel optional) or compact strings
      - entry["record_ids"]: legacy bare IDs (comma string / list / scalar);
        each item may also use the compact "RID@Computer" or
        "RID@Computer@Channel" form

    A bare RecordID is only a complete reference while that ID is unambiguous
    in the dataset; gate G6 rejects bare refs to duplicated RecordIDs.
    """
    refs: list[dict] = []
    seen: set = set()

    def push(record_id, computer="", channel="") -> None:
        record_id = str(record_id or "").strip()
        computer = str(computer or "").strip()
        channel = str(channel or "").strip()
        if not record_id:
            return
        key = (record_id, computer, channel)
        if key in seen:
            return
        seen.add(key)
        refs.append({"record_id": record_id, "computer": computer, "channel": channel})

    def push_item(item) -> None:
        if isinstance(item, dict):
            push(item.get("record_id") or item.get("rid"), item.get("computer"), item.get("channel"))
            return
        parts = str(item).split("@")
        push(parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")

    raw_refs = entry.get("refs")
    if isinstance(raw_refs, dict):
        raw_refs = [raw_refs]
    if isinstance(raw_refs, (list, tuple)):
        for item in raw_refs:
            push_item(item)
    elif raw_refs is not None:
        push_item(raw_refs)
    qualified_ids = {r["record_id"] for r in refs}
    for rid in _normalize_record_ids(entry.get("record_ids")):
        parts = rid.split("@")
        # A bare ID duplicating an already-qualified ref adds nothing.
        if len(parts) == 1 and parts[0] in qualified_ids:
            continue
        push_item(rid)
    return refs


def _ref_label(ref: dict) -> str:
    label = ref["record_id"]
    if ref.get("computer"):
        label += f"@{ref['computer']}"
        if ref.get("channel"):
            label += f"@{ref['channel']}"
    return label


def _entry_refs(container: dict) -> list[dict]:
    """Read stored evidence refs, falling back to legacy bare record_ids so
    state written before qualified refs existed keeps being validated."""
    if isinstance(container.get("refs"), list) and container["refs"]:
        return _normalize_refs({"refs": container["refs"]})
    return _normalize_refs({"record_ids": container.get("record_ids") or []})


def _require_substantive_rationale(rationale: str, context: str) -> None:
    normalized = " ".join(rationale.split()).lower()
    if len(normalized) < 6 or normalized in STUB_RATIONALES:
        _fail(
            f"rationale for {context} is too thin ({rationale!r}): state what in the"
            " event data justifies the verdict (fields, values, execution context),"
            " so reviewers can re-evaluate it"
        )


def _validate_variants(raw, title: str, verdict: str, rule_count: int) -> dict:
    """
    Validate a triage entry's behavior-variant evidence:
      {"fields": ["Computer", "SrcProc", ...],
       "groups": [{"key": {field: value, ...}, "count": N,
                   "verdict": "benign|attack|indeterminate", "note": "..."}]}

    Every event of the rule must fall into exactly one declared group (the sum
    of counts must equal the rule's event count; gate G10 recounts each group
    against the CSV), so a benign sample can no longer write off the events
    that were never looked at.
    """
    if not isinstance(raw, dict):
        _fail(f"variants for {title!r} must be an object with 'fields' and 'groups'")
    fields = raw.get("fields")
    groups = raw.get("groups")
    if not isinstance(fields, list) or not fields or not all(isinstance(f, str) and f.strip() for f in fields):
        _fail(f"variants.fields for {title!r} must be a non-empty list of field names")
    fields = [f.strip() for f in fields]
    if not isinstance(groups, list) or not groups:
        _fail(f"variants.groups for {title!r} must be a non-empty list")
    if len(groups) > VARIANT_GROUPS_CAP:
        _fail(
            f"variants for {title!r} declare {len(groups)} groups (cap {VARIANT_GROUPS_CAP}):"
            " the chosen fields are too unstable to be a meaningful grouping —"
            " drop per-event fields (timestamps, PIDs, ...) from variants.fields"
        )
    normalized_groups = []
    seen_keys = set()
    total = 0
    attack_groups = 0
    benign_groups = 0
    for i, group in enumerate(groups):
        if not isinstance(group, dict):
            _fail(f"variants.groups[{i}] for {title!r} must be an object")
        key = group.get("key")
        if not isinstance(key, dict) or set(key.keys()) != set(fields):
            _fail(
                f"variants.groups[{i}].key for {title!r} must contain exactly the"
                f" declared fields {fields}"
            )
        norm_key = {f: str(key[f] if key[f] is not None else "").strip() for f in fields}
        key_tuple = tuple(norm_key[f] for f in fields)
        if key_tuple in seen_keys:
            _fail(f"variants.groups[{i}] for {title!r} duplicates key {norm_key}")
        seen_keys.add(key_tuple)
        count = group.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            _fail(f"variants.groups[{i}].count for {title!r} must be a positive integer")
        group_verdict = (group.get("verdict") or "").strip()
        if group_verdict not in VARIANT_VERDICTS:
            _fail(
                f"variants.groups[{i}].verdict for {title!r} must be one of:"
                f" {', '.join(VARIANT_VERDICTS)}"
            )
        if group_verdict == "benign" and all(v == "" for v in key_tuple):
            _fail(
                f"variants.groups[{i}] for {title!r}: an empty-detail variant cannot be"
                " judged benign — there is nothing to base benignity on; use"
                " 'indeterminate' for events whose grouping fields are all empty"
            )
        total += count
        attack_groups += 1 if group_verdict == "attack" else 0
        benign_groups += 1 if group_verdict == "benign" else 0
        normalized_groups.append({
            "key": norm_key,
            "count": count,
            "verdict": group_verdict,
            "note": str(group.get("note") or "").strip(),
        })
    if total != rule_count:
        _fail(
            f"variants for {title!r} cover {total} events but the rule has"
            f" {rule_count}: every event must belong to exactly one group —"
            " re-run the GROUP BY and include ALL variants"
        )
    if verdict == "false_positive" and attack_groups:
        _fail(
            f"verdict for {title!r} is false_positive but variants contain"
            " attack group(s) — use verdict 'mixed'"
        )
    if verdict == "mixed" and not attack_groups:
        _fail(
            f"verdict for {title!r} is mixed but no variant group is judged"
            " 'attack' — use false_positive/indeterminate instead"
        )
    return {"fields": fields, "groups": normalized_groups}


def _normalize_hosts(value) -> list[str]:
    """Accept a comma string, a list, or a bare scalar; return host names."""
    if value is None:
        return []
    if isinstance(value, str):
        return _split_arg(value)
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _resolve_rule_titles(value, known_titles: set[str]) -> list[str]:
    """
    Normalize a finding's rule-title reference to a list.

    The CLI --rules value is a comma-separated string, but seeded rule titles
    may themselves contain commas (with or without a following space). Rather
    than split blindly, greedily consume the longest seeded title from the front
    of the string, tolerating a ", " or "," delimiter between titles. Unknown
    fragments (not seeded) are emitted verbatim so G4 can flag them.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if not isinstance(value, str):
        # Scalar non-string (e.g. a number): treat as a single opaque title.
        return [str(value)]
    rest = value.strip()
    if not rest:
        return []
    if rest in known_titles:
        return [rest]
    sorted_known = sorted(known_titles, key=len, reverse=True)
    titles: list[str] = []
    while rest:
        matched = None
        for known in sorted_known:
            if rest == known:
                matched, rest = known, ""
                break
            if rest.startswith(known + ", "):
                matched, rest = known, rest[len(known) + 2:]
                break
            if rest.startswith(known + ","):
                matched, rest = known, rest[len(known) + 1:]
                break
        if matched is not None:
            titles.append(matched)
            continue
        head, _, tail = rest.partition(",")
        if head.strip():
            titles.append(head.strip())
        rest = tail.lstrip(" ")
    return titles


def _apply_findings(state_dir: str, entries: list[dict]) -> None:
    manifest = _require_initialized(state_dir)
    has_record_id_col = "RecordID" in manifest["dataset"].get("columns", [])
    findings = _load(state_dir, FINDINGS)
    triage_rules = _load(state_dir, RULE_TRIAGE)["rules"]
    known_titles = {rule["rule_title"] for rule in triage_rules}
    pending_titles = {rule["rule_title"] for rule in triage_rules if rule["status"] == "pending"}
    for entry in entries:
        title = (entry.get("title") or "").strip()
        summary = (entry.get("summary") or "").strip()
        if not title or not summary:
            _fail("each finding requires 'title' and 'summary'")
        refs = _normalize_refs(entry)
        if has_record_id_col and not refs:
            _fail(
                f"finding {title!r} requires refs (or record_ids): cite the supporting"
                ' event(s) as {"record_id": ..., "computer": ..., "channel": ...}'
                " (gate G7), so every report claim can be traced back to the data."
            )
        rule_titles = _resolve_rule_titles(entry.get("rules") or entry.get("rule_titles"), known_titles)
        unknown = [t for t in rule_titles if t not in known_titles]
        if unknown:
            print(
                f"warning: rule title(s) not found in rule_triage.json: {', '.join(unknown)}"
                " — gate G4 matches exact seeded titles",
                file=sys.stderr,
            )
        cited_pending = [t for t in rule_titles if t in pending_titles]
        if cited_pending:
            print(
                f"warning: finding {title!r} cites rule(s) without a triage verdict:"
                f" {', '.join(cited_pending)} — record a triage verdict for them"
                " (any level) or gate G8 will fail",
                file=sys.stderr,
            )
        findings["findings"].append({
            "id": f"f{len(findings['findings']) + 1}",
            "title": title,
            "phase": (entry.get("phase") or "").strip(),
            "hosts": _normalize_hosts(entry.get("hosts")),
            "rule_titles": rule_titles,
            "refs": refs,
            "record_ids": [r["record_id"] for r in refs],
            "summary": summary,
            "query": (entry.get("query") or "").strip(),
            "created_at": _now(),
        })
    _save(state_dir, FINDINGS, findings)
    print(f"recorded {len(entries)} finding(s); total {len(findings['findings'])}")


def cmd_finding(args) -> None:
    if args.batch:
        _apply_findings(args.dir, _read_batch_stdin())
        return
    _apply_findings(args.dir, [{
        "title": args.title,
        "phase": args.phase,
        "hosts": args.hosts,
        "rules": args.rules,
        "record_ids": args.record_ids,
        "summary": args.summary,
        "query": args.query,
    }])


def _apply_iocs(state_dir: str, entries: list[dict]) -> None:
    _require_initialized(state_dir)
    iocs = _load(state_dir, IOCS)
    for entry in entries:
        ioc_type = (entry.get("type") or "").strip()
        value = (entry.get("value") or "").strip()
        if not ioc_type or not value:
            _fail("each IOC requires 'type' and 'value'")
        refs = _normalize_refs(entry)
        iocs["iocs"].append({
            "type": ioc_type,
            "value": value,
            "hosts": _normalize_hosts(entry.get("hosts")),
            "context": (entry.get("context") or "").strip(),
            "refs": refs,
            "record_ids": [r["record_id"] for r in refs],
            "created_at": _now(),
        })
    _save(state_dir, IOCS, iocs)
    print(f"recorded {len(entries)} IOC(s); total {len(iocs['iocs'])}")


def cmd_ioc(args) -> None:
    if args.batch:
        _apply_iocs(args.dir, _read_batch_stdin())
        return
    _apply_iocs(args.dir, [{
        "type": args.type,
        "value": args.value,
        "hosts": args.hosts,
        "context": args.context,
        "record_ids": args.record_ids,
    }])


def _apply_hosts(state_dir: str, entries: list[dict]) -> None:
    _require_initialized(state_dir)
    hosts = _load(state_dir, HOSTS)
    by_name = {h["name"]: h for h in hosts["hosts"]}
    for entry in entries:
        name = (entry.get("name") or "").strip()
        status = (entry.get("status") or "investigated").strip()
        if not name:
            _fail("each host entry requires 'name'")
        if status not in HOST_STATUSES:
            _fail(f"host status must be one of: {', '.join(HOST_STATUSES)}")
        record = by_name.get(name)
        if record is None:
            record = {"name": name, "status": status, "note": "", "updated_at": _now()}
            hosts["hosts"].append(record)
            by_name[name] = record
        record["status"] = status
        # Preserve an existing note when this update omits one (note=None),
        # so re-recording a host to change status does not erase the audit note.
        note = entry.get("note")
        if note is not None:
            record["note"] = str(note).strip()
        record["updated_at"] = _now()
    _save(state_dir, HOSTS, hosts)
    print(f"recorded coverage for {len(entries)} host(s); total {len(hosts['hosts'])}")


def cmd_host(args) -> None:
    if args.batch:
        _apply_hosts(args.dir, _read_batch_stdin())
        return
    if not args.name:
        _fail("--name is required (or use --batch)")
    _apply_hosts(args.dir, [{"name": args.name, "status": args.status, "note": args.note}])


def cmd_cluster(args) -> None:
    _require_initialized(args.dir)
    clusters = _load(args.dir, CLUSTERS)
    if args.add:
        if not args.start or not args.end:
            _fail("cluster --add requires --start and --end (YYYY-MM-DD)")
        # Manual clusters are the sole remedy for a G3 failure and their windows
        # are printed in the certified appendix, so reject malformed or reversed
        # dates instead of letting the gate pass on an unvalidated window.
        try:
            start_date = datetime.strptime(args.start, "%Y-%m-%d").date()
            end_date = datetime.strptime(args.end, "%Y-%m-%d").date()
        except ValueError:
            _fail(
                f"--start/--end must be YYYY-MM-DD dates"
                f" (got --start {args.start!r} --end {args.end!r})"
            )
        if end_date < start_date:
            _fail(f"--end {args.end} is before --start {args.start}")
        existing = {c["id"] for c in clusters["clusters"]}
        n = 1
        while f"m{n}" in existing:
            n += 1
        new_id = f"m{n}"
        clusters["clusters"].append({
            "id": new_id,
            "start": str(start_date),
            "end": str(end_date),
            "verdict": args.verdict,
            "note": args.note or "",
            "manual": True,
        })
        _save(args.dir, CLUSTERS, clusters)
        verdict_label = args.verdict or "(unjudged)"
        print(f"added cluster {new_id} ({start_date} ~ {end_date}) -> {verdict_label}")
        return
    if not args.id:
        _fail("cluster requires --id (to judge an existing cluster) or --add (to add one)")
    target = next((c for c in clusters["clusters"] if c["id"] == args.id), None)
    if target is None:
        known = ", ".join(c["id"] for c in clusters["clusters"]) or "(none)"
        _fail(f"unknown cluster id: {args.id}. Known clusters: {known}")
    if not args.verdict:
        _fail(f"verdict is required when judging cluster {args.id} (--verdict)")
    if args.verdict not in CLUSTER_VERDICTS:
        _fail(f"verdict must be one of: {', '.join(CLUSTER_VERDICTS)}")
    target["verdict"] = args.verdict
    # Preserve an existing note when this re-judge omits one (note=None), so
    # upgrading a verdict does not erase the recorded basis (same rule as hosts).
    if args.note is not None:
        target["note"] = args.note
    _save(args.dir, CLUSTERS, clusters)
    print(f"cluster {args.id} ({target['start']} ~ {target['end']}) -> {args.verdict}")


def cmd_env(args) -> None:
    """Record environment facts (legitimately deployed products, approved
    accounts, maintenance windows) with provenance, so false-positive
    rationales can cite them instead of relying on the model's general
    knowledge. 'inferred' entries alone must not settle a verdict."""
    _require_initialized(args.dir)
    env = _load_optional(args.dir, ENVIRONMENT, {"entries": [], "declared_no_info": False})
    if args.none:
        env["declared_no_info"] = True
        _save(args.dir, ENVIRONMENT, env)
        print("recorded: no environment information available for this investigation")
        return
    if args.list:
        if env.get("declared_no_info"):
            print("declared: no environment information available")
        entries = env.get("entries") or []
        if not entries:
            print("no environment entries recorded")
        for e in entries:
            line = f"  [{e.get('status')}] {e.get('category') or '-'}: {e.get('value')}"
            if e.get("source"):
                line += f" (source: {e['source']})"
            if e.get("note"):
                line += f" — {e['note']}"
            print(line)
        return
    if not args.value.strip():
        _fail("env requires --value (to add an entry), or --none / --list")
    status = (args.status or "").strip()
    if status not in ENV_STATUSES:
        _fail(
            f"--status must be one of: {', '.join(ENV_STATUSES)}"
            " (operator_confirmed = the user/operator stated it;"
            " observed = seen in the logs; inferred = model assumption)"
        )
    env["entries"].append({
        "value": args.value.strip(),
        "category": (args.category or "").strip(),
        "status": status,
        "source": (args.source or "").strip(),
        "note": (args.note or "").strip(),
        "recorded_at": _now(),
    })
    env["declared_no_info"] = False
    _save(args.dir, ENVIRONMENT, env)
    print(f"recorded environment entry ({status}): {args.value.strip()}")


def cmd_log_query(args) -> None:
    _require_initialized(args.dir)
    entry = {
        "ts": _now(),
        "tool": args.tool,
        "query_hash": args.query_hash or "",
        "dataset_version": args.dataset_version or "",
        "note": args.note or "",
        "has_more": bool(args.has_more),
        "accepted_truncation": bool(args.accept_truncation),
    }
    with open(_path(args.dir, QUERIES), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print("query logged")


def _load_queries(state_dir: str) -> tuple[list[dict], int]:
    """Return (parsed entries, count of corrupt lines skipped). A truncated last
    line (e.g. a crash mid-append) must not make the whole gate crash."""
    entries: list[dict] = []
    corrupt = 0
    try:
        # errors="replace": a byte-corrupt/truncated-multibyte line must be
        # tolerated (turned into a JSON parse error below), never crash the gate.
        with open(_path(state_dir, QUERIES), encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    corrupt += 1
                    continue
                # Valid JSON but not an object (e.g. a bare number/array) is also
                # unusable as a query record — count it as corrupt, don't append.
                if isinstance(obj, dict):
                    entries.append(obj)
                else:
                    corrupt += 1
    except FileNotFoundError:
        pass
    except OSError as exc:
        # An existing-but-unreadable audit log must not read as "no queries
        # logged" — that would let G5 pass vacuously while recorded truncation
        # gaps silently vanish. Fail loudly like _load does for the JSON files.
        _fail(f"{QUERIES} could not be read: {exc}")
    return entries, corrupt


# ---------- check / status / appendix ----------

def _resolve_ref(facts: DatasetFacts, ref: dict, rule_titles=None):
    """
    Resolve a qualified evidence ref against the scanned dataset.

    Returns (rows, gap): `rows` is the list of scanned rows the ref denotes
    (narrowed to `rule_titles` when given) if it resolves to exactly one event,
    otherwise None plus a human-readable gap message. A bare RecordID resolves
    only while it is unambiguous — duplicated RecordIDs (same value on several
    hosts/channels) must be qualified with computer (and channel).
    """
    rid = ref["record_id"]
    rows = facts.cited_rows.get(rid)
    if not rows:
        return None, f"RecordID {rid}: not found in dataset"
    if ref.get("computer"):
        rows = [r for r in rows if r["computer"] == ref["computer"]]
        if rows and ref.get("channel"):
            rows = [r for r in rows if r["channel"] == ref["channel"]]
        if not rows:
            return None, f"ref {_ref_label(ref)}: no such event in dataset"
        events = {(r["computer"], r["channel"]) for r in rows}
        if len(events) > 1:
            sample = ", ".join(sorted(ch or "?" for _, ch in events)[:4])
            return None, (
                f"ref {_ref_label(ref)} is still ambiguous across channels"
                f" ({sample}) — add \"channel\" to the ref"
            )
    else:
        events = {(r["computer"], r["channel"]) for r in rows}
        if len(events) > 1:
            sample = ", ".join(f"{c or '?'}/{ch or '?'}" for c, ch in sorted(events)[:4])
            more = ", ..." if len(events) > 4 else ""
            return None, (
                f"RecordID {rid} is ambiguous: {len(events)} different events share it"
                f" ({sample}{more}) — qualify the ref with computer (and channel)"
            )
    if rule_titles is not None:
        wanted = {rule_titles} if isinstance(rule_titles, str) else set(rule_titles)
        narrowed = [r for r in rows if r["rule_title"] in wanted]
        if not narrowed:
            got = ", ".join(sorted({r["rule_title"] or "(empty)" for r in rows})[:3])
            want = ", ".join(sorted(wanted)[:3])
            return None, (
                f"ref {_ref_label(ref)}: the event exists but was not detected by the"
                f" cited rule(s) [{want}] (its rows belong to: {got})"
            )
        rows = narrowed
    return rows, None


def run_check(state_dir: str, verify_hash: bool = True) -> dict:
    manifest = _load(state_dir, MANIFEST)
    triage = _load(state_dir, RULE_TRIAGE)
    clusters = _load(state_dir, CLUSTERS)
    findings = _load(state_dir, FINDINGS)
    iocs = _load(state_dir, IOCS)
    hosts = _load(state_dir, HOSTS)
    queries, corrupt_query_lines = _load_queries(state_dir)

    # Qualified evidence refs cited anywhere in the state. The CSV scan keeps
    # the concrete rows for exactly these IDs, so G6/G9 can resolve each ref to
    # one event and verify what was claimed about it.
    triage_refs = {rule["rule_title"]: _entry_refs(rule.get("evidence") or {}) for rule in triage["rules"]}
    finding_refs = {f["id"]: _entry_refs(f) for f in findings["findings"]}
    ioc_refs = [
        (f"ioc {i.get('type', '?')}: {str(i.get('value', '?'))[:40]}", _entry_refs(i))
        for i in iocs["iocs"]
    ]
    cited_ids = {ref["record_id"] for refs in triage_refs.values() for ref in refs}
    cited_ids.update(ref["record_id"] for refs in finding_refs.values() for ref in refs)
    cited_ids.update(ref["record_id"] for _, refs in ioc_refs for ref in refs)

    levels = manifest["strategy"]["levels_investigated"]
    csv_path = manifest["dataset"]["path"]
    gates = []

    def gate(gate_id, name, ok, detail, gaps=None):
        gates.append({
            "id": gate_id,
            "name": name,
            "status": "PASS" if ok else "FAIL",
            "detail": detail,
            "gaps": gaps or [],
        })

    # G0: dataset integrity. A missing CSV is always a hard failure: the gates
    # (G2 host coverage, G6 RecordID existence) validate against the dataset, so
    # without it no dataset-backed coverage can be certified. report.py surfaces
    # this and lets the user override with "force" if they accept an unverifiable
    # report. verify_hash re-hashes a present CSV to catch in-place modification.
    facts = None
    if not os.path.isfile(csv_path):
        gate("G0", "dataset integrity", False, f"CSV missing: {csv_path}")
    else:
        if verify_hash:
            current = _sha256(csv_path)
            matches = current == manifest["dataset"]["sha256"]
            gate("G0", "dataset integrity", matches,
                 "sha256 matches manifest" if matches else "CSV changed since init (sha256 mismatch)")
        else:
            gate("G0", "dataset integrity", True, "hash verification skipped")
        variant_specs = {
            r["rule_title"]: r["variants"]["fields"]
            for r in triage["rules"]
            if isinstance(r.get("variants"), dict) and r["variants"].get("fields")
        }
        facts = scan_csv(csv_path, cited_ids=cited_ids, variant_specs=variant_specs)

    # G1: rule triage coverage at investigated levels
    gate_rules = [r for r in triage["rules"] if set(r["levels"]) & set(levels)]
    pending = [r["rule_title"] for r in gate_rules if r["status"] == "pending"]
    gate("G1", "rule triage coverage", not pending,
         f"{len(gate_rules) - len(pending)}/{len(gate_rules)} rules at levels {levels} verified",
         pending)

    # G2: host coverage (hosts with events at investigated levels)
    if facts is None:
        gate("G2", "host coverage", True, "skipped (dataset unavailable)")
    elif "Computer" in manifest["dataset"]["columns"]:
        target_hosts = sorted(
            h for h, per_level in facts.hosts.items()
            if any(per_level.get(level) for level in levels)
        )
        covered = {h["name"] for h in hosts["hosts"]}
        missing_hosts = [h for h in target_hosts if h not in covered]
        gate("G2", "host coverage", not missing_hosts,
             f"{len(target_hosts) - len(missing_hosts)}/{len(target_hosts)} hosts with {'/'.join(levels)} events covered",
             missing_hosts)
    else:
        gate("G2", "host coverage", True, "skipped (no Computer column)")

    # G3: every activity cluster (auto-derived + manually added) is judged.
    # Rows whose Timestamp could not be parsed are excluded from clustering; that
    # is surfaced as a persistent, visible warning in the detail (so the appendix
    # never claims completeness it does not have) but is NOT a hard failure:
    # unparsed rows have no timestamp, so no cluster can provably cover them, and
    # a dataset-wide count must not block an otherwise-complete investigation.
    unjudged = [f"{c['id']} ({c['start']} ~ {c['end']})" for c in clusters["clusters"] if c["verdict"] is None]
    ts_total = manifest["dataset"].get("timestamp_total", 0)
    ts_parsed = manifest["dataset"].get("timestamp_parsed", ts_total)
    unparsed = ts_total - ts_parsed
    # Treat a missing/unknown row_count as non-empty: only an explicit 0 means
    # the dataset is genuinely empty. Otherwise an old/hand-edited manifest with
    # no row_count must not turn a zero-cluster dataset into a vacuous PASS.
    row_count = manifest["dataset"].get("row_count")
    dataset_is_empty = (row_count == 0)
    if not clusters["clusters"] and not dataset_is_empty:
        # No clusters at all for a non-empty dataset means temporal coverage was
        # never established (timestamps absent/unparseable). That is a real gap,
        # not a vacuous pass; the remedy is to add the window(s) with cluster --add.
        reason = ("Timestamps could not be parsed" if unparsed > 0
                  else "no usable Timestamp values")
        gate("G3", "activity cluster coverage", False,
             f"no activity clusters derived ({reason}); temporal coverage not established "
             "— add the window(s) with 'cluster --add' after checking the timestamp format",
             [f"0 clusters for {row_count if row_count is not None else 'unknown'} rows"])
    else:
        detail = f"{len(clusters['clusters']) - len(unjudged)}/{len(clusters['clusters'])} clusters judged"
        if unparsed > 0:
            detail += f"; WARNING: {unparsed}/{ts_total} rows have unparseable Timestamps, excluded from clusters"
        gate("G3", "activity cluster coverage", not unjudged, detail, unjudged)

    # G4: every attack- or mixed-verdict rule is referenced by at least one
    # finding (a mixed rule contains confirmed attack events, so it needs a
    # finding for its attack part just like a pure attack rule).
    attack_rules = {r["rule_title"] for r in triage["rules"] if r["verdict"] in ("attack", "mixed")}
    referenced = set()
    for finding in findings["findings"]:
        referenced.update(finding.get("rule_titles") or [])
    unreferenced = sorted(attack_rules - referenced)
    gate("G4", "attack rules linked to findings", not unreferenced,
         f"{len(attack_rules) - len(unreferenced)}/{len(attack_rules)} attack/mixed-verdict rules referenced by findings",
         unreferenced)

    # G5: no silently truncated tool results. See _unresolved_truncations for
    # how has_more entries are resolved (by an explicit accept, or a later entry
    # with the SAME query_hash that cleared has_more). A corrupt/truncated log
    # line is surfaced as a warning in the detail but does not block the gate
    # (its content is unknown, so failing forever on it is worse than noting it).
    unresolved = _unresolved_truncations(queries)
    gaps = [f"{q.get('tool', '?')} ({q.get('query_hash') or 'no hash'})" for q in unresolved]
    # An empty log is a PASS (logging is only required for truncations), but say
    # so honestly: "all logged queries ..." over zero entries would overstate
    # what was actually verified.
    if not queries:
        detail = "no queries logged (G5 only checks self-reported truncations)"
    elif not gaps:
        detail = "all logged queries fully paginated or explicitly truncated"
    else:
        detail = f"{len(unresolved)} unresolved has_more quer(ies)"
    if corrupt_query_lines:
        detail += f" (warning: {corrupt_query_lines} unparseable line(s) in queries.jsonl ignored)"
    gate("G5", "no unresolved pagination", not gaps, detail, gaps)

    # G6: every cited evidence ref resolves to exactly one event in the
    # dataset, that event was actually detected by the rule citing it, and a
    # recorded detail excerpt is a verbatim quote of the cited row. Enforced
    # whenever the RecordID column exists, so fabricated or ambiguous citations
    # are caught instead of vacuously passing (RecordIDs are NOT globally
    # unique: the same value can denote different events on different hosts).
    finding_evidence_computers: dict[str, set] = {}
    if facts is None:
        gate("G6", "evidence refs resolve in dataset", True, "skipped (dataset unavailable)")
    elif "RecordID" in manifest["dataset"]["columns"]:
        g6_gaps: list[str] = []
        total_refs = 0

        def check_ref(owner: str, ref: dict, rule_titles=None):
            nonlocal total_refs
            total_refs += 1
            rows, gap = _resolve_ref(facts, ref, rule_titles)
            if gap is None:
                return rows
            if ref["record_id"] in facts.cited_rows_truncated:
                # The row cap was hit for this RecordID, so a failed lookup may
                # be a cap artifact: skip (surfaced as a warning in the detail).
                return None
            g6_gaps.append(f"{owner}: {gap}")
            return None

        for rule in triage["rules"]:
            refs = triage_refs[rule["rule_title"]]
            if not refs:
                continue  # missing evidence is G7's finding, not G6's
            resolved_rows: list[dict] = []
            for ref in refs:
                rows = check_ref(f"rule {rule['rule_title']}", ref, rule["rule_title"])
                if rows:
                    resolved_rows.extend(rows)
            excerpt = " ".join((rule["evidence"].get("detail_excerpt") or "").split())
            if excerpt and resolved_rows:
                if not any(excerpt in " ".join(r["detail"].split()) for r in resolved_rows):
                    g6_gaps.append(
                        f"rule {rule['rule_title']}: detail_excerpt is not a verbatim"
                        " substring of any cited event's detail field — quote the"
                        " Details/AllFieldInfo content exactly (no paraphrase, no ellipsis)"
                    )

        for finding in findings["findings"]:
            computers: set = set()
            want_rules = set(finding.get("rule_titles") or []) or None
            for ref in finding_refs[finding["id"]]:
                rows = check_ref(f"finding {finding['id']} ({finding['title']})", ref, want_rules)
                if rows:
                    computers.update(r["computer"] for r in rows if r["computer"])
            finding_evidence_computers[finding["id"]] = computers

        for owner, refs in ioc_refs:
            for ref in refs:
                check_ref(owner, ref)

        detail = f"{total_refs} evidence ref(s) checked, {len(g6_gaps)} problem(s)"
        if facts.cited_rows_truncated:
            detail += (
                f" (warning: row cap hit for {len(facts.cited_rows_truncated)}"
                " RecordID(s); their failed lookups were skipped)"
            )
        gate("G6", "evidence refs resolve in dataset", not g6_gaps, detail, g6_gaps[:50])
    else:
        gate("G6", "evidence refs resolve in dataset", True, "skipped (no RecordID column)")

    # G7: every recorded verdict — attack, false_positive AND indeterminate —
    # and every finding cites at least one evidence ref, and a false_positive
    # verdict carries a verbatim detail excerpt. Complements G6 (cited refs
    # resolve): G6 alone passes vacuously when nothing is cited at all, which
    # would let mass exclusions ship with no auditable row-level evidence.
    # Only enforced when the dataset has a RecordID column (checked from the
    # manifest, so this works even when the CSV itself is unavailable).
    if "RecordID" in manifest["dataset"]["columns"]:
        dataset_columns = manifest["dataset"]["columns"]
        has_detail_col = ("Details" in dataset_columns) or ("AllFieldInfo" in dataset_columns)
        judged_rules = [r for r in triage["rules"] if r["verdict"]]
        no_evidence = []
        for r in judged_rules:
            reasons = []
            if not triage_refs[r["rule_title"]]:
                reasons.append("no refs")
            if (r["verdict"] == "false_positive" and has_detail_col
                    and not (r["evidence"].get("detail_excerpt") or "").strip()):
                reasons.append("false_positive without verbatim excerpt")
            if reasons:
                no_evidence.append(f"rule: {r['rule_title']} ({r['verdict']}: {', '.join(reasons)})")
        no_evidence += [
            f"finding: {f['id']} ({f['title']})" for f in findings["findings"]
            if not finding_refs[f["id"]]
        ]
        total = len(judged_rules) + len(findings["findings"])
        gate("G7", "verdicts cite row-level evidence", not no_evidence,
             f"{total - len(no_evidence)}/{total} verdicts and findings cite evidence refs",
             no_evidence)
    else:
        gate("G7", "verdicts cite row-level evidence", True, "skipped (no RecordID column)")

    # G8: every rule cited by a finding has a triage verdict, regardless of
    # level, and that verdict is compatible with being attack evidence: a
    # false_positive rule can never back a finding (re-triage it or drop the
    # citation). Indeterminate rules may be cited as supporting context and are
    # surfaced in the detail, not failed.
    triage_by_title = {r["rule_title"]: r for r in triage["rules"]}
    cited_pending = set()
    cited_unknown = set()
    cited_fp = set()
    cited_indeterminate = set()
    cited_total = set()
    for finding in findings["findings"]:
        for cited in finding.get("rule_titles") or []:
            cited_total.add(cited)
            rule = triage_by_title.get(cited)
            if rule is None:
                cited_unknown.add(f"{cited} (not a rule title seeded from the CSV)")
            elif rule["status"] == "pending":
                cited_pending.add(cited)
            elif rule["verdict"] == "false_positive":
                cited_fp.add(
                    f"{cited} (false_positive verdict cannot back a finding —"
                    " re-triage the rule or drop the citation)"
                )
            elif rule["verdict"] == "indeterminate":
                cited_indeterminate.add(cited)
    g8_gaps = sorted(cited_pending) + sorted(cited_unknown) + sorted(cited_fp)
    g8_detail = (
        f"{len(cited_total) - len(g8_gaps)}/{len(cited_total)} rules cited by findings"
        " have a compatible triage verdict"
    )
    if cited_indeterminate:
        g8_detail += (
            f" (note: {len(cited_indeterminate)} indeterminate rule(s) cited —"
            " allowed as supporting context only)"
        )
    gate("G8", "finding-cited rules triaged", not g8_gaps, g8_detail, g8_gaps)

    # G9: every host a finding names is backed by at least one cited event on
    # that host. Prevents narrative host attribution the evidence rows do not
    # support (e.g. citing HOST-A events for a claim about HOST-B). Uses the
    # per-finding computers resolved in G6.
    if facts is None:
        gate("G9", "finding hosts backed by evidence", True, "skipped (dataset unavailable)")
    elif "RecordID" in manifest["dataset"]["columns"] and "Computer" in manifest["dataset"]["columns"]:
        g9_gaps = []
        total_host_claims = 0
        for finding in findings["findings"]:
            evidence_computers = finding_evidence_computers.get(finding["id"], set())
            for host in (finding.get("hosts") or []):
                if not str(host).strip():
                    continue
                total_host_claims += 1
                if host not in evidence_computers:
                    g9_gaps.append(
                        f"finding {finding['id']} ({finding['title']}): host {host} is not"
                        " backed by any cited event — add a ref to an event on that host"
                    )
        gate("G9", "finding hosts backed by evidence", not g9_gaps,
             f"{total_host_claims - len(g9_gaps)}/{total_host_claims} finding-host claims backed by cited events",
             g9_gaps)
    else:
        gate("G9", "finding hosts backed by evidence", True, "skipped (no RecordID/Computer column)")

    # G10: a false_positive/mixed verdict over a high-volume rule must carry
    # complete behavior-variant evidence, and the declared variants are
    # recounted against the CSV: every declared group's count must match the
    # dataset, no dataset variant may be left unjudged, and empty-detail
    # variants can never be benign. This makes "sampled 2 events, excluded
    # 39,582" structurally impossible.
    g10_gaps: list[str] = []
    recounted = 0
    for r in triage["rules"]:
        verdict = r["verdict"]
        if verdict not in ("false_positive", "mixed"):
            continue
        variants = r.get("variants")
        title = r["rule_title"]
        if not variants:
            if r["count"] > VARIANT_EVIDENCE_THRESHOLD:
                g10_gaps.append(
                    f"rule {title}: {verdict} over {r['count']} events without variant"
                    " evidence — enumerate and judge every behavior variant (GROUP BY)"
                )
            continue
        groups = variants.get("groups") or []
        fields = variants.get("fields") or []
        attack_groups = sum(1 for g in groups if g.get("verdict") == "attack")
        if verdict == "false_positive" and attack_groups:
            g10_gaps.append(f"rule {title}: false_positive but variants contain attack group(s) — use 'mixed'")
        if verdict == "mixed" and not attack_groups:
            g10_gaps.append(f"rule {title}: mixed but no variant group is judged 'attack'")
        for g in groups:
            if (g.get("verdict") == "benign"
                    and all(str(v or "").strip() == "" for v in (g.get("key") or {}).values())):
                g10_gaps.append(
                    f"rule {title}: empty-detail variant judged benign — nothing to base"
                    " benignity on; judge it indeterminate"
                )
        if facts is None:
            continue
        recounted += 1
        if title in facts.variant_overflow:
            g10_gaps.append(
                f"rule {title}: more than {VARIANT_GROUPS_CAP} distinct variants for"
                f" fields {fields} — choose more stable grouping fields"
            )
            continue
        actual = facts.variant_counts.get(title, {})
        declared: dict[tuple, int] = {}
        for g in groups:
            key = tuple(str((g.get("key") or {}).get(f, "") or "").strip() for f in fields)
            declared[key] = declared.get(key, 0) + int(g.get("count") or 0)
        for key in sorted(declared):
            actual_count = actual.get(key)
            label = ", ".join(f"{f}={v!r}" for f, v in zip(fields, key))
            if actual_count is None:
                g10_gaps.append(f"rule {title}: declared variant ({label}) does not exist in the dataset")
            elif actual_count != declared[key]:
                g10_gaps.append(
                    f"rule {title}: variant ({label}) declared {declared[key]} events"
                    f" but the dataset has {actual_count}"
                )
        for key in sorted(set(actual) - set(declared)):
            label = ", ".join(f"{f}={v!r}" for f, v in zip(fields, key))
            g10_gaps.append(
                f"rule {title}: dataset variant ({label}, {actual[key]} events) is not"
                " judged — every variant needs a verdict"
            )
    g10_detail = f"{recounted} rule(s) with variant evidence recounted against the dataset"
    if facts is None:
        g10_detail = "structural checks only (dataset unavailable)"
    gate("G10", "variant coverage for high-volume verdicts", not g10_gaps, g10_detail, g10_gaps[:50])

    return {
        "ok": all(g["status"] == "PASS" for g in gates),
        "checked_at": _now(),
        "levels_investigated": levels,
        "gates": gates,
    }


def _unresolved_truncations(queries: list[dict]) -> list[dict]:
    """
    Return log entries that record a truncation still open at report time.

    An entry with has_more=true is a gap unless it is resolved:
      - accepted_truncation=true on that entry marks a deliberate, justified cap; or
      - a LATER entry with the SAME non-empty query_hash cleared it (has_more=false
        or accepted_truncation=true) — this is the "paginate fully, then re-log the
        same query_hash" workflow.
    A hashless has_more entry can only be resolved by its own accepted_truncation
    flag: without a query_hash there is no reliable way to correlate a follow-up,
    so an unrelated later hashless entry must NOT silently clear it.
    """
    # Latest state per non-empty query_hash (hash identifies the query).
    latest_by_hash: dict[str, dict] = {}
    for entry in queries:
        h = entry.get("query_hash")
        if h:
            latest_by_hash[h] = entry

    unresolved: list[dict] = []
    for entry in queries:
        if not entry.get("has_more"):
            continue
        if entry.get("accepted_truncation"):
            continue
        h = entry.get("query_hash")
        if h:
            final = latest_by_hash.get(h, entry)
            if final.get("has_more") and not final.get("accepted_truncation"):
                # Report each open hash once (dedupe by hash).
                if entry is final:
                    unresolved.append(entry)
        else:
            # Hashless has_more with no accept flag is always unresolved.
            unresolved.append(entry)
    return unresolved


def _print_check(result: dict) -> None:
    for g in result["gates"]:
        print(f"[{g['status']}] {g['id']} {g['name']}: {g['detail']}")
        for gap in g["gaps"][:20]:
            print(f"        - {gap}")
        if len(g["gaps"]) > 20:
            print(f"        ... and {len(g['gaps']) - 20} more")
    print(f"OVERALL: {'PASS' if result['ok'] else 'FAIL'}")


def cmd_check(args) -> None:
    result = run_check(args.dir, verify_hash=not args.no_hash)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_check(result)
    sys.exit(0 if result["ok"] else 1)


def cmd_status(args) -> None:
    manifest = _load(args.dir, MANIFEST)
    triage = _load(args.dir, RULE_TRIAGE)
    clusters = _load(args.dir, CLUSTERS)
    findings = _load(args.dir, FINDINGS)
    iocs = _load(args.dir, IOCS)
    hosts = _load(args.dir, HOSTS)

    levels = manifest["strategy"]["levels_investigated"]
    gate_rules = [r for r in triage["rules"] if set(r["levels"]) & set(levels)]
    pending = [r for r in gate_rules if r["status"] == "pending"]
    unjudged_clusters = [c for c in clusters["clusters"] if c["verdict"] is None]

    print(f"Investigation state: {os.path.abspath(args.dir)}")
    print(f"  dataset: {manifest['dataset']['path']}")
    print(f"  detail_source: {manifest['dataset']['detail_source']}  levels: {levels}")
    print(f"  hypothesis: {manifest['strategy']['hypothesis'] or '(not set)'}")
    print(f"  rule triage: {len(gate_rules) - len(pending)}/{len(gate_rules)} verified at investigated levels")
    for rule in pending[:10]:
        print(f"    pending: {rule['rule_title']} ({rule['count']} events)")
    if len(pending) > 10:
        print(f"    ... and {len(pending) - 10} more pending")
    print(f"  clusters: {len(clusters['clusters']) - len(unjudged_clusters)}/{len(clusters['clusters'])} judged")
    for c in unjudged_clusters[:5]:
        print(f"    unjudged: {c['id']} {c['start']} ~ {c['end']}")
    print(f"  findings: {len(findings['findings'])}  iocs: {len(iocs['iocs'])}  hosts covered: {len(hosts['hosts'])}")
    print("Next: verify pending rules (state.py triage), judge clusters (state.py cluster),")
    print("      then run 'state.py check' before generating the report.")


APPENDIX_LABELS = {
    "en": {
        "title": "## Appendix: Coverage & Reproducibility",
        "intro": "This appendix is generated automatically from the machine-readable investigation state.",
        "dataset": "Dataset",
        "gate": "Coverage gate",
        "result": "Result",
        "detail": "Detail",
        "triage_summary": "Rule triage summary",
        "verdict_attack": "attack",
        "verdict_fp": "false positive",
        "verdict_ind": "indeterminate",
        "verdict_mixed": "mixed",
        "pending_breakdown": "{in_scope} at investigated levels / {out_scope} at out-of-scope levels",
        "unresolved": "Unresolved coverage gaps",
        "state_files": "Machine-readable state files",
        "environment": "Environment profile",
        "env_none": "none available (explicitly declared by the operator)",
        "env_missing": "not recorded",
    },
    "ja": {
        "title": "## 付録: カバレッジと再現性",
        "intro": "この付録は機械可読な調査ステートから自動生成されています。",
        "dataset": "データセット",
        "gate": "カバレッジゲート",
        "result": "結果",
        "detail": "詳細",
        "triage_summary": "ルールトリアージ集計",
        "verdict_attack": "攻撃",
        "verdict_fp": "偽陽性",
        "verdict_ind": "判定不能",
        "verdict_mixed": "混在",
        "pending_breakdown": "調査対象レベル: {in_scope} / 対象外レベル: {out_scope}",
        "unresolved": "未解決のカバレッジギャップ",
        "state_files": "機械可読ステートファイル",
        "environment": "環境プロファイル",
        "env_none": "情報なし（オペレーターが明示的に申告）",
        "env_missing": "未記録",
    },
}


def appendix_markdown(state_dir: str, lang: str = "en", result: dict | None = None) -> str:
    labels = APPENDIX_LABELS.get(lang, APPENDIX_LABELS["en"])
    manifest = _load(state_dir, MANIFEST)
    triage = _load(state_dir, RULE_TRIAGE)
    if result is None:
        result = run_check(state_dir, verify_hash=False)

    # Read manifest fields defensively: an older-schema or hand-edited manifest
    # may omit some, and the appendix must render rather than crash.
    dataset = manifest.get("dataset", {}) if isinstance(manifest, dict) else {}
    ds_path = dataset.get("path") or "(unknown)"
    ds_sha = dataset.get("sha256") or ""
    sha_disp = (ds_sha[:16] + "...") if ds_sha else "(unknown)"
    ds_rows = dataset.get("row_count", "?")
    ds_detail = dataset.get("detail_source", "?")
    verdicts = {"attack": 0, "false_positive": 0, "indeterminate": 0, "mixed": 0, "pending": 0}
    # Split pending by scope: rules at out-of-scope levels legitimately stay
    # pending under G1, so a bare "pending: N" right next to "G1 PASS" reads as
    # a contradiction unless the breakdown is shown.
    gate_levels = set((manifest.get("strategy", {}) or {}).get("levels_investigated") or [])
    pending_in_scope = 0
    pending_out_scope = 0
    for rule in triage["rules"]:
        key = rule["verdict"] if rule["verdict"] in verdicts else "pending"
        verdicts[key] += 1
        if key == "pending":
            if set(rule.get("levels", {})) & gate_levels:
                pending_in_scope += 1
            else:
                pending_out_scope += 1
    pending_note = ""
    if verdicts["pending"]:
        pending_note = " (" + labels["pending_breakdown"].format(
            in_scope=pending_in_scope, out_scope=pending_out_scope) + ")"

    lines = [
        labels["title"],
        "",
        labels["intro"],
        "",
        f"- **{labels['dataset']}**: `{os.path.basename(ds_path)}` "
        f"(sha256: `{sha_disp}`, {ds_rows} rows, "
        f"detail_source: {ds_detail})",
        f"- **{labels['triage_summary']}**: "
        f"{labels['verdict_attack']}: {verdicts['attack']} / "
        f"{labels['verdict_fp']}: {verdicts['false_positive']} / "
        f"{labels['verdict_mixed']}: {verdicts['mixed']} / "
        f"{labels['verdict_ind']}: {verdicts['indeterminate']} / "
        f"pending: {verdicts['pending']}{pending_note}",
        "",
        f"| {labels['gate']} | {labels['result']} | {labels['detail']} |",
        "|---|---|---|",
    ]
    for g in result["gates"]:
        lines.append(f"| {g['id']} {g['name']} | {g['status']} | {g['detail']} |")

    failing = [g for g in result["gates"] if g["status"] == "FAIL"]
    if failing:
        lines += ["", f"### {labels['unresolved']}", ""]
        for g in failing:
            for gap in g["gaps"][:10]:
                lines.append(f"- {g['id']}: {gap}")

    env = _load_optional(state_dir, ENVIRONMENT, None)
    if env is None or not isinstance(env, dict):
        env_line = labels["env_missing"]
    elif env.get("entries"):
        entries = env["entries"]
        parts = [f"{e.get('value')} ({e.get('status')})" for e in entries[:10]]
        env_line = "; ".join(parts) + (" ..." if len(entries) > 10 else "")
    elif env.get("declared_no_info"):
        env_line = labels["env_none"]
    else:
        env_line = labels["env_missing"]
    lines += ["", f"- **{labels['environment']}**: {env_line}"]

    lines += [
        "",
        f"- **{labels['state_files']}**: `manifest.json`, `rule_triage.json`, `clusters.json`, "
        "`findings.json`, `iocs.json`, `hosts.json`, `environment.json`, `queries.jsonl`",
    ]
    return "\n".join(lines)


def cmd_appendix(args) -> None:
    print(appendix_markdown(args.dir, lang=args.lang))


# ---------- argument parsing ----------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hayabusa investigation state manager")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create and seed the state directory from a CSV")
    p.add_argument("--csv", required=True)
    p.add_argument("--dir", required=True)
    p.add_argument("--levels", help="comma-separated levels to investigate (default: auto)")
    p.add_argument("--hypothesis", default="")
    p.add_argument("--interval", default="")
    p.add_argument("--model", default="")
    p.add_argument("--skill", default="investigate")
    p.add_argument("--cluster-gap-days", type=int, default=DEFAULT_CLUSTER_GAP_DAYS)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("strategy", help="update hypothesis / interval / investigated levels")
    p.add_argument("--dir", required=True)
    p.add_argument("--hypothesis")
    p.add_argument("--interval")
    p.add_argument("--levels")
    p.set_defaults(func=cmd_strategy)

    p = sub.add_parser("triage", help="record a rule verdict (or --batch)")
    p.add_argument("--dir", required=True)
    p.add_argument("--batch", action="store_true", help="read a JSON array of entries from stdin")
    p.add_argument("--rule")
    p.add_argument("--verdict", choices=TRIAGE_VERDICTS)
    p.add_argument("--rationale", default="")
    p.add_argument("--record-ids", default="",
                   help='comma-separated evidence refs: "RID", "RID@Computer" or'
                        ' "RID@Computer@Channel" (qualify duplicated RecordIDs)')
    p.add_argument("--excerpt", default="",
                   help="verbatim quote of the cited event's detail field"
                        " (required for false_positive; verified by gate G6)")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("finding", help="record an attack finding (or --batch)")
    p.add_argument("--dir", required=True)
    p.add_argument("--batch", action="store_true")
    p.add_argument("--title", default="")
    p.add_argument("--phase", default="")
    p.add_argument("--hosts", default="")
    p.add_argument("--rules", default="", help="comma-separated related rule titles")
    p.add_argument("--record-ids", default="",
                   help='comma-separated evidence refs: "RID", "RID@Computer" or'
                        ' "RID@Computer@Channel" (qualify duplicated RecordIDs)')
    p.add_argument("--summary", default="")
    p.add_argument("--query", default="")
    p.set_defaults(func=cmd_finding)

    p = sub.add_parser("ioc", help="record an IOC (or --batch)")
    p.add_argument("--dir", required=True)
    p.add_argument("--batch", action="store_true")
    p.add_argument("--type", default="")
    p.add_argument("--value", default="")
    p.add_argument("--hosts", default="")
    p.add_argument("--context", default="")
    p.add_argument("--record-ids", default="")
    p.set_defaults(func=cmd_ioc)

    p = sub.add_parser("host", help="record host investigation coverage (or --batch)")
    p.add_argument("--dir", required=True)
    p.add_argument("--batch", action="store_true")
    p.add_argument("--name")
    p.add_argument("--status", choices=HOST_STATUSES, default="investigated")
    # default None so omitting --note on a re-record preserves the existing note
    p.add_argument("--note", default=None)
    p.set_defaults(func=cmd_host)

    p = sub.add_parser("cluster", help="judge an activity cluster (--id) or add one (--add)")
    p.add_argument("--dir", required=True)
    p.add_argument("--id", help="id of an existing cluster to judge")
    p.add_argument("--add", action="store_true", help="add a manual cluster (requires --start/--end)")
    p.add_argument("--start", help="cluster start date YYYY-MM-DD (with --add)")
    p.add_argument("--end", help="cluster end date YYYY-MM-DD (with --add)")
    p.add_argument("--verdict", choices=CLUSTER_VERDICTS)
    # default None so omitting --note on a re-judge preserves the existing note
    p.add_argument("--note", default=None)
    p.set_defaults(func=cmd_cluster)

    p = sub.add_parser("env", help="record environment facts with provenance (or --none / --list)")
    p.add_argument("--dir", required=True)
    p.add_argument("--value", default="", help="the fact, e.g. 'Veeam Backup is deployed on all servers'")
    p.add_argument("--category", default="", help="edr / backup / monitoring / config-mgmt / account / maintenance / other")
    p.add_argument("--status", default="", help="provenance: operator_confirmed | observed | inferred")
    p.add_argument("--source", default="", help="origin (user statement, CMDB id, log observation)")
    p.add_argument("--note", default="")
    p.add_argument("--none", action="store_true", help="declare that no environment information is available")
    p.add_argument("--list", action="store_true", help="print recorded entries")
    p.set_defaults(func=cmd_env)

    p = sub.add_parser("log-query", help="append a query audit entry")
    p.add_argument("--dir", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--query-hash", default="")
    p.add_argument("--dataset-version", default="")
    p.add_argument("--has-more", action="store_true")
    p.add_argument("--accept-truncation", action="store_true",
                   help="mark deliberate truncation as acceptable (documented cap)")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_log_query)

    p = sub.add_parser("status", help="progress summary (use to resume)")
    p.add_argument("--dir", required=True)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("check", help="run coverage gates (exit 0=PASS, 1=FAIL)")
    p.add_argument("--dir", required=True)
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-hash", action="store_true", help="skip sha256 verification")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("appendix", help="print the coverage appendix markdown")
    p.add_argument("--dir", required=True)
    p.add_argument("--lang", choices=("en", "ja"), default="en")
    p.set_defaults(func=cmd_appendix)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
