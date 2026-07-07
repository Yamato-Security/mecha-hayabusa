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
  findings.json     confirmed attack findings with evidence RecordIDs
  iocs.json         extracted IOCs with source RecordIDs
  hosts.json        per-host investigation coverage
  queries.jsonl     audit log of executed queries (query_hash, has_more)

Commands (all stdlib, no external dependencies):
  init      create the state directory and seed it from the CSV
  strategy  record the investigation hypothesis / levels / interval
  triage    record a verdict for one rule (or --batch from stdin)
  finding   record an attack finding (or --batch from stdin)
  ioc       record an IOC (or --batch from stdin)
  host      record host investigation coverage (or --batch from stdin)
  cluster   record a verdict for an activity cluster
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
TRIAGE_VERDICTS = ("attack", "false_positive", "indeterminate")
CLUSTER_VERDICTS = ("attack", "benign", "indeterminate")
HOST_STATUSES = ("investigated", "reviewed", "not_applicable")
DEFAULT_CLUSTER_GAP_DAYS = 7

MANIFEST = "manifest.json"
RULE_TRIAGE = "rule_triage.json"
CLUSTERS = "clusters.json"
FINDINGS = "findings.json"
IOCS = "iocs.json"
HOSTS = "hosts.json"
QUERIES = "queries.jsonl"

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
    # Last resort: ISO-8601 via fromisoformat. Normalize 'Z' and trim
    # >6 fractional digits (Hayabusa -O emits 7) for Python 3.9 compatibility.
    normalized = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
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


def scan_csv(csv_path: str) -> DatasetFacts:
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
            if title:
                facts.rules.setdefault(title, {}).setdefault(level, 0)
                facts.rules[title][level] += 1
            if host:
                facts.hosts.setdefault(host, {}).setdefault(level, 0)
                facts.hosts[host][level] += 1
            if record_id:
                facts.record_ids.add(record_id)
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
            "evidence": {"record_ids": [], "detail_excerpt": ""},
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
            " no activity clusters were derived. Check the timestamp format; if a wave is"
            " known, add it manually with 'state.py cluster --add --start ... --end ...'."
            " (This is reported as a warning in gate G3, not a hard failure.)"
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
        fresh = derive_clusters(facts, new_levels, clusters.get("gap_days", DEFAULT_CLUSTER_GAP_DAYS))
        clusters["clusters"] = fresh + manual
        rederived_clusters = (clusters, len(fresh), len(manual))

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
        clusters, n_fresh, n_manual = rederived_clusters
        _save(args.dir, CLUSTERS, clusters)
    _save(args.dir, MANIFEST, manifest)
    if rederived_clusters is not None:
        msg = f"re-derived {n_fresh} activity clusters (unjudged) for levels {new_levels}"
        if n_manual:
            msg += f" (kept {n_manual} manual cluster(s))"
        print(msg)
    print(f"strategy updated: {json.dumps(strategy, ensure_ascii=False)}")


def _apply_triage(state_dir: str, entries: list[dict]) -> None:
    # Validate the state dir BEFORE mutating: against a half-initialized dir
    # (no manifest) this refuses without writing, so re-running init can safely
    # recover instead of silently overwriting analyst-entered verdicts.
    manifest = _require_initialized(state_dir)
    gate_levels = set(manifest["strategy"]["levels_investigated"])
    has_record_id_col = "RecordID" in manifest["dataset"].get("columns", [])
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
        record_ids = entry.get("record_ids")
        if isinstance(record_ids, str):
            record_ids = _split_arg(record_ids)
        record_ids = [str(r) for r in (record_ids or [])]
        if verdict == "attack" and has_record_id_col and not record_ids:
            _fail(
                f"record_ids is required for an 'attack' verdict on {title!r}: cite the"
                " RecordID(s) of the event(s) you actually verified (gate G7). An attack"
                " claim with no row-level evidence is not auditable."
            )
        rule = by_title[title]
        rule["status"] = "verified"
        rule["verdict"] = verdict
        rule["rationale"] = rationale
        rule["evidence"]["record_ids"] = record_ids
        rule["evidence"]["detail_excerpt"] = (entry.get("excerpt") or "")[:2000]
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
    """Accept a comma string or a list; return a list of string RecordIDs."""
    if isinstance(value, str):
        value = _split_arg(value)
    return [str(item) for item in (value or [])]


def _normalize_hosts(value) -> list[str]:
    """Accept a comma string or a list; return a list of host names."""
    if isinstance(value, str):
        return _split_arg(value)
    return list(value or [])


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
        record_ids = _normalize_record_ids(entry.get("record_ids"))
        if has_record_id_col and not record_ids:
            _fail(
                f"finding {title!r} requires record_ids: cite the RecordID(s) of the"
                " supporting event(s) (gate G7), so every report claim can be traced"
                " back to the data."
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
            "record_ids": record_ids,
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
        iocs["iocs"].append({
            "type": ioc_type,
            "value": value,
            "hosts": _normalize_hosts(entry.get("hosts")),
            "context": (entry.get("context") or "").strip(),
            "record_ids": _normalize_record_ids(entry.get("record_ids")),
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
        existing = {c["id"] for c in clusters["clusters"]}
        n = 1
        while f"m{n}" in existing:
            n += 1
        new_id = f"m{n}"
        clusters["clusters"].append({
            "id": new_id,
            "start": args.start,
            "end": args.end,
            "verdict": args.verdict,
            "note": args.note or "",
            "manual": True,
        })
        _save(args.dir, CLUSTERS, clusters)
        verdict_label = args.verdict or "(unjudged)"
        print(f"added cluster {new_id} ({args.start} ~ {args.end}) -> {verdict_label}")
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
    target["note"] = args.note or ""
    _save(args.dir, CLUSTERS, clusters)
    print(f"cluster {args.id} ({target['start']} ~ {target['end']}) -> {args.verdict}")


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
    except (FileNotFoundError, OSError):
        pass
    return entries, corrupt


# ---------- check / status / appendix ----------

def run_check(state_dir: str, verify_hash: bool = True) -> dict:
    manifest = _load(state_dir, MANIFEST)
    triage = _load(state_dir, RULE_TRIAGE)
    clusters = _load(state_dir, CLUSTERS)
    findings = _load(state_dir, FINDINGS)
    iocs = _load(state_dir, IOCS)
    hosts = _load(state_dir, HOSTS)
    queries, corrupt_query_lines = _load_queries(state_dir)

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
        facts = scan_csv(csv_path)

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

    # G4: every attack-verdict rule is referenced by at least one finding
    attack_rules = {r["rule_title"] for r in triage["rules"] if r["verdict"] == "attack"}
    referenced = set()
    for finding in findings["findings"]:
        referenced.update(finding.get("rule_titles") or [])
    unreferenced = sorted(attack_rules - referenced)
    gate("G4", "attack rules linked to findings", not unreferenced,
         f"{len(attack_rules) - len(unreferenced)}/{len(attack_rules)} attack-verdict rules referenced by findings",
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

    # G6: cited RecordIDs exist in the dataset. Enforced whenever the RecordID
    # column exists (even if every value is empty), so fabricated citations are
    # caught instead of vacuously passing.
    if facts is None:
        gate("G6", "evidence RecordIDs exist", True, "skipped (dataset unavailable)")
    elif "RecordID" in manifest["dataset"]["columns"]:
        cited = set()
        for rule in triage["rules"]:
            cited.update(rule["evidence"].get("record_ids") or [])
        for finding in findings["findings"]:
            cited.update(finding.get("record_ids") or [])
        for ioc in iocs["iocs"]:
            cited.update(ioc.get("record_ids") or [])
        unknown = sorted(cited - facts.record_ids)
        gate("G6", "evidence RecordIDs exist", not unknown,
             f"{len(cited) - len(unknown)}/{len(cited)} cited RecordIDs found in dataset",
             unknown[:50])
    else:
        gate("G6", "evidence RecordIDs exist", True, "skipped (no RecordID column)")

    # G7: attack-verdict rules and findings must cite at least one RecordID.
    # Complements G6 (cited IDs exist in the dataset): G6 alone passes vacuously
    # when nothing is cited at all, which would let an entire attack narrative
    # ship with no row-level evidence. Only enforced when the dataset has a
    # RecordID column (checked from the manifest, so this works even when the
    # CSV itself is unavailable).
    if "RecordID" in manifest["dataset"]["columns"]:
        attack_rules_all = [r for r in triage["rules"] if r["verdict"] == "attack"]
        no_evidence = [
            f"rule: {r['rule_title']}" for r in attack_rules_all
            if not r["evidence"].get("record_ids")
        ]
        no_evidence += [
            f"finding: {f['id']} ({f['title']})" for f in findings["findings"]
            if not f.get("record_ids")
        ]
        total = len(attack_rules_all) + len(findings["findings"])
        gate("G7", "attack evidence cites RecordIDs", not no_evidence,
             f"{total - len(no_evidence)}/{total} attack-verdict rules and findings cite RecordIDs",
             no_evidence)
    else:
        gate("G7", "attack evidence cites RecordIDs", True, "skipped (no RecordID column)")

    # G8: every rule cited by a finding has a triage verdict, regardless of
    # level. Findings routinely cite info/low rules as supporting evidence
    # (logons, ticket requests, auth failures); those sit outside G1's scope
    # but must not enter the report narrative without the detail-field check.
    triage_by_title = {r["rule_title"]: r for r in triage["rules"]}
    cited_pending = set()
    cited_unknown = set()
    cited_total = set()
    for finding in findings["findings"]:
        for cited in finding.get("rule_titles") or []:
            cited_total.add(cited)
            rule = triage_by_title.get(cited)
            if rule is None:
                cited_unknown.add(f"{cited} (not a rule title seeded from the CSV)")
            elif rule["status"] == "pending":
                cited_pending.add(cited)
    g8_gaps = sorted(cited_pending) + sorted(cited_unknown)
    gate("G8", "finding-cited rules triaged", not g8_gaps,
         f"{len(cited_total) - len(g8_gaps)}/{len(cited_total)} rules cited by findings have a triage verdict",
         g8_gaps)

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
        "pending_breakdown": "{in_scope} at investigated levels / {out_scope} at out-of-scope levels",
        "unresolved": "Unresolved coverage gaps",
        "state_files": "Machine-readable state files",
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
        "pending_breakdown": "調査対象レベル: {in_scope} / 対象外レベル: {out_scope}",
        "unresolved": "未解決のカバレッジギャップ",
        "state_files": "機械可読ステートファイル",
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
    verdicts = {"attack": 0, "false_positive": 0, "indeterminate": 0, "pending": 0}
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

    lines += [
        "",
        f"- **{labels['state_files']}**: `manifest.json`, `rule_triage.json`, `clusters.json`, "
        "`findings.json`, `iocs.json`, `hosts.json`, `queries.jsonl`",
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
    p.add_argument("--record-ids", default="")
    p.add_argument("--excerpt", default="")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("finding", help="record an attack finding (or --batch)")
    p.add_argument("--dir", required=True)
    p.add_argument("--batch", action="store_true")
    p.add_argument("--title", default="")
    p.add_argument("--phase", default="")
    p.add_argument("--hosts", default="")
    p.add_argument("--rules", default="", help="comma-separated related rule titles")
    p.add_argument("--record-ids", default="")
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
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_cluster)

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
