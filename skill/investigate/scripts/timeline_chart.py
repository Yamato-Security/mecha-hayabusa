#!/usr/bin/env python3
"""
Hayabusa incident timeline visualization - Interactive ECharts HTML.

Input: JSON from stdin with the following structure:
{
  "events": [
    {"timestamp": "2024-09-12T08:30:00", "host": "HOST-A", "rule": "Rule Name", "level": "crit", "mitre": "T1003"},
    ...
  ],
  "phases": [
    {"name": "Phase 1: Initial Access", "start": "2024-09-12T08:00:00", "end": "2024-09-12T09:00:00"},
    ...
  ],
  "title": "Incident Timeline",
  "output": "/path/to/output.html"
}

- "phases" is optional. If provided, a phase ribbon is drawn above the chart.
- "title" is optional (default: "Incident Timeline").
- "output" is required.
"""

import html as html_mod
import json
import os
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


# --- Severity styles ---
LEVEL_STYLE = {
    "crit":  {"color": "#DC143C", "symbol": "diamond",  "size": 18, "label": "Critical"},
    "high":  {"color": "#FF8C00", "symbol": "circle",   "size": 14, "label": "High"},
    "med":   {"color": "#FFD700", "symbol": "rect",     "size": 12, "label": "Medium"},
    "low":   {"color": "#4682B4", "symbol": "triangle",  "size": 10, "label": "Low"},
    "info":  {"color": "#A9A9A9", "symbol": "circle",   "size": 8,  "label": "Info"},
}

TEMPLATE_PATH = Path(__file__).with_name("timeline_chart.html")
ECHARTS_JS_PATH = Path(__file__).with_name("echarts.min.js")


def parse_ts(ts_str):
    """Parse timestamp string and return a timezone-aware UTC datetime."""
    # Formats with explicit timezone
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S.%f%z"):
        try:
            return datetime.strptime(ts_str, fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    # Formats without timezone — assume UTC
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Fallback: truncate and assume UTC
    try:
        return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.strptime(ts_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)


def detect_segments(timestamps, gap_threshold_ratio=5.0):
    """Detect time segments by finding large gaps in timestamps.

    Returns list of (start, end) tuples for each segment.
    """
    if len(timestamps) < 2:
        ts_min = min(timestamps)
        ts_max = max(timestamps)
        pad = timedelta(hours=1)
        return [(ts_min - pad, ts_max + pad)]

    sorted_ts = sorted(timestamps)
    gaps = []
    for i in range(1, len(sorted_ts)):
        delta = (sorted_ts[i] - sorted_ts[i - 1]).total_seconds()
        gaps.append((delta, i))

    if not gaps:
        pad = timedelta(hours=1)
        return [(sorted_ts[0] - pad, sorted_ts[-1] + pad)]

    deltas = [g[0] for g in gaps]
    total_span = (sorted_ts[-1] - sorted_ts[0]).total_seconds()

    break_indices = []
    if len(deltas) >= 3:
        median_gap = statistics.median(deltas)
        threshold = median_gap * gap_threshold_ratio
        for delta, idx in gaps:
            if delta > threshold and delta > 0:
                break_indices.append(idx)
    else:
        if total_span > 0:
            max_gap_delta, max_gap_idx = max(gaps, key=lambda g: g[0])
            if max_gap_delta / total_span > 0.30:
                break_indices.append(max_gap_idx)

    if not break_indices:
        pad_seconds = max(total_span * 0.02, 60)
        pad = timedelta(seconds=pad_seconds)
        return [(sorted_ts[0] - pad, sorted_ts[-1] + pad)]

    break_indices.sort()
    segments = []
    prev = 0
    for bi in break_indices:
        seg_ts = sorted_ts[prev:bi]
        span = (seg_ts[-1] - seg_ts[0]).total_seconds() if len(seg_ts) > 1 else 3600
        pad = timedelta(seconds=max(span * 0.05, 60))
        segments.append((seg_ts[0] - pad, seg_ts[-1] + pad))
        prev = bi
    seg_ts = sorted_ts[prev:]
    span = (seg_ts[-1] - seg_ts[0]).total_seconds() if len(seg_ts) > 1 else 3600
    pad = timedelta(seconds=max(span * 0.05, 60))
    segments.append((seg_ts[0] - pad, seg_ts[-1] + pad))

    return segments


def ts_to_ms(dt):
    """Convert datetime to JavaScript-compatible millisecond timestamp."""
    return int(dt.timestamp() * 1000)


def build_segments_for_js(segments):
    """Build segment intervals as [[start_ms, end_ms], ...] for JS."""
    return [[ts_to_ms(s), ts_to_ms(e)] for s, e in segments]


def _safe_js_json(s):
    """Escape sequences that could break out of a <script> block."""
    return s.replace("</", r"<\/")


def render_html(template, *, title, all_events_json, phases_json, segments_json, echarts_js):
    """Replace placeholders in the HTML template."""
    html = template
    html = html.replace("{{ECHARTS_JS}}", echarts_js)
    html = html.replace("{{TITLE}}", html_mod.escape(title))
    html = html.replace("{{TITLE_JSON}}", _safe_js_json(json.dumps(title, ensure_ascii=False)))
    html = html.replace("{{ALL_EVENTS_JSON}}", _safe_js_json(all_events_json))
    html = html.replace("{{PHASES_JSON}}", _safe_js_json(phases_json))
    html = html.replace("{{SEGMENTS_JSON}}", _safe_js_json(segments_json))
    return html


def _fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def _require_list(data, key):
    """The collection itself must be a list before anything indexes into it."""
    value = data[key]
    if not isinstance(value, list):
        _fail(f"{key!r} must be a list, got {type(value).__name__}")
    return value


def _item_dict(item, index, collection):
    if not isinstance(item, dict):
        _fail(f"{collection}[{index}] must be an object, got {type(item).__name__}")
    return item


def _require_str(item, key, index, collection):
    _item_dict(item, index, collection)
    if key not in item:
        _fail(f"{collection}[{index}] is missing required key: {key!r}")
    value = item[key]
    if not isinstance(value, str):
        _fail(f"{collection}[{index}].{key} must be a string, got {type(value).__name__}")
    return value


def _optional_str(item, key, index, collection, default=""):
    value = item.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        _fail(f"{collection}[{index}].{key} must be a string, got {type(value).__name__}")
    return value


def _optional_str_list(item, key, index, collection):
    value = item.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        _fail(f"{collection}[{index}].{key} must be a list, got {type(value).__name__}")
    for position, entry in enumerate(value):
        if not isinstance(entry, str):
            _fail(
                f"{collection}[{index}].{key}[{position}] must be a string,"
                f" got {type(entry).__name__}"
            )
    return value


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        _fail(f"input is not valid JSON: {exc}")
    if not isinstance(data, dict):
        _fail("input must be a JSON object")
    for key in ("events", "output"):
        if key not in data:
            _fail(f"missing required key: {key!r}")
    events = data["events"]
    phases = data.get("phases", [])
    title = data.get("title", "Incident Timeline")
    output_path = data["output"]

    if not output_path.lower().endswith(".html"):
        print(f"Output path must end with .html, got: {output_path}", file=sys.stderr)
        sys.exit(1)

    # Validated here rather than beside the assignment so this block stays
    # clear of the localized title default the JP tree overrides.
    if not isinstance(events, list):
        _fail(f"'events' must be a list, got {type(events).__name__}")
    if not events:
        print("No events to plot", file=sys.stderr)
        sys.exit(1)

    # Parse events
    parsed = []
    for index, ev in enumerate(events):
        timestamp = _require_str(ev, "timestamp", index, "events")
        try:
            ts = parse_ts(timestamp)
        except (TypeError, ValueError) as exc:
            _fail(f"events[{index}].timestamp is not a valid timestamp: {timestamp!r} ({exc})")
        parsed.append({
            "ts": ts,
            "host": _require_str(ev, "host", index, "events"),
            "rule": _optional_str(ev, "rule", index, "events"),
            "level": (_optional_str(ev, "level", index, "events", "info") or "info").lower(),
            "mitre": _optional_str(ev, "mitre", index, "events"),
        })
    parsed.sort(key=lambda x: x["ts"])

    # Detect time segments
    all_ts = [ev["ts"] for ev in parsed]
    segments = detect_segments(all_ts)

    # Build data for template
    all_events_for_js = [
        {
            "timestamp": ev["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": ev["host"],
            "rule": ev["rule"],
            "level": ev["level"],
            "mitre": ev["mitre"],
        }
        for ev in parsed
    ]
    all_events_json = json.dumps(all_events_for_js, ensure_ascii=False)
    phases_json = json.dumps(phases, ensure_ascii=False)
    segments_json = json.dumps(build_segments_for_js(segments), ensure_ascii=False)

    # Read template and render
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    echarts_js = ECHARTS_JS_PATH.read_text(encoding="utf-8")
    html = render_html(
        template,
        title=title,
        all_events_json=all_events_json,
        phases_json=phases_json,
        segments_json=segments_json,
        echarts_js=echarts_js,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
