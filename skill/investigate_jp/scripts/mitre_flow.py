#!/usr/bin/env python3
"""
MITRE ATT&CK attack flow visualization - Interactive ECharts HTML (network graph).

Input: JSON from stdin with the following structure:
{
  "tactics": [
    {
      "id": "TA0001",
      "name": "Initial Access",
      "techniques": ["T1566 Phishing"],
      "hosts": ["HOST-A"],
      "event_count": 5,
      "time_range": "2024-09-12 08:00 ~ 09:00"
    },
    ...
  ],
  "title": "Attack Flow (MITRE ATT&CK)",
  "output": "/path/to/output.html"
}

- "title" is optional (default: "Attack Flow (MITRE ATT&CK)").
- "output" is required.
"""

import html as html_mod
import json
import math
import os
import sys
from pathlib import Path

TEMPLATE_PATH = Path(__file__).with_name("mitre_flow.html")
ECHARTS_JS_PATH = Path(__file__).with_name("echarts.min.js")

# Tactic colors (based on MITRE ATT&CK official-ish colors)
TACTIC_COLORS = {
    "TA0043": "#9C27B0",  # Reconnaissance
    "TA0042": "#7B1FA2",  # Resource Development
    "TA0001": "#D32F2F",  # Initial Access
    "TA0002": "#E64A19",  # Execution
    "TA0003": "#F57C00",  # Persistence
    "TA0004": "#FFA000",  # Privilege Escalation
    "TA0005": "#FBC02D",  # Defense Evasion
    "TA0006": "#689F38",  # Credential Access
    "TA0007": "#388E3C",  # Discovery
    "TA0008": "#00796B",  # Lateral Movement
    "TA0009": "#0097A7",  # Collection
    "TA0011": "#1976D2",  # Command and Control
    "TA0010": "#303F9F",  # Exfiltration
    "TA0040": "#5D4037",  # Impact
}

DEFAULT_COLOR = "#607D8B"


def compute_layout(tactics):
    """Compute layout: fixed tactic row + fan placement for techniques (pure Python, no networkx)."""
    pos = {}
    tactic_spacing = 200.0
    center_y = 300.0

    # Place tactics on a horizontal line
    for i, tac in enumerate(tactics):
        tid = tac.get("id", f"TA_{i}")
        pos[tid] = (i * tactic_spacing, center_y)

    # Assign each technique to its first-seen tactic for positioning
    node_primary_tactic = {}
    tactic_techs = {}
    for i, tac in enumerate(tactics):
        tid = tac.get("id", f"TA_{i}")
        techs = []
        for tech in tac.get("techniques", []):
            if tech not in node_primary_tactic:
                node_primary_tactic[tech] = tid
                techs.append(tech)
        tactic_techs[tid] = techs

    # Fan techniques below their primary tactic
    for i, tac in enumerate(tactics):
        tid = tac.get("id", f"TA_{i}")
        tx, ty = pos[tid]
        techs = tactic_techs[tid]
        if not techs:
            continue

        n_techs = len(techs)
        radius = 80.0 + 10.0 * n_techs
        radius = min(radius, 140.0)

        if n_techs == 1:
            angles = [math.radians(90)]
        else:
            spread = min(140, 45 * n_techs)
            angles = [
                math.radians(90 - spread / 2 + spread * j / (n_techs - 1))
                for j in range(n_techs)
            ]

        for j, tech in enumerate(techs):
            pos[tech] = (tx + radius * math.cos(angles[j]),
                         ty + radius * math.sin(angles[j]))

    return pos, tactic_techs


def build_nodes_and_links(tactics):
    """Build nodes and links lists for ECharts graph."""
    pos, tactic_techs = compute_layout(tactics)

    nodes = []
    links = []

    # Compute node sizes based on event count
    event_counts = [tac.get("event_count", 1) for tac in tactics]
    max_count = max(event_counts) if event_counts else 1
    min_count = min(event_counts) if event_counts else 1

    # Build tactic nodes
    for i, tac in enumerate(tactics):
        tid = tac.get("id", f"TA_{i}")
        name = tac.get("name", tid)
        event_count = tac.get("event_count", 0)
        time_range = tac.get("time_range", "")
        hosts = tac.get("hosts", [])
        color = TACTIC_COLORS.get(tid, DEFAULT_COLOR)
        techs = tac.get("techniques", [])

        # Size proportional to event count
        if max_count == min_count:
            size = 60
        else:
            size = 40 + 40 * (event_count - min_count) / (max_count - min_count)

        x, y = pos[tid]
        nodes.append({
            "id": tid,
            "name": f"{name}\n{tid}",
            "x": x,
            "y": y,
            "symbolSize": size,
            "category": 0,
            "itemStyle": {"color": color, "borderColor": "#fff", "borderWidth": 2},
            "label": {
                "show": True,
                "position": "top",
                "formatter": name,
                "fontSize": 12,
                "fontWeight": "bold",
                "color": "#333",
            },
            "tacticInfo": {
                "id": tid,
                "name": name,
                "event_count": event_count,
                "time_range": time_range,
                "hosts": hosts,
                "techniques": techs,
            },
        })

    # Build technique nodes
    all_techs_placed = set()
    for i, tac in enumerate(tactics):
        tid = tac.get("id", f"TA_{i}")
        for tech in tactic_techs.get(tid, []):
            if tech in all_techs_placed:
                continue
            all_techs_placed.add(tech)
            x, y = pos.get(tech, (0, 0))
            nodes.append({
                "id": tech,
                "name": tech,
                "x": x,
                "y": y,
                "symbolSize": 20,
                "category": 1,
                "itemStyle": {"color": "#E0E0E0", "borderColor": "#BDBDBD", "borderWidth": 1},
                "label": {
                    "show": True,
                    "position": "bottom",
                    "formatter": tech if len(tech) <= 35 else tech[:32] + "...",
                    "fontSize": 9,
                    "color": "#666",
                },
            })

    # Flow edges (tactic -> tactic)
    for i in range(len(tactics) - 1):
        src = tactics[i].get("id", f"TA_{i}")
        dst = tactics[i + 1].get("id", f"TA_{i+1}")
        links.append({
            "source": src,
            "target": dst,
            "lineStyle": {
                "color": "#333",
                "width": 3,
                "curveness": 0.1,
            },
            "symbol": ["none", "arrow"],
            "symbolSize": [0, 12],
        })

    # Technique edges (tactic -> technique)
    for i, tac in enumerate(tactics):
        tid = tac.get("id", f"TA_{i}")
        for tech in tactic_techs.get(tid, []):
            links.append({
                "source": tid,
                "target": tech,
                "lineStyle": {
                    "color": "#ccc",
                    "width": 1,
                    "opacity": 0.5,
                },
                "symbol": ["none", "none"],
            })

    return nodes, links


def _safe_js_json(s):
    """Escape sequences that could break out of a <script> block."""
    return s.replace("</", r"<\/")


def render_html(template, *, title, nodes_json, links_json, echarts_js):
    """Replace placeholders in the HTML template."""
    html = template
    html = html.replace("{{ECHARTS_JS}}", echarts_js)
    html = html.replace("{{TITLE}}", html_mod.escape(title))
    html = html.replace("{{TITLE_JSON}}", _safe_js_json(json.dumps(title, ensure_ascii=False)))
    html = html.replace("{{NODES_JSON}}", _safe_js_json(nodes_json))
    html = html.replace("{{LINKS_JSON}}", _safe_js_json(links_json))
    return html


def main():
    data = json.load(sys.stdin)
    tactics = data["tactics"]
    title = data.get("title", "Attack Flow (MITRE ATT&CK)")
    output_path = data["output"]

    if not output_path.lower().endswith(".html"):
        print(f"Output path must end with .html, got: {output_path}", file=sys.stderr)
        sys.exit(1)

    if not tactics:
        print("No tactics to plot", file=sys.stderr)
        sys.exit(1)

    nodes, links = build_nodes_and_links(tactics)
    nodes_json = json.dumps(nodes, ensure_ascii=False)
    links_json = json.dumps(links, ensure_ascii=False)

    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    echarts_js = ECHARTS_JS_PATH.read_text(encoding="utf-8")
    html = render_html(
        template,
        title=title,
        nodes_json=nodes_json,
        links_json=links_json,
        echarts_js=echarts_js,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
