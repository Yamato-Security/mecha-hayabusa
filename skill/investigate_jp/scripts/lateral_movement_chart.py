#!/usr/bin/env python3
"""
Lateral Movement visualization - Interactive ECharts HTML (directed graph).

Input: JSON from stdin with the following structure:
{
  "movements": [
    {
      "source_time": "2024-09-12T08:15:00Z",
      "source_host": "HOST-A",
      "source_event": "Mimikatz Credential Dumping",
      "source_level": "crit",
      "target_time": "2024-09-12T08:20:00Z",
      "target_host": "HOST-B",
      "target_event": "CobaltStrike Service Install",
      "target_level": "high",
      "delta_minutes": 5.0
    }
  ],
  "title": "横展開分析 (Lateral Movement)",
  "output": "/path/to/output.html"
}

- "title" is optional (default: "横展開分析 (Lateral Movement)").
- "output" is required.
"""

import html as html_mod
import json
import os
import re
import sys
from pathlib import Path

TEMPLATE_PATH = Path(__file__).with_name("lateral_movement_chart.html")
ECHARTS_JS_PATH = Path(__file__).with_name("echarts.min.js")

# Severity → color mapping
LEVEL_COLORS = {
    "crit": "#DC143C",
    "high": "#FF8C00",
    "med": "#FFD700",
    "low": "#4682B4",
    "info": "#A9A9A9",
}

DEFAULT_NODE_COLOR = "#607D8B"

# Severity → priority (higher = more severe)
LEVEL_PRIORITY = {"crit": 4, "high": 3, "med": 2, "low": 1, "info": 0}


def _highest_level(levels):
    """Return the most severe level from a set of levels."""
    best = "info"
    for lv in levels:
        if LEVEL_PRIORITY.get(lv, 0) > LEVEL_PRIORITY.get(best, 0):
            best = lv
    return best


_EXTERNAL_RE = re.compile(
    r"(?:"
    r"\d{1,3}(?:\.\d{1,3}){3}"            # IPv4
    r"|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"  # FQDN (one or more subdomains + TLD)
    r")"
)


def _is_external(hostname):
    """Heuristic: treat FQDNs with TLD and IP addresses as external."""
    return bool(_EXTERNAL_RE.fullmatch(hostname))


def compute_layout(movements):
    """Compute left-to-right layered layout based on attack propagation order.

    Uses BFS from the earliest source host to assign layers (columns).
    Hosts appearing first as source are placed leftmost, showing the
    propagation path clearly.  External hosts (C2 servers, IPs) are
    placed at the top or bottom edge of their layer for visual clarity.
    """
    if not movements:
        return {}

    # Build adjacency list and find the root (earliest source host)
    adj = {}
    all_hosts = []
    first_time = {}
    for m in movements:
        sh, th = m["source_host"], m["target_host"]
        adj.setdefault(sh, []).append(th)
        for h in (sh, th):
            if h not in first_time:
                first_time[h] = m.get("source_time", "") if h == sh else m.get("target_time", "")
                all_hosts.append(h)

    # BFS from the earliest host to assign layers
    root = all_hosts[0]
    layer = {root: 0}
    queue = [root]
    qi = 0
    while qi < len(queue):
        node = queue[qi]
        qi += 1
        for neighbor in adj.get(node, []):
            if neighbor not in layer:
                layer[neighbor] = layer[node] + 1
                queue.append(neighbor)

    # Assign remaining disconnected hosts to the rightmost layer + 1
    max_layer = max(layer.values()) if layer else 0
    for h in all_hosts:
        if h not in layer:
            max_layer += 1
            layer[h] = max_layer

    # Build undirected neighbor list (cross-layer only) for ordering
    neighbors = {}
    for m in movements:
        sh, th = m["source_host"], m["target_host"]
        if layer.get(sh) != layer.get(th):
            neighbors.setdefault(sh, []).append(th)
            neighbors.setdefault(th, []).append(sh)

    # Group hosts by layer, separating internal and external nodes.
    # External nodes (C2 servers, IPs) are placed at the edges of their
    # layer so lines to/from them don't cut through the main cluster.
    layers = {}
    for h, l in layer.items():
        layers.setdefault(l, []).append(h)

    x_spacing = 250.0
    y_spacing = 120.0
    external_top_y = 0.0  # external nodes pinned near top edge

    def _sort_layer(hosts_in_layer):
        """Sort: internal nodes in the middle, external at top/bottom."""
        internal = [h for h in hosts_in_layer if not _is_external(h)]
        external = [h for h in hosts_in_layer if _is_external(h)]
        return internal, external

    # Initial placement
    pos = {}
    for l, hosts_in_layer in layers.items():
        x = 120.0 + l * x_spacing
        internal, external = _sort_layer(hosts_in_layer)
        # Place internal nodes centered
        n_int = len(internal)
        total_int = (n_int - 1) * y_spacing if n_int > 1 else 0
        start_y = 300.0 - total_int / 2
        for i, h in enumerate(internal):
            pos[h] = (x, start_y + i * y_spacing)
        # Place external nodes at the top edge of the chart
        if external and internal:
            for i, h in enumerate(external):
                pos[h] = (x, external_top_y - i * y_spacing)
        elif external:
            for i, h in enumerate(external):
                pos[h] = (x, 300.0 + i * y_spacing)

    # Barycenter heuristic: reorder *internal* nodes within each layer
    # by average y-position of their cross-layer neighbors.
    num_layers = max(layers.keys()) + 1
    for _iteration in range(4):
        for l in range(num_layers):
            if l not in layers:
                continue
            internal = [h for h in layers[l] if not _is_external(h)]
            if len(internal) <= 1:
                continue
            barycenters = {}
            for h in internal:
                nbr_ys = [pos[n][1] for n in neighbors.get(h, [])
                          if n in pos]
                barycenters[h] = (sum(nbr_ys) / len(nbr_ys)
                                  if nbr_ys else pos[h][1])
            sorted_hosts = sorted(internal, key=lambda h: barycenters[h])
            # Update internal positions only
            x = pos[sorted_hosts[0]][0]
            n = len(sorted_hosts)
            total_height = (n - 1) * y_spacing
            start_y = 300.0 - total_height / 2
            for i, h in enumerate(sorted_hosts):
                pos[h] = (x, start_y + i * y_spacing)
            # Re-position external nodes at top edge
            external = [h for h in layers[l] if _is_external(h)]
            if external:
                for i, h in enumerate(external):
                    pos[h] = (x, external_top_y - i * y_spacing)

    return pos


def build_nodes_and_links(movements):
    """Build nodes and links lists for ECharts graph."""
    # Collect per-host stats
    host_stats = {}
    for m in movements:
        sh = m["source_host"]
        th = m["target_host"]
        for h in (sh, th):
            if h not in host_stats:
                host_stats[h] = {"as_source": 0, "as_target": 0, "levels": set()}
        host_stats[sh]["as_source"] += 1
        host_stats[sh]["levels"].add(m.get("source_level", "info"))
        host_stats[th]["as_target"] += 1
        host_stats[th]["levels"].add(m.get("target_level", "info"))

    hosts = list(host_stats.keys())
    pos = compute_layout(movements)

    # Node sizing based on total event count
    counts = {h: s["as_source"] + s["as_target"] for h, s in host_stats.items()}
    max_count = max(counts.values()) if counts else 1
    min_count = min(counts.values()) if counts else 1

    nodes = []
    for host in hosts:
        stats = host_stats[host]
        event_count = counts[host]
        highest = _highest_level(stats["levels"])
        color = LEVEL_COLORS.get(highest, DEFAULT_NODE_COLOR)

        if max_count == min_count:
            size = 55
        else:
            size = 35 + 40 * (event_count - min_count) / (max_count - min_count)

        x, y = pos.get(host, (400, 300))
        nodes.append({
            "id": host,
            "name": host,
            "x": x,
            "y": y,
            "symbolSize": size,
            "itemStyle": {
                "color": color,
                "borderColor": "#fff",
                "borderWidth": 2,
                "shadowBlur": 6,
                "shadowColor": "rgba(0,0,0,0.15)",
            },
            "label": {
                "show": True,
                "position": "bottom",
                "formatter": host,
                "fontSize": 12,
                "fontWeight": "bold",
                "color": "#333",
            },
            "hostInfo": {
                "event_count": event_count,
                "as_source": stats["as_source"],
                "as_target": stats["as_target"],
                "levels": sorted(stats["levels"],
                                 key=lambda l: LEVEL_PRIORITY.get(l, 0),
                                 reverse=True),
            },
        })

    # Aggregate edges between same host pairs for width
    edge_counts = {}
    for m in movements:
        key = (m["source_host"], m["target_host"])
        edge_counts[key] = edge_counts.get(key, 0) + 1

    links = []
    seen_pairs = set()
    for m in movements:
        sh = m["source_host"]
        th = m["target_host"]
        pair = (sh, th)

        # Compute curveness for parallel edges (A→B and B→A)
        reverse_exists = (th, sh) in edge_counts
        curveness = 0.2 if reverse_exists else 0.1

        count = edge_counts.get(pair, 1)
        width = min(1 + count, 8)

        sl = m.get("source_level", "info")
        tl = m.get("target_level", "info")
        edge_level = _highest_level([sl, tl])
        edge_color = LEVEL_COLORS.get(edge_level, "#999")

        # Edge label: show technique + time info
        label_text = ""
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            evt = m.get("source_event", "")
            if evt:
                evt_short = evt if len(evt) <= 25 else evt[:22] + "..."
            else:
                evt_short = ""
            # Extract HH:MM from timestamps
            st = m.get("source_time", "")
            delta = m.get("delta_minutes", 0)
            time_part = ""
            if st:
                # Parse HH:MM from ISO timestamp
                t_match = st[11:16] if len(st) >= 16 else ""
                if t_match:
                    time_part = f"{t_match} (+{delta}min)"
            parts = [p for p in [evt_short, time_part] if p]
            label_text = "\n".join(parts)

        links.append({
            "source": sh,
            "target": th,
            "lineStyle": {
                "color": edge_color,
                "width": width,
                "curveness": curveness,
                "opacity": 0.7,
            },
            "symbol": ["none", "arrow"],
            "symbolSize": [0, 12],
            "label": {
                "show": bool(label_text),
                "formatter": label_text,
                "fontSize": 10,
                "color": "#555",
                "backgroundColor": "rgba(255,255,255,0.85)",
                "padding": [2, 4],
                "borderRadius": 2,
            },
            "moveInfo": {
                "source_host": sh,
                "source_time": m.get("source_time", ""),
                "source_event": m.get("source_event", ""),
                "source_level": sl,
                "target_host": th,
                "target_time": m.get("target_time", ""),
                "target_event": m.get("target_event", ""),
                "target_level": tl,
                "delta_minutes": m.get("delta_minutes", 0),
            },
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
    movements = data["movements"]
    title = data.get("title", "横展開分析 (Lateral Movement)")
    output_path = data["output"]

    if not output_path.lower().endswith(".html"):
        print(f"Output path must end with .html, got: {output_path}", file=sys.stderr)
        sys.exit(1)

    if not movements:
        print("No lateral movement data to plot", file=sys.stderr)
        sys.exit(1)

    nodes, links = build_nodes_and_links(movements)
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
