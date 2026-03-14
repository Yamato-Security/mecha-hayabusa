#!/usr/bin/env python3
"""
Convert a Markdown incident report to a styled HTML report.

Input: JSON from stdin:
{
  "content": "# Report body in markdown syntax",
  "output": "/path/to/report.html",
  "title": "Report Title (optional)",
  "charts": {
    "timeline": "/path/to/timeline.html",
    "mitre_flow": "/path/to/mitre_flow.html"
  }
}

- "charts" is optional. When provided, markdown links to chart HTML files
  are replaced with <iframe> embeds.
- "title" is optional (extracted from first H1 in markdown if omitted).
"""

import html as html_mod
import json
import os
import re
import sys
from pathlib import Path

TEMPLATE_PATH = Path(__file__).with_name("report.html")

# ---------- minimal markdown -> HTML converter ----------
# Handles: h1-h4, tables, code blocks, blockquotes, ul/ol, hr, bold, italic,
#          inline code, links, paragraphs.  No external dependencies.


def _escape(text):
    """HTML-escape text, preserving already-converted tags."""
    return html_mod.escape(text)


def _safe_href(url: str):
    """Return a safely escaped href value or None if the URL is not allowed."""
    if url is None:
        return None
    url = url.strip()
    if not url:
        return None
    # Disallow control characters in URLs
    if any(ord(ch) < 32 for ch in url):
        return None
    # Detect an explicit scheme, e.g. "http:" or "javascript:"
    m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):', url)
    if m:
        scheme = m.group(1).lower()
        # Allow only a small set of safe schemes
        if scheme not in ('http', 'https', 'mailto'):
            return None
    else:
        # Disallow protocol-relative URLs like "//example.com"
        if url.startswith('//'):
            return None
    # Escape for inclusion inside an href attribute
    return html_mod.escape(url, quote=True)


def _link_replacer(match: "re.Match[str]") -> str:
    """Regex replacer to convert [text](url) into a safe <a> tag."""
    label = match.group(1)
    raw_url = match.group(2)
    safe_url = _safe_href(raw_url)
    if not safe_url:
        # If URL is unsafe, render just the label (already escaped) without a link.
        return label
    return f'<a href="{safe_url}">{label}</a>'


def _inline(text):
    """Convert inline markdown (bold, italic, code, links) to HTML."""
    # inline code first (so contents aren't processed further)
    parts = []
    while '`' in text:
        before, rest = text.split('`', 1)
        if '`' not in rest:
            text = before + '`' + rest
            break
        code_content, text = rest.split('`', 1)
        parts.append(_escape(before))
        parts.append(f'<code>{_escape(code_content)}</code>')
    parts.append(_escape(text))
    text = ''.join(parts)

    # bold **text** or __text__
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'__(.+?)__', r'<strong>\1</strong>', text)
    # italic *text* or _text_  (but not inside words with underscores)
    text = re.sub(r'(?<!\w)\*(.+?)\*(?!\w)', r'<em>\1</em>', text)
    text = re.sub(r'(?<!\w)_(.+?)_(?!\w)', r'<em>\1</em>', text)
    # links [text](url) with scheme validation and href escaping
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
    text = link_pattern.sub(_link_replacer, text)

    return text


def _make_id(text):
    """Create an HTML id from heading text."""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'[^\w\s-]', '', clean)
    clean = re.sub(r'\s+', '-', clean.strip()).lower()
    return clean or 'section'


def _severity_badge(cell_text):
    """Wrap severity level text in a styled span."""
    t = cell_text.strip().lower()
    for level in ('crit', 'high', 'med', 'low', 'info'):
        if t == level:
            return f'<span class="level-{level}">{_escape(cell_text.strip())}</span>'
    return _inline(cell_text.strip())


def _convert_table(lines):
    """Convert markdown table lines to HTML table."""
    if len(lines) < 2:
        return '<p>' + _escape(' '.join(lines)) + '</p>'

    headers = [c.strip() for c in lines[0].strip('|').split('|')]
    # skip separator line (line 1)
    rows = []
    for line in lines[2:]:
        cells = [c.strip() for c in line.strip('|').split('|')]
        rows.append(cells)

    # detect if there's a severity/level column
    level_cols = set()
    for i, h in enumerate(headers):
        if h.strip().lower() in ('level', 'severity'):
            level_cols.add(i)

    html_parts = ['<table>', '<thead><tr>']
    for h in headers:
        html_parts.append(f'<th>{_inline(h)}</th>')
    html_parts.append('</tr></thead><tbody>')

    for row in rows:
        html_parts.append('<tr>')
        for i, cell in enumerate(row):
            if i in level_cols:
                html_parts.append(f'<td>{_severity_badge(cell)}</td>')
            else:
                html_parts.append(f'<td>{_inline(cell)}</td>')
        html_parts.append('</tr>')

    html_parts.append('</tbody></table>')
    return '\n'.join(html_parts)


def md_to_html(md_text, chart_files=None):
    """Convert markdown to HTML body, returning (body_html, nav_items, title)."""
    chart_files = chart_files or {}
    lines = md_text.split('\n')
    body_parts = []
    nav_items = []
    title = ''
    section_ids = {}

    i = 0
    while i < len(lines):
        line = lines[i]

        # --- fenced code blocks ---
        if line.strip().startswith('```'):
            lang = line.strip()[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing ```
            code_text = _escape('\n'.join(code_lines))
            body_parts.append(f'<pre><code>{code_text}</code></pre>')
            continue

        # --- headings ---
        heading_match = re.match(r'^(#{1,4})\s+(.+)$', line)
        if heading_match:
            level = len(heading_match.group(1))
            text = heading_match.group(2).strip()
            inline_text = _inline(text)
            heading_id = _make_id(inline_text)

            # ensure unique ids
            if heading_id in section_ids:
                section_ids[heading_id] += 1
                heading_id = f'{heading_id}-{section_ids[heading_id]}'
            else:
                section_ids[heading_id] = 0

            if level == 1 and not title:
                title = re.sub(r'<[^>]+>', '', inline_text)

            body_parts.append(f'<h{level} id="{heading_id}">{inline_text}</h{level}>')

            # nav: h2 and h3
            if level == 2:
                nav_items.append(f'<a href="#{heading_id}">{re.sub("<[^>]+>", "", inline_text)}</a>')
            elif level == 3:
                nav_items.append(f'<a href="#{heading_id}" class="sub">{re.sub("<[^>]+>", "", inline_text)}</a>')

            i += 1
            continue

        # --- chart link replacement ---
        chart_match = re.match(r'^\[(.+?)\]\((.+?\.html)\)\s*$', line.strip())
        if chart_match:
            link_text = chart_match.group(1)
            link_href = chart_match.group(2)
            # check if this matches one of our chart files
            basename = os.path.basename(link_href)
            replaced = False
            for key, chart_path in chart_files.items():
                if basename == os.path.basename(chart_path):
                    rel = os.path.basename(chart_path)
                    extra_cls = ' chart-wide' if key == 'mitre_flow' else ''
                    body_parts.append(
                        f'<div class="chart-container{extra_cls}">'
                        f'<span class="chart-label">{_escape(link_text)}</span>'
                        f'<iframe src="{_escape(rel)}" loading="lazy"></iframe>'
                        f'</div>'
                    )
                    replaced = True
                    break
            if not replaced:
                body_parts.append(f'<div class="chart-container">'
                                  f'<span class="chart-label">{_escape(link_text)}</span>'
                                  f'<iframe src="{_escape(link_href)}" loading="lazy"></iframe>'
                                  f'</div>')
            i += 1
            continue

        # --- tables ---
        if '|' in line and line.strip().startswith('|'):
            table_lines = []
            while i < len(lines) and '|' in lines[i] and lines[i].strip().startswith('|'):
                table_lines.append(lines[i])
                i += 1
            body_parts.append(_convert_table(table_lines))
            continue

        # --- horizontal rule ---
        if re.match(r'^---+\s*$', line.strip()):
            body_parts.append('<hr>')
            i += 1
            continue

        # --- blockquote ---
        if line.strip().startswith('>'):
            bq_lines = []
            while i < len(lines) and lines[i].strip().startswith('>'):
                bq_lines.append(re.sub(r'^>\s?', '', lines[i]))
                i += 1
            bq_html = '<br>\n'.join(_inline(l) for l in bq_lines)
            body_parts.append(f'<blockquote>{bq_html}</blockquote>')
            continue

        # --- unordered list ---
        if re.match(r'^[\s]*[-*+]\s', line):
            list_items = []
            while i < len(lines) and re.match(r'^[\s]*[-*+]\s', lines[i]):
                item_text = re.sub(r'^[\s]*[-*+]\s', '', lines[i])
                list_items.append(f'<li>{_inline(item_text)}</li>')
                i += 1
            body_parts.append('<ul>\n' + '\n'.join(list_items) + '\n</ul>')
            continue

        # --- ordered list ---
        if re.match(r'^[\s]*\d+\.\s', line):
            list_items = []
            while i < len(lines) and re.match(r'^[\s]*\d+\.\s', lines[i]):
                item_text = re.sub(r'^[\s]*\d+\.\s', '', lines[i])
                list_items.append(f'<li>{_inline(item_text)}</li>')
                i += 1
            body_parts.append('<ol>\n' + '\n'.join(list_items) + '\n</ol>')
            continue

        # --- blank line ---
        if not line.strip():
            i += 1
            continue

        # --- paragraph ---
        para_lines = []
        while i < len(lines) and lines[i].strip() and \
              not lines[i].strip().startswith('#') and \
              not lines[i].strip().startswith('```') and \
              not lines[i].strip().startswith('>') and \
              not re.match(r'^---+\s*$', lines[i].strip()) and \
              not (lines[i].strip().startswith('|') and '|' in lines[i]) and \
              not re.match(r'^[\s]*[-*+]\s', lines[i]) and \
              not re.match(r'^[\s]*\d+\.\s', lines[i]) and \
              not re.match(r'^\[.+?\]\(.+?\.html\)\s*$', lines[i].strip()):
            para_lines.append(lines[i])
            i += 1
        body_parts.append(f'<p>{_inline(" ".join(para_lines))}</p>')

    return '\n'.join(body_parts), '\n'.join(nav_items), title


def render_report(template, *, title, body_html, nav_items_html):
    """Replace placeholders in the report HTML template."""
    html = template
    html = html.replace('{{TITLE}}', html_mod.escape(title))
    html = html.replace('{{NAV_ITEMS}}', nav_items_html)
    html = html.replace('{{BODY}}', body_html)
    return html


def main():
    data = json.load(sys.stdin)
    output_path = data["output"]
    given_title = data.get("title", "")
    chart_files = data.get("charts", {})

    if not output_path.lower().endswith(".html"):
        print(f"Output path must end with .html, got: {output_path}", file=sys.stderr)
        sys.exit(1)

    if "content" not in data:
        print('Input must include "content"', file=sys.stderr)
        sys.exit(1)

    md_text = data["content"]
    body_html, nav_items_html, extracted_title = md_to_html(md_text, chart_files)

    title = given_title or extracted_title or "Incident Report"

    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    html = render_report(
        template,
        title=title,
        body_html=body_html,
        nav_items_html=nav_items_html,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
