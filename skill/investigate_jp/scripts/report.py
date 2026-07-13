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
  },
  "state_dir": "/path/to/investigation/state (optional)",
  "force": false
}

- "charts" is optional. When provided, markdown links to chart HTML files
  are replaced with <iframe> embeds.
- "title" is optional (extracted from first H1 in markdown if omitted).
- "state_dir" is optional but auto-detected from the output directory when a
  manifest.json sits there. When set, coverage gates (state.py check) are run
  first: if any gate FAILs, report generation is refused (exit code 3) unless
  "force" is true, and a Coverage & Reproducibility appendix generated from the
  investigation state is added to the end of the report.
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


def _sanitize_href(url):
    """Return a safely escaped href value or None if the URL is not allowed.

    The scheme is detected with a regex on the stripped URL rather than
    urllib.parse.urlparse: pre-gh-102153 Pythons (e.g. 3.9.x) let a leading
    space/control character hide the scheme (" javascript:..." parses as
    scheme=""), which browsers would still execute. Control characters are
    rejected outright because browsers strip tab/newline inside URLs, turning
    e.g. "/\\t/host" into a protocol-relative "//host"."""
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
        # Disallow protocol-relative URLs like "//example.com". Browsers treat
        # backslashes as forward slashes, so normalize first to also reject
        # "\\host", "/\host" etc.
        if url.replace("\\", "/").startswith('//'):
            return None
    # Escape for inclusion inside an href attribute
    return html_mod.escape(url, quote=True)


def _link_replacer(match):
    """Replacer for markdown links [text](url) to safe <a href="...">."""
    link_text = match.group(1)
    raw_url = match.group(2)
    safe_href = _sanitize_href(raw_url)
    if not safe_href:
        # If URL is unsafe, render just the label (already escaped) without a link.
        return link_text
    # link_text has already been through _escape and any formatting regexes will
    # operate on this string, so we can insert it as-is.
    return f'<a href="{safe_href}">{link_text}</a>'


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

    # Protect <code>...</code> spans from further inline formatting.
    # The placeholder is delimited by NUL bytes (never present in report text and
    # not matched by the bold/italic/link regexes) so it survives those passes;
    # an underscore-based placeholder would be mangled by the __bold__ regex.
    code_spans = {}

    def _store_code_span(match):
        key = f"\x00CODESPAN{len(code_spans)}\x00"
        code_spans[key] = match.group(0)
        return key

    # Use DOTALL so code spans containing newlines are also preserved
    text = re.sub(r'(?s)<code>.*?</code>', _store_code_span, text)

    # bold **text** or __text__
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'__(.+?)__', r'<strong>\1</strong>', text)
    # italic *text* or _text_  (but not inside words with underscores)
    text = re.sub(r'(?<!\w)\*(.+?)\*(?!\w)', r'<em>\1</em>', text)
    text = re.sub(r'(?<!\w)_(.+?)_(?!\w)', r'<em>\1</em>', text)
    # links [text](url)
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', _link_replacer, text)

    # Restore original code spans
    for placeholder, span_html in code_spans.items():
        text = text.replace(placeholder, span_html)

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
    embedded_charts = set()

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
            src = link_href
            extra_cls = ''
            for key, chart_path in chart_files.items():
                if basename == os.path.basename(chart_path):
                    src = os.path.basename(chart_path)
                    if key == 'mitre_flow':
                        extra_cls = ' chart-wide'
                    break
            # Dedupe on the resolved iframe src, not the basename: two distinct
            # files may share a basename (hosts/a/timeline.html vs
            # hosts/b/timeline.html) and both must be embedded.
            if src in embedded_charts:
                # Chart already embedded above: render repeat references as a
                # plain link instead of loading the same (large) chart twice.
                body_parts.append(f'<p>{_inline(line.strip())}</p>')
                i += 1
                continue
            embedded_charts.add(src)
            body_parts.append(
                f'<div class="chart-container{extra_cls}">'
                f'<span class="chart-label">{_escape(link_text)}</span>'
                f'<iframe src="{_escape(src)}" loading="lazy"></iframe>'
                f'</div>'
            )
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


APPENDIX_LANG = "ja"


def _run_coverage_gate(state_dir, force):
    """Run state.py coverage gates; exit unless they PASS (or force). Returns appendix md."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import state as investigation_state
    except ImportError:
        if force:
            print(
                "warning: state.py not found next to report.py;"
                " generating the report without the coverage appendix",
                file=sys.stderr,
            )
            return ""
        print(
            "state.py not found next to report.py - report generation refused."
            ' Reinstall/update the skill scripts, or pass "force": true.',
            file=sys.stderr,
        )
        sys.exit(3)

    def _unreadable(detail):
        # A missing/corrupt/wrong-shaped state must not crash report.py: force
        # generates the report without the appendix, otherwise refuse cleanly.
        if force:
            print(
                f"warning: coverage state unreadable ({detail});"
                " generating the report without the coverage appendix",
                file=sys.stderr,
            )
            return ""
        print(
            f"Coverage state could not be checked ({detail}) - report generation refused."
            ' Fix the state directory or pass "force": true.',
            file=sys.stderr,
        )
        sys.exit(3)

    # Strict re-check: the coverage appendix certifies host/RecordID coverage
    # against the dataset, so the CSV must be present (a missing CSV fails G0 and
    # the report is refused unless forced). A present CSV is re-hashed to catch
    # tampering between Step 7-0 and report time.
    try:
        result = investigation_state.run_check(state_dir)
    except SystemExit as exc:
        return _unreadable(f"state.py exited {exc.code}")
    except Exception as exc:
        return _unreadable(f"{type(exc).__name__}: {exc}")

    if not result["ok"] and not force:
        print("Coverage gates FAILED - report generation refused.", file=sys.stderr)
        for g in result["gates"]:
            if g["status"] == "FAIL":
                print(f"  [{g['id']}] {g['name']}: {g['detail']}", file=sys.stderr)
                for gap in g["gaps"][:10]:
                    print(f"      - {gap}", file=sys.stderr)
        print(
            "Resolve the gaps (state.py status / triage / host / cluster ...) "
            'or pass "force": true to generate anyway.',
            file=sys.stderr,
        )
        sys.exit(3)

    # The appendix dereferences manifest fields run_check does not, so guard it
    # with the same fall-back rather than letting a malformed manifest crash.
    # _load/_fail inside appendix_markdown raise SystemExit, so catch that too.
    try:
        return investigation_state.appendix_markdown(state_dir, lang=APPENDIX_LANG, result=result)
    except SystemExit as exc:
        return _unreadable(f"appendix build failed: state.py exited {exc.code}")
    except Exception as exc:
        return _unreadable(f"appendix build failed: {type(exc).__name__}: {exc}")


def _looks_like_state_manifest(path):
    """True only if path is a state.py investigation manifest, so an unrelated
    manifest.json in the output directory is not mistaken for investigation
    state. Match the exact nested fields run_check dereferences: a generic
    manifest whose top-level "dataset"/"strategy" are strings or differently
    shaped dicts (common in ML/build outputs) must not turn the gate on."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    dataset = data.get("dataset")
    strategy = data.get("strategy")
    return (
        isinstance(dataset, dict)
        and "path" in dataset
        and "sha256" in dataset
        and isinstance(strategy, dict)
        and "levels_investigated" in strategy
    )


def _parse_force(value):
    """Interpret the 'force' field strictly: only JSON true or an explicit
    truthy string forces. In particular the string 'false' must NOT force."""
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return False


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        # Same failure mode state.py guards against: JSON built via a
        # single-quoted echo with Windows paths (C:\Users\...) in the content.
        print(
            f"error: stdin must be a JSON object: {exc}"
            " — write the JSON to a file with the Write tool and redirect it in"
            " (report.py < input.json); inline echo breaks on Windows paths.",
            file=sys.stderr,
        )
        sys.exit(1)
    output_path = data["output"]
    given_title = data.get("title", "")
    chart_files = data.get("charts", {})
    state_dir = data.get("state_dir", "")
    force = _parse_force(data.get("force", False))

    if not output_path.lower().endswith(".html"):
        print(f"Output path must end with .html, got: {output_path}", file=sys.stderr)
        sys.exit(1)

    if "content" not in data:
        print('Input must include "content"', file=sys.stderr)
        sys.exit(1)

    # The report is written inside STATE_DIR (SKILL.md guarantees this), so if
    # state_dir was omitted but a Hayabusa manifest.json sits next to the output,
    # use it. This keeps the coverage gate from being silently bypassed by a
    # forgotten field after context compaction. An unrelated manifest.json is
    # ignored (schema-checked), so reports written elsewhere are unaffected.
    if not state_dir:
        candidate = os.path.dirname(os.path.abspath(output_path))
        if _looks_like_state_manifest(os.path.join(candidate, "manifest.json")):
            state_dir = candidate
            print(
                f"note: state_dir not provided; found manifest.json in the output "
                f"directory, enforcing coverage gates against {candidate}",
                file=sys.stderr,
            )

    md_text = data["content"]
    if state_dir:
        appendix_md = _run_coverage_gate(state_dir, force)
        if appendix_md:
            md_text = md_text.rstrip() + "\n\n---\n\n" + appendix_md + "\n"
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
