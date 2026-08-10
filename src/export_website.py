"""Export the I2P Address Book as a self-contained HTML page."""

from __future__ import annotations

import json
import math
import pathlib
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .integration import get_address_book


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_TEMPLATE_DIR = pathlib.Path(__file__).parent / "browse_template.html"


def _humanize_bytes(value: int | None) -> str:
    """Format byte count into human-friendly string (e.g. '40.9KB')."""
    if value is None or value == 0:
        return ""
    if value < 1024:
        return f"{value}B"
    kb = value / 1024
    if kb < 1024:
        return f"{kb:.1f}KB"
    mb = kb / 1024
    return f"{mb:.1f}MB"


def _format_response_time(value: float | None) -> str:
    """Format response time in seconds (e.g. '6.4s'). Empty when missing."""
    if value is None or value == 0:
        return ""
    return f"{value:.1f}s"


def _transform_row(row: dict[str, Any]) -> dict[str, Any]:
    """Add display-friendly derived fields for the embedded JSON payload."""
    rt = row.get("response_time_sec")
    bl = row.get("body_length")
    summary = row.get("content_summary", "") or ""
    found_links_raw = row.get("found_links", "[]")

    return {
        "dns_name": row.get("dns_name", "") or "",
        "title": row.get("title", "") or "",
        "content_type": row.get("content_type", "") or "",
        "content_summary": (summary if summary else "Unidentified").replace("\n", " "),
        "deep_site_type": row.get("deep_site_type", "") or "",
        "detected_lang": row.get("detected_lang", "") or "",
        "reachable": bool(row.get("reachable", False)),
        "last_probed_utc": row.get("last_probed_utc", "") or "",
        "_rt": _format_response_time(rt),
        "_size": _humanize_bytes(bl) if isinstance(bl, (int, type(None))) else "",
        "found_links": found_links_raw if found_links_raw else "[]",
    }


# ---------------------------------------------------------------------------
# HTML template (minimal dark theme, proven from website/address_book.html)
# ---------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>I2P Address Book</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* --- Reset & base (minimal for slow connections) ------------------------ */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;font-size:12px;color:#e0e0e0;
    background:#0a0a0f;padding:8px;line-height:1.4}}

/* --- Stats bar ---------------------------------------------------------- */
.stats{{display:flex;gap:16px;padding:8px 12px;margin-bottom:8px;
      border:1px solid #333;border-radius:4px;background:#111;font-size:11px;flex-wrap:wrap}}
.stats span{{white-space:nowrap}}
.ok{{color:#5f5}} .down{{color:#f55}}

/* --- Controls ----------------------------------------------------------- */
.controls{{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;align-items:center}}
.controls input[type="text"]{{flex:1;min-width:160px;padding:4px 8px;
    background:#111;color:#ccc;border:1px solid #444;border-radius:3px;font-size:12px}}
.controls label{{font-size:11px;display:flex;align-items:center;gap:4px;white-space:nowrap}}
.controls select,.controls button{{padding:4px 8px;background:#1a1a1a;color:#ccc;
    border:1px solid #444;border-radius:3px;font-size:11px;cursor:pointer}}
.controls button:hover,.controls select:hover{{border-color:#888}}

/* --- Table (auto-layout so long text wraps) ---------------------------- */
table{{width:100%;border-collapse:collapse;table-layout:auto}}
th,td{{padding:4px 8px;border:1px solid #222;word-wrap:break-word;text-overflow:ellipsis}}
thead th{{position:sticky;top:0;background:#15151a;color:#aaa;cursor:pointer;user-select:none}}
thead th:hover{{background:#252530;color:#fff}}
thead .sort-asc::after{{content:' ▲'}} thead .sort-desc::after{{content:' ▼'}}

/* Column minimum widths */
  col.c-status{{min-width:48px;}}col.c-type{{min-width:70px;max-width:160px;}}
  col.c-site{{min-width:120px;}}col.c-title{{min-width:100px;}}
  col.c-summary{{min-width:150px;}}col.c-site-type{{min-width:80px;max-width:140px;}}
  col.c-rt{{min-width:48px;}}col.c-size{{min-width:48px;}}col.c-lang{{min-width:42px;}}
  col.c-time{{min-width:130px;}}col.c-probe{{min-width:28px;}}

tbody tr:nth-child(even){{background:#0e0e14}}
tbody tr:hover{{background:#1a1a28}}
td.unreachable{{color:#666;opacity:.55}}
.status-ok{{color:#5f5;font-weight:bold}}
.status-down{{color:#f55}}

/* --- Pagination --------------------------------------------------------- */
.pager{{text-align:center;margin-top:8px;padding:4px;color:#999;font-size:11px;display:flex;justify-content:center;gap:6px;align-items:center}}
.pager button{{padding:3px 10px;background:#1a1a1a;color:#ccc;border:1px solid #444;
     border-radius:3px;font-size:11px;cursor:pointer}}
.pager button:hover:not(:disabled){{border-color:#888}}
.pager button:disabled{{opacity:.35}}

/* --- Footer ------------------------------------------------------------- */
.footer{{text-align:center;color:#444;font-size:10px;margin-top:12px;padding:4px}}
</style>
</head>
<body>

<div class="stats" id="stats"></div>

<div class="controls">
  <input type="text" id="filter" placeholder="Filter dns / title / type / summary..." autofocus>
  <label><input type="checkbox" id="show-unreachable"> show unreachable</label>
  <label>rows <select id="pageSize">
      <option value="25">25</option>
      <option value="50" selected>50</option>
      <option value="100">100</option>
      <option value="200">200</option>
    </select></label>
  <button id="reset-btn">Reset</button>
</div>

<div style="overflow-x:auto">
<table id="grid" role="grid">
  <colgroup>
    <col class="c-status">
    <col class="c-type">
    <col class="c-site">
    <col class="c-title">
    <col class="c-summary">
    <col class="c-site-type">
    <col class="c-rt">
    <col class="c-size">
    <col class="c-lang">
    <col class="c-time">
    <col class="c-probe">
  </colgroup>
  <thead id="head"></thead>
  <tbody   id="body"></tbody>
</table>
</div>

<div class="pager" id="pager"></div>
<div class="footer" id="footer"></div>

<script>
// --- Embedded dataset ----------------------------------------------------
const DATA = {DATA_JSON};

// --- Column definitions --------------------------------------------------
const COLS = [
  {{key:'_status',     label:'Status'}},
  {{key:'content_type',label:'Type'}},
  {{key:'dns_name',    label:'Site'}},
  {{key:'title',       label:'Title'}},
  {{key:'content_summary',label:'Summary'}},
  {{key:'deep_site_type',label:'Site Type'}},
  {{key:'deep_purpose',   label:'Purpose'}},
  {{key:'deep_analyzed_at',label:'Analysed'}},
  {{key:'_rt',          label:'Response Time'}},
  {{key:'_size',       label:'Size'}},
  {{key:'detected_lang',label:'Language'}},
  {{key:'last_probed_utc',label:'Last Probed'}},
  {{key:'_probe',      label:'Links'}},
];

/* Precomputed display columns (added by Python for small JSON) */
for(const r of DATA){{
  r._status = r.reachable ? 'OK' : 'DOWN';
}}

// --- State ----------------------------------------------------------------
let   sortKey = 'dns_name';
let   sortAsc = false;
let   filterText = '';
let   showUnreachable = true;
let   pageSize = 50;
let   page = 1;

function visibleRow(){{
  return DATA.filter(r => {{
    if(!showUnreachable && !r.reachable) return false;
    if(filterText){{
      const q = filterText.toLowerCase();
      const haystack = [r.dns_name,r.title,r.content_type,r.deep_site_type,r.deep_purpose,r.content_summary]
                       .join(' ').toLowerCase();
      if(haystack.indexOf(q) === -1) return false;
    }}
    return true;
  }});
}}

function sortRows(arr){{
  arr.sort((a,b)=>{{
    let va = a[sortKey], vb = b[sortKey];
    if(va == null) va=''; if(vb==null) vb='';
    if(typeof va==='string'){{
      return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    }}
    return sortAsc ? va-vb : vb-va;
  }});
}}

function render(){{
  let rows = visibleRow();
  sortRows(rows);
  const total = Math.ceil(rows.length / pageSize) || 1;
  if(page > total) page = total;
  const slice = rows.slice((page-1)*pageSize, page*pageSize);

  // Header
  let h = '';
  for(const c of COLS){{
    const cls = sortKey===c.key ? (sortAsc?'sort-asc':'sort-desc') : '';
    h += `<th class="${{cls}}" data-key="${{c.key}}">${{esc(c.label)}}</th>`;
  }}
  document.getElementById('head').innerHTML = h;

  // Body
  let b = '';
  for(const r of slice){{
    const unreachClass = r.reachable ? '' : 'unreachable';
    const statusCls = r.reachable ? 'status-ok' : 'status-down';
    b += `<tr class="${{unreachClass}}">`;
    b += `<td class="${{statusCls}}">${{r._status}}</td>`;
    b += `<td>${{esc(r.content_type||'')}}</td>`;
    b += `<td style="overflow:visible;white-space:normal">${{esc(r.dns_name)}}</td>`;
    b += `<td title="${{esc((r.content_summary||'').replace(/"/g,'&quot;'))}}">${{esc(r.title||'')}}</td>`;
    const summary = esc(r.content_summary || '—');
    b += `<td title="${{esc((r.content_summary||'').replace(/"/g,'&quot;'))}}">`+`${{summary}}</td>`;
    b += `<td>${{esc(r.deep_site_type||'')}}</td>`;
    b += `<td title="${{esc((r.deep_purpose||'').replace(/"/g,'&quot;')))}}">${{esc((r.deep_purpose||'').substring(0,150))}}</td>`;
    b += `<td>${{esc(r.deep_analyzed_at||'')}}</td>`;
    b += `<td>${{esc(r._rt||'')}}</td>`;
    b += `<td>${{esc(r._size||'')}}</td>`;
    const langLabel = r.detected_lang && r.detected_lang !== 'en' ? r.detected_lang.toUpperCase() : '';
    b += `<td title="ISO 639-1">${{esc(langLabel)}}</td>`;
    b += `<td title="${{esc((r.content_summary||'').replace(/"/g,'&quot;'))}}">${{esc(r.last_probed_utc||'')}}</td>`;
    const linkCount = r.found_links && typeof r.found_links === 'string' ? JSON.parse(r.found_links+'').length : 0;
    b += `<td>${{linkCount}}</td>`;
    b += `</tr>`;
  }}
  document.getElementById('body').innerHTML = b;

  // Pagination
  let pg = '';
  pg += `<button ${{page<=1?'disabled':''}} onclick="goPage(page-1)">prev</button>`;
  pg += `<span>${{page}}/${{total}} (${{rows.length}})</span>`;
  pg += `<button ${{page>=total?'disabled':''}} onclick="goPage(page+1)">next</button>`;
  document.getElementById('pager').innerHTML = pg;

  // Stats
  const ok    = DATA.filter(r=>r.reachable).length;
  const down  = DATA.length - ok;
  document.getElementById('stats').innerHTML =
    `<span>Total: ${{DATA.length}}</span>
     <span class="ok">Reachable: ${{ok}}</span>
     <span class="down">Unreachable: ${{down}}</span>
     <span>Showing: ${{rows.length}} filtered</span>`;

  // Footer
  document.getElementById('footer').innerHTML =
    `Generated {FOOTER_TIMESTAMP} · I2P Indexer Address Book`;
}}

function goPage(n){{ page=n; render(); }}
function esc(s){{return(typeof s==='string')?s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'):'';}}

// --- Event listeners -----------------------------------------------------
document.getElementById('head').addEventListener('click',e=>{{
  const th=e.target.closest('th');
  if(!th) return;
  const key=th.dataset.key;
  if(sortKey===key) sortAsc=!sortAsc; else{{sortKey=key; sortAsc=true;}}
  page=1; render();
}});

document.getElementById('filter').addEventListener('input',e=>{{
  filterText=e.target.value; page=1; render();
}});

document.getElementById('show-unreachable').checked = true; // default on
document.getElementById('show-unreachable').addEventListener('change',e=>{{
  showUnreachable=e.target.checked; page=1; render();
}});

document.getElementById('pageSize').value = pageSize;
document.getElementById('pageSize').addEventListener('change',e=>{{
  pageSize=parseInt(e.target.value); page=1; render();
}});

document.getElementById('reset-btn').addEventListener('click',()=>{{
  filterText=''; document.getElementById('filter').value='';
  showUnreachable=true; document.getElementById('show-unreachable').checked=true;
  pageSize=50; document.getElementById('pageSize').value='50';
  sortKey='dns_name'; sortAsc=false; page=1; render();
}});

// --- Init ----------------------------------------------------------------
render();
</script>
</body>
</html>
"""


def generate_address_book_html(db_path: str, output_dir: str) -> pathlib.Path:
    """Generate a self-contained HTML address book from the I2P Indexer database.

    Reads the ``address_book`` view via :func:`get_address_book`, transforms raw
    fields into display strings, embeds the dataset as compact JSON inside an
    HTML template (dark theme, sortable table, pagination), and writes the
    result to *output_dir/address_book.html*.

    Args:
        db_path: Path to the I2P Indexer SQLite database.
        output_dir: Directory to write the HTML file into (created if missing).

    Returns:
        Absolute path to the generated ``address_book.html``.
    """
    # 1. Fetch all rows from the address book view
    raw_rows = get_address_book(db_path)

    # 2. Transform into embed-friendly display rows
    payload = [_transform_row(r) for r in raw_rows]

    # 3. Serialize to JSON with newlines (browsers cannot parse ~650 KB on a
    #     single line — V8/tokeniser silently drops the <script>).
    data_json = json.dumps(payload, indent=2)

    # Timestamp for footer
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    # 4. Render HTML template (data_json is indented JSON so browsers can
    #     parse it across multiple lines — avoids single-line ~650 KB limit)
    html = (
        HTML_TEMPLATE
        .replace("{DATA_JSON}", data_json)
        .replace("{FOOTER_TIMESTAMP}", timestamp)
        # The template uses doubled braces ({{}}) to guard against accidental
        # f-string interpolation.  Collapse them back to single braces now.
        .replace("{{", "{").replace("}}", "}")
    )

    # 5. Write to output directory
    out_path = pathlib.Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    target = out_path / "address_book.html"
    target.write_text(html, encoding="utf-8")
    return target.resolve()


def generate_address_book_txt(db_path: str, output_dir: str) -> pathlib.Path:
    """Generate an I2P router addressbook-style TXT file.

    Reads the ``address_book`` view via :func:`get_address_book`, formats each
    destination as a comment + key=value pair pair in the classic hosts.txt
    format used by I2P routers, and writes to *output_dir/address_book_hosts.txt*.

    Args:
        db_path: Path to the I2P Indexer SQLite database.
        output_dir: Directory to write the TXT file into (created if missing).

    Returns:
        Absolute path to the generated ``address_book_hosts.txt``.
    """
    # 1. Fetch all rows sorted by dns_name
    raw_rows = get_address_book(db_path)
    raw_rows.sort(key=lambda r: (r.get("dns_name") or "").lower())

    total = len(raw_rows)
    reachable_count = sum(1 for r in raw_rows if r.get("reachable"))
    down_count = total - reachable_count

    # 2. Header lines
    now_utc = datetime.utcnow()
    lines: list[str] = [
        f"# Address book: I2P Indexer (auto-generated by discovery probes)",
        f"# Exported: {now_utc.strftime('%a %b %d %H:%M:%S GMT %Y')}",
        f"# {total} entries",
        f"# Reachable: {reachable_count} | Down: {down_count}",
    ]

    # 3. Per-entry: comment line + key=value line
    for row in raw_rows:
        dns_name = row.get("dns_name", "") or ""
        b32 = (row.get("b32_addr") or "").strip().rstrip(".")
        reachable = bool(row.get("reachable"))
        status = "OK" if reachable else "DOWN"

        # Timestamp from last_probed_at (Unix epoch)
        probed_ts = row.get("last_probed_at")
        if probed_ts is not None:
            probed_str = datetime.utcfromtimestamp(probed_ts).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        else:
            probed_str = "N/A"

        if b32:
            comment = f"#{dns_name}: {b32}.b32.i2p [{status}] probed={probed_str}"
            value = f"{dns_name}={b32}.b32.i2p"
        else:
            comment = f"#{dns_name}:  [{status}] probed={probed_str}"
            value = f"{dns_name}="

        lines.append(comment)
        lines.append(value)

    # 4. Write to output directory
    out_path = pathlib.Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    target = out_path / "address_book_hosts.txt"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target.resolve()


def generate_index_html(output_dir: str) -> pathlib.Path:
    """Generate a project landing page with links to all exports and GitHub.

    Writes *index.html* into *output_dir*.

    Returns:
        Absolute path to the generated ``index.html``.
    """
    now_utc = datetime.utcnow()
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>I2P Indexer — Eepsite Discovery &amp; Cataloging</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;font-size:14px;color:#e0e0e0;
    background:#0a0a0f;line-height:1.6;max-width:820px;margin:0 auto;padding:32px 16px}}
h1{{font-size:24px;color:#fff;margin-bottom:4px;letter-spacing:-0.5px}}
h2{{font-size:16px;color:#aaa;margin:28px 0 8px;border-bottom:1px solid #222;padding-bottom:4px}}
h3{{font-size:13px;color:#888;margin:16px 0 6px}}
p{{margin:8px 0}}
a{{color:#5b9;text-decoration:none}} a:hover{{color:#7df;text-decoration:underline}}
code{{background:#14141a;padding:2px 6px;border-radius:3px;font-size:13px;color:#ccc}}
.hero{{text-align:center;padding:48px 0 32px;border-bottom:1px solid #222;margin-bottom:32px}}
.hero h1{{font-size:32px;margin-bottom:8px}}
.hero .subtitle{{color:#888;font-size:15px;max-width:600px;margin:0 auto}}
.hero .emoji{{font-size:48px;display:block;margin-bottom:16px}}
.links{{display:grid;gap:12px;margin:16px 0}}
.link-card{{display:flex;align-items:center;gap:12px;padding:14px 16px;
    background:#111;border:1px solid #2a2a30;border-radius:6px;text-decoration:none;color:#e0e0e0}}
.link-card:hover{{border-color:#5b9;background:#151520}}
.link-card .icon{{font-size:24px;flex-shrink:0;width:36px;text-align:center}}
.link-card .label{{font-weight:bold;font-size:14px}}
.link-card .desc{{font-size:12px;color:#888;margin-top:2px}}
.features{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:16px 0}}
.feature{{padding:14px;background:#111;border:1px solid #222;border-radius:6px}}
.feature h3{{margin:0 0 6px;color:#ccc}}
.feature p{{font-size:13px;color:#888;margin:0}}
pre{{background:#14141a;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px;margin:8px 0;border:1px solid #222}}
footer{{text-align:center;margin-top:48px;padding:16px;border-top:1px solid #222;
    font-size:12px;color:#555}}
</style>
</head>
<body>

<div class="hero">
  <span class="emoji">🦉</span>
  <h1>I2P Indexer</h1>
  <p class="subtitle">Client-side discovery and cataloging of I2P eepsites — probes, classifies, and exports a searchable address book from a local router daemon.</p>
</div>

<h2>Explore the Data</h2>
<div class="links">
  <a class="link-card" href="address_book_ui.html">
    <span class="icon">🔍</span>
    <div><div class="label">Interactive Address Book</div><div class="desc">Full interactive browse UI with sortable grid, search, filters, and per-entry detail panels.</div></div>
  </a>

  <a class="link-card" href="address_book.html">
    <span class="icon">📇</span>
    <div><div class="label">Address Book (Compact)</div><div class="desc">Self-contained HTML page with sortable table and embedded JSON — lightweight for slow connections.</div></div>
  </a>

  <a class="link-card" href="address_book_hosts.txt">
    <span class="icon">📋</span>
    <div><div class="label">Hosts Export</div><div class="desc">Plain text <code>dns=*.b32.i2p</code> format matching SUSI DNS export — importable by other I2P tools.</div></div>
  </a>

  <a class="link-card" href="https://github.com/BuboTheWise/I2P-Indexer">
    <span class="icon">⚡</span>
    <div><div class="label">Source on GitHub</div><div class="desc">View the code, report issues, or contribute extractors and sweep configurations.</div></div>
  </a>
</div>

<h2>What It Does</h2>
<div class="features">
  <div class="feature">
    <h3>B32-First Probing</h3>
    <p>Direct <code>*.b32.i2p</code> requests that bypass SU3/SUSI DNS — dramatically faster for dead targets.</p>
  </div>
  <div class="feature">
    <h3>Content Classification</h3>
    <p>Plugin-based extractors auto-classify sites into forums, blogs, marketplaces, wikis, and more.</p>
  </div>
  <div class="feature">
    <h3>Local Translation</h3>
    <p>Non-English summaries translated via Ollama (HY-MT2) — no external API calls required.</p>
  </div>
  <div class="feature">
    <h3>Sweep Filters</h3>
    <p>Probe subsets: reachable-only, needs-review, by content type, or crawl linked sites.</p>
  </div>
  <div class="feature">
    <h3>Persistent SQLite Store</h3>
    <p>All results survive across runs — query, re-probe, and track address drift over time.</p>
  </div>
  <div class="feature">
    <h3>Eepsite Export</h3>
    <p>Generate static HTML + text exports for hosting on I2P proxy servers with zero backend dependency.</p>
  </div>
</div>

<h2>Quick Start</h2>
<pre>
python3 probe_sweep.py export --browse-ui       # generate full interactive UI
python3 probe_sweep.py --sweep-filter reachable_only --ollama-url http://localhost:11434   # re-scan with translation
</pre>

<h2>License</h2>
<p><a href="https://github.com/BuboTheWise/I2P-Indexer/blob/master/LICENSE">MIT</a> — free for discovery, not surveillance.</p>

<footer>
  Generated by <a href="https://github.com/BuboTheWise/I2P-Indexer">I2P Indexer</a> · Exported {now_utc.strftime('%Y-%m-%d %H:%M UTC')}
</footer>

</body>
</html>"""

    out_path = pathlib.Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    target = out_path / "index.html"
    target.write_text(html, encoding="utf-8")
    return target.resolve()


# ---------------------------------------------------------------------------
# Enhanced browse UI (tabs, timeline, filters, language detection)
# ---------------------------------------------------------------------------

def _query_entries(db_path: str) -> list[dict]:
    """Fetch address_book rows and shape them for the enhanced browse UI JSON.

    Includes ``detected_lang`` and ``flags`` which the enhanced template consumes
    for filter dropdowns and row detail panels.  Since the ``address_book`` view
    does not expose these as top-level columns, we query the underlying
    discoveries table directly to get the latest probe per destination.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        # Get all rows from address_book view for base data
        ab_rows = get_address_book(db_path)

        # Build a mapping from ident_hash_hex to the actual detected_lang/flags
        # by querying discoveries for the latest probe per destination
        entries: list[dict] = []
        for r in ab_rows:
            # Parse flags JSON safely (DB stores it as a JSON string)
            flags_raw = r.get("flags")
            if isinstance(flags_raw, str):
                try:
                    flags_val = json.loads(flags_raw)
                except (json.JSONDecodeError, TypeError):
                    flags_val = []
            else:
                flags_val = flags_raw or []

            detected_lang = r.get("detected_lang", "") or ""
            # If the view didn't carry detected_lang as a column, we need to
            # fetch it from discoveries.  Try direct lookup first; if None/empty
            # then do a per-hash lookup.
            if not detected_lang:
                ident = r.get("ident_hash_hex", "")
                if ident:
                    cur2 = conn.cursor()
                    cur2.execute(
                        "SELECT detected_lang FROM discoveries "
                        "WHERE ident_hash_hex = ? ORDER BY probed_at DESC LIMIT 1",
                        (ident,),
                    )
                    hit = cur2.fetchone()
                    if hit and hit[0]:
                        detected_lang = hit[0]

            entries.append({
                "dns_name": r.get("dns_name", "") or "",
                "b32_addr": r.get("b32_addr", "") or "",
                "title": r.get("title", "") or "",
                "content_type": r.get("content_type", "") or "",
                "content_summary": (r.get("content_summary") or "").replace("\n", " "),
                "deep_site_type": r.get("deep_site_type", "") or "",
                "deep_purpose": (r.get("deep_purpose", "") or "").replace("\n", " "),
                "deep_analyzed_at": r.get("deep_analyzed_at", "") or "",
                "deep_analysis_json": r.get("deep_analysis", ""),
                "reachable": bool(r.get("reachable", False)),
                "last_probed_utc": r.get("last_probed_utc", "") or "",
                "response_time_sec": r.get("response_time_sec") or 0,
                "body_length": r.get("body_length") or 0,
                "bandwidth_kbps": r.get("bandwidth_kbps"),
                "detected_lang": detected_lang,
                "found_links": (r.get("found_links") or "[]"),
                "flags": flags_val,
                "interest_score": r.get("interest_score"),
                "interest_reasons": (r.get("interest_reasons", "") or ""),
                "content_depth": r.get("content_depth") or 0.0,
                "stability_index": r.get("stability_index") or 0.0,
            })

        return entries
    finally:
        conn.close()


def _query_reachability_series(db_path: str, bucket: str = 'hour') -> list[dict]:
    """Aggregate probe events into hourly buckets for the reachability trends chart.

    Returns a list of dicts with keys:
      - ts_utc: ISO-ish timestamp string for the bucket start (e.g. '2026-08-05 10:00')
      - total_probes: number of probe events in this bucket
      - reachable: number of probes that reached their destination
      - unreachable: number that did not
      - pct: reachability percentage (0-100)

    The aggregation window is driven by *bucket* ('hour' or 'day').  Hourly gives
    finer-grained sparkline data; daily collapses to one point per calendar day.
    """
    conn = sqlite3.connect(db_path)
    try:
        label = "strftime('%Y-%m-%d %H:00', datetime(probed_at, 'unixepoch'))"
        if bucket == 'day':
            label = "DATE(datetime(probed_at, 'unixepoch'))"

        cur = conn.cursor()
        cur.execute(f"""
            SELECT {label} AS ts_utc,
                   COUNT(*)                        AS total_probes,
                   SUM(CASE WHEN reachable=1 THEN 1 ELSE 0 END) AS reachable,
                   SUM(CASE WHEN reachable=0 THEN 1 ELSE 0 END) AS unreachable
            FROM discoveries
            GROUP BY {label}
            ORDER BY ts_utc ASC
        """)

        results: list[dict] = []
        for ts_utc, total, reached, unreach in cur.fetchall():
            pct_val = round(100.0 * reached / total) if total > 0 else 0.0
            # Include unique destination count per bucket (more meaningful than raw probe count)
            results.append({
                "ts_utc": ts_utc,
                "total_probes": total,
                "reachable": reached,
                "unreachable": unreach,
                "pct": pct_val,
            })
        return results
    finally:
        conn.close()


def _query_timeline(db_path: str) -> list[dict]:
    """Fetch the latest discovery per destination for the timeline tab.

    Returns one row per *ident_hash_hex* showing when it was last probed,
    whether it was reachable, and the HTTP status code — exactly what the
    enhanced template's timeline column expects.  Uses ``b32_addr`` as a
    readable fallback when ``i2p_dns_name`` is empty.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT d.i2p_dns_name,
                   CASE WHEN d.reachable THEN 1 ELSE 0 END AS reachable,
                   d.status_code,
                   datetime(d.probed_at, 'unixepoch') AS probed_at_utc
            FROM discoveries d
            INNER JOIN (
                SELECT ident_hash_hex, MAX(probed_at) AS max_probed
                FROM discoveries GROUP BY ident_hash_hex
            ) latest ON d.ident_hash_hex = latest.ident_hash_hex
                    AND d.probed_at = latest.max_probed
            ORDER BY d.probed_at DESC
        """)
        results: list[dict] = []
        for dns_name, reachable, status_code, probed_at_utc in cur.fetchall():
            # Use b32_addr as fallback when i2p_dns_name is empty/missing
            if not dns_name:
                cur2 = conn.cursor()
                cur2.execute(
                    "SELECT b32_addr FROM discoveries "
                    "WHERE ident_hash_hex = (SELECT ident_hash_hex FROM discoveries "
                    "  WHERE probed_at = ? LIMIT 1) LIMIT 1",
                    (datetime.strptime(probed_at_utc, "%Y-%m-%d %H:%M:%S")
                     .replace(tzinfo=timezone.utc).timestamp(),),
                )
                hit = cur2.fetchone()
                dns_name = hit[0] if hit else ""
            results.append({
                "dns_name": dns_name or "",
                "reachable": reachable,
                "status_code": status_code,
                "probed_at_utc": probed_at_utc,
            })
        return results
    finally:
        conn.close()


def generate_address_book_ui(
    db_path: str,
    output_dir: str,
    template_path: pathlib.Path | None = None,
    output_filename: str = "address_book_ui.html",
) -> pathlib.Path:
    """Generate the enhanced browse UI HTML with tabs, timeline, and filters.

    Uses ``browse_template.html`` from the source tree which provides a richer
    interface than :func:`generate_address_book_html` — tabbed navigation,
    interactive timeline view, type/language/status filters, row expansion
    panels, and dark theme matching the project style guide.

    Args:
        db_path: Path to the I2P Indexer SQLite database.
        output_dir: Directory to write the HTML file into (created if missing).
        template_path: Optional explicit path to the browse template.
            Defaults to ``src/browse_template.html`` alongside this module.

    Returns:
        Absolute path to the generated ``address_book_ui.html``.
    """
    # 1. Load template
    tmpl = template_path or _TEMPLATE_DIR
    html_template = tmpl.read_text(encoding="utf-8")

    # 2. Fetch data
    entries = _query_entries(db_path)
    items_timeline = _query_timeline(db_path)
    series = _query_reachability_series(db_path, bucket='hour')

    # 3. Serialize JSON payloads
    entries_json = json.dumps(entries, ensure_ascii=False)
    timeline_json = json.dumps(items_timeline, ensure_ascii=False)
    series_json = json.dumps(series, ensure_ascii=False)

    # Timestamp for header/footer
    export_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    # 4. Render template by replacing placeholders
    html = (
        html_template
        .replace("__ENTRIES_JSON__", entries_json)
        .replace("__TIMELINE_JSON__", timeline_json)
        .replace("__REACHABILITY_SERIES_JSON__", series_json)
        .replace("__EXPORT_TS__", export_ts)
    )

    # 5. Write to output directory
    out_path = pathlib.Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    # Use configurable output filename, defaulting to address_book_ui.html
    target = out_path / output_filename
    target.write_text(html, encoding="utf-8")
    return target.resolve()
