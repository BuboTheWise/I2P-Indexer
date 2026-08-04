"""Export the I2P Address Book as a self-contained HTML page."""

from __future__ import annotations

import json
import math
import pathlib
from datetime import datetime, timezone
from typing import Any

from .integration import get_address_book


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
    bw = row.get("bandwidth_kbps")
    summary = row.get("content_summary", "") or ""
    found_links_raw = row.get("found_links", "[]")

    return {
        "dns_name": row.get("dns_name", "") or "",
        "title": row.get("title", "") or "",
        "content_type": row.get("content_type", "") or "",
        "content_summary": summary if summary else "Unidentified",
        "reachable": bool(row.get("reachable", False)),
        "last_probed_utc": row.get("last_probed_utc", "") or "",
        "_rt": _format_response_time(rt),
        "_size": _humanize_bytes(bl) if isinstance(bl, (int, type(None))) else "",
        "_bw": str(bw) if bw is not None and bw != "" else "",
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

/* --- Table (fixed-width grid) ------------------------------------------- */
table{{width:100%;border-collapse:collapse;table-layout:fixed;word-break:break-all}}
th,td{{padding:3px 6px;border:1px solid #222;text-overflow:ellipsis;overflow:hidden;white-space:nowrap}}
thead th{{position:sticky;top:0;background:#15151a;color:#aaa;cursor:pointer;user-select:none}}
thead th:hover{{background:#252530;color:#fff}}
thead .sort-asc::after{{content:' ▲'}} thead .sort-desc::after{{content:' ▼'}}

/* Column widths (fixed, predictable) */
  col.c-status{{width:64px;}} col.c-type{{width:90px;}}
  col.c-site{{width:auto;}} col.c-title{{width:120px;}}
  col.c-rt{{width:64px;}} col.c-size{{width:64px;}}
  col.c-time{{width:150px;}} col.c-bw{{width:70px;}} col.c-probe{{width:30px;}}

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
    <col class="c-rt">
    <col class="c-size">
    <col class="c-time">
    <col class="c-bw">
    <col class="c-probe">
  </colgroup>
  <thead id="head"></thead>
  <tbody   id="body"></tbody>
</table>
</div>

<div class="pager" id="pager"></div>
<div class="footer" id="footer"></div>

<script>
// --- Embedded dataset (compact) ------------------------------------------
const DATA = {DATA_JSON};

// --- Column definitions --------------------------------------------------
const COLS = [
  {{key:'_status',     label:'Status',    width:64}},
  {{key:'content_type',label:'Type',      width:90}},
  {{key:'dns_name',    label:'Site',       width:null}},
  {{key:'title',       label:'Title',     width:120}},
  {{key:'_rt',         label:'Resp T',    width:64}},
  {{key:'_size',       label:'Size',      width:64}},
  {{key:'last_probed_utc',label:'Last Probed',width:150}},
  {{key:'_bw',         label:'Bandwidth',width:70}},
  {{key:'_probe',      label:'#L',        width:30}},
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
      const haystack = [r.dns_name,r.title,r.content_type,r.content_summary]
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
    b += `<td>${{esc(r._rt||'')}}</td>`;
    b += `<td>${{esc(r._size||'')}}</td>`;
    b += `<td title="${{esc((r.content_summary||'').replace(/"/g,'&quot;'))}}">${{esc(r.last_probed_utc||'')}}</td>`;
    b += `<td>${{esc(r._bw||'')}}</td>`;
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

    # 3. Serialize to compact JSON (no extra whitespace — file can be 500KB+)
    data_json = json.dumps(payload, separators=(",", ":"))

    # Timestamp for footer
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    # 4. Render HTML template
    html = (
        HTML_TEMPLATE
        .replace("{DATA_JSON}", data_json)
        .replace("{FOOTER_TIMESTAMP}", timestamp)
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
