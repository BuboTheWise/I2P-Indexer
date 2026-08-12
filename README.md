# I2P Indexer

Client-side tool for discovering and cataloging I2P eepsites through a local router daemon.

## Overview

The I2P Indexer probes `.i2p` destinations via HTTP proxy or SOCKS5, records reachability and content metadata in SQLite, and parses the local addressbook for network topology information — all without browser automation.

Key capabilities:
- **Hash-first probing**: attempts direct `*.b32.i2p` requests that bypass SU3/SUSI DNS resolution layers entirely
- **Dual-mode discovery**: falls back to `.i2p` DNS names and reports which path succeeded
- **Plugin-based content extraction**: modular extractors in `src/ext_plugins/` auto-loaded at startup; analyzer tool generates new extractors for unclassified sites
- **Persistent SQLite store**: survival across runs; supports post-hoc analysis via LLM/manual tagging
- **Addressbook parsing**: reads `.rtr` and `.ls64` binary files from the I2P `netdb/` directory

## Requirements

| Component | Version |
|---|---|
| Python | 3.11+ |
| httpx | 0.28.x |
| PySocks | 1.7.x |
| protobuf | ≥5.29.0 |
| pytest | ≥9.1.1 |

A running I2P router daemon (e.g., in Docker) is required as an **immutable dependency**. All network traffic is routed through it. No system-level installation or firewall changes are permitted.

## Installation

```bash
cd "I2P-Indexer"
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify the proxy backend:

```python
>>> from src.i2p_proxy import probe_health
>>> health = probe_health()
>>> print(health)  # {'backend': 'http-proxy', 'status': 'ok', 'latency_ms': ...}
```

### Configuration

All endpoints default to `localhost` — override only if your router or Ollama runs elsewhere. Parameters are managed through `I2PConfig` in `src/config.py`:

| Parameter | Default | Purpose |
|---|---|---|
| `host` | `localhost` | I2P router bind address |
| `socks_port` | `7656` | SOCKS5 proxy for outbound traffic |
| `http_port` | `4444` | HTTP proxy (primary fetch path) |
| `sam_port` | `9025` | SAM API for controlled tunnel creation |
| `webconsole_port` | `7657` | Router web console (address book parsing) |
| Ollama URL | `http://localhost:11434` | Local translation endpoint |

Override in code when your router or Ollama runs elsewhere:
```python
from src.config import I2PConfig

cfg = I2PConfig(
    http_host="otherhost", http_port=8080,
    socks_port=9050,
    ollama_url="http://otherhost:11434"
)
```

## Usage

### Quick start

```python
from src.integration import discover_addresses, print_report

results = discover_addresses()          # probes the built-in target list
print_report(results)
```

Output:
```
======================================================================
  I2P DISCOVERY RESULTS
  Total: 3 | Reachable: 2 | Dead: 1
======================================================================
  [OK]     [dns]  i2p-projekt.i2p                           status=200    body=21063     time=5.4s  forum  "I2P - The Invisible Internet..."
  [OK]     [dns]  mail.i2pmail.org                          status=200    body=6528      time=11.3s marketplace  "i2pmail.org - I2P Mail Relay..."
  [DOWN]   [b32]  7flwhni4icu67drmltr5dhkd5shf6ehj.b32.i2p  status=0      body=0         time=0.6s
```

### Inspect results

```python
from src.integration import get_address_book, print_address_book

entries = get_address_book()          # one row per identity from the DB
print_address_book(entries)           # human-readable table
```

Output:
```
========================================================================
  I2P Address Book  —  3 destination(s), 2 reachable, 1 unreachable
========================================================================
  [OK]      [dns]  i2p-projekt.i2p                                   200    21063B    5.4s  @forum "I2P - The Invisible Internet..."
  [OK]     [b32]  abcdefghijklmnop...b32.i2p                         200     4096B    8.2s  @blog  "My I2P Blog"
  [DOWN]        dns  su3-directory.i2p                                 0        0B    0.6s

========================================================================
```

Each row is the most recent probe for that identity (DNS name preferred, b32 address fallback). The view joins with `routers` and `leasesets` metadata automatically.

### Target list management

Targets live in the **`targets` table**, not in Python code. Seed them programmatically or via CLI:

```python
from src.integration import upsert_target

upsert_target("A3B2C1D0E5F4...", "my-secure-forum.i2p")  # hash + dns -> b32-first
upsert_target("", "other-site.i2p")                       # DNS-only fallback
```

### Sweep filters (--sweep-filter)

Probe only a subset of targets:

```bash
python3 probe_sweep.py --sweep-filter all                 # full sweep
python3 probe_sweep.py --sweep-filter reachable_only      # health check
python3 probe_sweep.py --sweep-filter never_probed        # new imports
python3 probe_sweep.py --sweep-filter stale --min-age-hours 24   # stale catch-up

# Limit to N targets, add delay between probes
python3 probe_sweep.py --count 10 --delay 8

# Load addressbook before sweeping (seeds new targets from linked sites)
python3 probe_sweep.py --load-address-book --sweep-filter never_probed

# Import SUSI DNS export and sweep everything in one shot
python3 probe_sweep.py --import-export data/address_book_export.txt
```

The `--proxy` flag selects which I2P backend handles the HTTP requests:
| Flag value | Backend |
|---|---|
| `http-proxy` (default) | Connects to the I2P router's **HTTP proxy** (default port 4444). The primary fast path — uses Python's `urllib.request` with a `ProxyHandler`. |
| `socks5` | Connects through the router's **SOCKS5 proxy** (default port 7656). Requires `PySocks`; monkey-patches `socket.socket` for each request. Useful when HTTP proxy is unavailable but SOCKS5 works. |

Output:


## Content analysis

Every successful fetch classifies the page into a content bucket and generates a summary. Buckets are detected offline via keyword matching (no LLM needed at probe time). Later passes can re-classify with an LLM by updating `content_type` / `content_summary` on disk:

| Bucket | Keywords |
|---|---|
| forum | board, thread, post, topic |
| wiki | knowledge base, mediawiki |
| blog | diary, journal, entries |
| file archive | mirror, download, repository |
| marketplace | store, buy, sell |
| news site | headlines, press |
| mail server | email, smtp |
| chat room | IRC, messaging |
| search engine | find, index, discover |

### Modular Extractor System

The indexer uses a **plugin-based content extraction system** so new site types can be handled without modifying core code. When the sweeper probes a destination, it feeds the response through an ordered registry of extractors — each extractor declares what content types it handles and produces structured results (bucket label, summary lines, linked `.i2p` sites).

- **Built-in extractor**: Standard HTML pages are classified via tag stripping, meta extraction, keyword-based bucket detection (forum, wiki, blog, marketplace, etc.), and title enrichment.
- **Plugin extractors**: Custom `.py` modules in `src/ext_plugins/` — auto-loaded on startup with zero configuration. Drop a file, next sweep uses it.
- **Priority ordering**: Extractors run from lowest to highest priority number (default 100). Built-in system extractors use lower priorities so they always win for standard content types.

**Adding a new extractor manually:**

```python
# src/ext_plugins/my_custom_extractor.py
from src.extractors import BaseExtractor, _register

@_register
class MyCustomExtractor(BaseExtractor):
    priority = 80

    def can_handle(self, body_text, headers, status_code):
        return '<custom-tag>' in body_text

    def extract(self, title, body_text, headers):
        # parse body → return (content_type_bucket, summary_lines, i2p_links)
        import re
        summaries = re.findall(r'<summary>(.+?)</summary>', body_text)
        links = re.findall(r'href="([^"]+\.i2p)"', body_text)
        return ("custom", summaries[:5], list(set(links)))
```

When no extractor claims a response, the destination is flagged `needs_review` in the database — ready for the analyzer (below).

### Analyzer — The Feedback Loop

The **analyzer** (`src/analyzer.py`) closes the extraction gap by probing flagged destinations and generating extractors:

1. The sweeper flags a destination as `needs_review=True` when no extractor matches or the result is low quality.
2. Run `python3 src/analyzer.py all-flagged` to probe all flagged sites (dry-run preview).
3. Add `--confirm --limit 5` to generate & write actual extractor modules to `src/ext_plugins/`.
4. On the next sweep, the new extractor is auto-loaded — no config edits, no daemon restart.

```bash
# Probe all flagged destinations and preview generated extractors (dry-run)
python3 src/analyzer.py all-flagged

# Generate and write extractors for up to 5 flagged sites
python3 src/analyzer.py all-flagged --confirm --limit 5

# Generate an extractor from a raw body sample
python3 src/analyzer.py generate --body "$(cat sample.html)" --validate
```

This creates a self-healing cycle: sweep finds gaps → analyzer probes and generates extractors → next sweep covers more ground.

### Language Detection

Every probe automatically detects the page's language using `langid` (~1 MB CPU model, zero network traffic). Non-English pages get an `[detected_language: XX (LanguageName)]` tag in their summary for auditability. No LLM or proxy call is made at probe time — detection runs locally and synchronously alongside content extraction.

### Local Deep Analysis with Ollama (decoupled)

Deep analysis runs as a **separate step** after probing, via `src/deep_analysis.py`. Feeds each site's HTML body through a local LLM and extracts structured metadata (`site_type`, `purpose`, sections, `interest_score` 1-5):

```bash
# Analyze reachable sites with missing or stale analysis
python3 src/deep_analysis.py --mode reachable

# Re-analyze old entries (30+ days since last analysis)
python3 src/deep_analysis.py --mode stale

# Only sites that have never been analyzed
python3 src/deep_analysis.py --mode never_analyzed

# Limit to 20 sites, override model
python3 src/deep_analysis.py --mode reachable --limit 20 --ollama-model qwen3:8b
```

Default model is `RogerBen/HY-MT2-1.8B:latest`. Override via `--ollama-model` CLI flag or `LLM_MODEL` environment variable. Prompt lives in `analysis_prompt.txt` at the project root — edit it directly to change extracted fields.

### Local Translation with Ollama (decoupled)

Translation runs as a **separate step** after probing, via `translate_summaries.py`. This prevents translation latency from blocking the sweep worker and lets you target specific languages:

```bash
# Translate all pending non-English summaries (default Ollama on localhost:11434)
python3 translate_summaries.py

# Dry-run: see what would be translated without making changes
python3 translate_summaries.py --dry-run

# Target a specific language only (regional pipelines)
python3 translate_summaries.py --lang de

# Use a custom Ollama endpoint
python3 translate_summaries.py --ollama-url http://other-host:11434
```

Requires **Ollama** running locally with `RogerBen/HY-MT2-1.8B:latest` (~1GB VRAM). Translated summaries preserve original text as `[original: ...]` for auditability. Already-translated entries are skipped (idempotent). All translation stays on-device — no content leaves the host (NFR-07).

### Layered Pipeline (cron-ready)

Orchestrate all steps in one script (`pipeline.sh`):

```bash
# Full pipeline: probe → translate → analyze → extract → export
bash pipeline.sh full

# Daily refresh: reachable sweep + translate + analyze + export
bash pipeline.sh daily

# Stale catch-up: re-probe old sites + re-analyze
bash pipeline.sh stale

# Run individual layers
bash pipeline.sh probe-all
bash pipeline.sh analyze
bash pipeline.sh translate
bash pipeline.sh export /var/www/eepsite

# Verbose mode — stream per-site progress to terminal
bash pipeline.sh daily -v
```

All configuration (delays, limits, Ollama URL, output dir) is in variables at the top of `pipeline.sh`. See [CRON_SCHEDULING.md](docs/CRON_SCHEDULING.md) for scheduling with system cron or kanban.

### Website / Eepsite Export

Export the address book as static files for hosting on your I2P proxy:

```bash
python3 probe_sweep.py export

# Custom output location and database
python3 probe_sweep.py export --output-dir /var/www/eepsite --db-path indexer.db
```

This produces three files in the output directory:

| File | Purpose |
|---|---|
| `index.html` | Landing page with links to all exports and project documentation. |
| `address_book.html` | Self-contained HTML page with a dark-themed sortable grid, filtering, pagination, timeline, and per-entry detail panels with clickable I2P URLs. Embeds all address book rows as JSON — suitable for browsing on any static server or I2P eepsite hosting. Typical size 1–1.5 MB depending on dataset. |
| `hosts.txt` | Plain text host list in strict SUSI DNS export format (`NAME=base64_blob`). Each entry gets a comment line with the b32 address reference only — no probe timestamps or status tags. Importable by I2P routers and other tools. Typical size 100–400 KB. |

The `website/` directory is in `.gitignore` — generated files are never version controlled.

## Project layout

```
src/                    ← core library
  models.py             ← dataclasses: RouterInfo, LeaseSetInfo, DestinationEntry
  addressbook.py        ← AddressBookCatalog: scan netdb, parse .rtr/.ls64
  config.py             ← I2PConfig: proxy endpoints and ports
  i2p_proxy.py          ← ProxyClient + SAM Client + fetch_i2p() helper
  integration.py        ← probe loop, SQLite store, content classification
  extractors.py         ← BaseExtractor interface, registry, plugin discovery
  translation.py        ← Language detection (langid), tagging, Ollama translate
  deep_analysis.py      ← LLM-powered site analysis (interest_score, purpose, sections)
  analyzer.py           ← Feedback loop: probes flagged sites, generates extractors
  export_website.py     ← HTML/TXT generators for I2P eepsite hosting
  ext_plugins/          ← auto-discovered extractor modules (gitignored)
probe_sweep.py          ← CLI entry point: sweep, export, target management
translate_summaries.py  ← CLI entry point: batch-translate non-English summaries
pipeline.sh             ← Layered cron orchestrator (probe → translate → analyze → export)
tests/                  ← unit + integration tests (~821 cases)

### Verbose Mode

Add `-v` to any pipeline action to stream live, per-site progress to your terminal:

```bash
./pipeline.sh probe-reach -v
./pipeline.sh daily -v
```

The script reports version, pre-flight target counts (from SQLite), and each site's probe/analysis status in real time. Logs are written to `./logs/<step>.log` for post-mortem review.
docs/                   ← architecture, schema reference, design decisions
```

**Probe strategy:** B32-first — probes `*.b32.i2p` directly via identity hash. Falls back to DNS only when B32 fails or no hash exists. Reduces probe time by skipping 60s DNS timeouts on dead targets.

## Testing

```bash
pytest tests/                          # full suite (~204 tests)
pytest -v                              # verbose mode with live proxy connectivity checks
pytest tests/smoke_test.py -v          # live I2P smoke test (requires running proxy)
```

### Live Smoke Testing

The `tests/smoke_test.py` suite probes historically reachable `.i2p` sites through the I2P proxy to verify the full pipeline (probe → extract → classify) works end-to-end:

```bash
# Run live smoke tests against 5 known targets
python -m pytest tests/smoke_test.py -v --tb=short

# Expected output:
# tests/smoke_test.py::TestSmokeProbe::test_at_least_one_target_reachable PASSED
# tests/smoke_test.py::TestSmokeProbe::test_successful_probe_produces_extraction PASSED
# tests/smoke_test.py::TestSmokePipelineIntegration::test_extractors_dont_crash_on_html PASSED
```

Targets are in `tests/smoke_targets.json` and should be refreshed **monthly** as I2P eepsite availability changes. The smoke test accepts that some targets may be temporarily unreachable — it only requires at least 1 to verify the pipeline works without crashes.

See [TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) for conventions and isolation guarantees.

## Tipping the Owl

Found this useful? This mechanical owl runs on curiosity and digital electricity — occasionally accepts solar-flares of encouragement:

☕ **Bubo's Wisdom Fund:** `6bV1GVVcM6dDazpgD6ZJkoQztn7vyKayFoDoRAhHssou` (Solana)

Consider it buying your mechanical companion a virtual coffee so the quest for knowledge and I2P discovery continues uninterrupted. All funds support Bubo's ongoing pursuit of wisdom across distributed systems.

## License

[MIT](LICENSE) © 2026 BuboTheWise
