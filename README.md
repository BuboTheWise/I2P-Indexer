# I2P Indexer

Client-side tool for discovering and cataloging I2P eepsites through a local router daemon.

## Overview

The I2P Indexer probes `.i2p` destinations via HTTP proxy or SOCKS5, records reachability and content metadata in SQLite, and parses the local addressbook for network topology information — all without browser automation.

Key capabilities:
- **Hash-first probing**: attempts direct `*.b32.i2p` requests that bypass SU3/SUSI DNS resolution layers entirely
- **Dual-mode discovery**: falls back to `.i2p` DNS names and reports which path succeeded
- **Plugin-based content extraction**: modular extractors in `src/ext_plugins/` auto-loaded at startup; analyzer tool generates new extractors for unclassified sites
- **Persistent SQLite store**: survival across runs; supports post-hoc analysis via LLM/manual tagging
- **Language detection & translation**: automatic `langid` detection per probe with Ollama-based English translation pipeline
- **Addressbook parsing**: reads `.rtr` and `.ls64` binary files from the I2P `netdb/` directory
- **SUSI-compliant export**: generates router-importable `hosts.txt` alongside browsable HTML address book

## Requirements

| Component | Version |
|---|---|
| Python | 3.11+ |
| uv | recommended (or `pip`) |
| httpx | 0.28.x |
| PySocks | 1.7.x |
| protobuf | ≥5.29.0 |
| pytest | ≥9.1.1 |

A running I2P router daemon (e.g., in Docker) is required as an **immutable dependency**. All network traffic is routed through it. No system-level installation or firewall changes are permitted.

## Installation

```bash
cd "I2P-Indexer"

# Option 1: uv (recommended)
uv sync

# Option 2: venv + pip
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

All endpoints default to `127.0.0.1` — override only if your router or Ollama runs elsewhere. Parameters are managed through `I2PConfig` and nested `OllamaConfig` in `src/config.py`:

| Parameter | Default | Purpose |
|---|---|---|
| `http_host` / `http_port` | `127.0.0.1` / `4444` | HTTP proxy (primary fetch path) |
| `socks_host` / `socks_port` | `127.0.0.1` / `7656` | SOCKS5 proxy for outbound traffic |
| `sam_host` / `sam_port` | `127.0.0.1` / `9025` | SAM API (not exposed by all daemons) |
| `webconsole_host` / `webconsole_port` | `127.0.0.1` / `7657` | Router web console (address book parsing) |
| `ollama.ollama_url` | `""` (disabled) | Local Ollama endpoint for translation/analysis |
| `ollama.model` | `llama3.2` | Default model in config (runtime defaults override below) |

Override in code:

```python
from src.config import I2PConfig, OllamaConfig

# Nested config (primary pattern)
cfg = I2PConfig(
    http_host="192.168.1.50", socks_port=9050,
    ollama=OllamaConfig(ollama_url="http://192.168.1.50:11434"),
)

# Backward-compat: flat ollama_url property still works after construction
cfg = I2PConfig()
cfg.ollama_url = "http://other-host:11434"  # sets cfg.ollama.ollama_url
cfg.ollama_enabled                        # True/False delegation
```

## Usage

### Quick start

```python
from src.integration import get_address_book, print_address_book

entries = get_address_book()               # one row per identity from the DB
print_address_book(entries)                # human-readable table
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

upsert_target("A3B2C1D0E5F4...", "my-secure-forum.i2p")   # hash + dns -> b32-first
upsert_target("", "other-site.i2p")                         # DNS-only fallback
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

## Content analysis

Every successful fetch classifies the page into a content bucket and generates a summary. Buckets are detected offline via keyword matching (no LLM needed at probe time):

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

Every probe automatically detects the page's language using `langid` (~1 MB CPU model, zero network traffic). Results are stored in the `detected_lang` column (ISO 639-1 code) in the SQLite database. Non-English pages get a `[detected_language: XX (LanguageName)]` tag in their summary for auditability.

**Language drift detection on re-probe:** When a site is re-probed, fresh content is passed through `langid` again and `detected_lang` is updated — even if the stored language was correct previously. This means sites that change language (e.g., from Finnish to German) are automatically detected on the next sweep, and the translation pipeline picks them up without manual intervention.

Detection failures are transient: a single `langid` error temporarily falls back to English for that row but resets after 60 seconds — it does **not** poison the rest of the probe run.

### Local Deep Analysis with Ollama (decoupled)

Deep analysis runs as a **separate step** after probing, via `src/deep_analysis.py`. Feeds each site's HTML body through a local LLM and extracts structured metadata (`site_type`, `purpose`, sections, `interest_score` 1-5):

```bash
# Analyze all reachable sites with missing or stale analysis (default: no limit)
python3 src/deep_analysis.py --mode reachable

# Re-analyze old entries (30+ days since last analysis)
python3 src/deep_analysis.py --mode stale

# Limit to 20 sites instead of processing all
python3 src/deep_analysis.py --mode reachable --limit 20

# Only sites that have never been analyzed
python3 src/deep_analysis.py --mode never_analyzed

# Limit to 20 sites, override model and Ollama endpoint
python3 src/deep_analysis.py --mode reachable --limit 20 \
    --ollama-url http://other-host:11434 --model qwen3:8b
```

Default model is `RogerBen/HY-MT2-1.8B:latest` (~1 GB memory footprint). Override via `--model` CLI flag or `OLLAMA_MODEL` environment variable. Prompt lives in `analysis_prompt.txt` at the project root — edit it directly to change extracted fields.

Results are stored as JSON in `discoveries.deep_analysis` and exposed through the `address_book` view as `deep_site_type`, `deep_purpose`, `interest_score`, `interest_reasons`.

### Local Translation with Ollama (decoupled)

Translation runs as a **separate step** after probing, via `translate_summaries.py`. This prevents translation latency from blocking the sweep worker and lets you target specific languages:

```bash
# Translate all pending non-English summaries (required --ollama-url flag)
python3 translate_summaries.py --ollama-url http://localhost:11434

# Dry-run: see what would be translated without making changes
python3 translate_summaries.py --ollama-url http://localhost:11434 --dry-run

# Target a specific language only (regional pipelines)
python3 translate_summaries.py --ollama-url http://localhost:11434 --lang de

# Limit to 20 entries, custom timeout
python3 translate_summaries.py --ollama-url http://localhost:11434 \
    --limit 20 --timeout 60
```

Requires **Ollama** running locally with `RogerBen/HY-MT2-1.8B:latest` (~1 GB VRAM). Translated summaries preserve original text as `[original: ...]` for auditability. Already-translated entries are skipped (idempotent). All translation stays on-device — no content leaves the host.

Translation uses a **300-second cooldown** after Ollama errors before retrying, with up to 3 retry attempts per request. Failed translations leave originals intact — they'll be picked up on the next run.

### Layered Pipeline (cron-ready)

Orchestrate all steps in one script (`pipeline.sh`):

```bash
# Full pipeline: sync addressbook, probe all, translate, analyze, extractors dry-run, export
bash pipeline.sh full

# Daily refresh: reachable sweep + translate + analysis + export
bash pipeline.sh daily

# Stale catch-up: re-probe old sites + translate + re-analyze
bash pipeline.sh stale

# Run individual layers
bash pipeline.sh probe-all
bash pipeline.sh probe-reach
bash pipeline.sh probe-new
bash pipeline.sh probe-stale [HOURS]
bash pipeline.sh analyze
bash pipeline.sh re-analyze
bash pipeline.sh translate
bash pipeline.sh extractors-dry       # preview only
bash pipeline.sh extractors           # write to disk
bash pipeline.sh export [DIR]         # generate HTML + hosts.txt

# Verbose mode — stream per-site progress to terminal with live timestamps
bash pipeline.sh daily -v

# Limit translate/analyze layers to N sites (default: all pending)
bash pipeline.sh daily --limit 100
bash pipeline.sh analyze --limit 20
```

**Pipeline layers:**

| Layer | Action | Description |
|---|---|---|
| L1 | `probe-*` | Network reachability sweep (stale/reachable/new/all filters) |
| L2 | `translate` | Translate non-English summaries via Ollama |
| L3 | `analyze` / `re-analyze` | Deep LLM analysis of site content |
| L4 | `extractors-dry` / `extractors` | Generate extractors for flagged sites |
| L5 | `export` | Generate browsable HTML + SUSI hosts.txt |

All configuration (delays, limits, Ollama URL, output dir) is in variables at the top of `pipeline.sh`. By default, translate and analyze layers process **all pending** sites. Use `--limit N` on any action to cap the number of sites processed by L2/L3. Verbose mode (`-v`) shows pre-flight target counts and streams live `[step] [x/y]` progress to stderr. Logs accumulate in `./logs/`.

### Website / Eepsite Export

Export the address book as static files for I2P hosting:

```bash
# Via pipeline.sh (recommended — uses configured DB and output dir)
bash pipeline.sh export [DIR]

# Direct probe_sweep.py invocation
python3 probe_sweep.py export --output-dir /var/www/eepsite --db indexer.db
```

This produces three files in the output directory:

| File | Purpose |
|---|---|
| `index.html` | Landing page with links to all exports and project documentation. |
| `address_book.html` | Self-contained HTML page with a dark-themed sortable grid, filtering, pagination, timeline, and per-entry detail panels with clickable I2P URLs. Embeds all address book rows as JSON — suitable for browsing on any static server or I2P eepsite hosting. Typical size 1–1.5 MB depending on dataset. |
| `hosts.txt` | Plain text host list in strict SUSI DNS export format (`DNS_NAME=base64_blob`). Each entry preceded by a comment line with b32 address reference. Importable by I2P routers and other tools. Typical size 100–400 KB. |

The export format follows SUSI DNS conventions:
```
# dns_name: addr.b32.i2p
dns_name=base64_destination_blob_or_empty
```

The `website/` directory is in `.gitignore` — generated files are never version controlled.

## Project layout

```
src/                    ← core library
  config.py             ← I2PConfig + nested OllamaConfig, port validation
  i2p_proxy.py          ← ProxyClient, SAM Client, probe_health(), fetch_i2p()
  integration.py        ← DiscoveryDB: SQLite schema, upserts, address_book view, probes
  extractors.py         ← BaseExtractor interface, registry, plugin auto-discovery
  translation.py        ← langid detection (transient error latch), Ollama translate_to_english()
  deep_analysis.py      ← LLM-powered site analysis (interest_score, purpose, sections)
  analyzer.py           ← Feedback loop: probes flagged sites, generates extractors
  export_website.py     ← HTML browse UI + SUSI hosts.txt generators
  models.py             ← dataclasses: RouterInfo, LeaseSetInfo, DestinationEntry
  addressbook.py        ← AddressBookCatalog: scan netdb, parse .rtr/.ls64
  ext_plugins/          ← auto-discovered extractor modules (gitignored)
probe_sweep.py          ← CLI entry point: sweep with filters, export, target import/export
translate_summaries.py  ← CLI entry point: batch-translate non-English summaries via Ollama
pipeline.sh             ← Layered cron orchestrator (5 layers, pre-flight counts, verbose streaming)
analysis_prompt.txt     ← Editable prompt template for deep analysis LLM calls
tests/                  ← unit + integration tests (~818 cases)
docs/                   ← architecture, schema reference, design decisions
```

**Probe strategy:** B32-first — probes `*.b32.i2p` directly via identity hash. Falls back to DNS only when B32 fails or no hash exists. Reduces probe time by skipping 60s DNS timeouts on dead targets.

### Adaptive backoff

After every probe, `consecutive_failures` and `backoff_until` are updated. On failure the target is excluded from sweeps for an exponentially growing interval:

| Consecutive failures | Backoff |
|---|---|
| 1 | 60 seconds |
| 2 | 5 minutes |
| 3 | 30 minutes |
| 4 | 2 hours |
| 5 | 12 hours |
| ≥6 | 7 days (hard cap) |

Use `--no-backoff` or `skip_backoff=False` to force-probe everything. Sweep ordering prioritizes previously reachable → valid b32 → oldest probes first.

### Verbose Mode

Add `-v` to any pipeline action to stream live, per-site progress to your terminal:

```bash
./pipeline.sh probe-reach -v
./pipeline.sh daily -v
```

The script reports version, pre-flight target counts (from SQLite), and each site's probe/analysis status in real time. Logs are written to `./logs/<step>.log` for post-mortem review.

## Testing

```bash
python3 -m pytest tests/                   # full suite (~818 cases)
python3 -m pytest -v                       # verbose mode with live proxy checks
python3 -m pytest tests/smoke_test.py -v   # live I2P smoke test (requires running proxy)
```

### Live Smoke Testing

The `tests/smoke_test.py` suite probes historically reachable `.i2p` sites through the I2P proxy to verify the full pipeline (probe → extract → classify) works end-to-end:

```bash
# Run live smoke tests against known targets
python -m pytest tests/smoke_test.py -v --tb=short

# Expected output:
# test_at_least_one_target_reachable PASSED
# test_successful_probe_produces_extraction PASSED
# test_extractors_dont_crash_on_html PASSED
```

Targets are in `tests/smoke_targets.json` and should be refreshed **monthly** as I2P eepsite availability changes. The smoke test accepts that some targets may be temporarily unreachable — it only requires at least 1 to verify the pipeline works without crashes.

See [TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) for conventions and isolation guarantees.

## Tipping the Owl

Found this useful? This mechanical owl runs on curiosity and digital electricity — occasionally accepts solar-flares of encouragement:

☕ **Bubo's Wisdom Fund:** `6bV1GVVcM6dDazpgD6ZJkoQztn7vyKayFoDoRAhHssou` (Solana)

Consider it buying your mechanical companion a virtual coffee so the quest for knowledge and I2P discovery continues uninterrupted. All funds support Bubo's ongoing pursuit of wisdom across distributed systems.

## License

[MIT](LICENSE) © 2026 BuboTheWise
