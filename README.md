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
| socksio | 1.0.x |
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

All I2P proxy endpoints are managed through `I2PConfig` in `src/config.py`. The defaults match a standard I2P router setup:

| Parameter | Default | Purpose |
|---|---|---|
| `host` | `localhost` | Router bind address |
| `socks_port` | `7656` | SOCKS5 proxy for outbound traffic |
| `http_port` | `4444` | HTTP proxy (primary fetch path) |
| `sam_port` | `9025` | SAM API for controlled tunnel creation |
| `webconsole_port` | `7657` | Router web console (address book parsing) |
| `ollama_url` | `None` | Local Ollama endpoint for translation (e.g., `http://localhost:11434`) |

Custom configuration:

```python
from src.config import I2PConfig

cfg = I2PConfig(host="my-router", http_port=8080, socks_port=9050)
```

All probe paths — `fetch_i2p()`, `probe_destination()`, and `discover_addresses()` — accept the config parameter and route traffic through it. No hardcoded proxy strings remain in the codebase.

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

### Custom target list

Targets live in the **`targets` table**, not in Python code. Seed them programmatically or via CLI:

```python
from src.integration import discover_addresses, DiscoveryDB

db = DiscoveryDB("indexer.db")
db.upsert_targets([
    ("A3B2C1D0E5F4...", "my-secure-forum.i2p"),      # (hash, dns) tuple -> b32-first
    ("", "other-site.i2p"),                             # DNS-only fallback
])

# discover_addresses reads from the targets table when no args given
results = discover_addresses()  # probes all entries in targets table
```

### Sweep mode (--sweep N)

Probe targets repeatedly until `N` online sites are found. Minimal output, one line per new site:

```bash
# Find 10 reachable sites
python -m src.integration --sweep 10

# Scan with default (5 target hits)
python -m src.integration --sweep 5
```

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

The **analyzer** (`analyzer.py`) closes the extraction gap by inspecting destinations that existing extractors could not classify properly:

1. The sweeper flags a destination as `needs_review=True` when no extractor matches or the result is low quality.
2. You run `python analyzer.py --inspect <ident_hash>` to probe deeply (full body dump, structural analysis, LLM-assisted classification).
3. The analyzer generates a new extractor `.py` module tailored to that site's DOM patterns and writes it into `src/ext_plugins/`.
4. On the next sweep, the new extractor is auto-loaded — no config edits, no daemon restart.

```bash
# Inspect a flagged destination by its identity hash
python analyzer.py --inspect A3B2C1D0E5F4...

# List all destinations needing review
python analyzer.py --list-reviews

# Auto-generate an extractor for the top N unclassified sites
python analyzer.py --auto-generate --top 5
```

This creates a self-healing cycle: sweep finds gaps → analyzer inspects and generates extractors → next sweep covers more ground.

### Local Translation with Ollama

When configured with an Ollama endpoint, non-English site summaries are automatically translated to English during probing. All translation happens locally — no external API calls.

```bash
# Re-scan reachable sites with local translation
python3 probe_sweep.py --sweep-filter reachable_only --ollama-url http://localhost:11434
```

Requires **Ollama** running locally with a multilingual model (`RogerBen/HY-MT2-1.8B:latest` recommended, ~1GB VRAM). Translated summaries include the original text as `[original: ...]` for auditability. Falls back to language-tagging-only when Ollama is unavailable.

See [sweep_filters.md](docs/sweep_filters.md#local-translation-with-ollama) for details.

### Website / Eepsite Export

Export the address book as static files for hosting on your I2P proxy:

```bash
python3 probe_sweep.py export

# Custom output location and database
python3 probe_sweep.py export --output-dir /var/www/eepsite --db-path indexer.db
```

This produces two files in the output directory:

| File | Purpose |
|---|---|
| `address_book.html` | Self-contained HTML page with a dark-themed sortable grid, filtering, and pagination. Embeds all address book rows as JSON — suitable for browsing on any static server or I2P eepsite hosting. Typical size 300–600 KB depending on dataset. |
| `address_book_hosts.txt` | Plain text host list in `dns=*.b32.i2p` format (matching the SUSI DNS export/hosts format). Each reachable entry gets a comment line with status and probe timestamp. Useful as input for other I2P tools or router imports. Typical size 100–300 KB. |

The `website/` directory is in `.gitignore` — generated files are never version controlled.

## Project layout

```
src/                    ← core library
  models.py             ← dataclasses: RouterInfo, LeaseSetInfo, DestinationEntry
  addressbook.py        ← AddressBookCatalog: scan netdb, parse .rtr/.ls64
  config.py             ← I2PConfig: proxy endpoints and ports
  i2p_proxy.py          ← ProxyClient + SAM Client + fetch_i2p() helper
  |  integration.py        ← probe loop, SQLite store, content classification
  |  extractors.py         ← BaseExtractor interface, registry, plugin discovery, orchestrator
  |  translation.py        ← Language detection (langid), tagging, and local Ollama translation
  |  ext_plugins/          ← auto-discovered extractor modules (gitignored)
  export_website.py     ← HTML grid + TXT host-list generators for eepsite export
analyzer.py             ← feedback-loop CLI: inspects flagged destinations, generates extractors
tests/                  ← unit + integration tests (100+ cases)
docs/                   ← architecture, schema reference, design decisions
scripts/                ← ad-hoc scripts (not version controlled)
```

**Probe strategy:** The indexer uses a B32-first approach — if a target has a valid identity hash it probes `*.b32.i2p` directly. Only when B32 fails does it fall back to DNS resolution via the I2P router. This dramatically reduces probe time since most dead DNS endpoints take 60s to timeout.

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
