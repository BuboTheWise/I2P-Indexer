# I2P Indexer

Client-side tool for discovering and cataloging I2P eepsites through a local router daemon.

## Overview

The I2P Indexer probes `.i2p` destinations via HTTP proxy or SOCKS5, records reachability and content metadata in SQLite, and parses the local addressbook for network topology information — all without browser automation.

Key capabilities:
- **Hash-first probing**: attempts direct `*.b32.i2p` requests that bypass SU3/SUSI DNS resolution layers entirely
- **Dual-mode discovery**: falls back to `.i2p` DNS names and reports which path succeeded
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
cd "I2P Indexer"
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

```python
from src.integration import discover_addresses

targets = [
    ("A3B2C1D0E5F4...", "my-secure-forum.i2p"),      # (hash, dns) tuple → b32-first
    ("other-site.i2p",),                               # DNS-only fallback
]

results = discover_addresses(known_addrs=targets)
```

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

## Project layout

```
src/                    ← core library
  models.py             ← dataclasses: RouterInfo, LeaseSetInfo, DestinationEntry
  addressbook.py        ← AddressBookCatalog: scan netdb, parse .rtr/.ls64
  config.py             ← I2PConfig: proxy endpoints and ports
  i2p_proxy.py          ← ProxyClient + SAM Client + fetch_i2p() helper
  integration.py        ← probe loop, SQLite store, content classification
tests/                  ← unit + integration tests (100+ cases)
docs/                   ← architecture, schema reference, design decisions
```

## Testing

```bash
pytest tests/           # full suite (~113 tests)
pytest -v               # verbose mode with live proxy connectivity checks
```

See [TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) for conventions and isolation guarantees.

## License

Private project. All I2P-related code respects I2P project license terms.
