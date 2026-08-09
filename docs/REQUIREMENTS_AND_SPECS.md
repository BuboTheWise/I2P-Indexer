# Product Specification

## 1. Purpose

The I2P Indexer is a client-side discovery and cataloging tool for the Invisible Internet Project (I2P) overlay network. Its mission is to systematically probe known `.i2p` destinations, record reachability data, classify content, and persist results in a queryable SQLite database — all through a local I2P router daemon without browser automation or system-level changes.

## 2. User Story

> As an operator monitoring the I2P darknet, I want to probe a list of known destinations, record which are currently reachable, classify what kind of content they serve, and persist that data across sessions so I can analyze trends over time.

## 3. Functional Requirements

### FR-01: Proxy Connectivity
The system shall connect to a local I2P daemon via HTTP proxy (port 4444) with automatic fallback to SOCKS5 (port 7656). If both backends fail, the fetch raises an error — no silent retries on dead networks.

### FR-02: Hash-First Probing
The system shall derive `.b32.i2p` addresses from SHA-1 identity hashes and attempt direct key-based HTTP requests **before** trying human-readable `.i2p` DNS names. This eliminates SU3/SUSI dependency for all hash-known destinations.

### FR-03: Dual-Mode Discovery
When both a hash and a DNS name are known, the system shall probe via both paths independently and record which succeeded. The `via_method` field captures `'b32'`, `'dns'`, or `'b32+dns'`.

### FR-04: Persistent Storage
All probe results shall be stored in a SQLite database (`indexer.db`) with WAL journal mode. The schema supports unlimited re-probes of the same destination — each attempt becomes a new row in `discoveries`.

### FR-05: Content Classification and Language Detection
On successful fetch, the system shall classify page content into a bucket (forum, wiki, blog, etc.) via offline keyword matching and generate a sentence-length summary. The system detects non-English content using `langid` (local, ~1 MB model) and stores ISO 639-1 language codes in the `detected_lang` column for structured filtering. **No external API or LLM call is made at probe time** — all processing is local per NFR-07.

### FR-06: Addressbook Parsing
The system shall scan the I2P `netdb/` directory for `.rtr` and `.ls64` binary files, parse them into `RouterInfo` and `LeaseSetInfo` dataclasses, and persist metadata to `routers` and `leasesets` tables.

### FR-07: Query Interface
The system shall provide a `query_db()` helper that accepts an identifier (hash or DNS name) and returns matching discovery records. Results include all content analysis fields (`content_type`, `content_summary`).

### FR-08: Terminal Report
The system shall render probe results as a formatted terminal report via `print_report()`, including status, response size, latency, and content classification.

### FR-09: Address Book View
The system shall expose an SQL view (`address_book`) that collapses multi-probe history into one row per "human identity." The dedup key is the DNS name when present (non-empty), otherwise the b32 address. Each row joins with `routers` and `leasesets` metadata via `ident_hash_hex`. Access via `get_address_book()`  → `list[dict]` and `print_address_book(entries)` for terminal display.

## 4. Non-Functional Requirements

### NFR-01: No Browser Automation
Selenium, Playwright, Puppeteer, and any headless browser tools are **prohibited**. All network interaction must be pure HTTP/SOCKS5 via `httpx`, `PySocks`, or standard library.

### NFR-02: Immutable Daemon Dependency
The I2P router daemon runs in Docker on the host. The indexer shall never install, configure, or modify it. No changes to `/etc/i2p/`, system packages, or systemd units.

### NFR-03: Test Parity
Every new module or significant change must include corresponding unit tests before merging. Target coverage is "all public methods exercised" — not a specific percentage metric. Tests run in isolation (in-memory DBs, mocked network).

### NFR-04: Credential Isolation
All tokens, tunnel keys, passwords, and proxy credentials must be parameterized and never committed to version control. `.env` files are ignored via `.gitignore`.

### NFR-05: Deterministic Identity Model
The canonical identity of every destination is its 40-character `ident_hash_hex`. All joins, lookups, and deduplication happen on this field — not on DNS names or base32 addresses (which can change).

### NFR-06: Graceful Degradation
Network failures shall be logged but never crash the probe loop. The indexer continues probing subsequent targets after any individual fetch timeout or connection error.

### NFR-07: Strict Offline Processing — Zero External Telemetry (**MANDATORY**)

All content processing — including language detection, classification, summarization, and translation — **must execute entirely on the local host machine**. Under no circumstances shall crawled I2P destination content (titles, summaries, body text, metadata) be sent to third-party services, cloud APIs, or any network endpoint outside the configured I2P tunnel.

**Rationale:** The I2P Indexer crawls destinations on anonymized overlay networks. Sending their content to external services (Google Translate, OpenAI APIs, language model inference endpoints, analytics trackers) constitutes an **extreme privacy violation** — it deanonymizes crawled sites, creates surveillance vectors, and defeats the core security model of the project.

**Specifically prohibited:**
- Cloud translation APIs (Google Translate, DeepL, Microsoft Translator, LibreTranslate hosted instances)
- LLM inference endpoints (OpenAI, Anthropic, Cohere, any hosted model API)
- Language detection services that phone home (`langdetect` with online fallbacks, `fasttext` with remote model downloads at runtime)
- Any library that makes HTTP requests as part of its normal operation
- Telemetry, usage tracking, or update-checking embedded in dependencies

**Permitted local-only tools:**
- `langid` — lightweight (~1 MB), CPU-only language detection, no network calls
- Bundled dictionaries, static phrase tables, rule-based transliteration packages
- Locally hosted quantized models (GGUF, ONNX) that run entirely on-CPU with update checking disabled
- Any library whose dependency tree contains zero outbound HTTP clients

**Enforcement:** All new dependencies must pass `external-package-audit` before being added to `requirements.txt`. Any library discovered to make external network calls must be replaced or sandboxed. This requirement **cannot be overridden** by convenience, speed, or accuracy trade-offs.

## 5. Constraints

| Constraint | Detail |
|---|---|
| Python version | 3.11+ only |
| Network latency | I2P tunnels average 1–10 seconds; timeouts set to 5s per-request with no retry storm |
| Firewall | Host firewall blocks all inbound traffic — daemon binds localhost only |
| SAM API | Port 9025 not exposed by Docker configuration; SAM client exists but is unusable |
| Java web console | CSRF-protected AJAX-loaded data at port 7657 — **not scrapable** via curl |

## 6. Future Work (Out of Scope for MVP)

- LLM-powered re-classification of `content_summary` fields post-probe (**only using local models — NFR-07**)
- **Translation is live via `translate_summaries.py`** — connects to a local Ollama instance (HY-MT2 model), runs as a standalone pass decoupled from probe sweeps. Still fully on-device per NFR-07. Future enhancements could include configurable models and batch parallel translation.
- Parallel probe execution (current design is sequential for reliability)
- Automatic destination discovery beyond the known list (crawling new links from fetched pages)
- Web UI for browsing the SQLite database contents
- Historical reachability trend graphs

## 7. Success Criteria

The system is considered production-ready when:
1. All 100+ tests pass with proper isolation (no real network calls in test suite).
2. The live probe cycle successfully reaches at least one known destination via `fetch_i2p()`.
3. The SQLite database persists across runs without schema migration issues.
4. Content classification correctly buckets ≥80% of manually verified destinations.
