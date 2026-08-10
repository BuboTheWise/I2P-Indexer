# Design & Architecture

## System Philosophy

The I2P Indexer is a **client-side discovery engine**. Its purpose is to systematically probe known `.i2p` destinations through a local router daemon and persist reachability data for offline analysis. The project adheres to these core principles:

1. **Hash-first addressing**: The canonical identity of every destination is its 40-character SHA-1 `ident_hash_hex`. Base32 addresses (`*.b32.i2p`) are derived from the hash, bypassing SU3/SUSI DNS resolution entirely. `.i2p` human-readable names are a secondary fallback only.

2. **Zero browser automation**: All connectivity is pure code — `httpx`, `PySocks`, raw sockets, or CLI tools. Selenium, Playwright, and Puppeteer are prohibited.

3. **Immutable I2P dependency**: A local Docker-hosted I2P router is a fixed working proxy. The indexer never installs, configures, or modifies the daemon. All network traffic flows through it.

4. **Persistent state over ephemerality**: Probe results survive across runs via SQLite WAL-mode databases. This enables longitudinal tracking (e.g., "site was reachable Tuesday but not Thursday").

5. **Dependency injection for testability**: Every database path is parameterized. No global singletons exist, enabling isolated pytest fixtures with temporary in-memory databases.

## Component Architecture

```
┌─────────────────────────────────────┐
│         User / CLI Driver           │
│    (discover_addresses, probe)      │
├─────────────────────────────────────┤
│        Integration Layer           │  ← src/integration.py
│   · probe_destination()            │
│   · DiscoveryDB (SQLite persistence)│
│   · _classify_content()            │
├──────────┬──────────────────────────┤
│          │                         │
┌──────────▼──────┐     ┌───────────▼──────────┐
│  Proxy Layer    │     │  Addressbook Catalog  │
│  src/i2p_proxy  │     │  src/addressbook.py   │
│  · fetch_i2p() │     │  · scan netdb/        │
│  · I2PProxyClient│    │  · parse .rtr files   │
│  · I2PSAMClient │     │  · parse .ls64 files  │
└───────┬────────┘     └────────┬──────────────┘
        │                        │
┌───────▼────────────────────────▼──────────────┐
│            Running I2P Daemon (Docker)         │
│   · HTTP proxy  : 127.0.0.1:4444               │
│   · SOCKS5 proxy: 127.0.0.1:7656               │
│   · SAM API     : 127.0.0.9025 (not exposed)   │
└──────────────────────────────────────────────────┘
```

## Data Flow

### Probe cycle

1. **Target list** is assembled from `known_addrs` (built-in or user-provided tuples of `(ident_hash_hex, i2p_dns_name)`).
2. **Hash → b32**: Each hash is converted to a `.b32.i2p` address via base32 encoding.
3. **Dual-mode probe**: The system attempts both `http://HASH.b32.i2p/` (direct key) and `http://NAME.i2p/` (DNS), recording which succeeded.
4. **Content extraction**: On success, the response body is parsed for `<title>`, size, and a keyword-based content classification pass.
5. **Persistence**: Results are written to three SQLite tables (`discoveries`, `routers`, `leasesets`) keyed by `ident_hash_hex`.
6. **Report generation**: `print_report()` renders a terminal summary; raw data remains queryable via SQL.

### Consolidated view (`address_book`)

For auditing, the `address_book` SQL view collapses all probe history into one row per "human identity." DNS name is primary (preferred for readability); b32 address is fallback when no DNS exists. Joined with `routers`/`leasesets` metadata. Access via `get_address_book()`  → `list[dict]`, or `print_address_book(entries)` for terminal output.

### Content classification and language detection pipeline

```
fetch_i2p() → Response.text
    │
    ├─► run_extractors()          ← plugin registry, BaseExtractor chain
    │   · can_handle()            ← first match wins
    │   · extract()               → (content_type, summary_lines, found_links)
    │
    └─► detect_language(title_text, body_text[:8192])  ← langid (local, no network)
        → (detected_lang, confidence)                   # e.g. ("de", 1.0)

    DiscoveryDB.record_discovery(content_type=..., content_summary=..., detected_lang=...)

### Async translation pass (post-probe, decoupled)

```
translate_summaries.py --ollama-url http://localhost:11434
    │
    ├─► get_pending_translations(db_path)              # reachable + non-EN + untagged
    │
    ├─► translate_text(text, source_lang, url)         # Ollama /api/generate (HY-MT2)
    │
    └─► build_translation_summary(original, translated, lang)
        → prepends [detected_language: XX], appends [original: …]
        → update_summary(db_path, id, new_summary)     # back to discoveries table
```

Translation runs as a **separate script** outside the probe sweep loop. This prevents translation failures from blocking probe workers and avoids polluting probe logs with LLM latency. Probe time only does language detection via `langid`.
```

Classification is intentionally **offline and heuristic-only**. No LLM call is made at probe time. Language detection uses `langid` (~1 MB model, CPU-only, zero network traffic). Non-English content is tagged with `[detected_language: XX (LanguageName)]` for auditability. Translation to English runs as a separate pass via `translate_summaries.py`, which connects to a local Ollama instance — still fully on-device per NFR-07 since no content leaves the host.

## Design Decisions and Rationale

| Decision | Rationale |
|---|---|
| Hash as primary key | `.b32.i2p` addresses are deterministic from the hash; no DNS lookup required. Far more reliable than SU3/SUSI hostname resolution. |
| SQLite WAL mode | Enables concurrent readers while writer holds lock — critical for long probe sessions with parallel analysis queries. |
| Dependency injection (`db_path`) | Eliminates global state, allowing pytest to create fresh temp databases per test without race conditions. |
| No Selenium/Playwright | I2P eepsites don't require JavaScript rendering for basic reachability checks. Pure HTTP is sufficient and dramatically faster/cheaper. |
| Keyword-based classification first | Keeps probe runtime predictable; avoids adding an LLM dependency to every fetch cycle. Post-hoc re-classification can batch-process the DB. |
| Separate `routers` / `leasesets` tables | Addressbook data (from `.rtr`/`.ls64` files) describes network topology, not endpoint behavior. Disjoint concerns warrant disjoint stores. |
|| DNS-first dedup in `address_book` view | Humans think in DNS names, not hashes. A site probed via two DNS names appears as two rows (separate entry points); b32-only probes fall back to the b32 address. Pivot to hash-based dedup if alias tracking proves unnecessary. |
|| Local language detection (`langid`) | No network dependency for detection. ~1 MB model, fast inference, reliable on HTML content that survives tag stripping. Confidence thresholds prevent false positives on short/mixed text. |
|| Translation decoupled from probe sweep (v0.4.5+) | Per NFR-07: crawled I2P content must never leave the host over non-I2P channels. `translate_summaries.py` uses a **local Ollama** endpoint (HY-MT2 model) so all translation stays on-device. Decoupling from probe prevents LLM latency from blocking workers and avoids silent failures in the main loop. |
|| Persistent `detected_lang` column | Structured language metadata enables filtering (e.g., "show all German sites"). Summary text gets `[detected_language: XX (LanguageName)]` prefix for auditability. |

## Language Detection Pipeline

### Module: `src/translation.py`

A post-extraction pipeline that detects the language of scraped page content using `langid` and **annotates** non-English summaries with a language tag. Runs in `_do_probe()` between content extraction and SQLite persistence. Translation is decoupled into `translate_summaries.py`, which processes tagged discoveries async via local Ollama — keeping probe workers unblocked and NFR-07 compliant.

| Entrypoint | Purpose | Depends On |
|---|---|---|
| `detect_language(title, body_text)` | Detect language from title + first 8192 chars of body text. Returns `(iso_code, confidence)`. Uses `langid.classify()` with negative-log-probability scoring normalized to thresholds (≤-50 → 1.0, ≤-20 → 0.7, else fallback). | `langid` (local, no network) |
| `process_content_for_language(title, summary_lines, detected_lang, confidence)` | Main pipeline: accepts pre-detected lang or detects itself → prepends `[detected_language: XX (LanguageName)]` tag to non-English summaries → returns `(tagged_lines, lang_code)`. Does **not** translate. Covers 29 languages via built-in `_LANG_NAMES`. | `detect_language` only |
| `reset_state()` | Clear global error flags for test isolation. | — |

### Integration in `_do_probe()` (line ~1640 of `src/integration.py`)

```
run_extractors() → ExtractorResult
       │
       ├─► detect_language(title_text, body_text)        # full page body
       │   → (det_lang, confidence)                       # e.g. ("de", 1.0)
       │
       └─► process_content_for_language(                     title=title_text,
           summary_lines=list(extractor_result.summary_lines),
           detected_lang=det_lang)
           → (tagged_summary_lines, final_lang_code)      # annotated, not translated
```

The tagged summary lines are joined with `"\n"` and stored in `content_summary`. The `detected_lang` ISO code is stored separately. Both are passed to `DiscoveryResult()` → `record_discovery()`.

#### SQL view annotation

The `address_book` view exposes `detected_lang_direct` (the latest non-null `detected_lang`) as a standalone column for programmatic filtering. Human-readable summaries include `(originally XX)` annotations — e.g., `... [forum] (originally de) 20.5KB in 5.4s — ...`.

### Deep Analysis Pipeline (post-probe, decoupled)

```
python3 -m src.deep_analysis --mode reachable [--limit N]
    │
    ├─► get_pending_analyses(db_path, mode)          # reachable + missing/stale analysis
    │
    ├─► analyze_site(body_text, ollama_url, model)   # Ollama /api/generate
    │   → {site_type, purpose, sections}              # structured JSON
    │
    └─► update_analysis(db_path, hash_hex, result_json, timestamp)
        → UPSERT deep_analysis column + last_analyzed_at
```

Deep analysis runs as a **separate script** outside the probe sweep loop. This prevents Ollama latency from blocking probe workers and keeps probe logs clean. The architecture mirrors `translate_summaries.py`: decoupled batch job, local-only LLM, graceful fallback on failure.

| Entrypoint | Purpose | Depends On |
|---|---|---|
| `get_pending_analyses(db_path, mode)` | Query targets needing analysis by mode (`reachable`, `stale`). Returns list of `(hash_hex, body_text)` pairs. | `DiscoveryDB` |
| `analyze_site(body_text, url, model)` | Strip HTML tags, truncate to 4096 chars, POST to Ollama `/api/generate`. Retry with cooldown on error. | `urllib.request`, local Ollama |
| `update_analysis(db_path, hash_hex, analysis_json, timestamp)` | Store JSON text in `deep_analysis` column; update `last_analyzed_at` epoch on targets table | `DiscoveryDB.sql_execute` |

**Configuration:**

| Setting | Default | Configurable Via | Purpose |
|---|---|---|---|
| Model name | `RogerBen/HY-MT2-1.8B:latest` | `--ollama-model` CLI flag, `OLLAMA_MODEL` env var | Future-proof model swapping without code changes |
| Ollama URL | `http://localhost:11434` | `--ollama-url` CLI flag, `OLLAMA_URL` env var | Match translation script convention |
| Request timeout | 30s | Code constant (can parameterize later) | Prevent hanging on slow inference |
| Body text limit | 4096 chars after tag strip | Code constant | Keep prompt tokens manageable for small models |
| Analysis prompt | `analysis_prompt.txt` in project root | `--prompt` CLI flag | Editable on-disk prompt template. Users tweak analysis behavior (fields, depth, language) without modifying Python source. Default shipped with repo covers site_type/purpose/sections. |

**Design rationale:**

| Choice | Reason |
|---|---|
| Decoupled from probe sweep | Same reason as translation: Ollama latency (2-5s) would multiply I2P latency (already 5-30s per site). Batch processing is efficient. |
| Default to HY-MT2 but configurable model | HY-MT2 is available now; `--ollama-model` flag and env var enable switching to larger models without touching code. |
| Store results as JSON text in discoveries | No schema migration needed for new fields — just parse the JSON when reading. Keeps it flexible as analysis prompt evolves. |
| Track `last_analyzed_at` on targets | Enables "stale analysis" detection. Sites probed 30+ days ago can be re-analyzed without re-probing. |

### Configuration and thresholds

| Setting | Source | Value | Purpose |
|---|---|---|---|
| Error suppression (detection) | Global `_detect_error` | `False` default | After first langid failure, all subsequent calls return `('en', 1.0)` — prevents repeated library failures |
| Confidence threshold | `min_confidence=0.4` param | 0.4 | Below this, detection defaults to English to avoid noisy false positives on sparse content |
| Short text skip (detection) | Hardcoded in `detect_language()` | `< 30 chars` | Combined title+body shorter than 30 chars is too unreliable — assume English |

### Graceful degradation

Detection failures never break probing:

- **Library unavailable** (e.g., import fails) → `('en', 1.0)` returned, detection suppressed entirely
- **Short strings (<30 chars)** → skipped entirely, treated as English
- **Low-confidence detection** → treated as English (`conf < 0.4`)
- **Exception in `_do_probe()` detection block** → probe still succeeds, `detected_lang` defaults to `"en"`, original summary preserved

### Design rationale

| Choice | Reason |
|---|---|
|| Language detection at probe time, translation async | Detection (`langid`) lives in `_do_probe()` — fast, reliable, no LLM. Translation runs post-sweep via `translate_summaries.py` + local Ollama (HY-MT2). Decoupling prevents blocking workers and keeps probe logs clean. Still fully on-device per NFR-07. |
| Full body for detection, not just summary | Title + 8KB of raw page text gives `langid` far more signal than summary lines alone — reduces false positives on mixed-language or short extracted summaries. |
| Language tag in summary text | Humans auditing address_book can immediately see which entries are non-English without querying the DB directly. |
| 29-language name mapping | Covers most languages likely encountered on I2P. Unknown codes still show ISO code without English name — graceful fallback. |
| Persistent `detected_lang` column | Enables structured queries (e.g., "show all non-English destinations") without parsing summary text. Supports future features like per-language probe prioritization. |
| Fallback to English on low confidence | Prevents false positives on short/mixed-language content that `langid` can't reliably classify. Safer than tagging uncertain content as foreign. |

### Translation via `translate_summaries.py` (live)

Translation is implemented as a standalone script that connects to a **local Ollama** endpoint, keeping all processing on-device per NFR-07:

```
python3 translate_summaries.py --ollama-url http://localhost:11434 [--dry-run] [--limit N] [--lang ru]
```

Key functions:
- `get_pending_translations()` — queries discoveries with `reachable=1`, non-English `detected_lang`, no translation markers already present
- `_needs_translation()` — checks summary text for `[detected_language:` / `[original:` patterns (idempotent)
- `build_translation_summary()` — prepends language tag, appends `[original: ...]` to translated line
- `translate_text()` — POSTs to Ollama `/api/generate` with HY-MT2 model; 5-minute cooldown on errors

The script is fully decoupled from the probe sweep. It can run independently at any time and safely skips already-translated entries. Per-request timeout defaults to 30s to avoid blocking on slow LLM inference.

## Configuration

Proxy endpoints are centralized in `I2PConfig` (`src/config.py`). Defaults match a standard I2P router:

| Setting | Default | Notes |
|---|---|---|
| `http_host` / `http_port` | 127.0.0.1 : 4444 | HTTP CONNECT proxy (primary) |
| `socks_host` / `socks_port` | 127.0.0.1 : 7656 | SOCKS5 fallback |
| `sam_host` / `sam_port` | 127.0.0.1 : 9025 | SAM v3.x (not exposed by Docker daemon) |
| `webconsole_host` / `webconsole_port` | 127.0.0.1 : 7657 | Java web console (reference only; CSRF-protected, not scrapable) |

All credentials (tokens, tunnel keys, passwords) must be parameterized and never committed to version control.

## Website Export Pipeline

The `export` subcommand transforms probe results into static files suitable for hosting as an I2P eepsite — browseable without any server-side runtime.

### Workflow

```
probe_sweep.py export
  │
  ├─► get_address_book(db_path)          ← reads address_book SQL view
  │                                     ← one row per identity, latest probe only
  │
  ├─► generate_address_book_html()       → website/address_book.html
  │   · transforms rows (humanize bytes, format times)
  │   · embeds dataset as JSON inside HTML template
  │   · single file: dark theme, sortable grid, filter, pagination
  │
  └─► generate_address_book_txt()        → website/address_book_hosts.txt
      · sorts by dns_name
      · hosts.txt format: dns=*.b32.i2p per entry
      · comment lines with [OK]/[DOWN] status + probe timestamp
```

### Design rationale

| Choice | Reason |
|---|---|
| Single self-contained HTML file | No external dependencies — works offline, on any static server, and trivially hostable as an I2P eepsite. Embedded JSON keeps the dataset in-memory for instant filtering/sorting. |
| Dark theme, fixed-width grid | I2P browsing is often done in low-bandwidth environments; minimal CSS reduces download size. Fixed column widths prevent layout shift during sort/filter operations. |
| TXT matches hosts.txt format | The `dns=address` line format matches what SUSI DNS export produces, making the file compatible with existing I2P tooling for router imports and address reconciliation. |
| Generated output never committed | `website/` is in `.gitignore`. Re-generating after each sweep ensures files reflect the latest probe state without stale data in version control. |

### SQL view → HTML columns mapping

The `address_book` view (defined in `src/integration.py`, line ~828) provides these columns to the HTML grid:

| View column | HTML grid column | Transform |
|---|---|---|
| `reachable` | Status | `OK` / `DOWN` with color coding |
| `content_type` | Type | raw value (e.g. `forum`, `blog`) |
| `dns_name` | Site | raw DNS or b32 fallback |
| `title` | Title | extracted page title, ellipsis overflow |
| `response_time_sec` | Resp T | formatted as `X.Xs` (empty when null) |
| `body_length` | Size | humanized bytes (`B`, `KB`, `MB`) |
| `last_probed_utc` | Last Probed | ISO datetime string |
| `routers.bandwidth_kbps` | Bandwidth | raw value from routers table join |
| `found_links` | #L | JSON array length (link count) |

### Size considerations

For the current dataset (~1500 destinations):

- **HTML**: ~300–600 KB depending on dataset size and summary text lengths. The embedded JSON payload is the main contributor.
- **TXT**: ~100–300 KB, roughly 2 lines per entry (comment + data).

These sizes are acceptable for I2P eepsite hosting — most users access these files locally over the tunnel, not over high-latency links. For datasets above 5000 entries, consider adding server-side pagination or splitting by `content_type`.

## Content Extraction Plugin System

### Why

I2P sites serve content through any Technology stack — forums on custom PHP frameworks, wikis with non-standard templates, static generators, binary APIs, JSON responders, raw text mirrors. A monolithic classifier that tries every detection heuristic in one giant function cannot adapt quickly to new site types. By the time someone writes a keyword rule for a new platform, three more variants appear behind closed tunnels.

The plugin system solves this by making content extraction **open-ended and self-healing**: new extractors are Python modules dropped into `src/ext_plugins/`. The sweeper auto-loads them on startup with zero configuration. When the analyzer inspects a poorly-understood destination, it generates a custom extractor tailored to that site's quirks — next sweep picks it up automatically.

### Architecture Diagram

```
┌──────────────┐     ┌─────────────────────┐     ┌─────────────────┐
│    Sweeper   │────►│  Extractor Registry  │────►│   Database      │
│ (integr.)    │     │  run_extractors()   │     │ DiscoveryDB.    │
└──────┬───────┘     └──────────┬──────────┘     └────────┬────────┘
       │                         │                          │
       │   ┌──────────────────────┤  (if no match / low quality)
       │   │                     ▼
       │   │             ┌─────────────┐
       │   │             │ needs_review│────────────► Flag in DB
       │   │             └──────┬──────┘
       │   │                    │
       │   │              ┌─────▼──────┐
       │   │              │ Analyzer   │  ← CLI: inspects flagged destinations
       │   │              │ (NEW)      │
       │   │              └─────┬──────┘
       │   │                    │  generates custom extractor .py
       │   │                    ▼
       │   │             ┌──────────────────┐
       │   └────────────►│ src/ext_plugins/ │  ← gitignored directory,
       │                 │ (auto-discovered) │    each .py = one extractor
       │                 └──────────────────┘
       │                         ▲ auto-loaded on next sweep start
       └─────────────────────────┘
```

### BaseExtractor Interface

Every content extractor inherits from `BaseExtractor` in `src/extractors.py`:

| Attribute / Method | Signature | Purpose |
|---|---|---|
| `priority` | `int = 100` | Lower = runs first. Built-in extractors override this to precede discovered plugins. |
| `can_handle(body, headers, status)` | `-> bool` | Inspect the raw response body text, HTTP headers, and status code. Return `True` only if this extractor knows how to process this content type. |
| `extract(title, body, headers)` | `-> (str, list[str], list[str])` | Produce a triple: `(content_type_bucket, summary_lines, linked_i2p_sites)`. If the extractor handles the response but yields little useful text, return a minimal `summary_lines` — the orchestrator detects partial extracts and sets `needs_review=True`. |

Minimal example skeleton:

```python
from src.extractors import BaseExtractor

class MyForumExtractor(BaseExtractor):
    priority = 90  # before default plugins, after built-in HTML

    def can_handle(self, body_text, headers, status_code):
        return '<div class="custom-forum-header">' in body_text

    def extract(self, title, body_text, headers):
        import re
        posts = [t.strip() for t in re.findall(r'<h3>(.+?)</h3>', body_text) if t.strip()]
        links = [m.group(1) for m in re.finditer(r'href="([^.]+\.i2p)"', body_text)]
        return ("forum", posts[:8], list(set(links)))
```

### Registry and Plugin Discovery

- **Registration**: The `_register` decorator (applied automatically — no manual step needed at the class level) appends an instance to the module-level `_registry`, sorted by `(priority, class_name)`.
- **Discovery**: `discover_plugins()` in `src/extractors.py` runs on import. It scans `src/ext_plugins/*.py`, skips files starting with `_`, then `importlib.import_module()` each candidate so that any `_register` calls inside fire immediately.
- **Ordering**: The orchestrator iterates the registry from lowest to highest priority. The first extractor whose `can_handle()` returns `True` wins — later extractors are not consulted for that response.
- **Priority convention**:

| Range | Who uses it |
|---|---|
| 0–49 | Built-in system extractors (HTML, plain text, known formats) |
| 50–99 | Statically authored extractors shipped with the repo |
| 100 | Default plugin priority (auto-generated or hand-written drop-ins) |
| 101+ | Fallback / catch-all patterns |

### Orchestrator (`run_extractors`)

The `run_extractors()` function in `src/extractors.py` is the entry point that replaces `_classify_content()` in the sweeper. It:

1. Iterates `_registry` from highest priority (lowest number) downward.
2. On the first `can_handle() → True`, calls `extract()` and validates the result.
3. Detects **partial extracts**: if body has >200 chars of text but the extractor returns <=1 summary line, it sets `needs_review=True` with reason `"partial_extract_only"`.
4. On any `no_extractor` scenario (nothing claimed), returns `ExtractorResult(needs_review=True, reason="no_extractor_claimed")`.
5. All extraction errors are caught per-extractor — a broken plugin never crashes the sweep.

### Component Responsibilities

| Component | File | Role |
|---|---|---|
| **Sweeper** | `src/integration.py` | Probes `.i2p` targets via HTTP proxy, collects response body + headers + status code, feeds them to `run_extractors()`. Records `ExtractorResult`, marks `needs_review` flags in SQLite. |
| **HtmlExtractor** (built-in) | `src/extractors.py` (or soon separate module) | Handles standard HTML pages: tag stripping, `<meta>` extraction, title enrichment, keyword-based bucket detection. Serves as the default "good enough" path. Priority < 100. |
| **Plugin extractors** | `src/ext_plugins/*.py` | Extractors generated by the analyzer or hand-written for specific sites. Zero config needed — drop a file, next sweep loads it. |
| **Analyzer** (NEW) | `analyzer.py` | CLI tool that inspects flagged destinations (`needs_review=True`). Performs a deeper probe with richer headers, body inspection, and LLM-assisted analysis to understand the site's structure. Outputs a new `.py` module into `src/ext_plugins/`. |

### The Feedback Loop

The plugin system creates an adaptive cycle:

```
Sweep probes → Extractors classify → Gaps detected (needs_review flag)
       ↑                                              │
       │                                              ▼
Next sweep auto-loads ─── Analyzer inspects & generates new extractors ──┘
```

1. The sweeper encounters a destination where no existing extractor claims the response, or an extractor produces only a partial result.
2. The row is flagged `needs_review=True` in the database with a reason code.
3. The user runs `analyzer.py --inspect <hash>` to probe the site more deeply (extra headers, full body dump, structural analysis).
4. The analyzer generates a Python module tailored to that site's DOM patterns or API response format and writes it into `src/ext_plugins/`.
5. On the next sweep, `discover_plugins()` picks up the new file automatically. No config edits, no restart of the daemon — the extractor is live in the registry.

### File Structure

```
src/
  extractors.py            ← BaseExtractor interface, registry, discover_plugins(),
                             run_extractors() orchestrator
  ext_plugins/             ← gitignored; auto-generated + hand-written extractor modules
                              (each *.py registers one or more BaseExtractor subclasses)
  integration.py           ← sweeper core: probe loop, fetch_i2p, _classify_content
                             (current keyword-based pass; gradually replaced by run_extractors())
analyzer.py                ← NEW: feedback-loop CLI tool; inspects flagged destinations,
                             generates new extractor modules into src/ext_plugins/
```

The `ext_plugins/` directory is in `.gitignore` — extractors generated for a specific network snapshot are considered runtime artifacts. If you discover a reusable pattern, copy the module into the main repo alongside a test case so it ships with upstream releases.
