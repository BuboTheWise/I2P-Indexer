# Database Schema Reference

The indexer uses a single SQLite file (`indexer.db`) with WAL journal mode. Four operational tables, auto-generated indexes, and a denormalized read view. Runtime database is in `.gitignore` — never committed to VCS.

## Table: `discoveries`

Stores the result of each probe attempt. One row per fetch — retries over time accumulate rows for the same destination.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | INTEGER | No (PK) | autoincrement | Surrogate key |
| `ident_hash_hex` | TEXT | No | — | 40-char SHA-1 identity hash (join key to `routers` / `leasesets`) |
| `b32_addr` | TEXT | No | — | Base32 address URL (`*.b32.i2p`) |
| `i2p_dns_name` | TEXT | Yes | `''` | Human-readable `.i2p` DNS name (e.g., `i2p-projekt.i2p`) |
| `probe_mode` | TEXT | No | — | Address type used: `'b32'` or `'dns'` |
| `reachable` | INTEGER | No | — | `1` = success, `0` = dead/error |
| `status_code` | INTEGER | Yes | `0` | HTTP response code (0 on network-level failure) |
| `body_length` | INTEGER | Yes | `0` | Response body size in bytes |
| `title` | TEXT | Yes | `''` | Extracted `<title>` tag text |
| `response_time` | REAL | Yes | `0.0` | Fetch latency in seconds |
| `via_method` | TEXT | Yes | `''` | Path that succeeded: `'b32'`, `'dns'`, or `'b32+dns'` |
| `content_type` | TEXT | Yes | `''` | Content bucket label (e.g., `"forum"`, `"news site"`) |
| `content_summary` | TEXT | Yes | `''` | Sentence-length description of page content. Non-English summaries are annotated with `[detected_language: XX (LanguageName)]` prefix for auditability. |
| `detected_lang` | TEXT | Yes | `''` (SQL) / `en` (runtime) | ISO 639-1 language code detected by `langid` (e.g., `de`, `ja`, `ru`). Runtime returns `en` as fallback on detection failure or text too short. Re-probes always re-detect — language drift is auto-corrected on the next sweep pass. |
| `content_hash` | TEXT | Yes | `''` | SHA-256 hash of response body for change detection |
| `last_modified` | TEXT | Yes | `''` | HTTP `Last-Modified` header value (if present) |
| `found_links` | TEXT | Yes | `'[]'` | JSON array of `.i2p` hostnames found in page content |
| `flags` | TEXT | Yes | `'[]'` | Free-form JSON array for arbitrary analysis notes (robots.txt quirks, tech stack fingerprints, contact signals) |
| `deep_analysis` | TEXT | Yes | `''` | JSON text from LLM deep analysis pass (site type, purpose, sections). Empty when not yet analyzed. Written by `src/deep_analysis.py`. Prompt loaded from `analysis_prompt.txt` on disk — editable without modifying Python source. |
| `error_msg` | TEXT | Yes | `''` | Error description on failure |
| `body_html` | TEXT | Yes | `''` | Cached HTML body for LLM deep analysis pipelines. Populated during probe or fetched on-demand via `src/deep_analysis.py` proxy client. |
| `probed_at` | REAL | Yes | `strftime('%s','now')` | Unix timestamp of probe |

### Flags JSON structure (WIP — heuristics coming in v2)

```json
[
  {"type": "robots_txt", "value": "disallow_all"},
  {"type": "tech_stack", "value": "wordpress/6.4"},
  {"type": "contact_signal", "value": "pgp_key_found"},
  {"type": "proxy_indicator", "value": "cloudflare"}
]
```

### Indexes

```sql
CREATE INDEX idx_disc_hash ON discoveries(ident_hash_hex);
CREATE INDEX idx_disc_dns  ON discoveries(i2p_dns_name);
```

---

## Table: `targets`

The authoritative target list for discovery sweeps. All probing sources (well-known defaults, addressbook ingest, manual seeds) upsert here first; the discovery loop reads from this table instead of hardcoded Python lists.

| Column | Type | PK | Default | Description |
|---|---|---|---|---|
| `id` | INTEGER | Yes (autoincrement) | — | Surrogate key |
| `ident_hash_hex` | TEXT | No (part of UNIQUE) | `''` | SHA-1 hash (empty for DNS-only seeds) |
| `b32_addr` | TEXT | No | `''` | Computed Base32 address from hash, or DNS name if no hash |
| `i2p_dns_name` | TEXT | No (part of UNIQUE) | `''` | Human-readable `.i2p` DNS name |
| `last_probed_at` | REAL | No | `0` | Unix timestamp of last probe |
| `source` | TEXT | No | `'manual'` | Origin: `'manual'`, `'addressbook'`, `'linked'` (auto-seeded) |
| `source_site` | TEXT | No | `''` | When `source='linked'`, the `.i2p` hostname of the parent site that discovered this target |
| `susi_active` | INTEGER | No | `0` | Whether destination appears active in SUSI DNS export |
| `first_seen_at` | REAL | No | `0` | Unix timestamp when target was first inserted |
| `last_updated_at` | REAL | No | `0` | Unix timestamp of last upsert / refresh |
| `consecutive_failures` | INTEGER | No | `0` | Count of consecutive probe failures — resets to 0 on success |
| `backoff_until` | REAL | No | `0` | Unix timestamp until which this target is excluded from sweeps. Uses exponential backoff: 60s → 300s → 1800s → 7200s → 43200s → capped at 604800s (7 days) |
| `last_analyzed_at` | REAL | No | `0` | Unix timestamp of last LLM deep analysis. Zero means never analyzed. Updated by `src/deep_analysis.py`. Enables stale-analysis detection. |
| `dest_data` | TEXT | No | `''` | Raw SUSI base64 destination blob for the target's identity. Populated automatically after successful b32 probes by querying the local router's internal DNS cache (`/susidns/export?book=router`). Used by `address_book_hosts.txt` exports so I2P routers can import entries directly without resolution. |

### Auto-seeding flow

When a probe succeeds and extracts `.i2p` links from page content:
1. Links are parsed via `_extract_i2p_links()` (regex for `*.i2p` hostnames)
2. New targets inserted via `upsert_targets_from_links(links, source_site=parent)` with `source='linked'`
3. Existing DNS names deduplicated — no duplicate probes
4. Next sweep run includes auto-seeded targets in the queue

#### Target queue ordering

`get_targets()` returns targets ordered by priority:

1. **Previously reachable first** — destinations with any `reachable=1` discovery record come before those never reached
2. **Valid b32 hash next** — among equal reachability tier, 40-char hashes (capable of direct b32 probing) before DNS-only
3. **Oldest probes first** — within same tier, targets with earlier `last_probed_at` get refreshed sooner

This means each sweep re-probes previously reachable sites first (highest success rate), then moves to unprobed territory.

#### Adaptive backoff

After every probe, `consecutive_failures` and `backoff_until` are updated via `DiscoveryDB.update_backoff_state()`. On failure the counter increments and the target is excluded from the next sweep for an exponentially growing interval:

| Consecutive failures | Backoff interval |
|---|---|
| 1 | 60 seconds |
| 2 | 5 minutes |
| 3 | 30 minutes |
| 4 | 2 hours |
| 5 | 12 hours |
| ≥6 | 7 days (hard cap) |

On success, `consecutive_failures` resets to 0 and `backoff_until` clears to 0. Target ordering (`get_targets()`) applies the backoff filter by default so sweep runs skip targets in their cooldown window. Use `--no-backoff` on the CLI or `skip_backoff=False` in code to force-probe everything regardless of backoff state.

```python
# Manual seeding
db.upsert_targets([
    ("F95763B5...", "su3-directory.i2p"),
    ("", "mail.i2pmail.org"),
])

# Auto-seeding (internal — called during probe loop)
db.upsert_targets_from_links(
    linked_sites=["shop.i2p", "wiki.i2p-projekt.i2p"],
    source_site="i2p-projekt.i2p",
)

# Read back for scanning (priority-ordered)
targets = db.get_targets()  # -> list[tuple[hash_hex, dns_name]]
```

---

## Table: `routers`

Parsed from `.rtr` files in the I2P `netdb/` directory. One row per known router identity. UPSERT on `ident_hash_hex`.

| Column | Type | PK | Default | Description |
|---|---|---|---|---|
| `ident_hash_hex` | TEXT | Yes | — | SHA-1 identity hash |
| `key_type` | INTEGER | No | `0` | Key algorithm (1=ElGamal, 3=ECIES) |
| `version` | INTEGER | No | `0` | Router protocol version |
| `bandwidth_kbps` | INTEGER | No | `0` | Advertised bandwidth capacity |
| `options_mask` | INTEGER | No | `0` | Transport capability bitmask |
| `caps` | TEXT | No | `''` | Capability string (e.g., `"fR4"`) |
| `published` | INTEGER | No | `0` | Whether router is published to netdb |
| `file_size` | INTEGER | No | `0` | Raw `.rtr` file size in bytes |
| `i2p_dns_name` | TEXT | No | `''` | Associated DNS name (if known) |
| `source` | TEXT | No | `'probe'` | Origin: `"probe"`, `"netdb"`, etc. |
| `updated_at` | REAL | No | now | Last update timestamp |

---

## Table: `leasesets`

Parsed from `.ls64` files in the I2P `netdb/` directory. One row per lease set identity. UPSERT on `ident_hash_hex`.

| Column | Type | PK | Default | Description |
|---|---|---|---|---|
| `ident_hash_hex` | TEXT | Yes | — | SHA-1 destination hash |
| `store_type` | INTEGER | No | `0` | NETDB store type enum |
| `num_leases` | INTEGER | No | `0` | Number of leases in set |
| `options_mask` | INTEGER | No | `0` | Lease set options bitmask |
| `leases_v1_count` | INTEGER | No | `0` | V1 tunnel lease count |
| `file_size` | INTEGER | No | `0` | Raw `.ls64` file size in bytes |
| `i2p_dns_name` | TEXT | No | `''` | Associated DNS name (if known) |
| `source` | TEXT | No | `'unknown'` | Origin of data |
| `updated_at` | REAL | No | now | Last update timestamp |

---

## Sweep Execution Model — CLI-First, User-Controlled

The system is **CLI-driven with no background daemons or implicit schedulers**. The user invokes sweeps explicitly. Internal state computes priority scores but never auto-triggers probes.

```bash
python3 probe_sweep.py                      # full sweep, 5s delay between probes
python3 probe_sweep.py --dry-run            # show targets without probing
python3 probe_sweep.py --delay 10           # longer cooldown (slow I2P network)
python3 probe_sweep.py --show-book          # print address book after sweep
python3 probe_sweep.py --respect-robots     # (future) filter targets by robots.txt disallow rules
```

### Design assumptions

- **Targets are frequently unavailable or extremely slow** — this is the default operating condition, not an edge case. Probing logic assumes 50%+ failure rate.
- **Robots.txt ignored by default** — we are building an index, not a polite web crawler. A `--respect-robots` flag exists for users who want to honor disallow rules. Without it, all targets are probed regardless of robots.txt.
- **Sequential execution only** — one probe at a time with a hard `time.sleep()` cooldown between probes. No concurrency or futures.
- **Defensive error handling** — failed probes increment counters but never crash the sweep. Timeout defaults are generous (60s) to accommodate I2P's slow tunnel establishment.
- **Rate limiting policy deferred** — re-probe intervals and backoff algorithms will be derived from empirical sweep data after initial manual runs.

### First sweep results (47 targets, July 31 2026)

| Metric | Count | Percentage |
|---|---|---|
| Probed | 47 | — |
| Reachable | 3 | 6.4% |
| Unavailable (502/timeout) | 44 | 93.6% |

Three sites responded: `i2p-projekt.i2p`, `mail.i2pmail.org`, `wiki.i2p-projekt.i2p`. All others returned 502 Domain Not Found (<1s) or gateway timeout (60s). Five new targets auto-seeded from discovered links. This confirms the "assume high unavailability" design assumption.

---

## View: `address_book`

A denormalized SQL view that collapses multi-row probe history into one row per "human identity." It is the primary read surface for auditing what we know about each destination and will serve as the data source for the web UI.

### Dedup key

The view uses a two-tier dedup strategy:
1. **When `i2p_dns_name` is present and non-empty** → the DNS name becomes the unique identity (e.g., `i2p-projekt.i2p`).
2. **When `i2p_dns_name` is empty** → falls back to `b32_addr`.

A site probed via both `test.i2p` and its raw b32 address appears as two rows — they represent distinct entry points. Two probes for the same DNS name collapse into one (the latest).

**Cross-probe coalescing:** `b32_addr` and `i2p_dns_name` are aggregated across all probe modes (`b32` and `dns`) using SQL window functions (`MAX(...) OVER (PARTITION BY ...)`). This means even if the most recent probe is DNS-only, the row still carries the b32 address from an earlier b32-mode probe — and vice versa. Every reachable site in the view has both identifiers populated.

### Columns (28 total) — human-readable first, technical at end

| Column | Source | Description |
|---|---|---|
| `dns_name` | computed (`CASE` + window coalesce) | Human-readable identity label — coalesced across probe modes |
| `content_type` | computations | Computed content classification |
| `reachable` | discoveries (latest) | 1 = UP, 0 = DOWN |
| `last_probed_utc` | computed (`datetime()`) | Human-readable UTC timestamp |
| `content_summary` | computations | Natural-language summary (may include `[detected_language: XX]` prefix) |
| `deep_site_type` | JSONEXTRACT on `deep_analysis` | LLM-classified site type (e.g., `"news site"`, `"forum"`) |
| `deep_purpose` | JSONEXTRACT on `deep_analysis` | LLM-generated purpose summary (truncated to 200 chars) |
| `deep_analyzed_at` | correlated subquery | Timestamp of most recent deep analysis run (`MAX(probed_at)` where `deep_analysis IS NOT NULL`) |
| `detected_lang` | discoveries (latest) | ISO 639-1 language code. **Updated on every re-probe** — language drift is auto-detected; sites that change language are picked up by the translation pipeline without manual intervention |
| `ident_hash_hex` | discoveries → routers/leasesets join | SHA-1 destination hash |
| `b32_addr` | window coalesce across probes | Base32 address — always populated if any probe resolved it |
| `status_code` | discoveries (latest) | HTTP status code or 0 |
| `body_length` | discoveries (latest) | Response body size in bytes |
| `title` | discoveries (latest) | Extracted page title |
| `response_time_sec` | discoveries (latest) | Round-trip time in seconds |
| `via_method` | discoveries (latest) | How we reached it (`b32`, `dns`) |
| `last_probed_at` | discoveries (latest) | Unix epoch seconds |
| `content_hash` | discoveries (latest) | SHA-256 hash of response body |
| `last_modified` | discoveries (latest) | HTTP Last-Modified header |
| `found_links` | discoveries (latest) | JSON array of `.i2p` hostnames |
| `flags` | discoveries (latest) | JSON array of analysis notes (robots.txt, tech stack, etc.) |
| `needs_review` | discoveries (latest) | Boolean flag for destinations flagged for manual review |
| `interest_score` | JSONEXTRACT on `deep_analysis` | Integer 1–5 from LLM analysis indicating overall site importance/priority |
| `interest_reasons` | JSONEXTRACT on `deep_analysis` | JSON array of reasons the LLM assigned the interest score |
| `content_depth` | computed | Numeric metric combining found link count and body length — rough proxy for content richness |
| `stability_index` | `routers` × `leasesets` × response_time | Composite reachability score: `(bandwidth_kbps × num_leases) / (response_time + 1)` |
| `deep_analysis` | discoveries (latest) | Full JSON payload from LLM deep analysis pass |
| `bandwidth_kbps` | routers (LEFT JOIN) | Advertised bandwidth |
| `router_caps` | routers (LEFT JOIN) | Capability string (e.g., `"fR4"`) |
| `num_leases` | leasesets (LEFT JOIN) | Active lease count |

**Browse UI features (v0.4.6+):**
- Clickable "Visit" links (`dns_name` and `b32_addr`) in expanded detail panels — open I2P destinations directly when browser proxy is configured.
- Collapsible raw JSON analysis panel (`deep_analysis`) for on-demand inspection without DOM bloat.
- Filter sidebar with "Site Type" dropdown and "Analysed After" date picker.

### Programmatic access

```python
from src.integration import get_address_book, print_address_book

entries = get_address_book()          # list[dict]  — ready for JSON/web export
print_address_book(entries)           # human-readable table to stdout
```

---

## Entity Relationship Diagram

```
  ┌──────────────┐       ┌────────────────┐       ┌──────────────┐
  │    targets   │       │      routers   │       │   leasesets  │
  ├──────────────┤       ├────────────────┤       ├──────────────┤
  │ PK id        │       │ PK ident_hash  │◄──────│ PK ident_hash│
  │ ident_hash   │─ ─ ─→│  bandwidth     │       │  num_leases  │
  │ b32_addr     │       │  caps          │       └──────────────┘
  │ i2p_dns_name │       └───────┬────────┘              ▲
  │ source       │               │                        │
  │ source_site  ← provenance    │ JOIN ON ident_hash     │
  └──────────────┘               ▼                        │
                                ┌──────────────────────┐  │
           (probes feed back   │      discoveries     │───┘
              to targets)      ├──────────────────────┤
                               │ id (auto PK)         │
                               │ ident_hash → join    │
                               │ b32, dns_name        │
                               │ reachable, status    │
                               │ title, resp_time     │
                               │ content_type/summary │
                               │ content_hash, modified│
                               │ found_links, flags   │
                               │ error_msg, probed_at │
                               └──────────┬───────────┘
                                          │ WINDOW + JOIN
                                          ▼
                                  ╔═══════════════════╗
                                  ║ address_book VIEW ║  (source_site pending)
                                  ╚═══════════════════╝
                                       1 row / identity
```

**Key relationships:**
- `targets` → `discoveries`: targets feed the probe loop; discoveries auto-seed new targets via link extraction
- `discoveries` → `routers/leasesets`: join on `ident_hash_hex` for network metadata
- `address_book` view: denormalized read surface, one row per identity (latest probe wins) — future web UI data source

