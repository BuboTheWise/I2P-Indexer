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

### Content classification pipeline

```
fetch_i2p() → Response.text
    │
    ├─► _TAG_RE.sub()          ← strip HTML tags
    ├─► type_keywords match    ← bucket detection (forum, wiki, blog...)
    └─► title extraction       ← summary string construction
           │
           ▼
    DiscoveryDB.record_discovery(content_type=..., content_summary=...)
```

Classification is intentionally **offline and heuristic-only**. No LLM or network call is made at probe time. The `content_type` and `content_summary` fields are designed for later re-classification by an LLM pass that reads from the SQLite store directly.

## Design Decisions and Rationale

| Decision | Rationale |
|---|---|
| Hash as primary key | `.b32.i2p` addresses are deterministic from the hash; no DNS lookup required. Far more reliable than SU3/SUSI hostname resolution. |
| SQLite WAL mode | Enables concurrent readers while writer holds lock — critical for long probe sessions with parallel analysis queries. |
| Dependency injection (`db_path`) | Eliminates global state, allowing pytest to create fresh temp databases per test without race conditions. |
| No Selenium/Playwright | I2P eepsites don't require JavaScript rendering for basic reachability checks. Pure HTTP is sufficient and dramatically faster/cheaper. |
| Keyword-based classification first | Keeps probe runtime predictable; avoids adding an LLM dependency to every fetch cycle. Post-hoc re-classification can batch-process the DB. |
| Separate `routers` / `leasesets` tables | Addressbook data (from `.rtr`/`.ls64` files) describes network topology, not endpoint behavior. Disjoint concerns warrant disjoint stores. |

## Configuration

Proxy endpoints are centralized in `I2PConfig` (`src/config.py`). Defaults match a standard I2P router:

| Setting | Default | Notes |
|---|---|---|
| `http_host` / `http_port` | 127.0.0.1 : 4444 | HTTP CONNECT proxy (primary) |
| `socks_host` / `socks_port` | 127.0.0.1 : 7656 | SOCKS5 fallback |
| `sam_host` / `sam_port` | 127.0.0.1 : 9025 | SAM v3.x (not exposed by Docker daemon) |
| `webconsole_host` / `webconsole_port` | 127.0.0.1 : 7657 | Java web console (reference only; CSRF-protected, not scrapable) |

All credentials (tokens, tunnel keys, passwords) must be parameterized and never committed to version control.
