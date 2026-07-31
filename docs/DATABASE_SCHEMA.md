# Database Schema Reference

The indexer uses a single SQLite file (`indexer.db`) with WAL journal mode. Three operational tables plus auto-generated indexes.

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
| `content_summary` | TEXT | Yes | `''` | Sentence-length description of page content |
| `error_msg` | TEXT | Yes | `''` | Error description on failure |
| `probed_at` | REAL | Yes | `strftime('%s','now')` | Unix timestamp of probe |

### Indexes

```sql
CREATE INDEX idx_disc_hash ON discoveries(ident_hash_hex);
CREATE INDEX idx_disc_dns  ON discoveries(i2p_dns_name);
```

### Example queries

**Most recent reachability status per destination:**
```sql
SELECT DISTINCT ON (ident_hash_hex)
    ident_hash_hex, i2p_dns_name, reachable, content_type, probed_at
FROM discoveries
ORDER BY ident_hash_hex, probed_at DESC;
```

**Sites that went offline since last probe:**
```sql
SELECT d1.ident_hash_hex, d1.i2p_dns_name
FROM discoveries d1
JOIN (
    SELECT DISTINCT ON (ident_hash_hex)
        ident_hash_hex, reachable, probed_at
    FROM discoveries
    ORDER BY ident_hash_hex, probed_at DESC
) d2 ON d1.ident_hash_hex = d2.ident_hash_hex
WHERE d2.reachable = 0;
```

**Reachability over time:**
```sql
SELECT datetime(probed_at, 'unixepoch') AS when,
       i2p_dns_name,
       reachable, status_code
FROM discoveries
ORDER BY ident_hash_hex, probed_at;
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

## Entity Relationship Diagram

```
  ┌──────────────────────┐       ┌────────────────────────┐
  │      routers         │       │        leasesets        │
  ├──────────────────────┤       ├────────────────────────┤
  │ PK ident_hash_hex    │◄──────│ PK ident_hash_hex      │
  │  key_type            │       │  store_type             │
  │  bandwidth_kbps      │       │  num_leases             │
  │  caps, published     │       │  leases_v1_count        │
  └──────────────────────┘       └────────────────────────┘
         │                               │
         │  JOIN ON ident_hash_hex       │
         ▼                               ▼
  ┌───────────────────────────────────────────────┐
  │                   discoveries                 │
  ├───────────────────────────────────────────────┤
  │ id (autoincrement surrogate key)              │
  │ ident_hash_hex → JOIN to routers/leasesets   │
  │ b32_addr, i2p_dns_name                       │
  │ reachable, status_code, body_length           │
  │ title, response_time, via_method             │
  │ content_type, content_summary                │
  │ error_msg, probed_at                         │
  │ IDX on ident_hash_hex, i2p_dns_name          │
  └───────────────────────────────────────────────┘
```

**Key relationships:**
- `discoveries` is the write-heavy table (one row per probe attempt).
- `routers` and `leasesets` are upsert-on-hash (network topology — stable, rarely changes per run).
- All three join on `ident_hash_hex`.
